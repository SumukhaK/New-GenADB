package engine

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// tunnel is a resumable, reliable byte stream between the desktop and the
// device agent that outlives individual relay/LAN connections. Both ends keep
// unacknowledged bytes; after a reconnect ("rejoin", authenticated with the
// session's resumption key and fresh per-epoch AEAD keys) each side resends
// from the offset the peer reports. adb never sees the network change.

const (
	recData = 1
	recAck  = 2
	recFin  = 3
	// recClose (v1.1.0+) ends the tunnel on purpose; the payload is a short
	// reason. The receiver closes without trying to rejoin.
	recClose = 4

	maxUnacked   = 16 << 20
	ackEvery     = 128 << 10
	rejoinWindow = 90 * time.Second // covers a minute-long radio loss plus dead-peer detection

	// End-to-end liveness. Relays, tunnels and carrier NATs can keep one leg
	// of a spliced path open after the other leg died (a phone losing its
	// cellular link for 40 s left the desktop leg healthy and the session
	// silently stuck). Each side sends a keepalive inside the secure channel
	// when it has written nothing for a while, and treats a path on which it
	// has received nothing for deadPeerAfter as broken, which triggers the
	// normal authenticated rejoin.
	keepaliveEvery = 5 * time.Second
	deadPeerAfter  = 20 * time.Second
)

type tunnel struct {
	sid       []byte
	resumeKey []byte
	initiator bool
	local     net.Conn

	mu       sync.Mutex
	cond     *sync.Cond
	conn     *secureConn
	epoch    int
	sendBuf  []byte
	sendBase uint64 // offset of sendBuf[0]
	sentNext uint64 // next offset to transmit on the current conn
	localEOF bool
	finSent  bool
	recvNext uint64
	unacked  int // bytes received since last ACK
	closed   bool
	broken   chan struct{} // signalled when current conn fails
	lastRecv time.Time     // last record received on the current conn

	peerCaps   []string
	peerReason string // reason the peer gave in a close record ("" = none)
}

func newTunnel(sc *secureConn, local net.Conn, initiator bool) *tunnel {
	t := &tunnel{sid: sc.sid, resumeKey: sc.resumeKey, initiator: initiator, local: local,
		broken: make(chan struct{}, 1), peerCaps: sc.peerCaps}
	t.cond = sync.NewCond(&t.mu)
	t.attach(sc, 0)
	return t
}

func (t *tunnel) sendEnd() uint64 { return t.sendBase + uint64(len(t.sendBuf)) }

// attach installs a new underlying connection; peerRecv is how much of our
// stream the peer has already received.
func (t *tunnel) attach(sc *secureConn, peerRecv uint64) {
	t.mu.Lock()
	t.conn = sc
	t.lastRecv = time.Now()
	t.epoch++
	ep := t.epoch
	t.ackLocked(peerRecv)
	t.sentNext = t.sendBase
	if peerRecv > t.sentNext {
		t.sentNext = peerRecv
	}
	t.finSent = false
	t.cond.Broadcast()
	t.mu.Unlock()
	go t.reader(sc, ep)
}

func (t *tunnel) ackLocked(off uint64) {
	if off > t.sendBase && off <= t.sendEnd() {
		t.sendBuf = t.sendBuf[off-t.sendBase:]
		t.sendBase = off
		if len(t.sendBuf) == 0 {
			t.sendBuf = nil
		}
		t.cond.Broadcast()
	}
}

func (t *tunnel) fail(ep int) {
	t.mu.Lock()
	if ep == t.epoch && t.conn != nil {
		t.conn.Close()
		t.conn = nil
		select {
		case t.broken <- struct{}{}:
		default:
		}
	}
	t.cond.Broadcast()
	t.mu.Unlock()
}

func (t *tunnel) close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	if t.conn != nil {
		t.conn.Close()
	}
	t.cond.Broadcast()
	t.mu.Unlock()
	t.local.Close()
	select {
	case t.broken <- struct{}{}:
	default:
	}
}

// closeWith ends the tunnel on purpose and, when the peer understands it,
// tells it why so it does not try to rejoin.
func (t *tunnel) closeWith(reason string) {
	t.mu.Lock()
	c := t.conn
	t.mu.Unlock()
	if c != nil && hasCap(t.peerCaps, capClose) {
		c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		c.Write(record(recClose, 0, []byte(reason)))
	}
	t.close()
}

// PeerReason is the reason the peer gave for closing ("" if it did not).
func (t *tunnel) PeerReason() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.peerReason
}

func cleanReason(b []byte) string {
	if len(b) > 128 {
		b = b[:128]
	}
	out := make([]rune, 0, len(b))
	for _, r := range string(b) {
		if r >= 0x20 && r != 0x7f {
			out = append(out, r)
		}
	}
	return string(out)
}

func record(typ byte, off uint64, payload []byte) []byte {
	b := make([]byte, 9+len(payload))
	b[0] = typ
	binary.BigEndian.PutUint64(b[1:], off)
	copy(b[9:], payload)
	return b
}

// run pumps data until the tunnel closes. reconnect is called (initiator
// side) whenever the underlying connection breaks; responders just wait for
// the peer to rejoin.
func (t *tunnel) run(reconnect func(t *tunnel) error) {
	go t.localReader()
	go t.sender()
	go t.acker()
	go t.watchdog()
	for {
		<-t.broken
		t.mu.Lock()
		closed := t.closed
		finished := t.localEOF && t.finSent && t.sentNext >= t.sendEnd()
		t.mu.Unlock()
		if closed {
			return
		}
		if finished {
			t.close()
			return
		}
		deadline := time.Now().Add(rejoinWindow)
		if reconnect == nil {
			// responder: wait for a rejoin to attach a new conn
			for {
				t.mu.Lock()
				ok := t.conn != nil || t.closed
				t.mu.Unlock()
				if ok {
					break
				}
				if time.Now().After(deadline) {
					t.close()
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			continue
		}
		backoff := 100 * time.Millisecond
		started := time.Now()
		for attempt := 1; ; attempt++ {
			err := reconnect(t)
			if err == nil {
				if attempt > 1 {
					logf("tunnel resumed after %s (%d attempts)", time.Since(started).Round(time.Millisecond), attempt)
				}
				break
			}
			if errors.Is(err, errDenied) || time.Now().After(deadline) {
				logf("tunnel closed, cannot resume: %v", err)
				t.close()
				return
			}
			if attempt == 1 {
				logf("tunnel path broke; resuming (%v)", err)
			}
			time.Sleep(backoff)
			if backoff < 400*time.Millisecond {
				backoff *= 2
			}
		}
	}
}

func (t *tunnel) localReader() {
	buf := make([]byte, 256<<10)
	for {
		n, err := t.local.Read(buf)
		t.mu.Lock()
		if n > 0 {
			for len(t.sendBuf) > maxUnacked && !t.closed {
				t.cond.Wait()
			}
			t.sendBuf = append(t.sendBuf, buf[:n]...)
		}
		if err != nil {
			t.localEOF = true
		}
		t.cond.Broadcast()
		t.mu.Unlock()
		if err != nil {
			return
		}
	}
}

func (t *tunnel) sender() {
	for {
		t.mu.Lock()
		for !t.closed && (t.conn == nil || (t.sentNext >= t.sendEnd() && !(t.localEOF && !t.finSent))) {
			t.cond.Wait()
		}
		if t.closed {
			t.mu.Unlock()
			return
		}
		c, ep := t.conn, t.epoch
		var rec []byte
		if t.sentNext < t.sendEnd() {
			start := t.sentNext - t.sendBase
			end := start + maxFrame - 64
			if end > uint64(len(t.sendBuf)) {
				end = uint64(len(t.sendBuf))
			}
			rec = record(recData, t.sentNext, t.sendBuf[start:end])
			t.sentNext += end - start
		} else {
			rec = record(recFin, t.sendEnd(), nil)
			t.finSent = true
		}
		t.mu.Unlock()
		if _, err := c.Write(rec); err != nil {
			t.fail(ep)
		}
	}
}

// acker flushes cumulative ACKs for small trickles of data, sends keepalives
// (a repeated cumulative ACK is harmless) and detects a dead peer.
func (t *tunnel) acker() {
	tk := time.NewTicker(100 * time.Millisecond)
	defer tk.Stop()
	lastKeepalive := time.Now()
	for range tk.C {
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			return
		}
		c, ep, off, pend := t.conn, t.epoch, t.recvNext, t.unacked
		if pend > 0 && c != nil {
			t.unacked = 0
		}
		t.mu.Unlock()
		if c != nil && pend == 0 && time.Since(lastKeepalive) >= keepaliveEvery {
			pend = -1 // keepalive
		}
		if pend != 0 && c != nil {
			lastKeepalive = time.Now()
			if _, err := c.Write(record(recAck, off, nil)); err != nil {
				t.fail(ep)
			}
		}
	}
}

// watchdog declares the current path dead when nothing has arrived on it for
// deadPeerAfter. It never writes, so a write blocked on a dead path (full
// socket buffers) cannot stall detection.
func (t *tunnel) watchdog() {
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	for range tk.C {
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			return
		}
		ep, idle := t.epoch, time.Since(t.lastRecv)
		dead := t.conn != nil && idle > deadPeerAfter
		t.mu.Unlock()
		if dead {
			logf("tunnel peer silent for %s; treating path as broken", idle.Round(time.Second))
			t.fail(ep)
		}
	}
}

func (t *tunnel) reader(sc *secureConn, ep int) {
	buf := make([]byte, maxFrame+64)
	for {
		n, err := sc.ReadRecord(buf)
		if err != nil || n < 9 {
			t.fail(ep)
			return
		}
		typ, off, payload := buf[0], binary.BigEndian.Uint64(buf[1:9]), buf[9:n]
		t.mu.Lock()
		if ep == t.epoch {
			t.lastRecv = time.Now()
		}
		t.mu.Unlock()
		switch typ {
		case recData:
			t.mu.Lock()
			if off > t.recvNext {
				t.mu.Unlock()
				t.fail(ep)
				return
			}
			skip := t.recvNext - off
			if skip < uint64(len(payload)) {
				payload = payload[skip:]
			} else {
				payload = nil
			}
			t.mu.Unlock()
			if len(payload) > 0 {
				if _, err := t.local.Write(payload); err != nil {
					t.close()
					return
				}
				t.mu.Lock()
				t.recvNext += uint64(len(payload))
				t.unacked += len(payload)
				doAck := t.unacked >= ackEvery
				if doAck {
					t.unacked = 0
				}
				off := t.recvNext
				t.mu.Unlock()
				if doAck {
					if _, err := sc.Write(record(recAck, off, nil)); err != nil {
						t.fail(ep)
						return
					}
				}
			}
		case recAck:
			t.mu.Lock()
			t.ackLocked(off)
			t.mu.Unlock()
		case recClose:
			t.mu.Lock()
			t.peerReason = cleanReason(payload)
			if t.peerReason == "" {
				t.peerReason = "closed"
			}
			t.mu.Unlock()
			t.close()
			return
		case recFin:
			t.mu.Lock()
			done := off == t.recvNext
			t.mu.Unlock()
			if done {
				t.close()
				return
			}
		}
	}
}

// ---------------------------------------------------------------- rejoin

type rejoinMsg struct {
	Mode  string `json:"mode"`
	SID   string `json:"sid"`
	Nonce []byte `json:"nonce"`
	Recv  uint64 `json:"recv"`
	MAC   []byte `json:"mac"`
	Err   string `json:"err,omitempty"`
}

func rejoinMAC(key []byte, label string, sid string, nonce []byte, recv uint64, other []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(label))
	m.Write([]byte(sid))
	m.Write(nonce)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], recv)
	m.Write(b[:])
	m.Write(other)
	return m.Sum(nil)
}

func epochSecure(c net.Conn, r io.Reader, t *tunnel, n1, n2 []byte) *secureConn {
	k, _ := hkdf.Key(sha256.New, t.resumeKey, append(append([]byte{}, n1...), n2...), "genadb epoch keys v1", 64)
	kk := keys{i2r: k[:32], r2i: k[32:], sid: t.sid, resume: t.resumeKey}
	return makeSecure(c, r, kk, t.initiator)
}

// clientRejoin re-attaches a tunnel over a fresh connection (initiator side).
func clientRejoin(c net.Conn, r io.Reader, t *tunnel) error {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	n1 := make([]byte, 32)
	rand.Read(n1)
	t.mu.Lock()
	recv := t.recvNext
	t.mu.Unlock()
	sid := hex.EncodeToString(t.sid)
	if _, err := writeMsg(c, rejoinMsg{Mode: "rejoin", SID: sid, Nonce: n1, Recv: recv,
		MAC: rejoinMAC(t.resumeKey, "rejoin-i", sid, n1, recv, nil)}); err != nil {
		return err
	}
	var rep rejoinMsg
	if _, err := readMsg(r, &rep); err != nil {
		return err
	}
	if rep.Err != "" {
		// The peer answered but has no such session (e.g. the device agent
		// restarted and its adbd connection died with it). Resuming is
		// impossible, so fail fast: closing adb's socket lets adb reconnect.
		return fmt.Errorf("%w: rejoin refused: %s", errDenied, rep.Err)
	}
	if !hmac.Equal(rep.MAC, rejoinMAC(t.resumeKey, "rejoin-r", sid, rep.Nonce, rep.Recv, n1)) {
		return errors.New("rejoin authentication failed")
	}
	t.attach(epochSecure(c, r, t, n1, rep.Nonce), rep.Recv)
	return nil
}

// serverRejoin handles a rejoin request for an existing tunnel.
func serverRejoin(c net.Conn, r io.Reader, m rejoinMsg, lookup func(string) *tunnel) error {
	t := lookup(m.SID)
	if t == nil || !hmac.Equal(m.MAC, rejoinMAC(t.resumeKey, "rejoin-i", m.SID, m.Nonce, m.Recv, nil)) {
		writeMsg(c, rejoinMsg{Err: "unknown session"})
		return errors.New("bad rejoin")
	}
	n2 := make([]byte, 32)
	rand.Read(n2)
	t.mu.Lock()
	recv := t.recvNext
	if t.conn != nil { // peer gave up on the old conn
		t.conn.Close()
		t.conn = nil
	}
	t.mu.Unlock()
	if _, err := writeMsg(c, rejoinMsg{Mode: "rejoined", SID: m.SID, Nonce: n2, Recv: recv,
		MAC: rejoinMAC(t.resumeKey, "rejoin-r", m.SID, n2, recv, m.Nonce)}); err != nil {
		return err
	}
	t.attach(epochSecure(c, r, t, m.Nonce, n2), m.Recv)
	return nil
}
