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
	"sync/atomic"
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

	maxUnacked = 16 << 20
	ackEvery   = 128 << 10
)

// tunnelTimes are the tunnel's liveness and resumption timings.
//
// End-to-end liveness: relays, tunnels and carrier NATs can keep one leg of
// a spliced path open after the other leg died (a phone losing its cellular
// link for 40 s left the desktop leg healthy and the session silently
// stuck). Each side sends a keepalive inside the secure channel when it has
// written nothing for keepaliveEvery, and treats a path on which it has
// received nothing for deadPeerAfter as broken, which triggers the normal
// authenticated rejoin. rejoinWindow covers a minute-long radio loss plus
// dead-peer detection.
type tunnelTimes struct {
	rejoinWindow, keepaliveEvery, deadPeerAfter time.Duration
}

var defaultTunnelTimes = tunnelTimes{rejoinWindow: 90 * time.Second, keepaliveEvery: 5 * time.Second,
	deadPeerAfter: 20 * time.Second}

// tunnelTiming is read when a tunnel is created (tests shorten it).
var tunnelTiming atomic.Pointer[tunnelTimes]

func init() { tunnelTiming.Store(&defaultTunnelTimes) }

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
	times    tunnelTimes
	broken   chan struct{} // signalled when current conn fails
	lastRecv time.Time     // last record received on the current conn

	peerCaps   []string
	peerReason string // reason the peer gave in a close record ("" = none)

	// Path events (v1.1.0+): path_down when the current connection breaks
	// (missed keepalives, read/write error), path_up when a rejoin attaches
	// a new one (with its transport), path_lost when the rejoin window ends.
	onPath    EventFunc
	downAt    time.Time // when the path went down (zero = up)
	transport string    // transport of the current connection
	lost      bool      // the rejoin window expired or the rejoin was refused
	localWhy  string    // reason this side gave to closeWith
}

// endReason says why a finished tunnel ended: the reason this side gave,
// peer_closed, path_lost or closed (a normal end of the adb stream).
func (t *tunnel) endReason() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case t.localWhy != "":
		return t.localWhy
	case t.peerReason != "":
		return "peer_closed"
	case t.lost:
		return "path_lost"
	}
	return "closed"
}

// ID is the short session id shared by both ends (and by audit records).
func (t *tunnel) ID() string { return hex.EncodeToString(t.sid[:8]) }

// observe sets the current transport and the path event receiver.
func (t *tunnel) observe(transport string, onPath EventFunc) {
	t.mu.Lock()
	t.transport, t.onPath = transport, onPath
	t.mu.Unlock()
}

func (t *tunnel) emitPath(ev string, f map[string]any) {
	t.mu.Lock()
	fn := t.onPath
	t.mu.Unlock()
	if fn == nil {
		return
	}
	f["session_id"] = t.ID()
	fn(ev, f)
}

// pathUp reports a resumed path; transport is lan | relay-tcp | relay-ws | relay-wss.
func (t *tunnel) pathUp(transport string) {
	t.mu.Lock()
	down := t.downAt
	t.downAt = time.Time{}
	t.transport = transport
	t.mu.Unlock()
	f := map[string]any{"transport": transport}
	if !down.IsZero() {
		f["outage_ms"] = time.Since(down).Milliseconds()
	}
	t.emitPath("path_up", f)
}

func (t *tunnel) pathLost(reason string) {
	t.mu.Lock()
	down := t.downAt
	t.lost = true
	t.mu.Unlock()
	f := map[string]any{"reason": reason}
	if !down.IsZero() {
		f["outage_ms"] = time.Since(down).Milliseconds()
	}
	t.emitPath("path_lost", f)
}

func newTunnel(sc *secureConn, local net.Conn, initiator bool) *tunnel {
	t := &tunnel{sid: sc.sid, resumeKey: sc.resumeKey, initiator: initiator, local: local,
		broken: make(chan struct{}, 1), peerCaps: sc.peerCaps, times: *tunnelTiming.Load()}
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

func (t *tunnel) fail(ep int, reason string) {
	t.mu.Lock()
	report := false
	if ep == t.epoch && t.conn != nil {
		t.conn.Close()
		t.conn = nil
		select {
		case t.broken <- struct{}{}:
		default:
		}
		// A connection ending after both FINs is a normal close, not an outage.
		if !t.closed && !(t.localEOF && t.finSent) && t.downAt.IsZero() {
			t.downAt = time.Now()
			report = true
		}
	}
	tr := t.transport
	t.cond.Broadcast()
	t.mu.Unlock()
	if report {
		t.emitPath("path_down", map[string]any{"reason": reason, "transport": tr})
	}
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
	if t.localWhy == "" && !t.closed {
		t.localWhy = reason
	}
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
func (t *tunnel) run(reconnect func(t *tunnel) (transport string, err error)) {
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
		deadline := time.Now().Add(t.times.rejoinWindow)
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
					t.pathLost("rejoin_window_expired")
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
			transport, err := reconnect(t)
			if err == nil {
				if attempt > 1 {
					logf("tunnel resumed after %s (%d attempts)", time.Since(started).Round(time.Millisecond), attempt)
				}
				t.pathUp(transport)
				break
			}
			t.mu.Lock()
			closed := t.closed
			t.mu.Unlock()
			if closed {
				return
			}
			if errors.Is(err, errDenied) || time.Now().After(deadline) {
				logf("tunnel closed, cannot resume: %v", err)
				reason := "rejoin_window_expired"
				if errors.Is(err, errDenied) {
					reason = "rejoin_refused"
				}
				t.pathLost(reason)
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
			t.fail(ep, "write_error")
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
		if c != nil && pend == 0 && time.Since(lastKeepalive) >= t.times.keepaliveEvery {
			pend = -1 // keepalive
		}
		if pend != 0 && c != nil {
			lastKeepalive = time.Now()
			if _, err := c.Write(record(recAck, off, nil)); err != nil {
				t.fail(ep, "write_error")
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
		dead := t.conn != nil && idle > t.times.deadPeerAfter
		t.mu.Unlock()
		if dead {
			logf("tunnel peer silent for %s; treating path as broken", idle.Round(time.Second))
			t.fail(ep, "keepalive_timeout")
		}
	}
}

func (t *tunnel) reader(sc *secureConn, ep int) {
	buf := make([]byte, maxFrame+64)
	for {
		n, err := sc.ReadRecord(buf)
		if err != nil || n < 9 {
			t.fail(ep, "read_error")
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
				t.fail(ep, "protocol_error")
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
						t.fail(ep, "write_error")
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
func serverRejoin(c net.Conn, r io.Reader, m rejoinMsg, lookup func(string) *tunnel, transport string) error {
	t := lookup(m.SID)
	if t == nil || !hmac.Equal(m.MAC, rejoinMAC(t.resumeKey, "rejoin-i", m.SID, m.Nonce, m.Recv, nil)) {
		writeMsg(c, rejoinMsg{Err: "unknown session"})
		return errors.New("bad rejoin")
	}
	n2 := make([]byte, 32)
	rand.Read(n2)
	t.mu.Lock()
	recv := t.recvNext
	replaced := false
	if t.conn != nil { // peer gave up on the old conn
		t.conn.Close()
		t.conn = nil
		if t.downAt.IsZero() {
			t.downAt = time.Now()
			replaced = true
		}
	}
	old := t.transport
	t.mu.Unlock()
	if replaced {
		t.emitPath("path_down", map[string]any{"reason": "peer_reconnected", "transport": old})
	}
	if _, err := writeMsg(c, rejoinMsg{Mode: "rejoined", SID: m.SID, Nonce: n2, Recv: recv,
		MAC: rejoinMAC(t.resumeKey, "rejoin-r", m.SID, n2, recv, m.Nonce)}); err != nil {
		return err
	}
	t.attach(epochSecure(c, r, t, m.Nonce, n2), m.Recv)
	t.pathUp(transport)
	return nil
}
