package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
)

// ADB-aware split flow control ("ack spoofing").
//
// Plain ADB allows only one unacknowledged WRTE per stream: the sender waits
// for the peer's OKAY before sending more. Over a relayed WAN path every
// payload therefore costs a full round trip. Each agent instead acknowledges
// WRTEs from its local endpoint immediately (the reliable, resumable tunnel
// guarantees delivery) and paces delivery to its local endpoint itself,
// one WRTE at a time, consuming the endpoint's OKAYs locally.
//
// Applied only to plaintext (legacy/tcpip) adbd transports without the
// delayed_ack feature; as soon as STLS is seen the stream is passed through
// untouched (end-to-end adb TLS cannot and must not be inspected).

const (
	aCNXN = 0x4E584E43
	aOPEN = 0x4E45504F
	aOKAY = 0x59414B4F
	aCLSE = 0x45534C43
	aWRTE = 0x45545257
	aSTLS = 0x534C5453

	accelMaxQueued = 32 << 20
)

type adbMsg struct {
	cmd, a0, a1 uint32
	raw         []byte // header + payload, as received
}

func readADB(r io.Reader) (*adbMsg, error) {
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	cmd := binary.LittleEndian.Uint32(hdr[0:])
	ln := binary.LittleEndian.Uint32(hdr[12:])
	magic := binary.LittleEndian.Uint32(hdr[20:])
	if magic != cmd^0xFFFFFFFF || ln > 16<<20 {
		return nil, errBadADB
	}
	raw := make([]byte, 24+ln)
	copy(raw, hdr)
	if _, err := io.ReadFull(r, raw[24:]); err != nil {
		return nil, err
	}
	return &adbMsg{cmd: cmd, a0: binary.LittleEndian.Uint32(hdr[4:]), a1: binary.LittleEndian.Uint32(hdr[8:]), raw: raw}, nil
}

func makeADB(cmd, a0, a1 uint32) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[0:], cmd)
	binary.LittleEndian.PutUint32(b[4:], a0)
	binary.LittleEndian.PutUint32(b[8:], a1)
	binary.LittleEndian.PutUint32(b[20:], cmd^0xFFFFFFFF)
	return b
}

type errString string

func (e errString) Error() string { return string(e) }

const errBadADB = errString("not an adb message stream")

type accelStream struct {
	established bool
	inflight    bool     // a WRTE delivered to local, awaiting its OKAY
	queue       [][]byte // messages (WRTE / CLSE) waiting for delivery to local
}

type adbAccel struct {
	local                 net.Conn // real endpoint (adb host or adbd)
	tun                   net.Conn // pipe end facing the tunnel
	lmu                   sync.Mutex
	mu                    sync.Mutex
	cond                  *sync.Cond
	off                   bool // passthrough mode
	dackLocal, dackRemote bool
	st                    map[uint32]*accelStream // keyed by the local endpoint's stream id
	queued                int
}

// accelerate returns the conn the tunnel should use in place of local.
func accelerate(local net.Conn) net.Conn {
	a, b := net.Pipe()
	x := &adbAccel{local: local, tun: b, st: map[uint32]*accelStream{}}
	x.cond = sync.NewCond(&x.mu)
	go x.fromLocal()
	go x.fromTunnel()
	return a
}

func (x *adbAccel) writeLocal(b []byte) error {
	x.lmu.Lock()
	defer x.lmu.Unlock()
	_, err := x.local.Write(b)
	return err
}

func (x *adbAccel) stream(id uint32) *accelStream {
	s := x.st[id]
	if s == nil {
		s = &accelStream{}
		x.st[id] = s
	}
	return s
}

func (x *adbAccel) shutdown() {
	x.local.Close()
	x.tun.Close()
	x.mu.Lock()
	x.off = true
	x.cond.Broadcast()
	x.mu.Unlock()
}

func (x *adbAccel) passthrough(src io.Reader, dst io.Writer, pending []byte) {
	if len(pending) > 0 {
		if _, err := dst.Write(pending); err != nil {
			x.shutdown()
			return
		}
	}
	io.Copy(dst, src)
	x.shutdown()
}

// checkCNXN: delayed_ack changes OKAY semantics but is only negotiated when
// both ends advertise it (newer hosts always do; Android 10 devices do not).
func (x *adbAccel) checkCNXN(m *adbMsg, fromLocal bool) {
	if m.cmd == aCNXN && bytes.Contains(m.raw[24:], []byte("delayed_ack")) {
		if fromLocal {
			x.dackLocal = true
		} else {
			x.dackRemote = true
		}
		if x.dackLocal && x.dackRemote {
			x.off = true
		}
	}
	if m.cmd == aSTLS {
		x.off = true
	}
}

// fromLocal: messages produced by the local endpoint, heading to the tunnel.
func (x *adbAccel) fromLocal() {
	for {
		m, err := readADB(x.local)
		if err != nil {
			x.shutdown()
			return
		}
		x.mu.Lock()
		x.checkCNXN(m, true)
		if x.off {
			x.mu.Unlock()
			x.passthroughLocal(m)
			return
		}
		switch m.cmd {
		case aOKAY:
			s := x.stream(m.a0)
			if !s.established {
				s.established = true // local acks an OPEN from the far side
				x.mu.Unlock()
				break
			}
			// local acknowledges a WRTE we delivered: release the next one
			s.inflight = false
			next := x.popLocked(m.a0)
			x.mu.Unlock()
			if next != nil {
				if err := x.writeLocal(next); err != nil {
					x.shutdown()
					return
				}
			}
			continue // consumed; the far side already got a spoofed ack
		case aWRTE:
			x.mu.Unlock()
			// acknowledge immediately; the tunnel guarantees delivery
			if err := x.writeLocal(makeADB(aOKAY, m.a1, m.a0)); err != nil {
				x.shutdown()
				return
			}
		case aCLSE:
			delete(x.st, m.a0)
			x.mu.Unlock()
		default:
			x.mu.Unlock()
		}
		if _, err := x.tun.Write(m.raw); err != nil {
			x.shutdown()
			return
		}
	}
}

func (x *adbAccel) passthroughLocal(m *adbMsg) {
	x.passthrough(x.local, x.tun, m.raw)
}

// popLocked returns the next message to deliver for stream id, if allowed.
func (x *adbAccel) popLocked(id uint32) []byte {
	s := x.st[id]
	if s == nil || s.inflight || len(s.queue) == 0 {
		return nil
	}
	b := s.queue[0]
	s.queue = s.queue[1:]
	x.queued -= len(b)
	x.cond.Broadcast()
	if binary.LittleEndian.Uint32(b) == aWRTE {
		s.inflight = true
	} else { // CLSE
		delete(x.st, id)
	}
	return b
}

// fromTunnel: messages from the far side, heading to the local endpoint.
func (x *adbAccel) fromTunnel() {
	for {
		m, err := readADB(x.tun)
		if err != nil {
			x.shutdown()
			return
		}
		x.mu.Lock()
		x.checkCNXN(m, false)
		if x.off {
			// flush anything still queued, then pass through
			x.mu.Unlock()
			x.passthrough(x.tun, &lockedWriter{x}, m.raw)
			return
		}
		var out []byte
		switch m.cmd {
		case aOKAY:
			s := x.stream(m.a1)
			if !s.established {
				s.established = true // far side acks an OPEN from local
				out = m.raw
			}
			// otherwise: ack for a WRTE we already acknowledged locally
		case aWRTE, aCLSE:
			s := x.stream(m.a1)
			for x.queued > accelMaxQueued && !x.off {
				x.cond.Wait()
			}
			s.queue = append(s.queue, m.raw)
			x.queued += len(m.raw)
			out = x.popLocked(m.a1)
		default:
			out = m.raw
		}
		x.mu.Unlock()
		if out != nil {
			if err := x.writeLocal(out); err != nil {
				x.shutdown()
				return
			}
		}
	}
}

type lockedWriter struct{ x *adbAccel }

func (w *lockedWriter) Write(b []byte) (int, error) {
	w.x.lmu.Lock()
	defer w.x.lmu.Unlock()
	return w.x.local.Write(b)
}
