package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"net"
	"strings"
	"sync"
	"time"
)

// ADB operation observer (corporate audit).
//
// It sits between the local adb host and the tunnel on the desktop side and
// reads the plaintext ADB transport to classify each stream (shell, push,
// pull, install, forward, ...), count its bytes and hash transferred files.
// It never stores contents and never alters the byte stream. When the
// transport is upgraded to TLS (Android 11+ Wireless debugging) the stream is
// end-to-end encrypted between adb and adbd and nothing can be classified, so
// only session-level records (bytes, duration) remain.

type adbOp struct {
	session, kind, path, command, sha256 string
	up, down                             int64
	duration                             time.Duration
	failed                               bool
}

type adbObserver struct {
	net.Conn
	session string
	onOp    func(adbOp)

	mu       sync.Mutex
	upBuf    []byte // host -> device
	downBuf  []byte // device -> host
	off      bool
	streams  map[uint32]*obsStream // keyed by the host's local stream id
	totUp    int64
	totDown  int64
	finished bool
}

func newADBObserver(c net.Conn, onOp func(adbOp), session string) *adbObserver {
	return &adbObserver{Conn: c, session: session, onOp: onOp, streams: map[uint32]*obsStream{}}
}

// Read carries host -> device bytes.
func (o *adbObserver) Read(p []byte) (int, error) {
	n, err := o.Conn.Read(p)
	if n > 0 {
		o.feed(p[:n], true)
	}
	return n, err
}

// Write carries device -> host bytes.
func (o *adbObserver) Write(p []byte) (int, error) {
	o.feed(p, false)
	return o.Conn.Write(p)
}

func (o *adbObserver) totals() (int64, int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.totUp, o.totDown
}

// finish reports streams that were still open when the session ended.
func (o *adbObserver) finish() {
	o.mu.Lock()
	o.finished = true
	var ops []adbOp
	for id, s := range o.streams {
		ops = append(ops, s.close(true)...)
		delete(o.streams, id)
	}
	o.mu.Unlock()
	o.report(ops)
}

func (o *adbObserver) report(ops []adbOp) {
	for _, op := range ops {
		op.session = o.session
		o.onOp(op)
	}
}

func (o *adbObserver) feed(b []byte, up bool) {
	o.mu.Lock()
	if up {
		o.totUp += int64(len(b))
	} else {
		o.totDown += int64(len(b))
	}
	if o.off || o.finished {
		o.mu.Unlock()
		return
	}
	buf := &o.downBuf
	if up {
		buf = &o.upBuf
	}
	*buf = append(*buf, b...)
	var ops []adbOp
	for len(*buf) >= 24 {
		cmd := binary.LittleEndian.Uint32((*buf)[0:])
		a0 := binary.LittleEndian.Uint32((*buf)[4:])
		a1 := binary.LittleEndian.Uint32((*buf)[8:])
		ln := binary.LittleEndian.Uint32((*buf)[12:])
		magic := binary.LittleEndian.Uint32((*buf)[20:])
		if magic != cmd^0xFFFFFFFF || ln > 16<<20 {
			o.stop()
			break
		}
		if uint32(len(*buf)) < 24+ln {
			break
		}
		payload := (*buf)[24 : 24+ln]
		if cmd == aSTLS {
			o.stop()
			break
		}
		ops = append(ops, o.message(cmd, a0, a1, payload, up)...)
		*buf = (*buf)[24+ln:]
	}
	if len(*buf) == 0 {
		*buf = nil
	}
	o.mu.Unlock()
	o.report(ops)
}

func (o *adbObserver) stop() {
	o.off = true
	o.upBuf, o.downBuf = nil, nil
	o.streams = map[uint32]*obsStream{}
}

func (o *adbObserver) message(cmd, a0, a1 uint32, payload []byte, up bool) []adbOp {
	switch {
	case up && cmd == aOPEN:
		svc := string(bytes.TrimRight(payload, "\x00"))
		o.streams[a0] = newObsStream(svc)
	case up && cmd == aWRTE:
		if s := o.streams[a0]; s != nil {
			s.up += int64(len(payload))
			s.hostData(payload)
		}
	case !up && cmd == aWRTE:
		if s := o.streams[a1]; s != nil {
			s.down += int64(len(payload))
			s.deviceData(payload)
		}
	case up && cmd == aCLSE:
		if s := o.streams[a0]; s != nil {
			delete(o.streams, a0)
			return s.close(false)
		}
	case !up && cmd == aCLSE:
		if s := o.streams[a1]; s != nil {
			delete(o.streams, a1)
			if a0 == 0 && s.up+s.down == 0 {
				s.refused = true // the device refused the OPEN
			}
			return s.close(false)
		}
	}
	return nil
}

// ---------------------------------------------------------------- streams

type obsStream struct {
	kind, path, command string
	start               time.Time
	up, down            int64
	refused             bool
	h                   hash.Hash // whole-stream upload hash (install)
	sync                *syncTracker
}

func newObsStream(svc string) *obsStream {
	s := &obsStream{start: time.Now()}
	s.kind, s.path, s.command = classify(svc)
	switch s.kind {
	case "install":
		s.h = sha256.New()
	case "sync":
		s.sync = &syncTracker{}
	}
	return s
}

func (s *obsStream) hostData(p []byte) {
	if s.h != nil {
		s.h.Write(p)
	}
	if s.sync != nil {
		s.sync.host(p)
	}
}

func (s *obsStream) deviceData(p []byte) {
	if s.sync != nil {
		s.sync.device(p)
	}
}

func (s *obsStream) close(interrupted bool) []adbOp {
	if s.sync != nil {
		ops := s.sync.done
		if t := s.sync.cur; t != nil && interrupted {
			ops = append(ops, t.op(true))
		}
		return ops
	}
	op := adbOp{kind: s.kind, path: s.path, command: s.command, up: s.up, down: s.down,
		duration: time.Since(s.start), failed: s.refused || interrupted}
	if s.h != nil && s.up > 0 {
		op.sha256 = hex.EncodeToString(s.h.Sum(nil))
	}
	return []adbOp{op}
}

// classify maps an adb service string to an operation kind. Only the
// command's first word is kept: arguments can contain secrets.
func classify(svc string) (kind, path, command string) {
	name, rest, _ := strings.Cut(svc, ":")
	if i := strings.IndexByte(name, ','); i >= 0 { // shell,v2,TERM=...,raw:cmd
		name = name[:i]
	}
	first := func(s string) string {
		// Skip leading VAR=value assignments: values are often credentials.
		for _, w := range strings.Fields(strings.ReplaceAll(s, "\x00", " ")) {
			if w = strings.Trim(w, `'"`); w != "" && !strings.Contains(w, "=") {
				return w
			}
		}
		return ""
	}
	lower := strings.ToLower(strings.ReplaceAll(rest, "\x00", " "))
	isInstall := strings.Contains(lower, "package") && strings.Contains(lower, "install") ||
		strings.HasPrefix(strings.TrimSpace(lower), "pm install")
	switch name {
	case "sync":
		return "sync", "", ""
	case "shell", "exec", "abb", "abb_exec":
		switch {
		case isInstall:
			return "install", "", first(rest)
		case first(rest) == "screencap":
			return "screencap", "", "screencap"
		case first(rest) == "screenrecord":
			return "screenrecord", "", "screenrecord"
		case name == "shell" && strings.TrimSpace(rest) == "":
			return "shell", "", "(interactive)"
		case name == "shell":
			return "shell", "", first(rest)
		}
		return "exec", "", first(rest)
	case "framebuffer":
		return "screencap", "", ""
	case "tcp", "localabstract", "localreserved", "localfilesystem", "dev":
		return "forward", name + ":" + rest, ""
	case "jdwp":
		return "debug", "jdwp:" + rest, ""
	case "reverse":
		return "reverse", "", ""
	}
	return "other", "", name
}

// ---------------------------------------------------------------- sync

// syncTracker follows the file sync protocol inside one "sync:" stream:
// requests from the host, responses from the device, in order.
type syncTracker struct {
	hbuf, dbuf []byte
	broken     bool
	expect     []byte // queue of response kinds: 's' stat1, 'S' stat2, 'l' list1, 'L' list2, 'r' recv, 'o' send status
	cur        *transfer
	done       []adbOp
	pendingV2  byte // 'S' or 'R' when a SND2/RCV2 setup awaits its 12-byte options block
	recvs      []*transfer
}

type transfer struct {
	kind, path string
	start      time.Time
	bytes      int64
	h          hash.Hash
	compressed bool
}

func (t *transfer) op(failed bool) adbOp {
	op := adbOp{kind: t.kind, path: t.path, duration: time.Since(t.start), failed: failed}
	if t.kind == "push" {
		op.up = t.bytes
	} else {
		op.down = t.bytes
	}
	if !t.compressed && !failed {
		op.sha256 = hex.EncodeToString(t.h.Sum(nil))
	}
	return op
}

func id4(b []byte) string { return string(b[:4]) }
func u32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

func (s *syncTracker) host(p []byte) {
	if s.broken {
		return
	}
	s.hbuf = append(s.hbuf, p...)
	for {
		if s.pendingV2 != 0 {
			// send_v2_setup is {id, mode, flags}; recv_v2_setup is {id, flags}.
			size := 12
			if s.pendingV2 == 'R' {
				size = 8
			}
			if len(s.hbuf) < size {
				return
			}
			if flags := u32(s.hbuf[size-4:]); flags != 0 {
				if s.pendingV2 == 'S' && s.cur != nil {
					s.cur.compressed = true
				} else if s.pendingV2 == 'R' && len(s.recvs) > 0 {
					s.recvs[len(s.recvs)-1].compressed = true
				}
			}
			s.hbuf, s.pendingV2 = s.hbuf[size:], 0
			continue
		}
		if len(s.hbuf) < 8 {
			return
		}
		id, n := id4(s.hbuf), u32(s.hbuf[4:])
		switch id {
		case "DONE": // end of a SEND; n is the mtime, no payload
			s.hbuf = s.hbuf[8:]
			continue
		case "QUIT":
			s.hbuf = s.hbuf[8:]
			continue
		}
		if n > 1<<20 && id != "DATA" || n > 1<<26 {
			s.fail()
			return
		}
		if uint32(len(s.hbuf)) < 8+n {
			return
		}
		body := s.hbuf[8 : 8+n]
		switch id {
		case "DATA":
			if s.cur != nil && s.cur.kind == "push" {
				s.cur.h.Write(body)
				s.cur.bytes += int64(len(body))
			}
		case "SEND", "SND2":
			path := string(body)
			if id == "SEND" {
				if i := strings.LastIndexByte(path, ','); i >= 0 {
					path = path[:i]
				}
			} else {
				s.pendingV2 = 'S'
			}
			s.cur = &transfer{kind: "push", path: path, start: time.Now(), h: sha256.New()}
			s.expect = append(s.expect, 'o')
		case "RECV", "RCV2":
			if id == "RCV2" {
				s.pendingV2 = 'R'
			}
			s.expect = append(s.expect, 'r')
			s.queueRecv(string(body))
		case "STAT":
			s.expect = append(s.expect, 's')
		case "STA2", "LST2":
			s.expect = append(s.expect, 'S')
		case "LIST":
			s.expect = append(s.expect, 'l')
		case "LIS2":
			s.expect = append(s.expect, 'L')
		default:
			s.fail()
			return
		}
		s.hbuf = s.hbuf[8+n:]
	}
}

// recvQueue holds pulls awaiting their data, in request order.
func (s *syncTracker) queueRecv(path string) {
	s.recvs = append(s.recvs, &transfer{kind: "pull", path: path, h: sha256.New()})
}

func (s *syncTracker) device(p []byte) {
	if s.broken {
		return
	}
	s.dbuf = append(s.dbuf, p...)
	for len(s.expect) > 0 {
		switch s.expect[0] {
		case 's':
			if len(s.dbuf) < 16 {
				return
			}
			s.dbuf = s.dbuf[16:]
		case 'S':
			if len(s.dbuf) < 72 {
				return
			}
			s.dbuf = s.dbuf[72:]
		case 'l', 'L':
			fixed := 20
			if s.expect[0] == 'L' {
				fixed = 76
			}
			if len(s.dbuf) < fixed {
				return
			}
			if id4(s.dbuf) == "DONE" {
				s.dbuf = s.dbuf[fixed:]
				break
			}
			nl := int(u32(s.dbuf[fixed-4:]))
			if nl > 4096 {
				s.fail()
				return
			}
			if len(s.dbuf) < fixed+nl {
				return
			}
			s.dbuf = s.dbuf[fixed+nl:]
			continue // more entries for the same listing
		case 'o':
			if len(s.dbuf) < 8 {
				return
			}
			n := int(u32(s.dbuf[4:]))
			if len(s.dbuf) < 8+n {
				return
			}
			ok := id4(s.dbuf) == "OKAY"
			s.dbuf = s.dbuf[8+n:]
			if s.cur != nil {
				s.done = append(s.done, s.cur.op(!ok))
				s.cur = nil
			}
		case 'r':
			if len(s.dbuf) < 8 {
				return
			}
			if len(s.recvs) == 0 {
				s.fail()
				return
			}
			t := s.recvs[0]
			if t.start.IsZero() {
				t.start = time.Now()
			}
			id, n := id4(s.dbuf), int(u32(s.dbuf[4:]))
			switch id {
			case "DATA":
				if len(s.dbuf) < 8+n {
					return
				}
				t.h.Write(s.dbuf[8 : 8+n])
				t.bytes += int64(n)
				s.dbuf = s.dbuf[8+n:]
				continue
			case "DONE":
				s.dbuf = s.dbuf[8:]
				s.done = append(s.done, t.op(false))
			case "FAIL":
				if len(s.dbuf) < 8+n {
					return
				}
				s.dbuf = s.dbuf[8+n:]
				s.done = append(s.done, t.op(true))
			default:
				s.fail()
				return
			}
			s.recvs = s.recvs[1:]
		}
		s.expect = s.expect[1:]
	}
}

func (s *syncTracker) fail() {
	s.broken = true
	s.hbuf, s.dbuf = nil, nil
}
