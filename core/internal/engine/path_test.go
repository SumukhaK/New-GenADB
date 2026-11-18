package engine

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// cutProxy forwards TCP to target and can drop, freeze or refuse paths.
type cutProxy struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	conns  []net.Conn
	refuse bool
	frozen bool
}

func newCutProxy(t *testing.T, target string) *cutProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &cutProxy{ln: ln, target: target}
	t.Cleanup(func() { ln.Close(); p.cut() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			refuse := p.refuse
			p.mu.Unlock()
			if refuse {
				c.Close()
				continue
			}
			u, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, u)
			p.mu.Unlock()
			go p.pump(c, u)
			go p.pump(u, c)
		}
	}()
	return p
}

func (p *cutProxy) pump(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		for {
			p.mu.Lock()
			f := p.frozen
			p.mu.Unlock()
			if !f {
				break
			}
			time.Sleep(20 * time.Millisecond) // a black hole: bytes vanish into a stalled leg
			n = 0
		}
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			dst.Close()
			return
		}
	}
}

func (p *cutProxy) addr() string { return p.ln.Addr().String() }

func (p *cutProxy) cut() {
	p.mu.Lock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
	p.mu.Unlock()
}

func (p *cutProxy) set(refuse, frozen bool) {
	p.mu.Lock()
	p.refuse, p.frozen = refuse, frozen
	p.mu.Unlock()
}

type evLog struct {
	mu  sync.Mutex
	evs []map[string]any
}

func (l *evLog) fn(ev string, f map[string]any) {
	m := map[string]any{"event": ev}
	for k, v := range f {
		m[k] = v
	}
	l.mu.Lock()
	l.evs = append(l.evs, m)
	l.mu.Unlock()
}

func (l *evLog) find(ev string) map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.evs {
		if e["event"] == ev {
			return e
		}
	}
	return nil
}

func (l *evLog) wait(t *testing.T, ev string, within time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if e := l.find(ev); e != nil {
			return e
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %s event within %s", ev, within)
	return nil
}

func echoServer(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

type pathWorld struct {
	proxy     *cutProxy
	desk, dev *evLog
	local     net.Conn
	cmds      chan DeviceCommand
	deskDone  chan error
}

// startPathWorld runs relay, device (adbd = echo) and a desktop that reaches
// the relay through a proxy the test can cut, and opens one adb stream.
func startPathWorld(t *testing.T, times tunnelTimes) *pathWorld {
	t.Helper()
	prev := tunnelTiming.Load()
	tunnelTiming.Store(&times)
	t.Cleanup(func() { tunnelTiming.Store(prev) })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ready := make(chan string, 1)
	go RunRelay(ctx, RelayConfig{Listen: "127.0.0.1:0", Events: func(ev string, f map[string]any) {
		if ev == "ready" {
			ready <- f["addr"].(string)
		}
	}})
	relay := <-ready
	w := &pathWorld{desk: &evLog{}, dev: &evLog{}, cmds: make(chan DeviceCommand), deskDone: make(chan error, 1)}
	codes := make(chan string, 4)
	go RunDevice(ctx, DeviceConfig{Relay: relay, ADBD: echoServer(t), State: t.TempDir(), DebugAllowed: true, Commands: w.cmds,
		Events: func(ev string, f map[string]any) {
			if ev == "pairing_code" {
				codes <- f["code"].(string)
			}
			w.dev.fn(ev, f)
		}})
	var code string
	select {
	case code = <-codes:
	case <-time.After(10 * time.Second):
		t.Fatal("no pairing code")
	}
	w.proxy = newCutProxy(t, relay)
	listening := make(chan string, 1)
	go func() {
		w.deskDone <- RunDesktop(ctx, DesktopConfig{Relay: w.proxy.addr(), State: t.TempDir(), Code: code, Label: "ci-laptop",
			Events: func(ev string, f map[string]any) {
				if ev == "listening" {
					listening <- f["addr"].(string)
				}
				w.desk.fn(ev, f)
			}})
	}()
	var addr string
	select {
	case addr = <-listening:
	case <-time.After(10 * time.Second):
		t.Fatal("desktop not listening")
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	w.local = c
	w.echo(t, "hello")
	return w
}

// echo sends one adb-framed message through the tunnel; adbd (an echo
// server) returns it unchanged.
func (w *pathWorld) echo(t *testing.T, s string) {
	t.Helper()
	msg := amsg(aCNXN, 0x01000001, 4096, []byte(s))
	w.local.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := w.local.Write(msg); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len(msg))
	if _, err := io.ReadFull(w.local, b); err != nil || string(b[24:]) != s {
		t.Fatalf("echo %q: %q %v", s, b, err)
	}
}

func TestPathDownUpOnDroppedRelayPath(t *testing.T) {
	w := startPathWorld(t, defaultTunnelTimes)
	w.proxy.cut()
	down := w.desk.wait(t, "path_down", 5*time.Second)
	up := w.desk.wait(t, "path_up", 10*time.Second)
	if down["transport"] != "relay-tcp" || down["reason"] == "" || down["session_id"] == "" {
		t.Fatalf("path_down %v", down)
	}
	if up["transport"] != "relay-tcp" || up["session_id"] != down["session_id"] {
		t.Fatalf("path_up %v", up)
	}
	if _, ok := up["outage_ms"]; !ok {
		t.Fatalf("path_up without outage_ms: %v", up)
	}
	devUp := w.dev.wait(t, "path_up", 5*time.Second)
	if devUp["transport"] != "relay-tcp" || devUp["session_id"] != down["session_id"] {
		t.Fatalf("device path_up %v (desktop session %v)", devUp, down["session_id"])
	}
	w.echo(t, "still here")
	if w.desk.find("path_lost") != nil || w.dev.find("path_lost") != nil {
		t.Fatal("path_lost after a successful rejoin")
	}
}

func TestPathDownOnMissedKeepalives(t *testing.T) {
	w := startPathWorld(t, tunnelTimes{rejoinWindow: 30 * time.Second, keepaliveEvery: 200 * time.Millisecond,
		deadPeerAfter: 1500 * time.Millisecond})
	w.proxy.set(false, true) // the path stays open but carries nothing
	down := w.desk.wait(t, "path_down", 6*time.Second)
	if down["reason"] != "keepalive_timeout" {
		t.Fatalf("path_down %v", down)
	}
	w.proxy.set(false, false)
	w.proxy.cut() // drop the frozen legs so the rejoin uses a fresh path
	w.desk.wait(t, "path_up", 10*time.Second)
	w.echo(t, "after freeze")
}

func TestPathLostWhenRejoinWindowEnds(t *testing.T) {
	w := startPathWorld(t, tunnelTimes{rejoinWindow: 1500 * time.Millisecond, keepaliveEvery: 5 * time.Second,
		deadPeerAfter: 20 * time.Second})
	w.proxy.set(true, false)
	w.proxy.cut()
	w.desk.wait(t, "path_down", 5*time.Second)
	lost := w.desk.wait(t, "path_lost", 10*time.Second)
	if lost["reason"] != "rejoin_window_expired" {
		t.Fatalf("path_lost %v", lost)
	}
	devLost := w.dev.wait(t, "path_lost", 10*time.Second)
	if devLost["session_id"] != lost["session_id"] {
		t.Fatalf("device path_lost %v", devLost)
	}
	if w.desk.find("path_up") != nil {
		t.Fatal("path_up although the window expired")
	}
	// adb sees the stream end.
	w.local.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := w.local.Read(make([]byte, 1)); err == nil {
		t.Fatal("local adb stream still open after path_lost")
	}
}

func TestNoPathEventsOnNormalClose(t *testing.T) {
	w := startPathWorld(t, defaultTunnelTimes)
	w.local.Close()
	time.Sleep(1500 * time.Millisecond)
	for _, l := range []*evLog{w.desk, w.dev} {
		for _, ev := range []string{"path_down", "path_up", "path_lost"} {
			if e := l.find(ev); e != nil {
				t.Fatalf("normal close produced %v", e)
			}
		}
	}
}
