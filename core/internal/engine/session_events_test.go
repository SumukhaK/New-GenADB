package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDeviceSessionEventsAndEndSession(t *testing.T) {
	w := startPathWorld(t, defaultTunnelTimes)
	open := w.dev.wait(t, "session_open", 5*time.Second)
	if open["peer_label"] != "ci-laptop" || open["transport"] != "relay-tcp" || open["kind"] != "adb" || open["session_id"] == "" {
		t.Fatalf("session_open %v", open)
	}
	// Only the real adb stream is a session: pairing and the pre-listen
	// check are probes and open none.
	w.dev.mu.Lock()
	n := 0
	for _, e := range w.dev.evs {
		if e["event"] == "session_open" {
			n++
		}
	}
	w.dev.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d session_open events, want 1", n)
	}
	id := open["session_id"].(string)

	reply := make(chan error, 1)
	w.cmds <- DeviceCommand{Op: "end_session", SessionID: "nope", Reply: reply}
	if err := <-reply; !errors.Is(err, ErrNoSuchSession) {
		t.Fatalf("unknown session: %v", err)
	}
	w.cmds <- DeviceCommand{Op: "end_session", SessionID: id, Reply: reply}
	if err := <-reply; err != nil {
		t.Fatal(err)
	}
	cl := w.dev.wait(t, "session_close", 5*time.Second)
	if cl["session_id"] != id || cl["reason"] != "ended_on_device" {
		t.Fatalf("session_close %v", cl)
	}
	// The desktop is told and ends its session instead of rejoining.
	pc := w.desk.wait(t, "peer_closed", 5*time.Second)
	if pc["reason"] != "peer_closed" || pc["peer_reason"] != "ended_on_device" {
		t.Fatalf("peer_closed %v", pc)
	}
	select {
	case err := <-w.deskDone:
		if !errors.Is(err, ErrPeerClosed) || !errors.Is(err, ErrDenied) {
			t.Fatalf("desktop ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("desktop session still running")
	}
	if w.desk.find("path_down") != nil {
		t.Fatal("a deliberate end must not look like an outage")
	}
}

func TestSessionCloseReasonOnNormalEnd(t *testing.T) {
	w := startPathWorld(t, defaultTunnelTimes)
	w.local.Close()
	cl := w.dev.wait(t, "session_close", 5*time.Second)
	if cl["reason"] != "closed" {
		t.Fatalf("session_close %v", cl)
	}
}

func TestControlStdinCommands(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := strings.NewReader("garbage\n" + `{"cmd":"end_session","session_id":"abc"}` + "\n")
	var log evLog
	cmds := readCommands(ctx, in, log.fn)
	c := <-cmds
	if c.Op != "end_session" || c.SessionID != "abc" {
		t.Fatalf("command %+v", c)
	}
	c.Reply <- ErrNoSuchSession
	r := log.wait(t, "command_result", 2*time.Second)
	if r["ok"] != false || r["session_id"] != "abc" || r["error"] == nil {
		t.Fatalf("command_result %v", r)
	}
}
