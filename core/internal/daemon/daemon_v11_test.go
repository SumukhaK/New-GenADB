package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sumukhak/new-genadb/core/pkg/genadb"
)

func errKind(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	d, _ := e["data"].(map[string]any)
	k, _ := d["kind"].(string)
	return k
}

func TestDaemonPairADBValidation(t *testing.T) {
	_, r := setup(t, "", genadb.WithRelayURL("127.0.0.1:1"))
	if errCode(r.call("session.pair_adb", map[string]any{"device_id": "d"})) != CodeInvalidParams {
		t.Fatal("missing pairing_code accepted")
	}
	if m := r.call("session.pair_adb", map[string]any{"device_id": "d", "pairing_port": 37000, "pairing_code": "12345"}); errCode(m) != CodeBadCode || errKind(m) != "bad_code" {
		t.Fatalf("short code: %v", m)
	}
	if m := r.call("session.pair_adb", map[string]any{"device_id": "d", "pairing_port": 37000, "pairing_code": "123456"}); errCode(m) != CodeNotPaired {
		t.Fatalf("unpaired device: %v", m)
	}
	if errCode(r.call("session.pair_adb", map[string]any{"device_id": "d", "pairing_code": "123456", "nope": true})) != CodeInvalidParams {
		t.Fatal("unknown params accepted")
	}
}

func TestDaemonSetTokenNeedsAuthAndCorporateMode(t *testing.T) {
	_, r := setup(t, "tok")
	if errCode(r.call("auth.set_token", map[string]any{"token": "a.b.c"})) != CodeUnauthorized {
		t.Fatal("auth.set_token before auth")
	}
	r.call("auth", map[string]any{"token": "tok"})
	if errCode(r.call("auth.set_token", map[string]any{})) != CodeInvalidParams {
		t.Fatal("empty token accepted")
	}
	if m := r.call("auth.set_token", map[string]any{"token": "a.b.c"}); errCode(m) != CodeDenied {
		t.Fatalf("solo daemon accepted a token: %v", m)
	}
}

// blackholeRelay accepts connections and never answers, so session.connect
// stays in flight (as against a relay behind a stalled proxy).
func blackholeRelay(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for _, c := range held {
			c.Close()
		}
		mu.Unlock()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	return ln.Addr().String()
}

// send writes a request without waiting; collect reads replies by id.
func (r *rpc) send(id any, method string, params any) {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	r.c.Write(append(b, '\n'))
}

func (r *rpc) await(id string, within time.Duration) map[string]any {
	r.t.Helper()
	deadline := time.Now().Add(within)
	for {
		if m, ok := r.pending[id]; ok {
			delete(r.pending, id)
			return m
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("no reply to %s within %s", id, within)
		}
		r.c.SetReadDeadline(deadline)
		if !r.sc.Scan() {
			r.t.Fatalf("no reply to %s: %v", id, r.sc.Err())
		}
		var m map[string]any
		json.Unmarshal(r.sc.Bytes(), &m)
		if _, isNote := m["method"]; isNote {
			continue
		}
		if r.pending == nil {
			r.pending = map[string]map[string]any{}
		}
		r.pending[fmt.Sprint(m["id"])] = m
	}
}

func TestDaemonSlowConnectDoesNotBlockOtherCalls(t *testing.T) {
	_, r := setup(t, "", genadb.WithRelayURL(blackholeRelay(t)), genadb.WithAuditConfig(genadb.AuditConfig{Mode: genadb.AuditOn}))
	// Pairing goes to the relay first, which never answers.
	r.send("c1", "session.connect", map[string]any{"pairing_code": "1234-567890", "timeout_ms": 60000})
	r.send("c2", "session.connect", map[string]any{"device_id": "dev-B", "pairing_code": "1234-567890", "timeout_ms": 60000})
	time.Sleep(200 * time.Millisecond) // both connects are now stuck at the relay
	start := time.Now()
	r.send(1, "session.list", nil)
	r.send(2, "version", nil)
	r.send(3, "audit.verify", nil)
	for _, id := range []string{"1", "2", "3"} {
		if m := r.await(id, 2*time.Second); errCode(m) != 0 {
			t.Fatalf("call %s failed: %v", id, m)
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("calls behind an in-flight connect took %v", d)
	}
	// Cancel the first connect by its request id: it answers at once.
	r.send(4, "session.cancel", map[string]any{"request_id": "c1"})
	if m := r.await("4", 2*time.Second); m["result"].(map[string]any)["cancelled"] != float64(1) {
		t.Fatalf("cancel by id: %v", m)
	}
	if m := r.await("c1", 3*time.Second); errCode(m) != CodeCancelled || errKind(m) != "cancelled" {
		t.Fatalf("cancelled connect answered %v", m)
	}
	// And the second by device id.
	r.send(5, "session.cancel", map[string]any{"device_id": "dev-B"})
	if m := r.await("5", 2*time.Second); m["result"].(map[string]any)["cancelled"] != float64(1) {
		t.Fatalf("cancel by device: %v", m)
	}
	if m := r.await("c2", 3*time.Second); errCode(m) != CodeCancelled {
		t.Fatalf("cancelled connect answered %v", m)
	}
	r.send(6, "session.cancel", map[string]any{"request_id": "nope"})
	if m := r.await("6", 2*time.Second); m["result"].(map[string]any)["cancelled"] != float64(0) {
		t.Fatalf("cancel of unknown id: %v", m)
	}
	r.send(7, "session.cancel", map[string]any{})
	if errCode(r.await("7", 2*time.Second)) != CodeInvalidParams {
		t.Fatal("cancel without a target accepted")
	}
	if s := r.call("session.list", nil)["result"].(map[string]any)["sessions"].([]any); len(s) != 0 {
		t.Fatalf("a cancelled connect left a session: %v", s)
	}
}

// A request that arrives right after auth must see the connection
// authenticated, even though requests now run concurrently.
func TestDaemonAuthIsOrderedBeforeLaterRequests(t *testing.T) {
	_, r := setup(t, "tok")
	for i := 0; i < 20; i++ {
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "a", "method": "auth", "params": map[string]any{"token": "tok"}})
		v, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "v", "method": "version"})
		r.c.Write(append(append(b, '\n'), append(v, '\n')...))
		if errCode(r.await("a", 2*time.Second)) != 0 || errCode(r.await("v", 2*time.Second)) != 0 {
			t.Fatal("version raced ahead of auth")
		}
	}
}

func TestDaemonPrintsReadyLine(t *testing.T) {
	state := t.TempDir()
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, "setu-daemon", []string{"--listen", "127.0.0.1:0", "--state", state}, pw) }()
	sc := bufio.NewScanner(pr)
	got := make(chan string, 1)
	go func() {
		if sc.Scan() {
			got <- sc.Text()
		}
	}()
	var line string
	select {
	case line = <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("no ready line")
	}
	var ev ReadyEvent
	if err := json.Unmarshal([]byte(line), &ev); err != nil || ev.Event != "daemon_ready" || ev.Version != genadb.Version || ev.PID == 0 {
		t.Fatalf("ready line %q: %v", line, err)
	}
	if !strings.HasPrefix(ev.Listen, "127.0.0.1:") || strings.HasSuffix(ev.Listen, ":0") {
		t.Fatalf("listen %q", ev.Listen)
	}
	tok, err := os.ReadFile(ev.TokenFile)
	if err != nil {
		t.Fatal(err)
	}
	nc, err := net.Dial("tcp", ev.Listen)
	if err != nil {
		t.Fatalf("ready line announced %s but it does not accept: %v", ev.Listen, err)
	}
	r := &rpc{t: t, c: nc, sc: bufio.NewScanner(nc)}
	if errCode(r.call("auth", map[string]any{"token": strings.TrimSpace(string(tok))})) != 0 {
		t.Fatal("auth with the token file failed")
	}
	if r.call("version", nil)["result"].(map[string]any)["version"] != genadb.Version {
		t.Fatal("version")
	}
	nc.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not stop")
	}
}
