package genadb_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sumukhak/new-genadb/core/internal/daemon"
	"github.com/sumukhak/new-genadb/core/internal/engine"
	"github.com/sumukhak/new-genadb/core/pkg/genadb"
	"github.com/sumukhak/new-genadb/core/pkg/genadb/audit"
)

const (
	aCNXN = 0x4E584E43
	aOPEN = 0x4E45504F
	aOKAY = 0x59414B4F
	aCLSE = 0x45534C43
	aWRTE = 0x45545257
)

func amsg(cmd, a0, a1 uint32, payload []byte) []byte {
	b := make([]byte, 24+len(payload))
	binary.LittleEndian.PutUint32(b[0:], cmd)
	binary.LittleEndian.PutUint32(b[4:], a0)
	binary.LittleEndian.PutUint32(b[8:], a1)
	binary.LittleEndian.PutUint32(b[12:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(b[20:], cmd^0xFFFFFFFF)
	copy(b[24:], payload)
	return b
}

type amsgT struct {
	cmd, a0, a1 uint32
	payload     []byte
}

func readMsg(r io.Reader) (amsgT, error) {
	h := make([]byte, 24)
	if _, err := io.ReadFull(r, h); err != nil {
		return amsgT{}, err
	}
	m := amsgT{cmd: binary.LittleEndian.Uint32(h), a0: binary.LittleEndian.Uint32(h[4:]), a1: binary.LittleEndian.Uint32(h[8:])}
	m.payload = make([]byte, binary.LittleEndian.Uint32(h[12:]))
	_, err := io.ReadFull(r, m.payload)
	return m, err
}

func syncReq(id string, body []byte) []byte {
	b := make([]byte, 8+len(body))
	copy(b, id)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(body)))
	copy(b[8:], body)
	return b
}

// fakeADBD answers CNXN, accepts every OPEN, acks every WRTE and completes
// sync SENDs with an OKAY status, which is all the audit observer needs.
func fakeADBD(t *testing.T) string {
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
			go func(c net.Conn) {
				defer c.Close()
				next := uint32(100)
				for {
					m, err := readMsg(c)
					if err != nil {
						return
					}
					switch m.cmd {
					case aCNXN:
						c.Write(amsg(aCNXN, 0x01000001, 256*1024, []byte("device::ro.product.name=fake;\x00")))
					case aOPEN:
						next++
						c.Write(amsg(aOKAY, next, m.a0, nil))
					case aWRTE:
						c.Write(amsg(aOKAY, m.a1, m.a0, nil))
						if n := len(m.payload); n >= 8 && string(m.payload[n-8:n-4]) == "DONE" {
							c.Write(amsg(aWRTE, m.a1, m.a0, syncReq("OKAY", nil)))
						}
					case aCLSE:
						c.Write(amsg(aCLSE, m.a1, m.a0, nil))
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

type fixture struct {
	relay string
	code  string
	ctx   context.Context
}

// startWorld runs a relay and a device agent (through the SDK) in-process.
func startWorld(t *testing.T) fixture {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ready := make(chan string, 1)
	go engine.RunRelay(ctx, engine.RelayConfig{Listen: "127.0.0.1:0", Events: func(ev string, f map[string]any) {
		if ev == "ready" {
			ready <- f["addr"].(string)
		}
	}})
	var relay string
	select {
	case relay = <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not start")
	}
	codes := make(chan string, 4)
	dev, err := genadb.New(genadb.WithRelayURL(relay), genadb.WithStateDir(t.TempDir()), genadb.WithEventHandler(func(e genadb.Event) {
		if e.Type == "pairing_code" {
			codes <- e.Fields["code"].(string)
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close() })
	go dev.HostDevice(ctx, genadb.HostConfig{ADBD: fakeADBD(t)})
	select {
	case code := <-codes:
		return fixture{relay: relay, code: code, ctx: ctx}
	case <-time.After(10 * time.Second):
		t.Fatal("device did not publish a pairing code")
	}
	return fixture{}
}

// adbPush plays the host side of `adb push` through the session.
func adbPush(t *testing.T, addr, path string, content []byte) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	c.Write(amsg(aCNXN, 0x01000001, 256*1024, []byte("host::\x00")))
	if m, err := readMsg(c); err != nil || m.cmd != aCNXN {
		t.Fatalf("CNXN: %v %x", err, m.cmd)
	}
	c.Write(amsg(aOPEN, 1, 0, []byte("sync:\x00")))
	m, err := readMsg(c)
	if err != nil || m.cmd != aOKAY {
		t.Fatalf("OPEN: %v %x", err, m.cmd)
	}
	remote := m.a0
	done := make([]byte, 8)
	copy(done, "DONE")
	payload := append(append(syncReq("SEND", []byte(path+",33206")), syncReq("DATA", content)...), done...)
	c.Write(amsg(aWRTE, 1, remote, payload))
	for {
		m, err := readMsg(c)
		if err != nil {
			t.Fatalf("waiting for push status: %v", err)
		}
		if m.cmd == aWRTE {
			if !bytes.HasPrefix(m.payload, []byte("OKAY")) {
				t.Fatalf("push status %q", m.payload)
			}
			c.Write(amsg(aOKAY, 1, remote, nil))
			break
		}
	}
	c.Write(amsg(aCLSE, 1, remote, nil))
	readMsg(c)
}

func waitFor(t *testing.T, what string, f func() bool) {
	deadline := time.Now().Add(10 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestPairConnectAuditReportAndWebhook(t *testing.T) {
	w := startWorld(t)
	secret := []byte("test-webhook-secret")
	var hookMu sync.Mutex
	var hooked []audit.Event
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !audit.VerifySignature(secret, r.Header.Get("X-GenADB-Timestamp"), r.Header.Get("X-GenADB-Signature"), body) {
			http.Error(rw, "bad signature", http.StatusUnauthorized)
			return
		}
		var e audit.Event
		json.Unmarshal(body, &e)
		hookMu.Lock()
		hooked = append(hooked, e)
		hookMu.Unlock()
	}))
	defer srv.Close()

	state := t.TempDir()
	var evMu sync.Mutex
	seen := map[string]int{}
	c, err := genadb.New(
		genadb.WithRelayURL(w.relay),
		genadb.WithStateDir(state),
		genadb.WithAuditConfig(genadb.AuditConfig{Mode: genadb.AuditOn, WebhookURL: srv.URL, WebhookSecret: secret}),
		genadb.WithReconnectPolicy(genadb.NoReconnect),
		genadb.WithEventHandler(func(e genadb.Event) { evMu.Lock(); seen[e.Type]++; evMu.Unlock() }),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// A wrong code is a typed denial.
	bad := w.code[:len(w.code)-1] + "Z"
	if strings.HasSuffix(w.code, "Z") {
		bad = w.code[:len(w.code)-1] + "Y"
	}
	if _, err := c.Connect(w.ctx, genadb.ConnectRequest{PairingCode: bad}); !errors.Is(err, genadb.ErrDenied) {
		t.Fatalf("wrong code: %v", err)
	}
	if _, err := c.Connect(w.ctx, genadb.ConnectRequest{DeviceID: "never-paired"}); !errors.Is(err, genadb.ErrNotPaired) {
		t.Fatalf("unpaired device: %v", err)
	}

	sess, err := c.Connect(w.ctx, genadb.ConnectRequest{PairingCode: w.code})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if sess.ADBAddr() == "" || sess.DeviceID() == "" {
		t.Fatalf("session = %q %q", sess.ADBAddr(), sess.DeviceID())
	}
	devs, _ := c.Devices(w.ctx)
	if len(devs) != 1 || devs[0].ID != sess.DeviceID() {
		t.Fatalf("devices = %+v", devs)
	}

	content := bytes.Repeat([]byte("audited bytes "), 1000)
	adbPush(t, sess.ADBAddr(), "/sdcard/Download/app.bin", content)

	readLog := func() []audit.Event {
		evs, _ := audit.ReadFile(c.AuditPath())
		return evs
	}
	waitFor(t, "session_end record", func() bool {
		for _, e := range readLog() {
			if e["event"] == "session_end" {
				return true
			}
		}
		return false
	})
	evs := readLog()
	if st := audit.Verify(evs); !st.Valid {
		t.Fatalf("chain: %+v", st)
	}
	var push audit.Event
	for _, e := range evs {
		if e["event"] == "adb_op" && e["op"] == "push" {
			push = e
		}
	}
	want := sha256.Sum256(content)
	if push == nil || push["sha256"] != hex.EncodeToString(want[:]) || push["path"] != "/sdcard/Download/app.bin" ||
		push["device"] != sess.DeviceID() || push["transport"] != nil && push["transport"] == "" {
		t.Fatalf("push record = %v", push)
	}
	raw, _ := json.Marshal(evs)
	if bytes.Contains(raw, []byte("audited bytes")) || bytes.Contains(raw, []byte(w.code)) {
		t.Fatal("audit log contains file contents or the pairing code")
	}

	for _, f := range []audit.Format{audit.FormatJSON, audit.FormatCSV, audit.FormatHTML} {
		var buf bytes.Buffer
		if err := c.ExportAuditReport(&buf, f, audit.Options{}); err != nil {
			t.Fatalf("%s report: %v", f, err)
		}
		if !strings.Contains(buf.String(), "push") {
			t.Fatalf("%s report lacks the push:\n%s", f, buf.String())
		}
	}

	sess.Stop()
	if err := sess.Err(); err != nil {
		t.Fatalf("stopped session err = %v", err)
	}
	if len(c.Sessions()) != 0 {
		t.Fatal("session still listed after Stop")
	}
	c.Close()
	waitFor(t, "webhook deliveries", func() bool { hookMu.Lock(); defer hookMu.Unlock(); return len(hooked) >= len(evs) })
	hookMu.Lock()
	for i, e := range hooked[:len(evs)] {
		if e["event_hash"] != evs[i]["event_hash"] {
			t.Fatalf("webhook record %d differs from the file", i)
		}
	}
	hookMu.Unlock()
	evMu.Lock()
	defer evMu.Unlock()
	for _, typ := range []string{genadb.EventPaired, genadb.EventListening, genadb.EventSessionUp, genadb.EventAudit, genadb.EventSessionDown} {
		if seen[typ] == 0 {
			t.Errorf("no %q event (seen %v)", typ, seen)
		}
	}
}

func TestSoloAuditOffByDefault(t *testing.T) {
	c, err := genadb.New(genadb.WithStateDir(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.AuditPath() != "" {
		t.Fatal("solo mode must not audit by default")
	}
	if err := c.ExportAuditReport(io.Discard, audit.FormatJSON, audit.Options{}); !errors.Is(err, genadb.ErrAuditDisabled) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.Connect(context.Background(), genadb.ConnectRequest{DeviceID: "x"}); !errors.Is(err, genadb.ErrNoRelay) {
		t.Fatalf("err = %v", err)
	}
}

func TestCorporateRequiresTokenAndAudit(t *testing.T) {
	dir := t.TempDir()
	if _, err := genadb.New(genadb.WithStateDir(dir), genadb.WithMode(genadb.ModeCorporate)); !errors.Is(err, genadb.ErrTokenInvalid) {
		t.Fatalf("no token: %v", err)
	}
	pol := filepath.Join(dir, "policy.json")
	if _, err := genadb.New(genadb.WithStateDir(dir), genadb.WithCorporateToken("t", pol),
		genadb.WithAuditConfig(genadb.AuditConfig{Mode: genadb.AuditOff})); err == nil {
		t.Fatal("corporate mode accepted AuditOff")
	}
	c, err := genadb.New(genadb.WithStateDir(dir), genadb.WithCorporateToken("t", pol))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.AuditPath() != filepath.Join(dir, "audit.jsonl") {
		t.Fatalf("corporate audit path = %q", c.AuditPath())
	}
}

func TestDoctor(t *testing.T) {
	w := startWorld(t)
	r := genadb.Diagnose(w.ctx, genadb.DoctorOptions{StateDir: t.TempDir(), Relay: w.relay, ADBPath: "/nonexistent/adb"})
	got := map[string]genadb.CheckStatus{}
	for _, c := range r.Checks {
		got[c.Name] = c.Status
	}
	if got["relay_reach"] != genadb.CheckOK || got["relay_dns"] != genadb.CheckOK || got["state"] != genadb.CheckOK {
		t.Fatalf("checks = %+v", r.Checks)
	}
	if got["adb"] != genadb.CheckWarn {
		t.Fatalf("missing adb should warn: %+v", r.Checks)
	}
	r = genadb.Diagnose(w.ctx, genadb.DoctorOptions{StateDir: t.TempDir(), Relay: "127.0.0.1:1", Timeout: 2 * time.Second})
	if r.OK {
		t.Fatalf("unreachable relay reported OK: %+v", r.Checks)
	}
}

// Regression: a UI that subscribes to events and stops reading, or an event
// handler that blocks, must not stall ADB tunnels (audit records are written
// on the data path and republished as events).
func TestBlockedEventConsumersDoNotStallTunnels(t *testing.T) {
	w := startWorld(t)
	srv := &daemon.Server{}
	block := make(chan struct{})
	defer close(block)
	c, err := genadb.New(
		genadb.WithRelayURL(w.relay),
		genadb.WithStateDir(t.TempDir()),
		genadb.WithAuditConfig(genadb.AuditConfig{Mode: genadb.AuditOn}),
		genadb.WithEventHandler(func(e genadb.Event) {
			srv.Publish(e)
			<-block // a handler that never returns
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	srv.Client = c

	// A daemon client that subscribes and then never reads again.
	ui, server := net.Pipe()
	defer ui.Close()
	go srv.ServeConn(w.ctx, server)
	ui.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"events.subscribe"}` + "\n"))
	buf := make([]byte, 256)
	ui.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := ui.Read(buf); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	sess, err := c.Connect(w.ctx, genadb.ConnectRequest{PairingCode: w.code})
	if err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte("x"), 1<<20)
	start := time.Now()
	const pushes = 8
	for i := 0; i < pushes; i++ {
		done := make(chan struct{})
		go func() { defer close(done); adbPush(t, sess.ADBAddr(), fmt.Sprintf("/sdcard/f%d", i), content) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("push %d stalled behind blocked event consumers", i)
		}
	}
	elapsed := time.Since(start)
	waitFor(t, "audit records", func() bool {
		evs, _ := audit.ReadFile(c.AuditPath())
		n := 0
		for _, e := range evs {
			if e["op"] == "push" {
				n++
			}
		}
		return n == pushes
	})
	if c.DroppedEvents() == 0 {
		// Not an error by itself, but proves the consumers really were stuck.
		t.Log("no events dropped")
	}
	t.Logf("%d x 1 MiB pushes in %v with a blocked handler and a stalled subscriber (%d events dropped)", pushes, elapsed, c.DroppedEvents())
}
