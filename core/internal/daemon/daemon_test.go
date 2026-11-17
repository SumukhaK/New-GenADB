package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sumukhak/new-genadb/core/pkg/genadb"
)

type rpc struct {
	t  *testing.T
	c  net.Conn
	sc *bufio.Scanner
	id int
}

func (r *rpc) call(method string, params any) map[string]any {
	r.id++
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": r.id, "method": method, "params": params})
	r.c.Write(append(b, '\n'))
	for {
		m := r.next()
		if _, isNote := m["method"]; !isNote {
			return m
		}
	}
}

func (r *rpc) next() map[string]any {
	r.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if !r.sc.Scan() {
		r.t.Fatalf("no response: %v", r.sc.Err())
	}
	var m map[string]any
	if err := json.Unmarshal(r.sc.Bytes(), &m); err != nil {
		r.t.Fatal(err)
	}
	return m
}

func errCode(m map[string]any) int {
	e, ok := m["error"].(map[string]any)
	if !ok {
		return 0
	}
	return int(e["code"].(float64))
}

func setup(t *testing.T, token string, opts ...genadb.Option) (*Server, *rpc) {
	srv := &Server{Token: token}
	c, err := genadb.New(append([]genadb.Option{genadb.WithStateDir(t.TempDir()), genadb.WithEventHandler(srv.Publish)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	srv.Client = c
	a, b := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); a.Close(); b.Close() })
	go srv.ServeConn(ctx, a)
	return srv, &rpc{t: t, c: b, sc: bufio.NewScanner(b)}
}

func TestDaemonAuthAndMethods(t *testing.T) {
	srv, r := setup(t, "s3cret-token")
	if errCode(r.call("version", nil)) != CodeUnauthorized {
		t.Fatal("unauthenticated call allowed")
	}
	if errCode(r.call("auth", map[string]any{"token": "wrong"})) != CodeUnauthorized {
		t.Fatal("wrong token accepted")
	}
	if m := r.call("auth", map[string]any{"token": "s3cret-token"}); errCode(m) != 0 {
		t.Fatalf("auth: %v", m)
	}
	v := r.call("version", nil)["result"].(map[string]any)
	if v["version"] != genadb.Version || v["mode"] != "solo" || v["audit"] != false {
		t.Fatalf("version = %v", v)
	}
	if d := r.call("devices.list", nil)["result"].(map[string]any)["devices"].([]any); len(d) != 0 {
		t.Fatalf("devices = %v", d)
	}
	if k := r.call("identity.public_key", nil)["result"].(map[string]any)["public_key"].(string); k == "" {
		t.Fatal("no public key")
	}
	m := r.call("audit.report", map[string]any{"format": "csv"})
	if errCode(m) != CodeAuditDisabled || m["error"].(map[string]any)["data"].(map[string]any)["kind"] != "audit_disabled" {
		t.Fatalf("audit.report in solo = %v", m)
	}
	if errCode(r.call("session.connect", map[string]any{"device_id": "x", "bogus": 1})) != CodeInvalidParams {
		t.Fatal("unknown params accepted")
	}
	if errCode(r.call("session.stop", map[string]any{"session_id": "nope"})) != CodeNoSession {
		t.Fatal("stop of unknown session")
	}
	if errCode(r.call("no.such.method", nil)) != CodeMethodNotFound {
		t.Fatal("unknown method")
	}
	if s := r.call("session.list", nil)["result"].(map[string]any)["sessions"].([]any); len(s) != 0 {
		t.Fatalf("sessions = %v", s)
	}
	doc := r.call("doctor", nil)["result"].(map[string]any)
	if doc["version"] != genadb.Version {
		t.Fatalf("doctor = %v", doc)
	}

	r.call("events.subscribe", nil)
	go srv.Publish(genadb.Event{Type: "online", Fields: map[string]any{"device_id": "d1"}})
	n := r.next()
	if n["method"] != "event" || n["params"].(map[string]any)["type"] != "online" {
		t.Fatalf("notification = %v", n)
	}
	// malformed input gets a parse error, not a dropped connection
	r.c.Write([]byte("{not json\n"))
	if errCode(r.next()) != CodeParse {
		t.Fatal("parse error expected")
	}
}

func TestDaemonCorporateAuditReport(t *testing.T) {
	_, r := setup(t, "", genadb.WithAuditConfig(genadb.AuditConfig{Mode: genadb.AuditOn}))
	m := r.call("audit.report", map[string]any{"format": "json"})
	res := m["result"].(map[string]any)
	if res["format"] != "json" || res["report"] == nil {
		t.Fatalf("report = %v", m)
	}
	v := r.call("audit.verify", nil)["result"].(map[string]any)
	if v["valid"] != true {
		t.Fatalf("verify = %v", v)
	}
	if errCode(r.call("audit.report", map[string]any{"format": "pdf"})) != CodeInvalidParams {
		t.Fatal("bad format accepted")
	}
	if !strings.Contains(r.call("audit.report", map[string]any{"format": "html"})["result"].(map[string]any)["content"].(string), "<html") {
		t.Fatal("html report")
	}
}
