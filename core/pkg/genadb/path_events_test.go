package genadb_test

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sumukhak/new-genadb/core/pkg/genadb"
)

// cuttable dials TCP relays and can sever every stream it opened, the way a
// Wi-Fi to cellular hand-over does.
type cuttable struct {
	mu    sync.Mutex
	conns []net.Conn
}

func (c *cuttable) Dial(spec string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", spec, 5*time.Second)
	if err == nil {
		c.mu.Lock()
		c.conns = append(c.conns, conn)
		c.mu.Unlock()
	}
	return conn, err
}
func (c *cuttable) Label(string) string { return "relay-tcp" }
func (c *cuttable) cut() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, x := range c.conns {
		x.Close()
	}
	c.conns = nil
}

// The v1.1.0 path events reach SetuClient consumers (Events and the handler)
// with the exported type names, so a UI can show "reconnecting" without
// parsing engine output.
func TestSetuClientEmitsPathEvents(t *testing.T) {
	w := startWorld(t)
	tr := &cuttable{}
	evs := make(chan genadb.Event, 64)
	c, err := genadb.New(genadb.WithRelayURL(w.relay), genadb.WithStateDir(t.TempDir()),
		genadb.WithTransport(tr), genadb.WithReconnectPolicy(genadb.NoReconnect),
		genadb.WithEventHandler(func(e genadb.Event) {
			switch e.Type {
			case genadb.EventPathDown, genadb.EventPathUp, genadb.EventPathLost:
				evs <- e
			}
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := c.Connect(w.ctx, genadb.ConnectRequest{PairingCode: w.code})
	if err != nil {
		t.Fatal(err)
	}
	// An adb client keeps one tunnel open.
	ac, err := net.DialTimeout("tcp", s.ADBAddr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ac.Close()
	ac.Write(amsg(aCNXN, 0x01000001, 256*1024, []byte("host::\x00")))
	ac.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := readMsg(ac); err != nil {
		t.Fatalf("no CNXN reply through the tunnel: %v", err)
	}

	tr.cut()
	next := func(want string) genadb.Event {
		t.Helper()
		select {
		case e := <-evs:
			if e.Type != want {
				t.Fatalf("got %s %v, want %s", e.Type, e.Fields, want)
			}
			return e
		case <-time.After(20 * time.Second):
			t.Fatalf("no %s event", want)
		}
		return genadb.Event{}
	}
	down := next(genadb.EventPathDown)
	if down.Session != s.ID() || down.Fields["transport"] != "relay-tcp" || down.Fields["session_id"] == "" {
		t.Fatalf("path_down %+v", down)
	}
	up := next(genadb.EventPathUp)
	if up.Fields["session_id"] != down.Fields["session_id"] || up.Fields["transport"] != "relay-tcp" {
		t.Fatalf("path_up %+v", up)
	}
	if _, ok := up.Fields["outage_ms"]; !ok {
		t.Fatalf("path_up without outage_ms: %+v", up)
	}
	// The adb connection survived the outage.
	ac.Write(amsg(aCNXN, 0x01000001, 256*1024, []byte("host::\x00")))
	if _, err := readMsg(ac); err != nil {
		t.Fatalf("adb stream did not survive the path change: %v", err)
	}
}
