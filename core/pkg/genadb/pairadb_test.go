package genadb_test

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sumukhak/new-genadb/core/pkg/genadb"
)

// pairedClient pairs a fresh desktop client with the world's device and
// returns it with the device id. The pairing session is stopped again.
func pairedClient(t *testing.T, w fixture, opts ...genadb.Option) (*genadb.SetuClient, string) {
	t.Helper()
	c, err := genadb.New(append([]genadb.Option{genadb.WithRelayURL(w.relay), genadb.WithStateDir(t.TempDir()),
		genadb.WithReconnectPolicy(genadb.NoReconnect)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, err := c.Connect(ctx, genadb.ConnectRequest{PairingCode: w.code})
	if err != nil {
		t.Fatal(err)
	}
	id := s.DeviceID()
	s.Stop()
	return c, id
}

// fakePairingService plays the phone's Wireless-debugging pairing port: it
// reads one line and answers "PAIRED <line>".
func fakePairingService(t *testing.T) (port int, got func() []string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var lines []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				l, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return
				}
				mu.Lock()
				lines = append(lines, strings.TrimSpace(l))
				mu.Unlock()
				c.Write([]byte("PAIRED " + l))
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), lines...) }
}

// fakeADBPair stands in for `adb pair`: it speaks to the tunnelled pairing
// service and reports success when the service answered.
func fakeADBPair(ctx context.Context, adbPath, addr, code string) (string, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	c.Write([]byte("SPAKE2 " + code + "\n"))
	l, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return "", errors.New("Failed: Unable to start pairing client.")
	}
	return "Successfully paired to " + addr + " " + strings.TrimSpace(l), nil
}

func TestPairADBTunnelsWirelessDebuggingPairing(t *testing.T) {
	w := startWorld(t)
	port, got := fakePairingService(t)
	var evMu sync.Mutex
	var pairEvents []genadb.Event
	c, id := pairedClient(t, w, genadb.WithADBPairer(fakeADBPair), genadb.WithEventHandler(func(e genadb.Event) {
		if e.Type == genadb.EventADBPair {
			evMu.Lock()
			pairEvents = append(pairEvents, e)
			evMu.Unlock()
		}
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := c.PairADB(ctx, genadb.PairADBRequest{DeviceID: id, PairingPort: port, PairingCode: "123456"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Paired || res.Transport != "relay-tcp" || res.DeviceID != id {
		t.Fatalf("result %+v", res)
	}
	if !strings.Contains(res.Output, "PAIRED SPAKE2 123456") {
		t.Fatalf("output %q", res.Output)
	}
	if l := got(); len(l) != 1 || l[0] != "SPAKE2 123456" {
		t.Fatalf("pairing service saw %q", l)
	}
	waitFor(t, "adb_pair event", func() bool { evMu.Lock(); defer evMu.Unlock(); return len(pairEvents) == 1 })
	if pairEvents[0].Fields["paired"] != true {
		t.Fatalf("event %+v", pairEvents[0])
	}
}

func TestPairADBReportsUnreachablePairingService(t *testing.T) {
	w := startWorld(t)
	// A port nothing listens on: the dialog was closed on the phone.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	c, id := pairedClient(t, w, genadb.WithADBPairer(fakeADBPair))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := c.PairADB(ctx, genadb.PairADBRequest{DeviceID: id, PairingPort: port, PairingCode: "123456"})
	if !errors.Is(err, genadb.ErrADBPairFailed) {
		t.Fatalf("want ErrADBPairFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "pairing service unreachable") {
		t.Fatalf("error should carry the device's reason: %v", err)
	}
}

func TestPairADBValidatesInput(t *testing.T) {
	w := startWorld(t)
	c, id := pairedClient(t, w, genadb.WithADBPairer(fakeADBPair))
	ctx := context.Background()
	for _, code := range []string{"", "12345", "1234567", "12a456", "1234-567890"} {
		if _, err := c.PairADB(ctx, genadb.PairADBRequest{DeviceID: id, PairingPort: 1, PairingCode: code}); !errors.Is(err, genadb.ErrBadCode) {
			t.Fatalf("code %q: %v", code, err)
		}
	}
	if _, err := c.PairADB(ctx, genadb.PairADBRequest{DeviceID: id, PairingPort: 70000, PairingCode: "123456"}); !errors.Is(err, genadb.ErrDenied) {
		t.Fatalf("bad port: %v", err)
	}
	if _, err := c.PairADB(ctx, genadb.PairADBRequest{PairingPort: 1, PairingCode: "123456"}); !errors.Is(err, genadb.ErrNoDevice) {
		t.Fatalf("no device: %v", err)
	}
	if _, err := c.PairADB(ctx, genadb.PairADBRequest{DeviceID: "dev-unknown", PairingPort: 1, PairingCode: "123456"}); !errors.Is(err, genadb.ErrNotPaired) {
		t.Fatalf("unpaired device: %v", err)
	}
}

func TestExecADBPairNeedsSuccessLine(t *testing.T) {
	// "true" exits 0 but prints nothing: not a success.
	if _, err := genadb.ExecADBPair(context.Background(), "true", "127.0.0.1:1", "123456"); err == nil {
		t.Fatal("silent exit 0 must not count as paired")
	}
	if _, err := genadb.ExecADBPair(context.Background(), "/nonexistent/adb", "127.0.0.1:1", "123456"); err == nil {
		t.Fatal("missing adb must fail")
	}
}
