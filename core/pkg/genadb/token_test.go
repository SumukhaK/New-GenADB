package genadb_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sumukhak/new-genadb/core/pkg/genadb"
	"github.com/sumukhak/new-genadb/core/pkg/genadb/audit"
)

// tryADB opens an adb connection through a session and completes the CNXN
// exchange, which needs a fresh authenticated stream to the device.
func tryADB(addr string) error {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	c.Write(amsg(aCNXN, 0x01000001, 256*1024, []byte("host::\x00")))
	m, err := readMsg(c)
	if err != nil {
		return err
	}
	if m.cmd != aCNXN {
		return fmt.Errorf("got %x, want CNXN", m.cmd)
	}
	return nil
}

func connectCorp(t *testing.T, c *genadb.SetuClient, dev string) *genadb.SetuSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, err := c.Connect(ctx, genadb.ConnectRequest{DeviceID: dev})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The relay allows 30 s of clock skew, so a token "expired 27 s ago" is
// still accepted for about 3 s.
const almostExpired = -27 * time.Second

func TestSetTokenRotatesLiveSessionWithoutRestart(t *testing.T) {
	w := startCorp(t, corpOpts{})
	rotated, pub, _ := w.desktop(t, "alice", almostExpired)
	stale, _, _ := w.desktop(t, "alice", almostExpired)
	s1 := connectCorp(t, rotated, w.deviceID)
	s2 := connectCorp(t, stale, w.deviceID)
	if err := tryADB(s1.ADBAddr()); err != nil {
		t.Fatal(err)
	}
	fresh := w.mint("alice", "user", pub, time.Hour)
	info, err := rotated.SetToken(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if info.Subject != "alice" || info.ExpiresAt.Before(time.Now()) {
		t.Fatalf("info %+v", info)
	}
	time.Sleep(4 * time.Second) // the original tokens are now expired
	if err := tryADB(s1.ADBAddr()); err != nil {
		t.Fatalf("rotated session cannot open a new adb connection: %v", err)
	}
	if err := tryADB(s2.ADBAddr()); err == nil {
		t.Fatal("control: a session on an expired token still opened a stream")
	}
	select {
	case <-s1.Done():
		t.Fatal("rotation dropped the session")
	default:
	}
	// The audit trail follows the rotation: token_rotated, then a session
	// recorded under the new token id.
	evs, err := audit.ReadFile(rotated.AuditPath())
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	rot := false
	for _, e := range evs {
		switch e["event"] {
		case "token_rotated":
			rot = true
			if e["token_id"] != info.TokenID {
				t.Fatalf("token_rotated %v", e)
			}
		case "session_start":
			ids = append(ids, fmt.Sprint(e["token_id"]))
		}
	}
	if !rot || len(ids) != 2 || ids[0] == ids[1] || ids[1] != info.TokenID {
		t.Fatalf("audit token ids %v (rotated=%v, want second = %s)", ids, rot, info.TokenID)
	}
	if st, err := audit.VerifyFile(rotated.AuditPath(), audit.VerifyOptions{}); err != nil || !st.Valid {
		t.Fatalf("audit chain: %+v %v", st, err)
	}
}

func TestSetTokenRejectsBadTokens(t *testing.T) {
	w := startCorp(t, corpOpts{grants: map[string][]string{"alice": {"dev-A"}, "bob": {"dev-A"}}})
	c, pub, orig := w.desktop(t, "alice", time.Hour)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub := b64.EncodeToString(otherPriv.Public().(ed25519.PublicKey))
	forger := *w
	_, forger.idp, _ = ed25519.GenerateKey(rand.Reader)
	cases := map[string]struct {
		tok  string
		want error
	}{
		"expired":     {w.mint("alice", "user", pub, -time.Hour), genadb.ErrTokenExpired},
		"forged":      {forger.mint("alice", "user", pub, time.Hour), genadb.ErrTokenInvalid},
		"other key":   {w.mint("alice", "user", otherPub, time.Hour), genadb.ErrTokenInvalid},
		"device type": {w.mint("alice", "device", pub, time.Hour), genadb.ErrTokenInvalid},
		"garbage":     {"not-a-jwt", genadb.ErrTokenInvalid},
	}
	for name, tc := range cases {
		if _, err := c.SetToken(tc.tok); !errors.Is(err, tc.want) || !errors.Is(err, genadb.ErrDenied) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}
	// Switching users under live sessions is refused; without sessions it is fine.
	s := connectCorp(t, c, w.deviceID)
	bob := w.mint("bob", "user", pub, time.Hour)
	if _, err := c.SetToken(bob); !errors.Is(err, genadb.ErrTokenInvalid) {
		t.Fatalf("subject switch with live sessions: %v", err)
	}
	if err := tryADB(s.ADBAddr()); err != nil {
		t.Fatalf("a rejected token must leave the current one in place: %v", err)
	}
	s.Stop()
	if info, err := c.SetToken(bob); err != nil || info.Subject != "bob" {
		t.Fatalf("subject switch without sessions: %+v %v", info, err)
	}

	solo, err := genadb.New(genadb.WithStateDir(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer solo.Close()
	if _, err := solo.SetToken(orig); !errors.Is(err, genadb.ErrDenied) {
		t.Fatalf("solo SetToken: %v", err)
	}
}

func TestWatchIdentityFileRotatesAndReportsBadTokens(t *testing.T) {
	w := startCorp(t, corpOpts{})
	var mu sync.Mutex
	var got []genadb.Event
	c, pub, tok := w.desktop(t, "alice", time.Hour, genadb.WithEventHandler(func(e genadb.Event) {
		if e.Type == genadb.EventTokenUpdated || e.Type == genadb.EventError {
			mu.Lock()
			got = append(got, e)
			mu.Unlock()
		}
	}))
	path := filepath.Join(t.TempDir(), "identity.jwt")
	os.WriteFile(path, []byte(tok+"\n"), 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.WatchIdentityFile(ctx, path, 20*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	if len(got) != 0 {
		t.Fatalf("unchanged file produced events: %v", got)
	}
	mu.Unlock()
	next := w.mint("alice", "user", pub, 2*time.Hour)
	os.WriteFile(path, []byte(next+"\n"), 0o600)
	waitFor(t, "token_updated", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 1 })
	os.WriteFile(path, []byte("garbage\n"), 0o600)
	waitFor(t, "identity_file error", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 2 })
	mu.Lock()
	defer mu.Unlock()
	if got[0].Type != genadb.EventTokenUpdated || got[0].Fields["subject"] != "alice" {
		t.Fatalf("first event %+v", got[0])
	}
	if got[1].Type != genadb.EventError || got[1].Fields["source"] != "identity_file" {
		t.Fatalf("second event %+v", got[1])
	}
}

// dialADB opens an adb connection through a session and leaves it open.
func dialADB(addr string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	c.Write(amsg(aCNXN, 0x01000001, 256*1024, []byte("host::\x00")))
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err := readMsg(c); err != nil {
		c.Close()
		return nil, err
	}
	c.SetReadDeadline(time.Time{})
	return c, nil
}
