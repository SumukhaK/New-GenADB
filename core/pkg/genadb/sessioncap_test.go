package genadb_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sumukhak/new-genadb/core/pkg/genadb"
)

func readClosed(t *testing.T, c interface {
	Read([]byte) (int, error)
	SetReadDeadline(time.Time) error
}, within time.Duration) bool {
	c.SetReadDeadline(time.Now().Add(within))
	_, err := c.Read(make([]byte, 1))
	var ne interface{ Timeout() bool }
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

func TestMaxSessionSecondsEndsTheSessionForGood(t *testing.T) {
	w := startCorp(t, corpOpts{maxSessionSeconds: 2})
	var mu sync.Mutex
	var expired, down []genadb.Event
	alice, _, _ := w.desktop(t, "alice", time.Hour, genadb.WithReconnectPolicy(genadb.DefaultReconnectPolicy),
		genadb.WithEventHandler(func(e genadb.Event) {
			mu.Lock()
			defer mu.Unlock()
			switch e.Type {
			case "session_expired":
				expired = append(expired, e)
			case genadb.EventSessionDown:
				down = append(down, e)
			}
		}))
	s := connectCorp(t, alice, w.deviceID)
	held, err := dialADB(s.ADBAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	select {
	case <-s.Done():
	case <-time.After(8 * time.Second):
		t.Fatal("session outlived max_session_seconds (silent rejoin bypass)")
	}
	if err := s.Err(); !errors.Is(err, genadb.ErrSessionExpired) || !errors.Is(err, genadb.ErrDenied) {
		t.Fatalf("session ended with %v, want ErrSessionExpired", err)
	}
	if !readClosed(t, held, 3*time.Second) {
		t.Fatal("the adb stream survived the cap")
	}
	// Not retried behind the caller's back, even with the default policy.
	time.Sleep(1500 * time.Millisecond)
	if n := len(alice.Sessions()); n != 0 {
		t.Fatalf("%d sessions after expiry", n)
	}
	mu.Lock()
	if len(expired) != 1 || len(down) != 1 {
		t.Fatalf("events: expired=%v down=%v", expired, down)
	}
	mu.Unlock()
	// Re-authenticating (a new Connect) starts a fresh session.
	s2 := connectCorp(t, alice, w.deviceID)
	if err := tryADB(s2.ADBAddr()); err != nil {
		t.Fatal(err)
	}
	s2.Stop()
}

// The device enforces the cap itself: a desktop (and relay) whose policy
// has no cap cannot keep a tunnel alive past the device's limit.
func TestDeviceEnforcesSessionCapOnItsOwn(t *testing.T) {
	w := startCorp(t, corpOpts{deviceMaxSession: 2})
	alice, _, _ := w.desktop(t, "alice", time.Hour)
	s := connectCorp(t, alice, w.deviceID)
	defer s.Stop()
	held, err := dialADB(s.ADBAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	start := time.Now()
	if !readClosed(t, held, 8*time.Second) {
		t.Fatal("tunnel outlived the device's max_session_seconds")
	}
	if d := time.Since(start); d < time.Second {
		t.Fatalf("closed too early (%v)", d)
	}
	select {
	case <-s.Done():
		if !errors.Is(s.Err(), genadb.ErrSessionExpired) {
			t.Fatalf("session ended with %v", s.Err())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("desktop did not end the session after the device's session_expired")
	}
}
