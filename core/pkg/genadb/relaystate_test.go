package genadb_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sumukhak/new-genadb/core/internal/engine"
	"github.com/sumukhak/new-genadb/core/pkg/genadb"
)

func (w *corpWorld) adminCall(t *testing.T, method, path string, body any, auth bool) (int, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, "http://"+w.admin+path, rd)
	if auth {
		req.Header.Set("Authorization", "Bearer "+w.adminToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func connectErr(c *genadb.SetuClient, dev string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, err := c.Connect(ctx, genadb.ConnectRequest{DeviceID: dev})
	if err == nil {
		s.Stop()
	}
	return err
}

func TestRevocationsSurviveRelayRestart(t *testing.T) {
	state := t.TempDir()
	w := startCorp(t, corpOpts{relayState: state, grants: map[string][]string{"alice": {"dev-A"}, "bob": {"dev-A"}}})
	alice, _, _ := w.desktop(t, "alice", time.Hour)
	bob, _, _ := w.desktop(t, "bob", time.Hour)
	if err := connectErr(alice, w.deviceID); err != nil {
		t.Fatal(err)
	}
	if code, m := w.adminCall(t, "POST", "/v1/revoke", map[string]string{"user": "alice"}, true); code != 200 || m["persisted"] != true {
		t.Fatalf("revoke: %d %v", code, m)
	}
	var f struct{ Users, Devices []string }
	b, err := os.ReadFile(filepath.Join(state, "revocations.json"))
	if err != nil || json.Unmarshal(b, &f) != nil || len(f.Users) != 1 || f.Users[0] != "alice" {
		t.Fatalf("revocations.json = %s %v", b, err)
	}
	if st, _ := os.Stat(filepath.Join(state, "revocations.json")); st.Mode().Perm() != 0o600 {
		t.Fatalf("revocations.json mode %v", st.Mode())
	}

	w.stopRelay()
	w.startRelay(t)
	if err := connectErr(alice, w.deviceID); !errors.Is(err, genadb.ErrRevoked) {
		t.Fatalf("restart un-revoked alice: %v", err)
	}
	waitFor(t, "device back online", func() bool { return connectErr(bob, w.deviceID) == nil })
	_, m := w.adminCall(t, "GET", "/v1/revocations", nil, true)
	if u, _ := m["users"].([]any); len(u) != 1 || u[0] != "alice" {
		t.Fatalf("revocations after restart: %v", m)
	}
	if code, _ := w.adminCall(t, "POST", "/v1/unrevoke", map[string]string{"user": "alice"}, true); code != 200 {
		t.Fatal("unrevoke")
	}
	w.stopRelay()
	w.startRelay(t)
	waitFor(t, "alice restored", func() bool { return connectErr(alice, w.deviceID) == nil })
}

func TestCorruptRevocationsFailClosed(t *testing.T) {
	state := t.TempDir()
	os.WriteFile(filepath.Join(state, "revocations.json"), []byte("{not json"), 0o600)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := engine.RunRelay(ctx, engine.RelayConfig{Listen: "127.0.0.1:0", StateDir: state})
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("relay must refuse an unreadable revocation list, got %v", err)
	}
}

func TestAdminDevicesAndUserPresence(t *testing.T) {
	w := startCorp(t, corpOpts{grants: map[string][]string{"alice": {"dev-A", "dev-B"}, "bob": {}, "carol": {"dev-A"}}})
	if code, _ := w.adminCall(t, "GET", "/v1/devices", nil, false); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /v1/devices: %d", code)
	}
	if code, _ := w.adminCall(t, "POST", "/v1/devices", nil, true); code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /v1/devices: %d", code)
	}
	alice, _, _ := w.desktop(t, "alice", time.Hour)
	s := connectCorp(t, alice, w.deviceID)
	defer s.Stop()
	// keep one relayed stream open so the session count is visible
	held := make(chan struct{})
	go func() {
		c, err := dialADB(s.ADBAddr())
		if err == nil {
			<-held
			c.Close()
		}
	}()
	defer close(held)
	waitFor(t, "relayed session", func() bool {
		_, m := w.adminCall(t, "GET", "/v1/devices", nil, true)
		d, _ := m["devices"].([]any)
		return len(d) == 1 && d[0].(map[string]any)["sessions"].(float64) >= 1
	})
	_, m := w.adminCall(t, "GET", "/v1/devices", nil, true)
	d := m["devices"].([]any)[0].(map[string]any)
	if d["device_id"] != "dev-A" || d["online"] != true || d["transport"] != "tcp" || d["connected_at"] == nil {
		t.Fatalf("admin listing %v", d)
	}

	p, err := alice.Presence(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 2 || p[0].DeviceID != "dev-A" || !p[0].Online || p[0].ConnectedAt == nil || p[1].DeviceID != "dev-B" || p[1].Online {
		t.Fatalf("alice presence %+v", p)
	}
	bob, _, _ := w.desktop(t, "bob", time.Hour)
	if p, err := bob.Presence(context.Background()); err != nil || len(p) != 0 {
		t.Fatalf("bob presence %+v %v", p, err)
	}
	// A revoked device is never shown as available; a revoked user is refused.
	w.adminCall(t, "POST", "/v1/revoke", map[string]string{"device": "dev-A"}, true)
	carol, _, _ := w.desktop(t, "carol", time.Hour)
	if p, err := carol.Presence(context.Background()); err != nil || len(p) != 1 || p[0].Online {
		t.Fatalf("revoked device shown available: %+v %v", p, err)
	}
	_, m = w.adminCall(t, "GET", "/v1/devices", nil, true)
	if m["devices"].([]any)[0].(map[string]any)["revoked"] != true {
		t.Fatalf("admin listing must flag the revocation: %v", m)
	}
	w.adminCall(t, "POST", "/v1/revoke", map[string]string{"user": "carol"}, true)
	if _, err := carol.Presence(context.Background()); !errors.Is(err, genadb.ErrRevoked) {
		t.Fatalf("revoked user presence: %v", err)
	}
	solo, _ := genadb.New(genadb.WithStateDir(t.TempDir()), genadb.WithRelayURL(w.relay))
	defer solo.Close()
	if _, err := solo.Presence(context.Background()); !errors.Is(err, genadb.ErrDenied) {
		t.Fatalf("solo presence: %v", err)
	}
}
