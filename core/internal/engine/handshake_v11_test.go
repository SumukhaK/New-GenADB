package engine

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"testing"
)

func testKeys() keys {
	k := keys{confirm: make([]byte, 32)}
	rand.Read(k.confirm)
	return k
}

func TestHandshakeMetaIsSealed(t *testing.T) {
	k := testKeys()
	m := handshakeMeta{Target: "adb-pair:37123", Label: "build-box"}
	ct := sealMeta(k, m)
	if bytes.Contains(ct, []byte("adb-pair")) || bytes.Contains(ct, []byte("build-box")) {
		t.Fatal("metadata visible in the clear")
	}
	got, err := openMeta(k, ct)
	if err != nil || got != m {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	ct[3] ^= 1
	if _, err := openMeta(k, ct); err == nil {
		t.Fatal("tampered metadata accepted")
	}
	if _, err := openMeta(testKeys(), sealMeta(k, m)); err == nil {
		t.Fatal("metadata opened under another session's key")
	}
	if got, err := openMeta(k, nil); err != nil || got != (handshakeMeta{}) {
		t.Fatal("absent metadata must mean adbd")
	}
}

// runServer drives serverHandshake on one end of a pipe and returns what the
// client side reads as M2 (raw JSON).
func m2For(t *testing.T, m1 hsMsg) map[string]any {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_, dev, _ := ed25519.GenerateKey(rand.Reader)
	pol := responderPolicy{id: dev, authorize: func(ed25519.PublicKey, string) error { return nil },
		pairing: func() (string, string, bool) { return "", "", false }, pairResult: func(bool, ed25519.PublicKey) {}}
	b1, _ := json.Marshal(m1)
	go serverHandshake(a, a, pol, b1, m1)
	var raw json.RawMessage
	if _, err := readMsg(b, &raw); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(raw, &m)
	return m
}

// A v1.0.x desktop re-encodes M2 with its own struct to hash the transcript,
// so the device must not add fields it does not know about.
func TestDeviceAnnouncesCapsOnlyToV11Desktops(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	old := hsMsg{Mode: "resume", Eph: eph.PublicKey().Bytes(), ID: pub}
	if _, ok := m2For(t, old)["caps"]; ok {
		t.Fatal("caps sent to a v1.0 desktop")
	}
	cur := old
	cur.Caps = []string{capV11}
	caps, _ := m2For(t, cur)["caps"].([]any)
	if len(caps) == 0 {
		t.Fatal("no caps for a v1.1 desktop")
	}
	found := false
	for _, c := range caps {
		found = found || c == capADBPair
	}
	if !found {
		t.Fatalf("caps %v lack %s", caps, capADBPair)
	}
}

func TestPairingTargetNeedsDeviceSupport(t *testing.T) {
	// Device side that strips caps, as a v1.0.x agent would.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_, dev, _ := ed25519.GenerateKey(rand.Reader)
	_, desk, _ := ed25519.GenerateKey(rand.Reader)
	go func() {
		var m1 hsMsg
		b1, err := readMsg(a, &m1)
		if err != nil {
			return
		}
		m1.Caps = nil
		pol := responderPolicy{id: dev, authorize: func(ed25519.PublicKey, string) error { return nil }}
		// An old device hashes the raw M1 but never answers with caps.
		serverHandshake(a, a, pol, b1, m1)
	}()
	_, _, err := clientHandshake(b, b, initiatorParams{id: desk, mode: "resume", target: "adb-pair:1"})
	if !errors.Is(err, ErrUnsupported) || !errors.Is(err, ErrDenied) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
}
