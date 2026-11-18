package genadb_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sumukhak/new-genadb/core/internal/engine"
	"github.com/sumukhak/new-genadb/core/pkg/genadb"
)

var b64 = base64.RawURLEncoding

// corpWorld is a corporate relay, IdP and enrolled device, in-process.
type corpWorld struct {
	relay, admin, adminToken string
	policyPath, stateDir     string
	relayID, deviceID        string
	idp                      ed25519.PrivateKey
	deviceEvents             chan genadb.Event
	stopDevice               context.CancelFunc
	relayCfg                 engine.RelayConfig
	stopRelay                func()
}

type corpOpts struct {
	maxSessionSeconds int
	grants            map[string][]string
	relayState        string // persisted revocations live here ("" = temp)
}

func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// mint issues an EdDSA JWT like the organisation's IdP would. expIn is
// relative to now; the relay allows 30 s of clock skew.
func (w *corpWorld) mint(sub, typ, pub string, expIn time.Duration) string {
	jti := make([]byte, 8)
	rand.Read(jti)
	now := time.Now()
	cl := map[string]any{"iss": "https://idp.test", "sub": sub, "aud": w.relayID, "typ": typ,
		"iat": now.Unix(), "exp": now.Add(expIn).Unix(), "jti": hex.EncodeToString(jti), "cnf": map[string]string{"key": pub}}
	h := b64.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	cb, _ := json.Marshal(cl)
	signing := h + "." + b64.EncodeToString(cb)
	return signing + "." + b64.EncodeToString(ed25519.Sign(w.idp, []byte(signing)))
}

func startCorp(t *testing.T, o corpOpts) *corpWorld {
	t.Helper()
	pub, idp, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	w := &corpWorld{idp: idp, relayID: "relay-test", deviceID: "dev-A", stateDir: dir,
		adminToken: "admin-secret-token", deviceEvents: make(chan genadb.Event, 256)}
	if o.grants == nil {
		o.grants = map[string][]string{"alice": {"dev-A"}}
	}
	var grants []map[string]any
	for u, d := range o.grants {
		grants = append(grants, map[string]any{"user": u, "devices": d})
	}
	pol := map[string]any{"relay_id": w.relayID, "issuer": "https://idp.test", "idp_ed25519_public_key": b64.EncodeToString(pub),
		"grants": grants, "max_session_seconds": o.maxSessionSeconds}
	pb, _ := json.Marshal(pol)
	w.policyPath = filepath.Join(dir, "policy.json")
	os.WriteFile(w.policyPath, pb, 0o644)

	w.admin = freeAddr(t)
	rs := o.relayState
	if rs == "" {
		rs = t.TempDir()
	}
	w.relayCfg = engine.RelayConfig{Listen: freeAddr(t), Mode: "corporate", PolicyPath: w.policyPath,
		AdminListen: w.admin, AdminToken: w.adminToken, StateDir: rs}
	w.startRelay(t)
	w.startDevice(t)
	return w
}

// startRelay (re)starts the relay on the same addresses and state.
func (w *corpWorld) startRelay(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	cfg := w.relayCfg
	cfg.Events = func(ev string, f map[string]any) {
		if ev == "ready" {
			ready <- f["addr"].(string)
		}
	}
	go func() { done <- engine.RunRelay(ctx, cfg) }()
	w.stopRelay = func() {
		cancel()
		<-done
		time.Sleep(100 * time.Millisecond) // let the admin listener's port go
	}
	t.Cleanup(cancel)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case w.relay = <-ready:
			return
		case err := <-done:
			// the previous instance may still hold a port for a moment: retry
			if err == nil || errors.Is(err, context.Canceled) {
				t.Fatalf("relay stopped: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
			go func() { done <- engine.RunRelay(ctx, cfg) }()
		case <-deadline:
			t.Fatal("relay did not start")
		}
	}
}

func (w *corpWorld) startDevice(t *testing.T) {
	t.Helper()
	devState := filepath.Join(w.stateDir, "device")
	dpub, err := engine.Keygen(devState)
	if err != nil {
		t.Fatal(err)
	}
	enroll := w.mint(w.deviceID, "device", dpub, time.Hour)
	online := make(chan struct{}, 1)
	dev, err := genadb.New(genadb.WithRelayURL(w.relay), genadb.WithStateDir(devState),
		genadb.WithCorporateToken(enroll, w.policyPath), genadb.WithEventHandler(func(e genadb.Event) {
			if e.Type == "online" {
				select {
				case online <- struct{}{}:
				default:
				}
			}
			select {
			case w.deviceEvents <- e:
			default:
			}
		}))
	if err != nil {
		t.Fatal(err)
	}
	dctx, dcancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	w.stopDevice = func() { dcancel(); <-done; dev.Close() }
	t.Cleanup(func() { dcancel() })
	go func() {
		defer close(done)
		dev.HostDevice(dctx, genadb.HostConfig{ADBD: fakeADBD(t), EnrollmentToken: enroll})
	}()
	select {
	case <-online:
	case <-time.After(10 * time.Second):
		t.Fatal("corporate device did not come online")
	}
}

// desktop returns a corporate desktop client for user, plus its public key.
func (w *corpWorld) desktop(t *testing.T, user string, expIn time.Duration, opts ...genadb.Option) (*genadb.SetuClient, string, string) {
	t.Helper()
	state := t.TempDir()
	pub, err := engine.Keygen(state)
	if err != nil {
		t.Fatal(err)
	}
	tok := w.mint(user, "user", pub, expIn)
	c, err := genadb.New(append([]genadb.Option{genadb.WithRelayURL(w.relay), genadb.WithStateDir(state),
		genadb.WithCorporateToken(tok, w.policyPath), genadb.WithReconnectPolicy(genadb.NoReconnect)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, pub, tok
}
