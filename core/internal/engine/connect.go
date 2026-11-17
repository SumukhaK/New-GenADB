package engine

import (
	"context"
	"encoding/hex"
	"sync"

	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/sumukhak/new-genadb/core/pkg/genadb/audit"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type desktopAgent struct {
	relayAddr, state, token string
	key                     ed25519.PrivateKey
	dial                    Dialer
	events                  EventFunc
	audit                   audit.Sink
	user, tokenID, deviceID string

	mu      sync.Mutex
	tunnels map[*tunnel]struct{}
}

// EventFunc receives machine-readable agent events ("listening",
// "pairing_code", "online", ...). It must not block.
type EventFunc func(event string, fields map[string]any)

// DesktopConfig configures the desktop-side connect agent.
type DesktopConfig struct {
	Relay      string           // relay address: host:port, ws://... or wss://...
	State      string           // directory for the identity key and paired devices
	Listen     string           // local adb endpoint to expose (default 127.0.0.1:0)
	Mode       string           // "solo" (default) or "corporate"
	Code       string           // pairing code shown on the phone (first connect, solo)
	Device     string           // previously paired / granted device id
	Identity   string           // user identity JWT (corporate)
	PolicyPath string           // policy file (corporate)
	Transport  TransportOptions // relay transport options
	Dial       Dialer           // overrides the relay dialer (nil = Transport.Dialer())
	Events     EventFunc        // receives events; nil = discard
	Audit      audit.Sink       // receives session/operation records; nil = none
}

// RunDesktop pairs (if a code is given), verifies the device, exposes a local
// adb endpoint and tunnels every adb connection to the device until ctx is
// cancelled. It returns ctx.Err() after a clean shutdown.
func RunDesktop(ctx context.Context, cfg DesktopConfig) error {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	if cfg.Mode == "" {
		cfg.Mode = "solo"
	}
	if cfg.Dial == nil {
		cfg.Dial = cfg.Transport.Dialer()
	}
	if cfg.Events == nil {
		cfg.Events = func(string, map[string]any) {}
	}
	if cfg.State == "" {
		cfg.State = "."
	}
	key, err := loadOrCreateKey(cfg.State)
	if err != nil {
		return err
	}
	a := &desktopAgent{relayAddr: cfg.Relay, state: cfg.State, key: key, token: cfg.Identity, dial: cfg.Dial,
		events: cfg.Events, audit: cfg.Audit, tunnels: map[*tunnel]struct{}{}}
	params := initiatorParams{id: key, mode: "resume", token: cfg.Identity}
	if cfg.Mode == "corporate" {
		if cfg.Identity == "" {
			return fmt.Errorf("%w: corporate mode requires an identity token", errDenied)
		}
		pol, err := loadPolicy(cfg.PolicyPath)
		if err != nil {
			return err
		}
		if cfg.Device == "" {
			return fmt.Errorf("corporate mode requires a device id")
		}
		// Audit identity: the token's subject and ID, never the token itself.
		if cl, err := pol.verifyToken(cfg.Identity, "user", key.Public().(ed25519.PublicKey)); err == nil {
			a.user, a.tokenID = cl.Sub, cl.Jti
		}
		want := cfg.Device
		// the device must prove an MDM enrollment bound to the key it uses
		params.verifyPeer = func(peer ed25519.PublicKey, tok string) error {
			cl, err := pol.verifyToken(tok, "device", peer)
			if err != nil {
				return fmt.Errorf("device enrollment: %w", err)
			}
			if cl.Sub != want {
				return fmt.Errorf("device enrollment is for %q, not %q", cl.Sub, want)
			}
			return nil
		}
	}
	id := cfg.Device
	if cfg.Code != "" {
		np, secret, ok := strings.Cut(cfg.Code, "-")
		if !ok {
			return fmt.Errorf("%w: %w: pairing code must look like NNNN-SSSSSS", errDenied, ErrBadCode)
		}
		c, br, did, err := a.openSession(hello{Role: "desktop", Code: np})
		if err != nil {
			return err
		}
		_, peer, err := clientHandshake(c, br, initiatorParams{id: key, mode: "pair", secret: secret, nameplate: np})
		c.Close()
		if err != nil {
			return fmt.Errorf("%w: %w", errDenied, err)
		}
		if err := savePeer(cfg.State, did, peer); err != nil {
			return err
		}
		id = did
		cfg.Events("paired", map[string]any{"device_id": id})
	}
	if cfg.Mode != "corporate" {
		pinned, err := loadPeer(cfg.State, id)
		if err != nil {
			return fmt.Errorf("%w: %w: %q", errDenied, ErrNotPaired, id)
		}
		params.pinnedPeer = pinned
	}
	a.deviceID = id
	// verify the device is reachable and still trusts us before exposing a port
	c, br, rep0, err := a.openSessionRep(hello{Role: "desktop", DeviceID: id})
	if err != nil {
		return err
	}
	lan := rep0.LAN
	_, _, err = clientHandshake(c, br, params)
	c.Close()
	if err != nil {
		return fmt.Errorf("%w: %v", errDenied, err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() {
		ln.Close()
		a.mu.Lock()
		for t := range a.tunnels {
			t.close()
		}
		a.mu.Unlock()
	})
	defer stop()
	cfg.Events("listening", map[string]any{"addr": ln.Addr().String(), "device_id": id})
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go a.serveADB(conn, id, lan, params)
	}
}

// serveADB carries one adb host connection to the device.
func (a *desktopAgent) serveADB(conn net.Conn, id, lan string, params initiatorParams) {
	sc, path, err := a.establishPatiently(id, lan, params)
	if err != nil {
		logf("adb connection from %s refused: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}
	local := conn
	var obs *adbObserver
	if a.audit != nil {
		obs = newADBObserver(conn, a.recordOp, hex.EncodeToString(sc.sid[:8]))
		local = obs
		a.record(audit.Event{"event": "session_start", "session": obs.session, "transport": path})
	}
	t := newTunnel(sc, accelerate(local), true)
	a.mu.Lock()
	a.tunnels[t] = struct{}{}
	a.mu.Unlock()
	started := time.Now()
	t.run(func(t *tunnel) error { return a.rejoin(id, lan, t) })
	a.mu.Lock()
	delete(a.tunnels, t)
	a.mu.Unlock()
	if obs != nil {
		obs.finish()
		up, down := obs.totals()
		a.record(audit.Event{"event": "session_end", "session": obs.session, "transport": path,
			"bytes_up": up, "bytes_down": down, "duration_ms": time.Since(started).Milliseconds()})
	}
}

func (a *desktopAgent) record(e audit.Event) {
	if a.audit == nil {
		return
	}
	e["role"] = "desktop"
	e["device"] = a.deviceID
	if a.user != "" {
		e["user"] = a.user
	}
	if a.tokenID != "" {
		e["token_id"] = a.tokenID
	}
	if err := a.audit.Write(e); err != nil {
		logf("audit write failed: %v", err)
	}
}

func (a *desktopAgent) recordOp(op adbOp) {
	e := audit.Event{"event": "adb_op", "session": op.session, "op": op.kind, "bytes_up": op.up, "bytes_down": op.down,
		"duration_ms": op.duration.Milliseconds()}
	if op.path != "" {
		e["path"] = op.path
	}
	if op.command != "" {
		e["command"] = op.command
	}
	if op.sha256 != "" {
		e["sha256"] = op.sha256
	}
	if op.failed {
		e["result"] = "failed"
	}
	a.record(e)
}

// establishWait bounds how long a fresh adb connection is held open while the
// device is transiently unreachable (agent restarting, phone roaming). adb
// keeps reconnecting a dropped tcp transport; holding its socket until the
// device is back turns that reconnect into a success instead of a burned
// attempt. Denials are never retried.
const establishWait = 8 * time.Second

func (a *desktopAgent) establishPatiently(id, lan string, params initiatorParams) (*secureConn, string, error) {
	deadline := time.Now().Add(establishWait)
	backoff := 200 * time.Millisecond
	for attempt := 1; ; attempt++ {
		sc, path, err := a.establish(id, lan, params)
		if err == nil {
			if attempt > 1 {
				logf("session established after %d attempts", attempt)
			}
			return sc, path, nil
		}
		if errors.Is(err, errDenied) || time.Now().Add(backoff).After(deadline) {
			return nil, "", err
		}
		if attempt == 1 {
			logf("device not reachable yet (%v); retrying for up to %s", err, establishWait)
		}
		time.Sleep(backoff)
		if backoff < time.Second {
			backoff *= 2
		}
	}
}

// establish opens a new authenticated stream, preferring the direct LAN
// path. It also reports which path was used ("lan" or a relay label).
func (a *desktopAgent) establish(id, lan string, params initiatorParams) (*secureConn, string, error) {
	if lan != "" {
		if dc, err := net.DialTimeout("tcp", lan, 700*time.Millisecond); err == nil {
			if tc, ok := dc.(*net.TCPConn); ok {
				tc.SetNoDelay(true)
			}
			if sc, _, err := clientHandshake(dc, dc, params); err == nil {
				return sc, "lan", nil
			}
			dc.Close()
		}
	}
	c, br, _, err := a.openSession(hello{Role: "desktop", DeviceID: id})
	if err != nil {
		return nil, "", err
	}
	sc, _, err := clientHandshake(c, br, params)
	if err != nil {
		c.Close()
		return nil, "", err
	}
	return sc, TransportLabel(a.relayAddr), nil
}

// rejoin re-attaches an existing tunnel after the underlying path broke.
func (a *desktopAgent) rejoin(id, lan string, t *tunnel) error {
	if lan != "" {
		if dc, err := net.DialTimeout("tcp", lan, 700*time.Millisecond); err == nil {
			if err := clientRejoin(dc, dc, t); err == nil {
				return nil
			}
			dc.Close()
		}
	}
	c, br, _, err := a.openSession(hello{Role: "desktop", DeviceID: id})
	if err != nil {
		return err
	}
	if err := clientRejoin(c, br, t); err != nil {
		c.Close()
		return err
	}
	return nil
}

func (a *desktopAgent) openSession(h hello) (net.Conn, *bufio.Reader, string, error) {
	c, br, rep, err := a.openSessionRep(h)
	return c, br, rep.DeviceID, err
}

// openSessionRep asks the relay for a spliced stream to the device.
func (a *desktopAgent) openSessionRep(h hello) (net.Conn, *bufio.Reader, reply, error) {
	c, err := a.dial(a.relayAddr)
	if err != nil {
		return nil, nil, reply{}, err
	}
	br := bufio.NewReader(c)
	h.Identity = a.token
	rep, err := relayHello(c, br, h, a.key)
	if err != nil {
		c.Close()
		return nil, nil, reply{}, err
	}
	if !rep.OK {
		c.Close()
		switch rep.Reason {
		case "device offline", "unknown device or code", "device did not answer", "device busy", "rate limited":
			return nil, nil, reply{}, fmt.Errorf("%w: %s", ErrUnavailable, rep.Reason)
		}
		return nil, nil, reply{}, deniedError(rep.Reason)
	}
	return c, br, rep, nil
}

func peerPath(state, id string) string {
	return filepath.Join(state, "peers", base64.RawURLEncoding.EncodeToString([]byte(id)))
}

func savePeer(state, id string, k ed25519.PublicKey) error {
	if err := os.MkdirAll(filepath.Join(state, "peers"), 0o700); err != nil {
		return err
	}
	return os.WriteFile(peerPath(state, id), []byte(base64.RawURLEncoding.EncodeToString(k)), 0o600)
}

func loadPeer(state, id string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(peerPath(state, id))
	if err != nil {
		return nil, err
	}
	k, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("corrupt pin")
	}
	return ed25519.PublicKey(k), nil
}
