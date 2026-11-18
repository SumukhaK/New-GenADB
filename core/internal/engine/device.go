package engine

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxPairFailures = 3

type deviceAgent struct {
	relayAddr, state, mode, id string
	adbd                       *adbdResolver
	key                        ed25519.PrivateKey

	mu        sync.Mutex
	nameplate string
	secret    string
	failures  int
	pins      map[string]bool
	ctrl      net.Conn
	ctrlMu    sync.Mutex
	pol       *policy
	token     string
	lan       string
	tunnels   map[string]*tunnel
	dial      Dialer
	events    EventFunc
}

// serveLAN accepts direct connections from desktops on the same network.
// They go through exactly the same authenticated handshake as relayed ones.
func (d *deviceAgent) serveLAN(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
		}
		go d.serveStream(c, "lan")
	}
}

// DeviceConfig configures the phone-side device agent.
type DeviceConfig struct {
	Relay        string           // relay address: host:port, ws://... or wss://...
	ADBD         string           // adbd endpoint host:port, "auto", "mdns" or "auto-legacy"
	State        string           // directory for the identity key, device id and pins
	Mode         string           // "solo" (default) or "corporate"
	Enroll       string           // device enrollment JWT (corporate)
	PolicyPath   string           // policy file (corporate)
	DebugAllowed bool             // false = MDM DISALLOW_DEBUGGING_FEATURES: never tunnel
	LANListen    string           // solo: accept direct connections on this address
	LANAdvertise string           // solo: address advertised to desktops (default LANListen)
	Transport    TransportOptions // relay transport options
	Dial         Dialer           // overrides the relay dialer
	Events       EventFunc        // receives events; nil = discard
	// Commands (v1.1.0+) lets the host app act on live sessions, e.g. end
	// one from the phone. nil = no commands.
	Commands <-chan DeviceCommand
}

// DeviceCommand is a request from the app hosting the device agent.
type DeviceCommand struct {
	Op        string     // "end_session"
	SessionID string     // the session_id from session_open
	Reply     chan error // optional; receives the outcome
}

// ErrNoSuchSession: a command named a session that is not open.
var ErrNoSuchSession = errors.New("no such session")

// RunDevice registers the device with the relay and serves tunnels to adbd
// until ctx is cancelled. When debugging is disallowed it emits "blocked" and
// waits for ctx without ever touching adbd.
func RunDevice(ctx context.Context, cfg DeviceConfig) error {
	if cfg.Events == nil {
		cfg.Events = func(string, map[string]any) {}
	}
	if cfg.Mode == "" {
		cfg.Mode = "solo"
	}
	if cfg.State == "" {
		cfg.State = "."
	}
	if cfg.ADBD == "" {
		cfg.ADBD = "127.0.0.1:5555"
	}
	if cfg.Dial == nil {
		cfg.Dial = cfg.Transport.Dialer()
	}
	if !cfg.DebugAllowed {
		// MDM has disabled debugging features: never offer a tunnel to adbd.
		cfg.Events("blocked", map[string]any{"reason": "debugging_disallowed"})
		<-ctx.Done()
		return ctx.Err()
	}
	key, err := loadOrCreateKey(cfg.State)
	if err != nil {
		return err
	}
	id, err := deviceID(cfg.State, cfg.Mode, cfg.Enroll)
	if err != nil {
		return err
	}
	res := newAdbdResolver(cfg.ADBD)
	res.events = cfg.Events
	d := &deviceAgent{relayAddr: cfg.Relay, adbd: res, state: cfg.State, mode: cfg.Mode, id: id, key: key,
		pins: loadPins(cfg.State), token: cfg.Enroll, tunnels: map[string]*tunnel{}, dial: cfg.Dial, events: cfg.Events}
	if d.mode == "corporate" {
		if d.pol, err = loadPolicy(cfg.PolicyPath); err != nil {
			return err
		}
		d.pol.scopedTo(id) // the phone needs nothing about other devices
		if _, err := d.pol.verifyToken(cfg.Enroll, "device", key.Public().(ed25519.PublicKey)); err != nil {
			return fmt.Errorf("enrollment token: %w", err)
		}
	}
	if d.mode == "solo" {
		d.newCode()
		if cfg.LANListen != "" {
			ln, err := net.Listen("tcp", cfg.LANListen)
			if err != nil {
				return err
			}
			defer context.AfterFunc(ctx, func() { ln.Close() })()
			d.lan = cfg.LANAdvertise
			if d.lan == "" {
				d.lan = ln.Addr().String()
			}
			go d.serveLAN(ln)
		}
	}
	defer context.AfterFunc(ctx, func() {
		d.ctrlMu.Lock()
		if d.ctrl != nil {
			d.ctrl.Close()
		}
		d.ctrlMu.Unlock()
		d.mu.Lock()
		for _, t := range d.tunnels {
			t.close()
		}
		d.mu.Unlock()
	})()
	if cfg.Commands != nil {
		go d.serveCommands(ctx, cfg.Commands)
	}
	announced := false
	// Reconnect quickly after a session that was up for a while (a relay
	// restart), back off to 5 s once the network has been down for ~10 s, and log only
	// the first failure of a streak to keep the log and the radio quiet.
	backoff, failures := time.Second, 0
	for {
		started := time.Now()
		err := d.session(&announced)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Since(started) > 30*time.Second {
			backoff, failures = time.Second, 0
		}
		failures++
		if failures == 1 {
			logf("relay session ended: %v; reconnecting", err)
		} else if failures%30 == 0 {
			logf("relay still unreachable after %d attempts: %v", failures, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if failures > 10 && backoff < 5*time.Second {
			backoff += time.Second
		}
	}
}

func (d *deviceAgent) newCode() {
	d.nameplate = randDigits(4)
	d.secret = randDigits(6)
	d.failures = 0
}

func (d *deviceAgent) emitCode() {
	d.events("pairing_code", map[string]any{"code": d.nameplate + "-" + d.secret, "device_id": d.id})
}

// rotateCode issues a fresh code and tells the relay the new nameplate.
func (d *deviceAgent) rotateCode() {
	d.newCode()
	np := d.nameplate
	d.emitCode()
	d.ctrlMu.Lock()
	if d.ctrl != nil {
		writeHello(d.ctrl, hello{Role: "device", DeviceID: d.id, Code: np, LAN: d.lan})
	}
	d.ctrlMu.Unlock()
}

func (d *deviceAgent) session(announced *bool) error {
	c, err := d.dial(d.relayAddr)
	if err != nil {
		return err
	}
	defer c.Close()
	br := bufio.NewReader(c)
	d.mu.Lock()
	np := d.nameplate
	d.mu.Unlock()
	rep, err := relayHello(c, br, hello{Role: "device", DeviceID: d.id, Code: np, Identity: d.token, LAN: d.lan}, d.key)
	if err != nil {
		return err
	}
	if !rep.OK {
		d.mu.Lock()
		d.newCode()
		d.mu.Unlock()
		return fmt.Errorf("relay refused registration: %s", rep.Reason)
	}
	d.ctrlMu.Lock()
	d.ctrl = c
	d.ctrlMu.Unlock()
	defer func() { d.ctrlMu.Lock(); d.ctrl = nil; d.ctrlMu.Unlock() }()
	if !*announced {
		d.events("online", map[string]any{"device_id": d.id})
		if d.mode == "solo" {
			d.mu.Lock()
			d.emitCode()
			d.mu.Unlock()
		}
		*announced = true
	}
	for {
		var m reply
		if err := readHello(br, &m); err != nil {
			return err
		}
		if m.Open != "" {
			go d.openData(m.Open)
		}
	}
}

func (d *deviceAgent) policy() responderPolicy {
	return responderPolicy{
		id:    d.key,
		token: d.token,
		pairing: func() (string, string, bool) {
			d.mu.Lock()
			defer d.mu.Unlock()
			return d.secret, d.nameplate, d.secret != "" && d.mode == "solo"
		},
		pairResult: func(ok bool, peer ed25519.PublicKey) {
			d.mu.Lock()
			defer d.mu.Unlock()
			if ok {
				d.pins[pinKey(peer)] = true
				savePins(d.state, d.pins)
				d.rotateCode() // a code is single-use
				return
			}
			d.failures++
			if d.failures >= maxPairFailures {
				d.rotateCode() // burn after repeated failures
			}
		},
		authorize: func(peer ed25519.PublicKey, token string) error {
			d.mu.Lock()
			defer d.mu.Unlock()
			if d.pins[pinKey(peer)] {
				return nil
			}
			if d.mode == "corporate" {
				// defence in depth: the device re-checks the user's token,
				// its binding to the peer key and the grant itself.
				cl, err := d.pol.verifyToken(token, "user", peer)
				if err != nil {
					return err
				}
				if !d.pol.granted(cl.Sub, d.id) {
					return errDenied
				}
				return nil
			}
			return errDenied
		},
	}
}

func (d *deviceAgent) openData(sid string) {
	c, err := d.dial(d.relayAddr)
	if err != nil {
		return
	}
	if err := writeHello(c, hello{Role: "data", SID: sid}); err != nil {
		c.Close()
		return
	}
	d.serveStream(c, TransportLabel(d.relayAddr))
}

// handshakeSlots bounds concurrent unauthenticated handshakes so a flood of
// session opens cannot exhaust the phone.
var handshakeSlots = make(chan struct{}, 16)

// serveStream authenticates one stream (transport: lan or a relay label)
// and serves it: a new tunnel to adbd, an adb pairing stream, or a rejoin.
func (d *deviceAgent) serveStream(c net.Conn, transport string) {
	select {
	case handshakeSlots <- struct{}{}:
	default:
		c.Close()
		return
	}
	released := false
	release := func() {
		if !released {
			released = true
			<-handshakeSlots
		}
	}
	defer release()
	var m1 hsMsg
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	b1, err := readMsg(c, &m1)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		c.Close()
		return
	}
	if m1.Mode == "rejoin" {
		var rj rejoinMsg
		if json.Unmarshal(b1, &rj) != nil {
			c.Close()
		} else if err := serverRejoin(c, c, rj, d.lookupTunnel, transport); err != nil {
			logf("rejoin refused: %v", err)
			c.Close()
		}
		return
	}
	sc, hs, err := serverHandshake(c, c, d.policy(), b1, m1)
	if err != nil {
		logf("handshake failed: %v", err)
		c.Close()
		return
	}
	if hs.meta.Target == "probe" {
		// The desktop only checked that we answer and trust it.
		c.Close()
		return
	}
	if strings.HasPrefix(hs.meta.Target, "adb-pair:") {
		release()
		d.servePairing(sc, hs, transport)
		return
	}
	if hs.meta.Target != "" {
		logf("unknown stream target %q", hs.meta.Target)
		c.Close()
		return
	}
	a, err := d.dialAdbdPatiently() // adbd is only touched after authentication
	if err != nil {
		logf("adbd unreachable: %v", err)
		d.events("adbd_unreachable", map[string]any{"reason": err.Error()})
		c.Close()
		return
	}
	release()
	d.runTunnel(newTunnel(sc, accelerate(a), false), transport, "adb", d.peerLabel(hs))
}

// serveCommands applies host-app commands until ctx ends.
func (d *deviceAgent) serveCommands(ctx context.Context, cmds <-chan DeviceCommand) {
	for {
		select {
		case <-ctx.Done():
			return
		case c, ok := <-cmds:
			if !ok {
				return
			}
			var err error
			switch c.Op {
			case "end_session":
				err = d.endSession(c.SessionID)
			default:
				err = fmt.Errorf("unknown command %q", c.Op)
			}
			if c.Reply != nil {
				c.Reply <- err
			}
		}
	}
}

// endSession closes one session from the phone: the desktop is told
// (ended_on_device), ends its session instead of rejoining, and the stream
// cannot be resumed.
func (d *deviceAgent) endSession(id string) error {
	d.mu.Lock()
	var hit *tunnel
	for _, t := range d.tunnels {
		if t.ID() == id {
			hit = t
		}
	}
	d.mu.Unlock()
	if hit == nil {
		return fmt.Errorf("%w: %q", ErrNoSuchSession, id)
	}
	logf("session %s ended on the device", id)
	hit.closeWith("ended_on_device")
	return nil
}

// peerLabel names the desktop in the phone's session list: the label it
// sent (sealed in the handshake), else the corporate user, else a short
// fingerprint of its key.
func (d *deviceAgent) peerLabel(hs handshakeResult) string {
	if l := cleanReason([]byte(hs.meta.Label)); l != "" {
		return l // untrusted text from an authenticated peer: printable, bounded
	}
	if d.mode == "corporate" && d.pol != nil && hs.token != "" {
		if cl, err := d.pol.verifyToken(hs.token, "user", hs.peer); err == nil {
			return cl.Sub
		}
	}
	if len(hs.peer) > 0 {
		sum := sha256.Sum256(hs.peer)
		return "desktop-" + hex.EncodeToString(sum[:4])
	}
	return "desktop"
}

func (d *deviceAgent) runTunnel(t *tunnel, transport, kind, label string) {
	t.observe(transport, d.events)
	d.events("session_open", map[string]any{"session_id": t.ID(), "peer_label": label, "transport": transport, "kind": kind})
	defer func() {
		d.events("session_close", map[string]any{"session_id": t.ID(), "reason": t.endReason()})
	}()
	if d.mode == "corporate" && d.pol != nil && d.pol.MaxSessionSeconds > 0 {
		// Hard cap, enforced here because the device is the party that must
		// not be talked into more: the tunnel is closed (and can no longer be
		// rejoined) once it is max_session_seconds old, whatever the desktop
		// does. A new stream needs a full, token-checked handshake.
		tm := time.AfterFunc(time.Duration(d.pol.MaxSessionSeconds)*time.Second, func() {
			logf("session %s reached max_session_seconds", t.ID())
			t.closeWith("session_expired")
		})
		defer tm.Stop()
	}
	key := hex.EncodeToString(t.sid)
	d.mu.Lock()
	d.tunnels[key] = t
	d.mu.Unlock()
	t.run(nil)
	d.mu.Lock()
	delete(d.tunnels, key)
	d.mu.Unlock()
}

// servePairing carries an Android 11+ Wireless-debugging pairing exchange
// (adb pair, _adb-tls-pairing._tcp) from an authenticated desktop to the
// pairing service on this phone. The pairing code itself never reaches us:
// adb on the desktop and adbd run their own SPAKE2 exchange inside our
// end-to-end encrypted tunnel.
func (d *deviceAgent) servePairing(sc *secureConn, hs handshakeResult, transport string) {
	port, err := strconv.Atoi(strings.TrimPrefix(hs.meta.Target, "adb-pair:"))
	if err != nil || port < 0 || port > 65535 {
		sc.Close()
		return
	}
	pc, addr, err := d.dialPairing(port)
	if err != nil {
		logf("adb pairing service unreachable: %v", err)
		d.events("adb_pair_unreachable", map[string]any{"port": port, "reason": err.Error()})
		t := newTunnel(sc, &nopConn{}, false)
		t.closeWith("pairing service unreachable: open Wireless debugging > Pair device with pairing code on the phone")
		return
	}
	d.events("adb_pair_open", map[string]any{"addr": addr})
	d.runTunnel(newTunnel(sc, pc, false), transport, "adb-pair", d.peerLabel(hs))
	d.events("adb_pair_closed", map[string]any{"addr": addr})
}

// dialPairing finds the Wireless-debugging pairing service. port is what the
// phone's "Pair device with pairing code" dialog shows (0 = discover it).
func (d *deviceAgent) dialPairing(port int) (net.Conn, string, error) {
	var cands []string
	if port > 0 {
		if a, err := d.adbd.current(); err == nil {
			if h, _, err := net.SplitHostPort(a); err == nil {
				cands = append(cands, net.JoinHostPort(h, strconv.Itoa(port)))
			}
		}
		if lo := net.JoinHostPort("127.0.0.1", strconv.Itoa(port)); len(cands) == 0 || cands[0] != lo {
			cands = append(cands, lo)
		}
	}
	var last error = fmt.Errorf("no pairing service advertised")
	for _, a := range cands {
		c, err := dialTimeout(a, adbdDialTimeout)
		if err == nil {
			return c, a, nil
		}
		last = err
	}
	if pairingBrowse == nil {
		return nil, "", last
	}
	eps, err := pairingBrowse()
	if err != nil && len(eps) == 0 {
		return nil, "", fmt.Errorf("%v; mDNS: %v", last, err)
	}
	for _, ep := range eps {
		if _, p, _ := net.SplitHostPort(ep); port > 0 && p != strconv.Itoa(port) {
			continue
		}
		if c, err := dialTimeout(ep, adbdDialTimeout); err == nil {
			return c, ep, nil
		} else {
			last = err
		}
	}
	return nil, "", last
}

// pairingBrowse discovers _adb-tls-pairing._tcp endpoints (overridable in tests).
var pairingBrowse = func() ([]string, error) {
	return browse("_adb-tls-pairing._tcp.local.", 1500*time.Millisecond)
}

// nopConn stands in for the local side of a tunnel that is closed at once.
type nopConn struct{ net.Conn }

func (*nopConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (*nopConn) Write(b []byte) (int, error) { return len(b), nil }
func (*nopConn) Close() error                { return nil }

func (d *deviceAgent) lookupTunnel(sid string) *tunnel {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.tunnels[sid]
}

func pinKey(k ed25519.PublicKey) string { return base64.RawURLEncoding.EncodeToString(k) }

func loadPins(state string) map[string]bool {
	m := map[string]bool{}
	b, err := os.ReadFile(filepath.Join(state, "peers.json"))
	if err == nil {
		json.Unmarshal(b, &m)
	}
	return m
}

func savePins(state string, m map[string]bool) {
	b, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(state, "peers.json"), b, 0o600)
}

func deviceID(state, mode, enroll string) (string, error) {
	if mode == "corporate" && enroll != "" {
		parts := strings.Split(enroll, ".")
		if len(parts) == 3 {
			if b, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				var cl struct {
					Sub string `json:"sub"`
				}
				if json.Unmarshal(b, &cl) == nil && cl.Sub != "" {
					return cl.Sub, nil
				}
			}
		}
	}
	p := filepath.Join(state, "device_id")
	if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
		return strings.TrimSpace(string(b)), nil
	}
	b := make([]byte, 6)
	rand.Read(b)
	id := "dev-" + base64.RawURLEncoding.EncodeToString(b)
	return id, os.WriteFile(p, []byte(id), 0o600)
}

func randDigits(n int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		v, _ := rand.Int(rand.Reader, big.NewInt(10))
		sb.WriteByte(byte('0' + v.Int64()))
	}
	return sb.String()
}

// adbdWait bounds how long an authenticated session waits for adbd to become
// reachable (a dozing radio or adbd restarting after a Wireless-debugging
// toggle) before giving up. adb abandons a transport whose CNXN is unanswered after
// about 10 s, so the whole wait must finish well inside that.
const (
	adbdWait        = 7 * time.Second
	adbdDialTimeout = 2 * time.Second
)

func (d *deviceAgent) dialAdbdPatiently() (net.Conn, error) {
	deadline := time.Now().Add(adbdWait)
	for attempt := 1; ; attempt++ {
		c, err := d.dialAdbd()
		if err == nil {
			if attempt > 1 {
				logf("adbd reachable after %d attempts", attempt)
			}
			return c, nil
		}
		if time.Now().Add(adbdDialTimeout + 300*time.Millisecond).After(deadline) {
			return nil, err
		}
		if attempt == 1 {
			logf("adbd not reachable yet (%v); retrying for up to %s", err, adbdWait)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// dialAdbd connects to the current adbd endpoint, re-discovering it once if
// the remembered port stopped working (Wireless debugging toggled, network
// change).
func (d *deviceAgent) dialAdbd() (net.Conn, error) {
	addr, err := d.adbd.current()
	if err == nil {
		var c net.Conn
		if c, err = dialTimeout(addr, adbdDialTimeout); err == nil {
			return c, nil
		}
	}
	addr, rerr := d.adbd.refresh()
	if rerr != nil {
		if err == nil {
			err = rerr
		}
		return nil, err
	}
	return dialTimeout(addr, adbdDialTimeout)
}
