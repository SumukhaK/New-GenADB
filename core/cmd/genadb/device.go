package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
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
		go d.serveStream(c)
	}
}

func cmdDevice(args []string) error {
	fs := flag.NewFlagSet("device", flag.ContinueOnError)
	relayAddr := fs.String("relay", "", "relay address")
	adbd := fs.String("adbd", "127.0.0.1:5555", "adbd endpoint host:port, or 'auto' to discover Wireless debugging via mDNS (auto-legacy: _adb._tcp)")
	state := fs.String("state", ".", "state directory")
	mode := fs.String("mode", "solo", "solo|corporate")
	fs.String("name", "", "device name")
	enroll := fs.String("enroll", "", "device enrollment JWT (corporate)")
	policyPath := fs.String("policy", "", "policy file (corporate)")
	debugPolicy := fs.String("debug-policy", "allowed", "allowed|disallowed (MDM DISALLOW_DEBUGGING_FEATURES)")
	addTransportFlags(fs)
	lanListen := fs.String("lan-listen", "", "LAN listen address (solo: direct path)")
	lanAdvertise := fs.String("lan-advertise", "", "LAN address to advertise (default: lan-listen)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *debugPolicy != "allowed" {
		// MDM has disabled debugging features: never offer a tunnel to adbd.
		emit("blocked", map[string]any{"reason": "debugging_disallowed"})
		select {} // stay visible to the UI but do nothing
	}
	key, err := loadOrCreateKey(*state)
	if err != nil {
		return err
	}
	id, err := deviceID(*state, *mode, *enroll)
	if err != nil {
		return err
	}
	d := &deviceAgent{relayAddr: *relayAddr, adbd: newAdbdResolver(*adbd), state: *state, mode: *mode, id: id, key: key,
		pins: loadPins(*state), token: *enroll, tunnels: map[string]*tunnel{}}
	if d.mode == "corporate" {
		if d.pol, err = loadPolicy(*policyPath); err != nil {
			return err
		}
		if _, err := d.pol.verifyToken(*enroll, "device", key.Public().(ed25519.PublicKey)); err != nil {
			return fmt.Errorf("enrollment token: %w", err)
		}
	}
	if d.mode == "solo" {
		d.newCode()
		if *lanListen != "" {
			ln, err := net.Listen("tcp", *lanListen)
			if err != nil {
				return err
			}
			d.lan = *lanAdvertise
			if d.lan == "" {
				d.lan = ln.Addr().String()
			}
			go d.serveLAN(ln)
		}
	}
	announced := false
	for {
		err := d.session(&announced)
		logf("relay session ended: %v; reconnecting", err)
		time.Sleep(time.Second)
	}
}

func (d *deviceAgent) newCode() {
	d.nameplate = randDigits(4)
	d.secret = randDigits(6)
	d.failures = 0
}

func (d *deviceAgent) emitCode() {
	emit("pairing_code", map[string]any{"code": d.nameplate + "-" + d.secret, "device_id": d.id})
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
	c, err := dialRelay(d.relayAddr)
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
		emit("online", map[string]any{"device_id": d.id})
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
	c, err := dialRelay(d.relayAddr)
	if err != nil {
		return
	}
	if err := writeHello(c, hello{Role: "data", SID: sid}); err != nil {
		c.Close()
		return
	}
	d.serveStream(c)
}

// handshakeSlots bounds concurrent unauthenticated handshakes so a flood of
// session opens cannot exhaust the phone.
var handshakeSlots = make(chan struct{}, 16)

func (d *deviceAgent) serveStream(c net.Conn) {
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
		} else if err := serverRejoin(c, c, rj, d.lookupTunnel); err != nil {
			logf("rejoin refused: %v", err)
			c.Close()
		}
		return
	}
	sc, _, err := serverHandshake(c, c, d.policy(), b1, m1)
	if err != nil {
		logf("handshake failed: %v", err)
		c.Close()
		return
	}
	a, err := d.dialAdbdPatiently() // adbd is only touched after authentication
	if err != nil {
		logf("adbd unreachable: %v", err)
		emit("adbd_unreachable", map[string]any{"reason": err.Error()})
		c.Close()
		return
	}
	release()
	t := newTunnel(sc, accelerate(a), false)
	key := hex.EncodeToString(t.sid)
	d.mu.Lock()
	d.tunnels[key] = t
	d.mu.Unlock()
	t.run(nil)
	d.mu.Lock()
	delete(d.tunnels, key)
	d.mu.Unlock()
}

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
// toggle) before giving up. It stays under adb's own 10 s connect timeout
// budget for the common case of a single slow attempt.
const adbdWait = 12 * time.Second

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
		if time.Now().After(deadline) {
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
		if c, err = dial(addr); err == nil {
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
	return dial(addr)
}
