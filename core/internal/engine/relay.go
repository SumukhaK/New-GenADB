package engine

import (
	"context"

	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sumukhak/new-genadb/core/pkg/genadb/audit"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type hello struct {
	Role     string `json:"role"`
	DeviceID string `json:"device_id,omitempty"`
	Code     string `json:"code,omitempty"` // public nameplate only, never the secret
	SID      string `json:"sid,omitempty"`
	Probe    bool   `json:"probe,omitempty"`
	Identity string `json:"identity,omitempty"`
	Pub      string `json:"pub,omitempty"`
	Sig      []byte `json:"sig,omitempty"`
	LAN      string `json:"lan,omitempty"` // solo only: device's direct LAN endpoint
}

type reply struct {
	OK        bool   `json:"ok"`
	DeviceID  string `json:"device_id,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Open      string `json:"open,omitempty"`
	Challenge []byte `json:"challenge,omitempty"`
	LAN       string `json:"lan,omitempty"`
	// Devices answers a "presence" hello (v1.1.0+, corporate).
	Devices []DevicePresence `json:"devices,omitempty"`
}

// DevicePresence is one device in a presence answer or the admin
// GET /v1/devices listing.
type DevicePresence struct {
	DeviceID    string     `json:"device_id"`
	Online      bool       `json:"online"`
	ConnectedAt *time.Time `json:"connected_at,omitempty"`
	Transport   string     `json:"transport,omitempty"` // how the device reaches the relay: tcp | ws | wss
	Sessions    int        `json:"sessions"`            // relayed sessions open to it now
	Revoked     bool       `json:"revoked,omitempty"`   // admin listing only
}

type deviceEntry struct {
	conn      net.Conn
	code      string
	lan       string
	since     time.Time
	transport string
	wmu       sync.Mutex
}

type session struct {
	user, device string
	conns        []net.Conn
	once         sync.Once
}

func (s *session) kill() {
	for _, c := range s.conns {
		c.Close()
	}
}

type relay struct {
	mu             sync.Mutex
	corporate      bool
	pol            *policy
	devices        map[string]*deviceEntry
	pending        map[string]chan net.Conn // sid -> data conn from device
	pendR          map[string]*bufio.Reader
	sessions       map[string]*session
	revoked        map[string]bool // "user:<u>" / "device:<d>"
	audit          audit.Sink
	limits         *limiter
	pendingBy      map[string]int // device id -> session opens awaiting the device
	trustForwarded bool
	revFile        string // persisted revocations ("" = memory only)
	policyPath     string
	persistMu      sync.Mutex // serialises writes of revFile
}

const maxPendingPerDevice = 16

func (r *relay) allow(ip, kind string) bool { return r.limits.take(ip, kind, false) }

// RelayConfig configures the rendezvous relay.
type RelayConfig struct {
	Listen         string     // raw TCP listen address
	Mode           string     // "solo" (default) or "corporate"
	PolicyPath     string     // policy file (corporate)
	AuditPath      string     // hash-chained JSONL audit log ("" = none)
	AuditKeyFile   string     // anchor key ("" = audit-anchor.key next to the log)
	Audit          audit.Sink // additional audit sink (e.g. a webhook)
	AdminListen    string     // admin API listen address ("" = off)
	AdminToken     string     // bearer token for the admin API
	WSListen       string     // also accept WebSocket clients here
	TLSCert        string     // serve wss:// on WSListen with this certificate
	TLSKey         string
	TrustForwarded bool      // take client IPs from proxy headers on WSListen
	Events         EventFunc // receives "ready"; nil = discard
	// StateDir keeps relay state that must survive restarts (v1.1.0+):
	// revocations.json. "" = revocations live in memory only.
	StateDir string
}

// RunRelay serves the relay until ctx is cancelled.
func RunRelay(ctx context.Context, cfg RelayConfig) error {
	if cfg.Events == nil {
		cfg.Events = func(string, map[string]any) {}
	}
	if cfg.Mode == "" {
		cfg.Mode = "solo"
	}
	r := &relay{devices: map[string]*deviceEntry{}, pending: map[string]chan net.Conn{},
		pendR: map[string]*bufio.Reader{}, sessions: map[string]*session{}, revoked: map[string]bool{},
		limits: newLimiter(), pendingBy: map[string]int{}}
	r.trustForwarded = cfg.TrustForwarded
	if cfg.StateDir != "" {
		r.revFile = filepath.Join(cfg.StateDir, "revocations.json")
		rev, err := loadRevocations(r.revFile)
		if err != nil {
			// Fail closed: starting with an unreadable list would quietly
			// un-revoke every revoked user and device.
			return fmt.Errorf("revocations: %w", err)
		}
		for k := range rev {
			r.revoked[k] = true
		}
		if len(rev) > 0 {
			logf("loaded %d revocations from %s", len(rev), r.revFile)
		}
	}
	if cfg.Mode == "corporate" {
		p, err := loadPolicy(cfg.PolicyPath)
		if err != nil {
			return err
		}
		r.corporate, r.pol, r.policyPath = true, p, cfg.PolicyPath
	}
	// The file seals each record (seq + hash chain) and then tees the sealed
	// record to any extra sink, so webhooks see exactly what the file holds.
	switch {
	case cfg.AuditPath != "":
		f, err := audit.OpenFileWith(cfg.AuditPath, audit.FileOptions{Sync: true, AnchorKeyFile: cfg.AuditKeyFile})
		if err != nil {
			return err
		}
		if cfg.Audit != nil {
			f.Tee(cfg.Audit)
		}
		r.audit = f
	case cfg.Audit != nil:
		r.audit = audit.Chained(cfg.Audit)
	}
	if r.audit != nil {
		defer r.audit.Close()
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	var closers []func() error
	closers = append(closers, ln.Close)
	if cfg.AdminListen != "" {
		if cfg.AdminToken == "" {
			ln.Close()
			return errors.New("the admin API requires an admin token")
		}
		aln, err := net.Listen("tcp", cfg.AdminListen)
		if err != nil {
			ln.Close()
			return err
		}
		closers = append(closers, aln.Close)
		go http.Serve(aln, r.adminHandler(cfg.AdminToken))
	}
	if cfg.WSListen != "" {
		wln, err := r.serveWebSocket(cfg.WSListen, cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			for _, c := range closers {
				c()
			}
			return err
		}
		closers = append(closers, wln.Close)
	}
	defer context.AfterFunc(ctx, func() {
		for _, c := range closers {
			c()
		}
		// Shutting down drops every client, as a process exit would, so
		// devices and desktops reconnect to whatever relay comes next.
		r.mu.Lock()
		for _, e := range r.devices {
			e.conn.Close()
		}
		for _, s := range r.sessions {
			s.kill()
		}
		r.mu.Unlock()
	})()
	cfg.Events("ready", map[string]any{"addr": ln.Addr().String(), "mode": cfg.Mode, "ws": cfg.WSListen})
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
		}
		if !r.allow(clientIP(c.RemoteAddr().String()), "accept") {
			c.Close()
			continue
		}
		go r.handle(c)
	}
}

func (r *relay) auditEvent(event string, f map[string]any) {
	if r.audit == nil {
		return
	}
	m := audit.Event{"event": event}
	for k, v := range f {
		m[k] = v
	}
	if err := r.audit.Write(m); err != nil {
		logf("audit write failed: %v", err)
	}
}

func (r *relay) adminHandler(token string) http.Handler {
	mux := http.NewServeMux()
	authed := func(w http.ResponseWriter, req *http.Request, method string) bool {
		if req.Method != method {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return false
		}
		want := "Bearer " + token
		if subtle.ConstantTimeCompare([]byte(req.Header.Get("Authorization")), []byte(want)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return false
		}
		return true
	}
	reply := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
	target := func(w http.ResponseWriter, req *http.Request) (user, device string, ok bool) {
		var body struct{ User, Device string }
		if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096)).Decode(&body); err != nil ||
			(body.User == "" && body.Device == "") {
			http.Error(w, "bad request", http.StatusBadRequest)
			return "", "", false
		}
		return body.User, body.Device, true
	}
	mux.HandleFunc("/v1/revoke", func(w http.ResponseWriter, req *http.Request) {
		if !authed(w, req, http.MethodPost) {
			return
		}
		user, device, ok := target(w, req)
		if !ok {
			return
		}
		var kill []*session
		r.mu.Lock()
		if user != "" {
			r.revoked["user:"+user] = true
		}
		if device != "" {
			r.revoked["device:"+device] = true
		}
		for sid, s := range r.sessions {
			if (user != "" && s.user == user) || (device != "" && s.device == device) {
				kill = append(kill, s)
				delete(r.sessions, sid)
			}
		}
		r.mu.Unlock()
		for _, s := range kill {
			s.kill()
		}
		perr := r.persistRevocations()
		r.auditEvent("revoked", map[string]any{"user": user, "device": device, "sessions_killed": len(kill), "persisted": perr == nil})
		if perr != nil {
			// Revoked in memory (enforced now) but would not survive a restart.
			logf("revocation not persisted: %v", perr)
			http.Error(w, "revoked in memory but not persisted: "+perr.Error(), http.StatusInternalServerError)
			return
		}
		reply(w, map[string]any{"ok": true, "sessions_killed": len(kill), "persisted": r.revFile != ""})
	})
	mux.HandleFunc("/v1/unrevoke", func(w http.ResponseWriter, req *http.Request) {
		if !authed(w, req, http.MethodPost) {
			return
		}
		user, device, ok := target(w, req)
		if !ok {
			return
		}
		r.mu.Lock()
		if user != "" {
			delete(r.revoked, "user:"+user)
		}
		if device != "" {
			delete(r.revoked, "device:"+device)
		}
		r.mu.Unlock()
		perr := r.persistRevocations()
		r.auditEvent("unrevoked", map[string]any{"user": user, "device": device, "persisted": perr == nil})
		if perr != nil {
			http.Error(w, "unrevoked in memory but not persisted: "+perr.Error(), http.StatusInternalServerError)
			return
		}
		reply(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("/v1/revocations", func(w http.ResponseWriter, req *http.Request) {
		if !authed(w, req, http.MethodGet) {
			return
		}
		users, devices := []string{}, []string{}
		r.mu.Lock()
		for k := range r.revoked {
			if u, ok := strings.CutPrefix(k, "user:"); ok {
				users = append(users, u)
			} else if d, ok := strings.CutPrefix(k, "device:"); ok {
				devices = append(devices, d)
			}
		}
		r.mu.Unlock()
		sort.Strings(users)
		sort.Strings(devices)
		reply(w, map[string]any{"users": users, "devices": devices})
	})
	mux.HandleFunc("/v1/policy", func(w http.ResponseWriter, req *http.Request) {
		// GET /v1/policy?device=<id>: the policy to push to that one device
		// through MDM (its own grants only).
		if !authed(w, req, http.MethodGet) {
			return
		}
		if r.policyPath == "" {
			http.Error(w, "no policy (solo relay)", http.StatusNotFound)
			return
		}
		raw, err := os.ReadFile(r.policyPath)
		if err != nil {
			http.Error(w, "policy unreadable", http.StatusInternalServerError)
			return
		}
		out, err := ScopePolicy(raw, req.URL.Query().Get("device"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(append(out, '\n'))
	})
	mux.HandleFunc("/v1/devices", func(w http.ResponseWriter, req *http.Request) {
		if !authed(w, req, http.MethodGet) {
			return
		}
		reply(w, map[string]any{"devices": r.presence(nil, true)})
	})
	return mux
}

// presence lists connected devices, or, when only is non-nil, exactly the
// devices in only (online or not). Revocation flags are for admins.
func (r *relay) presence(only []string, admin bool) []DevicePresence {
	r.mu.Lock()
	defer r.mu.Unlock()
	sessions := map[string]int{}
	for _, s := range r.sessions {
		sessions[s.device]++
	}
	entry := func(id string) DevicePresence {
		p := DevicePresence{DeviceID: id, Sessions: sessions[id]}
		if e := r.devices[id]; e != nil {
			since := e.since.UTC()
			p.Online, p.ConnectedAt, p.Transport = true, &since, e.transport
		}
		if admin {
			p.Revoked = r.revoked["device:"+id]
		}
		return p
	}
	out := []DevicePresence{}
	if only != nil {
		for _, id := range only {
			if r.revoked["device:"+id] {
				out = append(out, DevicePresence{DeviceID: id}) // revoked: never shown as available
				continue
			}
			out = append(out, entry(id))
		}
		return out
	}
	for id := range r.devices {
		out = append(out, entry(id))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}

type revocationFile struct {
	Version int      `json:"version"`
	Users   []string `json:"users"`
	Devices []string `json:"devices"`
}

func loadRevocations(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f revocationFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s is corrupt (%v); fix or remove it deliberately", path, err)
	}
	m := map[string]bool{}
	for _, u := range f.Users {
		m["user:"+u] = true
	}
	for _, d := range f.Devices {
		m["device:"+d] = true
	}
	return m, nil
}

// persistRevocations writes the current list atomically (temp file, fsync,
// rename) so a crash leaves either the old or the new list, never half.
func (r *relay) persistRevocations() error {
	if r.revFile == "" {
		return nil
	}
	r.persistMu.Lock()
	defer r.persistMu.Unlock()
	f := revocationFile{Version: 1, Users: []string{}, Devices: []string{}}
	r.mu.Lock()
	for k := range r.revoked {
		if u, ok := strings.CutPrefix(k, "user:"); ok {
			f.Users = append(f.Users, u)
		} else if d, ok := strings.CutPrefix(k, "device:"); ok {
			f.Devices = append(f.Devices, d)
		}
	}
	r.mu.Unlock()
	sort.Strings(f.Users)
	sort.Strings(f.Devices)
	b, _ := json.MarshalIndent(f, "", "  ")
	if err := os.MkdirAll(filepath.Dir(r.revFile), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(r.revFile), ".revocations-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), r.revFile); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(r.revFile)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// authenticate runs the corporate proof-of-possession exchange and returns
// the verified subject.
func (r *relay) authenticate(c net.Conn, br *bufio.Reader, h hello, typ string) (string, error) {
	if h.Identity == "" {
		return "", errors.New("identity token required")
	}
	pubb, err := base64.RawURLEncoding.DecodeString(h.Pub)
	if err != nil || len(pubb) != ed25519.PublicKeySize {
		return "", errors.New("bad public key")
	}
	cl, err := r.pol.verifyToken(h.Identity, typ, ed25519.PublicKey(pubb))
	if err != nil {
		return "", err
	}
	chal := make([]byte, 32)
	rand.Read(chal)
	if err := writeHello(c, reply{OK: true, Challenge: chal}); err != nil {
		return "", err
	}
	var proof hello
	if err := readHello(br, &proof); err != nil {
		return "", err
	}
	if !ed25519.Verify(ed25519.PublicKey(pubb), popMessage(chal, h.Identity), proof.Sig) {
		return "", errors.New("proof of possession failed")
	}
	return cl.Sub, nil
}

func (r *relay) deny(c net.Conn, f map[string]any, reason string) {
	r.allow(clientIP(c.RemoteAddr().String()), "auth-fail")
	f["reason"] = reason
	r.auditEvent("denied", f)
	writeHello(c, reply{OK: false, Reason: reason})
	c.Close()
}

func (r *relay) handle(c net.Conn) {
	ip := clientIP(c.RemoteAddr().String())
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	var h hello
	if err := readHello(br, &h); err != nil {
		c.Close()
		return
	}
	limited := func(kind string) bool {
		if !r.limits.take(ip, "auth-fail", true) || !r.allow(ip, kind) {
			r.auditEvent("rate_limited", map[string]any{"role": h.Role, "kind": kind})
			writeHello(c, reply{OK: false, Reason: "rate limited"})
			c.Close()
			return true
		}
		return false
	}
	switch h.Role {
	case "device":
		if limited("device") {
			return
		}
		if r.corporate {
			sub, err := r.authenticate(c, br, h, "device")
			if err != nil || sub != h.DeviceID {
				if err == nil {
					err = errors.New("device id does not match token subject")
				}
				r.deny(c, map[string]any{"device": h.DeviceID, "role": "device"}, err.Error())
				return
			}
			r.mu.Lock()
			rev := r.revoked["device:"+sub]
			r.mu.Unlock()
			if rev {
				r.deny(c, map[string]any{"device": sub, "role": "device"}, "device revoked")
				return
			}
			h.Code = ""
		}
		c.SetReadDeadline(time.Time{})
		e := &deviceEntry{conn: c, code: h.Code, since: time.Now(), transport: relayTransport(c)}
		if !r.corporate {
			e.lan = h.LAN
		}
		r.mu.Lock()
		for did, o := range r.devices {
			if h.Code != "" && o.code == h.Code && did != h.DeviceID {
				r.mu.Unlock()
				writeHello(c, reply{OK: false, Reason: "nameplate taken"})
				c.Close()
				return
			}
		}
		if old := r.devices[h.DeviceID]; old != nil {
			old.conn.Close()
		}
		r.devices[h.DeviceID] = e
		r.mu.Unlock()
		r.auditEvent("device_online", map[string]any{"device": h.DeviceID})
		writeHello(c, reply{OK: true})
		// control connection: the device may announce a new nameplate
		for {
			var upd hello
			if err := readHello(br, &upd); err != nil {
				break
			}
			if !r.corporate {
				r.mu.Lock()
				e.code = upd.Code
				r.mu.Unlock()
			}
		}
		r.mu.Lock()
		if r.devices[h.DeviceID] == e {
			delete(r.devices, h.DeviceID)
		}
		r.mu.Unlock()
		r.auditEvent("device_offline", map[string]any{"device": h.DeviceID})
		c.Close()
	case "data":
		c.SetReadDeadline(time.Time{})
		r.mu.Lock()
		ch := r.pending[h.SID]
		r.pendR[h.SID] = br
		r.mu.Unlock()
		if ch == nil {
			c.Close()
			return
		}
		ch <- c
	case "desktop":
		if limited("desktop") {
			return
		}
		user := ""
		if r.corporate {
			sub, err := r.authenticate(c, br, h, "user")
			if err != nil {
				r.deny(c, map[string]any{"device": h.DeviceID, "role": "desktop"}, err.Error())
				return
			}
			user = sub
			r.mu.Lock()
			rev := r.revoked["user:"+user] || r.revoked["device:"+h.DeviceID]
			r.mu.Unlock()
			if rev {
				r.deny(c, map[string]any{"user": user, "device": h.DeviceID}, "revoked")
				return
			}
			if !r.pol.granted(user, h.DeviceID) {
				r.deny(c, map[string]any{"user": user, "device": h.DeviceID}, "no grant for device")
				return
			}
			h.Code = ""
		}
		c.SetReadDeadline(time.Time{})
		r.mu.Lock()
		id := h.DeviceID
		if h.Code != "" {
			id = ""
			for did, e := range r.devices {
				if e.code != "" && e.code == h.Code {
					id = did
				}
			}
		}
		e := r.devices[id]
		r.mu.Unlock()
		if e == nil {
			if r.corporate {
				r.deny(c, map[string]any{"user": user, "device": h.DeviceID}, "device offline")
				return
			}
			writeHello(c, reply{OK: false, Reason: "unknown device or code"})
			c.Close()
			return
		}
		sidb := make([]byte, 16)
		rand.Read(sidb)
		sid := hex.EncodeToString(sidb)
		ch := make(chan net.Conn, 1)
		r.mu.Lock()
		if r.pendingBy[id] >= maxPendingPerDevice {
			r.mu.Unlock()
			writeHello(c, reply{OK: false, Reason: "device busy"})
			c.Close()
			return
		}
		r.pendingBy[id]++
		r.pending[sid] = ch
		r.mu.Unlock()
		e.wmu.Lock()
		err := writeHello(e.conn, reply{OK: true, Open: sid})
		e.wmu.Unlock()
		var dc net.Conn
		if err == nil {
			select {
			case dc = <-ch:
			case <-time.After(10 * time.Second):
			}
		}
		r.mu.Lock()
		dbr := r.pendR[sid]
		delete(r.pending, sid)
		delete(r.pendR, sid)
		r.pendingBy[id]--
		r.mu.Unlock()
		if dc == nil {
			writeHello(c, reply{OK: false, Reason: "device did not answer"})
			c.Close()
			return
		}
		s := &session{user: user, device: id, conns: []net.Conn{c, dc}}
		r.mu.Lock()
		r.sessions[sid] = s
		r.mu.Unlock()
		if r.corporate {
			r.auditEvent("session_start", map[string]any{"user": user, "device": id, "session": sid})
			if r.pol.MaxSessionSeconds > 0 {
				t := time.AfterFunc(time.Duration(r.pol.MaxSessionSeconds)*time.Second, s.kill)
				defer t.Stop()
			}
		}
		writeHello(c, reply{OK: true, DeviceID: id, LAN: e.lan})
		splice(c, br, dc, dbr)
		r.mu.Lock()
		delete(r.sessions, sid)
		r.mu.Unlock()
		if r.corporate {
			r.auditEvent("session_end", map[string]any{"user": user, "device": id, "session": sid})
		}
	case "presence":
		// Which granted devices are online now (v1.1.0+, corporate): lets
		// a desktop show real availability, authenticated exactly like a
		// session open but without touching any device.
		if limited("desktop") {
			return
		}
		if !r.corporate {
			writeHello(c, reply{OK: false, Reason: "presence requires corporate mode"})
			c.Close()
			return
		}
		sub, err := r.authenticate(c, br, h, "user")
		if err != nil {
			r.deny(c, map[string]any{"role": "presence"}, err.Error())
			return
		}
		r.mu.Lock()
		rev := r.revoked["user:"+sub]
		r.mu.Unlock()
		if rev {
			r.deny(c, map[string]any{"user": sub, "role": "presence"}, "revoked")
			return
		}
		writeHello(c, reply{OK: true, Devices: r.presence(r.pol.devicesFor(sub), false)})
		c.Close()
	default:
		c.Close()
	}
}
