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
	"github.com/sumukhak/new-genadb/core/pkg/genadb/audit"
	"net"
	"net/http"
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
}

type deviceEntry struct {
	conn net.Conn
	code string
	lan  string
	wmu  sync.Mutex
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
}

const maxPendingPerDevice = 16

func (r *relay) allow(ip, kind string) bool { return r.limits.take(ip, kind, false) }

// RelayConfig configures the rendezvous relay.
type RelayConfig struct {
	Listen         string     // raw TCP listen address
	Mode           string     // "solo" (default) or "corporate"
	PolicyPath     string     // policy file (corporate)
	AuditPath      string     // hash-chained JSONL audit log ("" = none)
	Audit          audit.Sink // additional audit sink (e.g. a webhook)
	AdminListen    string     // admin API listen address ("" = off)
	AdminToken     string     // bearer token for the admin API
	WSListen       string     // also accept WebSocket clients here
	TLSCert        string     // serve wss:// on WSListen with this certificate
	TLSKey         string
	TrustForwarded bool      // take client IPs from proxy headers on WSListen
	Events         EventFunc // receives "ready"; nil = discard
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
	if cfg.Mode == "corporate" {
		p, err := loadPolicy(cfg.PolicyPath)
		if err != nil {
			return err
		}
		r.corporate, r.pol = true, p
	}
	var sinks audit.MultiSink
	if cfg.AuditPath != "" {
		f, err := audit.OpenFile(cfg.AuditPath, true)
		if err != nil {
			return err
		}
		sinks = append(sinks, f)
	}
	if cfg.Audit != nil {
		sinks = append(sinks, cfg.Audit)
	}
	if len(sinks) > 0 {
		r.audit = sinks
		defer sinks.Close()
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
	mux.HandleFunc("/v1/revoke", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		want := "Bearer " + token
		if subtle.ConstantTimeCompare([]byte(req.Header.Get("Authorization")), []byte(want)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct{ User, Device string }
		if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096)).Decode(&body); err != nil ||
			(body.User == "" && body.Device == "") {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var kill []*session
		r.mu.Lock()
		if body.User != "" {
			r.revoked["user:"+body.User] = true
		}
		if body.Device != "" {
			r.revoked["device:"+body.Device] = true
		}
		for sid, s := range r.sessions {
			if (body.User != "" && s.user == body.User) || (body.Device != "" && s.device == body.Device) {
				kill = append(kill, s)
				delete(r.sessions, sid)
			}
		}
		r.mu.Unlock()
		for _, s := range kill {
			s.kill()
		}
		r.auditEvent("revoked", map[string]any{"user": body.User, "device": body.Device, "sessions_killed": len(kill)})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "sessions_killed": len(kill)})
	})
	return mux
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
		e := &deviceEntry{conn: c, code: h.Code}
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
	default:
		c.Close()
	}
}
