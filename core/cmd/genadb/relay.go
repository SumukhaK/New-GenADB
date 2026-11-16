package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"net"
	"net/http"
	"os"
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
	mu        sync.Mutex
	corporate bool
	pol       *policy
	devices   map[string]*deviceEntry
	pending   map[string]chan net.Conn // sid -> data conn from device
	pendR     map[string]*bufio.Reader
	sessions  map[string]*session
	revoked   map[string]bool // "user:<u>" / "device:<d>"
	auditMu   sync.Mutex
	audit     *os.File
}

func cmdRelay(args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:7000", "listen address")
	mode := fs.String("mode", "solo", "solo|corporate")
	policyPath := fs.String("policy", "", "policy file (corporate)")
	auditPath := fs.String("audit", "", "audit log path (JSONL)")
	adminAddr := fs.String("admin", "", "admin listen address")
	adminToken := fs.String("admin-token", "", "admin bearer token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	r := &relay{devices: map[string]*deviceEntry{}, pending: map[string]chan net.Conn{},
		pendR: map[string]*bufio.Reader{}, sessions: map[string]*session{}, revoked: map[string]bool{}}
	if *mode == "corporate" {
		p, err := loadPolicy(*policyPath)
		if err != nil {
			return err
		}
		r.corporate, r.pol = true, p
	}
	if *auditPath != "" {
		f, err := os.OpenFile(*auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		r.audit = f
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	if *adminAddr != "" {
		if *adminToken == "" {
			return errors.New("--admin requires --admin-token")
		}
		aln, err := net.Listen("tcp", *adminAddr)
		if err != nil {
			return err
		}
		go http.Serve(aln, r.adminHandler(*adminToken))
	}
	emit("ready", map[string]any{"addr": ln.Addr().String(), "mode": *mode})
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
		}
		go r.handle(c)
	}
}

func (r *relay) auditEvent(event string, f map[string]any) {
	if r.audit == nil {
		return
	}
	m := map[string]any{"ts": time.Now().UTC().Format(time.RFC3339Nano), "event": event}
	for k, v := range f {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	r.auditMu.Lock()
	r.audit.Write(append(b, '\n'))
	r.audit.Sync()
	r.auditMu.Unlock()
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
	f["reason"] = reason
	r.auditEvent("denied", f)
	writeHello(c, reply{OK: false, Reason: reason})
	c.Close()
}

func (r *relay) handle(c net.Conn) {
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	var h hello
	if err := readHello(br, &h); err != nil {
		c.Close()
		return
	}
	switch h.Role {
	case "device":
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
