// Package daemon serves the genadb SDK over JSON-RPC 2.0 so that IDE plugins,
// UIs and scripts in any language can drive sessions. Messages are single
// JSON objects separated by newlines, over stdio or a loopback TCP socket
// that requires a token from a 0600 file.
package daemon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sumukhak/new-genadb/core/pkg/genadb"
	"github.com/sumukhak/new-genadb/core/pkg/genadb/audit"
)

// JSON-RPC error codes. -32000.. are application errors mapped from the
// SDK's sentinel errors so clients can branch without parsing messages.
const (
	CodeParse          = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
	CodeUnauthorized   = -32001
	CodeDenied         = -32010
	CodeUnavailable    = -32011
	CodeNotPaired      = -32012
	CodeBadCode        = -32013
	CodeRevoked        = -32014
	CodeTokenInvalid   = -32015
	CodeTokenExpired   = -32016
	CodeNoGrant        = -32017
	CodeBlocked        = -32018
	CodeNoSession      = -32020
	CodeAuditDisabled  = -32021
	CodeCancelled      = -32022
	CodeADBPairFailed  = -32023
	CodeUnsupported    = -32024
	CodeSessionExpired = -32025
	CodePeerClosed     = -32026
)

// Error is a JSON-RPC error object. Data.kind names the sentinel.
type Error struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}

func (e *Error) Error() string { return e.Message }

var sentinels = []struct {
	err  error
	code int
	kind string
}{
	{genadb.ErrSessionExpired, CodeSessionExpired, "session_expired"},
	{genadb.ErrPeerClosed, CodePeerClosed, "peer_closed"},
	{genadb.ErrUnsupported, CodeUnsupported, "unsupported"},
	{genadb.ErrADBPairFailed, CodeADBPairFailed, "adb_pair_failed"},
	{genadb.ErrBadCode, CodeBadCode, "bad_code"},
	{genadb.ErrNotPaired, CodeNotPaired, "not_paired"},
	{genadb.ErrRevoked, CodeRevoked, "revoked"},
	{genadb.ErrTokenExpired, CodeTokenExpired, "token_expired"},
	{genadb.ErrTokenInvalid, CodeTokenInvalid, "token_invalid"},
	{genadb.ErrNoGrant, CodeNoGrant, "no_grant"},
	{genadb.ErrBlocked, CodeBlocked, "blocked"},
	{genadb.ErrDenied, CodeDenied, "denied"},
	{genadb.ErrUnavailable, CodeUnavailable, "unavailable"},
	{genadb.ErrNoSession, CodeNoSession, "no_session"},
	{genadb.ErrAuditDisabled, CodeAuditDisabled, "audit_disabled"},
}

func toRPCError(err error) *Error {
	var re *Error
	if errors.As(err, &re) {
		return re
	}
	for _, s := range sentinels {
		if errors.Is(err, s.err) {
			return &Error{Code: s.code, Message: err.Error(), Data: map[string]any{"kind": s.kind}}
		}
	}
	return &Error{Code: CodeInternal, Message: err.Error()}
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type notification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

// Server dispatches JSON-RPC calls to a genadb.Client.
type Server struct {
	Client *genadb.Client
	// Token, when non-empty, must be presented with "auth" before any other
	// call on a connection. Leave empty only for stdio.
	Token string

	mu   sync.Mutex
	subs map[*conn]struct{}
}

// SubscriberQueue is how many events may wait for one subscriber. A
// subscriber that falls further behind loses events (it is told how many
// with an "events.dropped" notification) and never slows anyone else.
const SubscriberQueue = 256

// WriteTimeout bounds one write to a client. A client that stops reading
// for this long is disconnected.
const WriteTimeout = 10 * time.Second

// Publish forwards an SDK event to subscribed connections. Wire it with
// genadb.WithEventHandler(srv.Publish). It never blocks: each subscriber has
// its own bounded queue drained by its own goroutine.
func (s *Server) Publish(e genadb.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.subs {
		select {
		case c.queue <- e:
		default:
			c.dropped.Add(1)
		}
	}
}

type conn struct {
	srv     *Server
	w       io.Writer
	wmu     sync.Mutex
	authed  bool
	broken  atomic.Bool
	closer  io.Closer // set for network connections
	queue   chan genadb.Event
	dropped atomic.Uint64
	stop    chan struct{}
}

func (c *conn) send(v any) {
	b, err := json.Marshal(v)
	if err != nil || c.broken.Load() {
		return
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if d, ok := c.w.(interface{ SetWriteDeadline(time.Time) error }); ok {
		d.SetWriteDeadline(time.Now().Add(WriteTimeout))
	}
	if _, err := c.w.Write(append(b, '\n')); err != nil {
		// A client that stopped reading: drop it rather than hold anything up.
		c.broken.Store(true)
		if c.closer != nil {
			c.closer.Close()
		}
	}
}

func (c *conn) notify(method string, params any) {
	c.send(notification{JSONRPC: "2.0", Method: method, Params: params})
}

// pump delivers queued events to one subscriber.
func (c *conn) pump() {
	for {
		select {
		case e := <-c.queue:
			if n := c.dropped.Swap(0); n > 0 {
				c.notify("events.dropped", map[string]any{"count": n})
			}
			c.notify("event", e)
		case <-c.stop:
			return
		}
	}
}

func (s *Server) subscribe(c *conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subs == nil {
		s.subs = map[*conn]struct{}{}
	}
	if _, ok := s.subs[c]; ok {
		return
	}
	c.queue = make(chan genadb.Event, SubscriberQueue)
	c.stop = make(chan struct{})
	s.subs[c] = struct{}{}
	go c.pump()
}

func (s *Server) unsubscribe(c *conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.subs[c]; ok {
		delete(s.subs, c)
		close(c.stop)
	}
}

// ServeConn handles one stream until EOF or ctx ends.
func (s *Server) ServeConn(ctx context.Context, rw io.ReadWriter) error {
	c := &conn{srv: s, w: rw, authed: s.Token == ""}
	if cl, ok := rw.(io.Closer); ok {
		c.closer = cl
	}
	defer s.unsubscribe(c)
	sc := bufio.NewScanner(rw)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			c.send(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &Error{Code: CodeParse, Message: "parse error"}})
			continue
		}
		if req.JSONRPC != "2.0" || req.Method == "" {
			c.send(response{JSONRPC: "2.0", ID: orNull(req.ID), Error: &Error{Code: CodeInvalidRequest, Message: "invalid request"}})
			continue
		}
		res, err := s.call(ctx, c, req)
		if len(req.ID) == 0 { // notification: no reply
			continue
		}
		r := response{JSONRPC: "2.0", ID: req.ID}
		if err != nil {
			r.Error = toRPCError(err)
		} else {
			if res == nil {
				res = struct{}{}
			}
			r.Result = res
		}
		c.send(r)
	}
	return sc.Err()
}

func orNull(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

// Listen serves loopback TCP connections until ctx ends.
func (s *Server) Listen(ctx context.Context, ln net.Listener) error {
	context.AfterFunc(ctx, func() { ln.Close() })
	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go func() {
			defer nc.Close()
			s.ServeConn(ctx, nc)
		}()
	}
}

func decode(p json.RawMessage, v any) error {
	if len(p) == 0 || string(p) == "null" {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(p))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return &Error{Code: CodeInvalidParams, Message: "invalid params: " + err.Error()}
	}
	return nil
}

// SessionInfo describes a live session.
type SessionInfo struct {
	ID       string    `json:"session_id"`
	ADBAddr  string    `json:"adb_addr"`
	DeviceID string    `json:"device_id"`
	Started  time.Time `json:"started"`
}

func info(s *genadb.Session) SessionInfo {
	return SessionInfo{ID: s.ID(), ADBAddr: s.ADBAddr(), DeviceID: s.DeviceID(), Started: s.Started()}
}

func (s *Server) call(ctx context.Context, c *conn, req request) (any, error) {
	if req.Method == "auth" {
		var p struct {
			Token string `json:"token"`
		}
		if err := decode(req.Params, &p); err != nil {
			return nil, err
		}
		if s.Token != "" && subtle.ConstantTimeCompare([]byte(p.Token), []byte(s.Token)) != 1 {
			return nil, &Error{Code: CodeUnauthorized, Message: "bad token"}
		}
		c.authed = true
		return map[string]any{"ok": true}, nil
	}
	if !c.authed {
		return nil, &Error{Code: CodeUnauthorized, Message: "call auth first"}
	}
	cl := s.Client
	switch req.Method {
	case "auth.set_token":
		var p struct {
			Token string `json:"token"`
		}
		if err := decode(req.Params, &p); err != nil {
			return nil, err
		}
		if p.Token == "" {
			return nil, &Error{Code: CodeInvalidParams, Message: "token is required"}
		}
		return cl.SetToken(p.Token)

	case "version":
		return map[string]any{"version": genadb.Version, "mode": cl.Mode(), "audit": cl.AuditPath() != ""}, nil

	case "doctor":
		return cl.Doctor(ctx), nil

	case "identity.public_key":
		k, err := cl.PublicKey()
		return map[string]any{"public_key": k}, err

	case "devices.list":
		d, err := cl.Devices(ctx)
		if d == nil {
			d = []genadb.DeviceInfo{}
		}
		return map[string]any{"devices": d}, err

	case "devices.forget":
		var p struct {
			DeviceID string `json:"device_id"`
		}
		if err := decode(req.Params, &p); err != nil {
			return nil, err
		}
		return nil, cl.Forget(p.DeviceID)

	case "session.connect":
		var p struct {
			DeviceID    string `json:"device_id"`
			PairingCode string `json:"pairing_code"`
			Listen      string `json:"listen"`
			TimeoutMS   int    `json:"timeout_ms"`
		}
		if err := decode(req.Params, &p); err != nil {
			return nil, err
		}
		if p.TimeoutMS <= 0 {
			p.TimeoutMS = 60000
		}
		cctx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutMS)*time.Millisecond)
		defer cancel()
		sess, err := cl.Connect(cctx, genadb.ConnectRequest{DeviceID: p.DeviceID, PairingCode: p.PairingCode, Listen: p.Listen})
		if err != nil {
			return nil, err
		}
		return info(sess), nil

	case "session.pair_adb":
		var p struct {
			DeviceID    string `json:"device_id"`
			PairingPort int    `json:"pairing_port"`
			PairingCode string `json:"pairing_code"`
			ADBPath     string `json:"adb_path"`
			TimeoutMS   int    `json:"timeout_ms"`
		}
		if err := decode(req.Params, &p); err != nil {
			return nil, err
		}
		if p.DeviceID == "" || p.PairingCode == "" {
			return nil, &Error{Code: CodeInvalidParams, Message: "device_id and pairing_code are required"}
		}
		if p.TimeoutMS <= 0 {
			p.TimeoutMS = 60000
		}
		cctx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutMS)*time.Millisecond)
		defer cancel()
		return cl.PairADB(cctx, genadb.PairADBRequest{DeviceID: p.DeviceID, PairingPort: p.PairingPort,
			PairingCode: p.PairingCode, ADBPath: p.ADBPath})

	case "session.list":
		out := []SessionInfo{}
		for _, ss := range cl.Sessions() {
			out = append(out, info(ss))
		}
		return map[string]any{"sessions": out}, nil

	case "session.stop":
		var p struct {
			ID string `json:"session_id"`
		}
		if err := decode(req.Params, &p); err != nil {
			return nil, err
		}
		ss, ok := cl.Session(p.ID)
		if !ok {
			return nil, genadb.ErrNoSession
		}
		ss.Stop()
		return nil, nil

	case "events.subscribe":
		s.subscribe(c)
		return map[string]any{"subscribed": true}, nil

	case "events.unsubscribe":
		s.unsubscribe(c)
		return map[string]any{"subscribed": false}, nil

	case "audit.report":
		var p struct {
			Format string `json:"format"`
			Since  string `json:"since"`
			Until  string `json:"until"`
			Events bool   `json:"include_events"`
		}
		if err := decode(req.Params, &p); err != nil {
			return nil, err
		}
		if p.Format == "" {
			p.Format = "json"
		}
		f, err := audit.ParseFormat(p.Format)
		if err != nil {
			return nil, &Error{Code: CodeInvalidParams, Message: err.Error()}
		}
		opt := audit.Options{IncludeEvents: p.Events}
		for _, t := range []struct {
			s   string
			dst *time.Time
		}{{p.Since, &opt.Since}, {p.Until, &opt.Until}} {
			if t.s == "" {
				continue
			}
			v, err := time.Parse(time.RFC3339, t.s)
			if err != nil {
				return nil, &Error{Code: CodeInvalidParams, Message: "since/until must be RFC 3339"}
			}
			*t.dst = v
		}
		var buf bytes.Buffer
		if err := cl.ExportAuditReport(&buf, f, opt); err != nil {
			return nil, err
		}
		if f == audit.FormatJSON {
			return map[string]any{"format": f, "report": json.RawMessage(buf.Bytes())}, nil
		}
		return map[string]any{"format": f, "content": buf.String()}, nil

	case "audit.verify":
		if cl.AuditPath() == "" {
			return nil, genadb.ErrAuditDisabled
		}
		return audit.VerifyFile(cl.AuditPath(), audit.VerifyOptions{AnchorKeyFile: cl.AuditAnchorKeyFile()})
	}
	return nil, &Error{Code: CodeMethodNotFound, Message: fmt.Sprintf("method %q not found", req.Method)}
}
