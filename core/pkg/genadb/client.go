package genadb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/sumukhak/new-genadb/core/internal/engine"
	"github.com/sumukhak/new-genadb/core/pkg/genadb/audit"
)

// Version is the SDK and engine version.
const Version = engine.Version

// Client manages connections from this machine to remote devices. It is safe
// for concurrent use. Create one with New and release it with Close.
type Client struct {
	cfg       config
	events    chan Event
	sink      audit.Sink // nil when audit is off
	auditPath string

	mu       sync.Mutex
	sessions map[string]*Session
	seq      int
	closed   bool
	closeErr error
}

// New builds a Client. It creates the state directory and, when auditing is
// enabled, opens the audit log.
func New(opts ...Option) (*Client, error) {
	cfg := config{mode: ModeSolo, reconnect: DefaultReconnectPolicy, eventBuf: 256}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.state == "" {
		cfg.state = defaultState()
	}
	if cfg.transport == nil {
		cfg.transport = DefaultTransport(cfg.topts)
	}
	if cfg.discoverer == nil {
		cfg.discoverer = stateDiscoverer{cfg.state}
	}
	if cfg.reconnect.InitialDelay <= 0 {
		cfg.reconnect.InitialDelay = time.Second
	}
	if cfg.reconnect.MaxDelay < cfg.reconnect.InitialDelay {
		cfg.reconnect.MaxDelay = 30 * time.Second
	}
	switch cfg.mode {
	case ModeSolo:
	case ModeCorporate:
		if cfg.auth == nil {
			return nil, fmt.Errorf("%w: corporate mode needs WithCorporateToken or WithAuthProvider", ErrTokenInvalid)
		}
		if cfg.policyPath == "" {
			return nil, errors.New("genadb: corporate mode needs a policy file")
		}
		if cfg.audit.Mode == AuditOff {
			return nil, errors.New("genadb: audit cannot be disabled in corporate mode")
		}
	default:
		return nil, fmt.Errorf("genadb: unknown mode %q", cfg.mode)
	}
	if err := os.MkdirAll(cfg.state, 0o700); err != nil {
		return nil, err
	}
	if cfg.logger != nil {
		engine.SetLogger(cfg.logger)
	}
	c := &Client{cfg: cfg, events: make(chan Event, max(cfg.eventBuf, 1)), sessions: map[string]*Session{}}
	if c.auditEnabled() {
		if err := c.openAudit(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Client) auditEnabled() bool {
	switch c.cfg.audit.Mode {
	case AuditOn:
		return true
	case AuditOff:
		return false
	}
	return c.cfg.mode == ModeCorporate
}

func (c *Client) openAudit() error {
	c.auditPath = c.cfg.audit.Path
	if c.auditPath == "" {
		c.auditPath = filepath.Join(c.cfg.state, "audit.jsonl")
	}
	f, err := audit.OpenFile(c.auditPath, c.cfg.mode == ModeCorporate)
	if err != nil {
		return fmt.Errorf("genadb: audit log: %w", err)
	}
	if u := c.cfg.audit.WebhookURL; u != "" {
		w, err := audit.NewWebhookSink(u, c.cfg.audit.WebhookSecret, nil)
		if err != nil {
			f.Close()
			return fmt.Errorf("genadb: audit webhook: %w", err)
		}
		f.Tee(w)
	}
	f.Tee(c.cfg.audit.Sinks...)
	f.Tee(eventTap{c})
	c.sink = f
	return nil
}

// eventTap republishes sealed audit records as EventAudit events.
type eventTap struct{ c *Client }

func (t eventTap) Write(e audit.Event) error {
	t.c.emit(Event{Type: EventAudit, Fields: e})
	return nil
}
func (eventTap) Close() error { return nil }

// Mode reports the client's operating mode.
func (c *Client) Mode() Mode { return c.cfg.mode }

// StateDir reports where keys, pins and the default audit log live.
func (c *Client) StateDir() string { return c.cfg.state }

// AuditPath is the audit log file, or "" when auditing is off.
func (c *Client) AuditPath() string { return c.auditPath }

// Events returns the event channel. Events are dropped, not queued, when the
// reader falls behind; use WithEventHandler for lossless delivery.
func (c *Client) Events() <-chan Event { return c.events }

func (c *Client) emit(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if c.cfg.onEvent != nil {
		c.cfg.onEvent(e)
	}
	select {
	case c.events <- e:
	default:
	}
}

// PublicKey returns this machine's identity public key (creating the key on
// first use). Corporate token issuers bind user tokens to it.
func (c *Client) PublicKey() (string, error) { return engine.Keygen(c.cfg.state) }

// Devices lists devices from the configured DeviceDiscoverer.
func (c *Client) Devices(ctx context.Context) ([]DeviceInfo, error) {
	return c.cfg.discoverer.Devices(ctx)
}

// Forget removes the pairing pin for a device.
func (c *Client) Forget(deviceID string) error { return engine.ForgetDevice(c.cfg.state, deviceID) }

// ConnectRequest describes a session to start.
type ConnectRequest struct {
	// DeviceID of a paired (solo) or granted (corporate) device.
	DeviceID string
	// PairingCode shown on the phone; pairs first, then connects (solo).
	PairingCode string
	// Listen is the local adb endpoint (default 127.0.0.1:0, i.e. any port).
	Listen string
}

// Connect pairs if a code is given, verifies the device, and returns once its
// local adb endpoint is listening. The session runs until Stop, Client.Close
// or ctx is cancelled; transient failures are retried per ReconnectPolicy.
func (c *Client) Connect(ctx context.Context, req ConnectRequest) (*Session, error) {
	if c.cfg.relay == "" {
		return nil, ErrNoRelay
	}
	if req.DeviceID == "" && req.PairingCode == "" {
		return nil, ErrNoDevice
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	c.seq++
	id := "s" + strconv.Itoa(c.seq)
	c.mu.Unlock()

	sctx, cancel := context.WithCancel(context.Background())
	s := &Session{id: id, c: c, cancel: cancel, done: make(chan struct{}), ready: make(chan struct{}),
		deviceID: req.DeviceID, started: time.Now()}
	go s.run(sctx, req)

	select {
	case <-s.ready:
	case <-s.done:
		return nil, s.err
	case <-ctx.Done():
		s.Stop()
		return nil, ctx.Err()
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		s.Stop()
		return nil, ErrClosed
	}
	c.sessions[id] = s
	c.mu.Unlock()
	c.emit(Event{Type: EventSessionUp, Session: id, Fields: map[string]any{"addr": s.ADBAddr(), "device_id": s.DeviceID()}})
	return s, nil
}

// Session returns a live session by id.
func (c *Client) Session(id string) (*Session, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.sessions[id]
	return s, ok
}

// Sessions lists live sessions, oldest first.
func (c *Client) Sessions() []*Session {
	c.mu.Lock()
	out := make([]*Session, 0, len(c.sessions))
	for _, s := range c.sessions {
		out = append(out, s)
	}
	c.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].started.Before(out[j].started) })
	return out
}

func (c *Client) drop(s *Session) {
	c.mu.Lock()
	delete(c.sessions, s.id)
	c.mu.Unlock()
}

// ExportAuditReport writes the audit log as a report. JSON and HTML reports
// include chain verification, per-user / per-device / per-operation totals,
// sessions and denials; CSV is one row per record.
func (c *Client) ExportAuditReport(w io.Writer, f audit.Format, opt audit.Options) error {
	if c.auditPath == "" {
		return ErrAuditDisabled
	}
	evs, err := audit.ReadFile(c.auditPath)
	if err != nil {
		return err
	}
	if opt.Source == "" {
		opt.Source = c.auditPath
	}
	return audit.Export(w, evs, f, opt)
}

// Close stops every session and closes the audit log.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return c.closeErr
	}
	c.closed = true
	ss := make([]*Session, 0, len(c.sessions))
	for _, s := range c.sessions {
		ss = append(ss, s)
	}
	c.mu.Unlock()
	for _, s := range ss {
		s.Stop()
	}
	if c.sink != nil {
		c.closeErr = c.sink.Close()
	}
	return c.closeErr
}

// Session is one device exposed as a local adb endpoint.
type Session struct {
	id      string
	c       *Client
	cancel  context.CancelFunc
	started time.Time

	ready     chan struct{}
	readyOnce sync.Once
	done      chan struct{}
	err       error

	mu       sync.Mutex
	addr     string
	deviceID string
}

// ID is the client-unique session id.
func (s *Session) ID() string { return s.id }

// ADBAddr is the local endpoint to pass to `adb connect`.
func (s *Session) ADBAddr() string { s.mu.Lock(); defer s.mu.Unlock(); return s.addr }

// DeviceID is the remote device.
func (s *Session) DeviceID() string { s.mu.Lock(); defer s.mu.Unlock(); return s.deviceID }

// Started is when the session was requested.
func (s *Session) Started() time.Time { return s.started }

// Done is closed when the session has ended.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err is why the session ended (nil after Stop).
func (s *Session) Err() error { <-s.done; return s.err }

// Stop ends the session and waits for it to shut down.
func (s *Session) Stop() { s.cancel(); <-s.done }

func (s *Session) run(ctx context.Context, req ConnectRequest) {
	defer close(s.done)
	defer s.c.drop(s)
	pol := s.c.cfg.reconnect
	delay := pol.InitialDelay
	code := req.PairingCode
	for attempt := 1; ; attempt++ {
		err := s.runOnce(ctx, req, code)
		if ctx.Err() != nil {
			s.c.emit(Event{Type: EventSessionDown, Session: s.id})
			return
		}
		// A pairing code is single-use: after pairing, reconnect by device id.
		if s.DeviceID() != "" {
			code, req.DeviceID = "", s.DeviceID()
		}
		retry := !errors.Is(err, ErrDenied) && (pol.MaxAttempts == 0 || attempt < pol.MaxAttempts)
		if !retry {
			s.err = err
			s.c.emit(Event{Type: EventSessionDown, Session: s.id, Fields: map[string]any{"error": errText(err)}})
			return
		}
		s.c.emit(Event{Type: EventRetrying, Session: s.id, Fields: map[string]any{"attempt": attempt, "error": errText(err), "delay_ms": delay.Milliseconds()}})
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			s.c.emit(Event{Type: EventSessionDown, Session: s.id})
			return
		}
		delay = min(delay*2, pol.MaxDelay)
	}
}

func (s *Session) runOnce(ctx context.Context, req ConnectRequest, code string) error {
	cfg := engine.DesktopConfig{
		Relay:  s.c.cfg.relay,
		State:  s.c.cfg.state,
		Listen: req.Listen,
		Mode:   string(s.c.cfg.mode),
		Code:   code,
		Device: req.DeviceID,
		Dial:   engine.Dialer(s.c.cfg.transport.Dial),
		Audit:  s.c.sink,
		Events: func(ev string, f map[string]any) {
			switch ev {
			case "paired", "listening":
				s.mu.Lock()
				if d, ok := f["device_id"].(string); ok && d != "" {
					s.deviceID = d
				}
				if a, ok := f["addr"].(string); ok && ev == "listening" {
					s.addr = a
				}
				s.mu.Unlock()
			}
			s.c.emit(Event{Type: ev, Session: s.id, Fields: f})
			if ev == "listening" {
				s.readyOnce.Do(func() { close(s.ready) })
			}
		},
	}
	if s.c.cfg.mode == ModeCorporate {
		tok, err := s.c.cfg.auth.Token(ctx)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrTokenInvalid, err)
		}
		cfg.Identity, cfg.PolicyPath = tok, s.c.cfg.policyPath
	}
	// Reuse the address a restarted session listened on, so IDEs keep working.
	if a := s.ADBAddr(); a != "" {
		cfg.Listen = a
	}
	err := engine.RunDesktop(ctx, cfg)
	if errors.Is(err, context.Canceled) && ctx.Err() == nil {
		err = fmt.Errorf("%w: session ended", ErrUnavailable)
	}
	return err
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
