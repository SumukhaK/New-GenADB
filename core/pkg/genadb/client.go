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
	"sync/atomic"
	"time"

	"github.com/sumukhak/new-genadb/core/internal/engine"
	"github.com/sumukhak/new-genadb/core/pkg/genadb/audit"
)

// Version is the SDK and engine version.
const Version = engine.Version

// SetuClient manages connections from this machine to remote devices. It is safe
// for concurrent use. Create one with New and release it with Close.
type SetuClient struct {
	cfg       config
	events    chan Event
	sink      audit.Sink // nil when audit is off
	auditPath string

	// Events are delivered by one dispatcher goroutine so that a slow
	// handler or channel reader never blocks the agents (audit records are
	// produced on the ADB data path).
	dispatch chan Event
	quit     chan struct{}
	dispDone chan struct{}
	dropped  atomic.Uint64

	mu       sync.Mutex
	sessions map[string]*SetuSession
	seq      int
	closed   bool
	closeErr error
}

// New builds a Client. It creates the state directory and, when auditing is
// enabled, opens the audit log.
func New(opts ...Option) (*SetuClient, error) {
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
	c := &SetuClient{cfg: cfg, events: make(chan Event, max(cfg.eventBuf, 1)), sessions: map[string]*SetuSession{},
		dispatch: make(chan Event, dispatchBuffer), quit: make(chan struct{}), dispDone: make(chan struct{})}
	go c.dispatcher()
	if c.auditEnabled() {
		if err := c.openAudit(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *SetuClient) auditEnabled() bool {
	switch c.cfg.audit.Mode {
	case AuditOn:
		return true
	case AuditOff:
		return false
	}
	return c.cfg.mode == ModeCorporate
}

func (c *SetuClient) openAudit() error {
	c.auditPath = c.cfg.audit.Path
	if c.auditPath == "" {
		c.auditPath = filepath.Join(c.cfg.state, "audit.jsonl")
	}
	f, err := audit.OpenFileWith(c.auditPath, audit.FileOptions{Sync: c.cfg.mode == ModeCorporate,
		AnchorKeyFile: c.cfg.audit.AnchorKeyFile})
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
type eventTap struct{ c *SetuClient }

func (t eventTap) Write(e audit.Event) error {
	t.c.emit(Event{Type: EventAudit, Fields: e})
	return nil
}
func (eventTap) Close() error { return nil }

// Mode reports the client's operating mode.
func (c *SetuClient) Mode() Mode { return c.cfg.mode }

// StateDir reports where keys, pins and the default audit log live.
func (c *SetuClient) StateDir() string { return c.cfg.state }

// AuditPath is the audit log file, or "" when auditing is off.
func (c *SetuClient) AuditPath() string { return c.auditPath }

// AuditAnchorKeyFile returns the configured anchor key file ("" = the default
// next to the log).
func (c *SetuClient) AuditAnchorKeyFile() string { return c.cfg.audit.AnchorKeyFile }

// Events returns the event channel. Events are dropped, not queued, when the
// reader falls behind; use WithEventHandler for lossless delivery.
func (c *SetuClient) Events() <-chan Event { return c.events }

// dispatchBuffer is how many events may wait for a slow handler before
// new ones are dropped (counted by DroppedEvents).
const dispatchBuffer = 4096

// emit never blocks.
func (c *SetuClient) emit(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	select {
	case c.dispatch <- e:
	default:
		c.dropped.Add(1)
	}
}

func (c *SetuClient) deliver(e Event) {
	if c.cfg.onEvent != nil {
		c.cfg.onEvent(e)
	}
	select {
	case c.events <- e:
	default:
		c.dropped.Add(1)
	}
}

func (c *SetuClient) dispatcher() {
	defer close(c.dispDone)
	for {
		select {
		case e := <-c.dispatch:
			c.deliver(e)
		case <-c.quit:
			for {
				select {
				case e := <-c.dispatch:
					c.deliver(e)
				default:
					return
				}
			}
		}
	}
}

// DroppedEvents counts events discarded because the event handler or the
// Events channel reader fell behind. Audit records are never dropped from
// the audit log itself, only from the event stream.
func (c *SetuClient) DroppedEvents() uint64 { return c.dropped.Load() }

// PublicKey returns this machine's identity public key (creating the key on
// first use). Corporate token issuers bind user tokens to it.
func (c *SetuClient) PublicKey() (string, error) { return engine.Keygen(c.cfg.state) }

// Devices lists devices from the configured DeviceDiscoverer.
func (c *SetuClient) Devices(ctx context.Context) ([]DeviceInfo, error) {
	return c.cfg.discoverer.Devices(ctx)
}

// Forget removes the pairing pin for a device.
func (c *SetuClient) Forget(deviceID string) error { return engine.ForgetDevice(c.cfg.state, deviceID) }

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
// local adb endpoint is listening, or with the first error: a wrong, mistyped
// or expired code fails fast with ErrBadCode. Once up, the session runs until
// Stop or Client.Close, and transient failures are retried per ReconnectPolicy.
func (c *SetuClient) Connect(ctx context.Context, req ConnectRequest) (*SetuSession, error) {
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
	s := &SetuSession{id: id, c: c, cancel: cancel, done: make(chan struct{}), ready: make(chan struct{}),
		deviceID: req.DeviceID, started: time.Now()}
	go s.run(sctx, req)

	select {
	case <-s.ready:
	case <-s.done:
		return nil, s.err
	case <-ctx.Done():
		s.Stop()
		if s.err != nil {
			return nil, fmt.Errorf("%w (last error: %w)", ctx.Err(), s.err)
		}
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
func (c *SetuClient) Session(id string) (*SetuSession, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.sessions[id]
	return s, ok
}

// Sessions lists live sessions, oldest first.
func (c *SetuClient) Sessions() []*SetuSession {
	c.mu.Lock()
	out := make([]*SetuSession, 0, len(c.sessions))
	for _, s := range c.sessions {
		out = append(out, s)
	}
	c.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].started.Before(out[j].started) })
	return out
}

func (c *SetuClient) drop(s *SetuSession) {
	c.mu.Lock()
	delete(c.sessions, s.id)
	c.mu.Unlock()
}

// ExportAuditReport writes the audit log as a report. JSON and HTML reports
// include chain verification, per-user / per-device / per-operation totals,
// sessions and denials; CSV is one row per record.
func (c *SetuClient) ExportAuditReport(w io.Writer, f audit.Format, opt audit.Options) error {
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
func (c *SetuClient) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return c.closeErr
	}
	c.closed = true
	ss := make([]*SetuSession, 0, len(c.sessions))
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
	close(c.quit)
	// Deliver what is queued, but never let a stuck handler hang Close.
	select {
	case <-c.dispDone:
	case <-time.After(2 * time.Second):
	}
	return c.closeErr
}

// SetuSession is one device exposed as a local adb endpoint.
type SetuSession struct {
	id      string
	c       *SetuClient
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
func (s *SetuSession) ID() string { return s.id }

// ADBAddr is the local endpoint to pass to `adb connect`.
func (s *SetuSession) ADBAddr() string { s.mu.Lock(); defer s.mu.Unlock(); return s.addr }

// DeviceID is the remote device.
func (s *SetuSession) DeviceID() string { s.mu.Lock(); defer s.mu.Unlock(); return s.deviceID }

// Started is when the session was requested.
func (s *SetuSession) Started() time.Time { return s.started }

// Done is closed when the session has ended.
func (s *SetuSession) Done() <-chan struct{} { return s.done }

// Err is why the session ended (nil after Stop).
func (s *SetuSession) Err() error { <-s.done; return s.err }

// Stop ends the session and waits for it to shut down.
func (s *SetuSession) Stop() { s.cancel(); <-s.done }

func (s *SetuSession) run(ctx context.Context, req ConnectRequest) {
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
		// Before the first "listening" the caller is still inside Connect:
		// fail fast with the real error (bad code, not paired, relay down)
		// instead of retrying behind its back. The policy covers live sessions.
		select {
		case <-s.ready:
		default:
			s.err = err
			s.c.emit(Event{Type: EventSessionDown, Session: s.id, Fields: map[string]any{"error": errText(err)}})
			return
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

func (s *SetuSession) runOnce(ctx context.Context, req ConnectRequest, code string) error {
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
