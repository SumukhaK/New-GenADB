package genadb

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Mode selects solo (personal, pairing-code trust) or corporate (identity
// tokens, policy grants, mandatory audit) operation.
type Mode string

const (
	ModeSolo      Mode = "solo"
	ModeCorporate Mode = "corporate"
)

// AuditMode controls whether audit records are written.
type AuditMode int

const (
	// AuditAuto: off in solo mode, on in corporate mode (the default).
	AuditAuto AuditMode = iota
	// AuditOn: always record.
	AuditOn
	// AuditOff: never record. Not allowed in corporate mode.
	AuditOff
)

// AuditConfig configures audit logging.
type AuditConfig struct {
	Mode AuditMode
	// Path of the hash-chained JSONL log. Default: <state>/audit.jsonl.
	Path string
	// WebhookURL, when set, also POSTs every record (HMAC-SHA256 signed with
	// WebhookSecret) to a collector. Delivery is asynchronous with retries.
	WebhookURL    string
	WebhookSecret []byte
	// Sinks are extra destinations (SIEM forwarders, tests, ...).
	Sinks []AuditSink
}

// ReconnectPolicy controls how Connect retries a session that fails to
// start or stops because the relay or device became unavailable. Live
// tunnels already survive network changes on their own; this policy covers
// the agent as a whole. Denials (ErrDenied) are never retried.
type ReconnectPolicy struct {
	MaxAttempts  int           // 0 = retry until the context ends; 1 = no retries
	InitialDelay time.Duration // default 1s
	MaxDelay     time.Duration // default 30s
}

// DefaultReconnectPolicy retries forever with 1s..30s exponential backoff.
var DefaultReconnectPolicy = ReconnectPolicy{InitialDelay: time.Second, MaxDelay: 30 * time.Second}

// NoReconnect fails on the first error.
var NoReconnect = ReconnectPolicy{MaxAttempts: 1}

type config struct {
	relay      string
	state      string
	mode       Mode
	auth       AuthProvider
	policyPath string
	transport  TransportProvider
	topts      TransportOptions
	discoverer DeviceDiscoverer
	audit      AuditConfig
	reconnect  ReconnectPolicy
	onEvent    func(Event)
	logger     func(string)
	eventBuf   int
}

// Option configures a Client.
type Option func(*config)

// WithRelayURL sets the relay: host:port, ws://host/path or wss://host/path.
func WithRelayURL(url string) Option { return func(c *config) { c.relay = url } }

// WithStateDir sets where the identity key, device pins and (by default) the
// audit log live. A leading "~/" expands to the home directory. Default:
// the user config directory + "/genadb".
func WithStateDir(dir string) Option { return func(c *config) { c.state = expandHome(dir) } }

// WithMode selects solo or corporate mode. WithCorporateToken implies
// corporate mode.
func WithMode(m Mode) Option { return func(c *config) { c.mode = m } }

// WithCorporateToken enables corporate mode with a fixed identity token and
// the organisation policy file that verifies it.
func WithCorporateToken(token, policyPath string) Option {
	return func(c *config) {
		c.mode, c.auth, c.policyPath = ModeCorporate, StaticToken(token), policyPath
	}
}

// WithAuthProvider enables corporate mode with a token source (e.g. one that
// refreshes from an identity provider).
func WithAuthProvider(p AuthProvider, policyPath string) Option {
	return func(c *config) { c.mode, c.auth, c.policyPath = ModeCorporate, p, policyPath }
}

// WithAuditConfig configures audit logging.
func WithAuditConfig(a AuditConfig) Option { return func(c *config) { c.audit = a } }

// WithReconnectPolicy sets the session restart policy.
func WithReconnectPolicy(p ReconnectPolicy) Option { return func(c *config) { c.reconnect = p } }

// WithTransportOptions configures the default relay transport (proxy, CA, pin).
func WithTransportOptions(o TransportOptions) Option { return func(c *config) { c.topts = o } }

// WithTransport replaces the relay transport.
func WithTransport(t TransportProvider) Option { return func(c *config) { c.transport = t } }

// WithDeviceDiscoverer replaces the device list source.
func WithDeviceDiscoverer(d DeviceDiscoverer) Option { return func(c *config) { c.discoverer = d } }

// WithEventHandler registers a callback for every event, in addition to the
// Events channel. It is called synchronously and must not block.
func WithEventHandler(f func(Event)) Option { return func(c *config) { c.onEvent = f } }

// WithEventBuffer sets the Events channel capacity (default 256). When the
// channel is full, new events are dropped rather than stalling tunnels.
func WithEventBuffer(n int) Option { return func(c *config) { c.eventBuf = n } }

// WithLogger receives human-readable diagnostic lines (default: stderr).
// The logger is process-wide: the last Client to set one wins.
func WithLogger(f func(line string)) Option { return func(c *config) { c.logger = f } }

func defaultState() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "genadb")
	}
	return ".genadb"
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}
