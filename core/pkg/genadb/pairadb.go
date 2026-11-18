package genadb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/sumukhak/new-genadb/core/internal/engine"
)

// PairADBRequest asks to pair this computer's adb key with a remote phone's
// Android 11+ Wireless debugging, over the end-to-end encrypted Setu bridge.
// The phone must show Settings > Developer options > Wireless debugging >
// "Pair device with pairing code"; that dialog shows the port and the code.
type PairADBRequest struct {
	// DeviceID of a paired (solo) or granted (corporate) device.
	DeviceID string
	// PairingPort is the port in the phone's pairing dialog (the part after
	// the colon). 0 asks the phone to discover it (_adb-tls-pairing._tcp).
	PairingPort int
	// PairingCode is the six-digit Wi-Fi pairing code from the same dialog.
	// It is handed to adb on this computer and never leaves it except inside
	// adb's own SPAKE2 exchange with the phone, which the tunnel encrypts.
	PairingCode string
	// ADBPath overrides the adb executable for this call (default: the
	// WithADBPath option, else "adb" on PATH).
	ADBPath string
}

// PairADBResult describes a completed pairing.
type PairADBResult struct {
	DeviceID  string `json:"device_id"`
	Paired    bool   `json:"paired"`
	Transport string `json:"transport"` // lan | relay-tcp | relay-ws | relay-wss
	Output    string `json:"output,omitempty"`
}

// ADBPairer runs the host side of `adb pair` against addr (a loopback
// address that reaches the phone's pairing service) and returns adb's
// output. Replace it with WithADBPairer in tests or to use an embedded adb.
type ADBPairer func(ctx context.Context, adbPath, addr, code string) (output string, err error)

// WithADBPath sets the adb executable PairADB runs (default "adb" on PATH).
func WithADBPath(path string) Option { return func(c *config) { c.adbPath = path } }

// WithADBPairer replaces how PairADB drives adb (default: exec `adb pair`).
func WithADBPairer(p ADBPairer) Option { return func(c *config) { c.adbPairer = p } }

var pairingCodeRE = regexp.MustCompile(`^[0-9]{6}$`)

// ExecADBPair is the default ADBPairer: it runs `adb pair <addr> <code>`.
// adb prints "Successfully paired to ..." on success; anything else fails.
func ExecADBPair(ctx context.Context, adbPath, addr, code string) (string, error) {
	if adbPath == "" {
		adbPath = "adb"
	}
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, adbPath, "pair", addr, code)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	text := strings.TrimSpace(out.String())
	if err == nil && strings.Contains(text, "Successfully paired") {
		return text, nil
	}
	if err == nil {
		err = errors.New("adb did not report success")
	}
	if text != "" {
		err = fmt.Errorf("%w: %s", err, text)
	}
	return text, err
}

// PairADB pairs this computer's adb key with the phone's Wireless debugging
// through the Setu bridge, so `adb connect` works later without the two
// being on the same Wi-Fi. It fails with ErrUnsupported when the phone runs
// a pre-1.1.0 agent and with ErrADBPairFailed when adb reports a failure
// (wrong or expired code, dialog closed).
func (c *SetuClient) PairADB(ctx context.Context, req PairADBRequest) (*PairADBResult, error) {
	if c.cfg.relay == "" {
		return nil, ErrNoRelay
	}
	if req.DeviceID == "" {
		return nil, ErrNoDevice
	}
	if !pairingCodeRE.MatchString(req.PairingCode) {
		return nil, fmt.Errorf("%w: %w: the Wi-Fi pairing code is six digits", ErrDenied, ErrBadCode)
	}
	if req.PairingPort < 0 || req.PairingPort > 65535 {
		return nil, fmt.Errorf("%w: pairing port %d out of range", ErrDenied, req.PairingPort)
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}
	cfg, err := c.desktopConfig(ctx, req.DeviceID)
	if err != nil {
		return nil, err
	}
	pairer := c.cfg.adbPairer
	if pairer == nil {
		pairer = ExecADBPair
	}
	adb := req.ADBPath
	if adb == "" {
		adb = c.cfg.adbPath
	}
	var output string
	started := time.Now()
	transport, err := engine.PairADB(ctx, cfg, req.PairingPort, func(ctx context.Context, addr string) error {
		out, err := pairer(ctx, adb, addr, req.PairingCode)
		output = out
		return err
	})
	if err != nil {
		c.emit(Event{Type: EventADBPair, Fields: map[string]any{"device_id": req.DeviceID, "paired": false, "error": errText(err)}})
		return nil, err
	}
	c.emit(Event{Type: EventADBPair, Fields: map[string]any{"device_id": req.DeviceID, "paired": true, "transport": transport,
		"duration_ms": time.Since(started).Milliseconds()}})
	return &PairADBResult{DeviceID: req.DeviceID, Paired: true, Transport: transport, Output: output}, nil
}
