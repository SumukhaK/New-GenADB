package genadb

import (
	"context"

	"github.com/sumukhak/new-genadb/core/internal/engine"
)

// HostConfig configures the device-side agent, for programs that run on (or
// next to) the phone, such as the Android library's agent process.
type HostConfig struct {
	// ADBD is the adbd endpoint: host:port, "auto" (default), "mdns" or
	// "auto-legacy".
	ADBD string
	// EnrollmentToken is the device enrollment JWT (corporate mode).
	EnrollmentToken string
	// DebuggingDisallowed mirrors the device-management restriction: when
	// true the agent reports ErrBlocked-style "blocked" and never touches adbd.
	DebuggingDisallowed bool
	// LANListen (solo) accepts direct connections on this address so desktops
	// on the same network skip the relay; LANAdvertise overrides the address
	// desktops are told to use.
	LANListen, LANAdvertise string
}

// HostDevice registers this device with the relay and serves adb tunnels
// until ctx is cancelled. Events: "pairing_code", "online", "blocked",
// "adbd_endpoint", "adbd_unreachable".
func (c *SetuClient) HostDevice(ctx context.Context, h HostConfig) error {
	if c.cfg.relay == "" {
		return ErrNoRelay
	}
	if h.ADBD == "" {
		h.ADBD = "auto"
	}
	cfg := engine.DeviceConfig{
		Relay:        c.cfg.relay,
		ADBD:         h.ADBD,
		State:        c.cfg.state,
		Mode:         string(c.cfg.mode),
		Enroll:       h.EnrollmentToken,
		PolicyPath:   c.cfg.policyPath,
		DebugAllowed: !h.DebuggingDisallowed,
		LANListen:    h.LANListen,
		LANAdvertise: h.LANAdvertise,
		Dial:         engine.Dialer(c.cfg.transport.Dial),
		Events: func(ev string, f map[string]any) {
			c.emit(Event{Type: ev, Session: "device", Fields: f})
		},
	}
	return engine.RunDevice(ctx, cfg)
}
