package genadb

import (
	"context"
	"fmt"
	"time"

	"github.com/sumukhak/new-genadb/core/internal/engine"
)

// DevicePresence is a granted device and whether it is connected to the
// relay right now.
type DevicePresence struct {
	DeviceID    string     `json:"device_id"`
	Online      bool       `json:"online"`
	ConnectedAt *time.Time `json:"connected_at,omitempty"`
	Transport   string     `json:"transport,omitempty"` // device to relay: tcp | ws | wss
	Sessions    int        `json:"sessions"`            // relayed sessions open to it now
}

// Presence lists the devices the corporate policy grants this user, with
// live availability from the relay (corporate mode). Devices that are
// granted but revoked are reported offline.
func (c *SetuClient) Presence(ctx context.Context) ([]DevicePresence, error) {
	if c.cfg.mode != ModeCorporate {
		return nil, fmt.Errorf("%w: presence needs corporate mode", ErrDenied)
	}
	if c.cfg.relay == "" {
		return nil, ErrNoRelay
	}
	cfg, err := c.desktopConfig(ctx, "")
	if err != nil {
		return nil, err
	}
	list, err := engine.Presence(ctx, cfg)
	if err != nil {
		return nil, err
	}
	out := make([]DevicePresence, 0, len(list))
	for _, p := range list {
		out = append(out, DevicePresence{DeviceID: p.DeviceID, Online: p.Online, ConnectedAt: p.ConnectedAt,
			Transport: p.Transport, Sessions: p.Sessions})
	}
	return out, nil
}
