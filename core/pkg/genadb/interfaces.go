package genadb

import (
	"context"
	"net"

	"github.com/sumukhak/new-genadb/core/internal/engine"
	"github.com/sumukhak/new-genadb/core/pkg/genadb/audit"
)

// TransportProvider opens byte streams to the relay. The default provider
// understands host:port (TCP), ws:// and wss:// (through HTTP proxies, with an
// optional extra CA and certificate pin).
type TransportProvider interface {
	// Dial opens a stream to the relay at spec.
	Dial(spec string) (net.Conn, error)
	// Label names the transport for audit records, e.g. "relay-wss".
	Label(spec string) string
}

// AuthProvider supplies the user identity token for corporate mode. It is
// asked once per Connect; implementations may refresh tokens.
type AuthProvider interface {
	Token(ctx context.Context) (string, error)
}

// AuditSink receives hash-chained audit records. See package audit for the
// file and webhook implementations.
type AuditSink = audit.Sink

// DeviceInfo describes a device known to this client.
type DeviceInfo struct {
	ID     string `json:"id"`
	Paired bool   `json:"paired"`
	Source string `json:"source"` // "state" for local pins, otherwise provider-defined
}

// DeviceDiscoverer lists devices the user can connect to. The default lists
// the devices paired in the state directory.
type DeviceDiscoverer interface {
	Devices(ctx context.Context) ([]DeviceInfo, error)
}

// TransportOptions configure the default TransportProvider.
type TransportOptions struct {
	Proxy  string // HTTP CONNECT proxy for ws/wss relays ("" = environment)
	CAFile string // extra CA / self-signed relay certificate (PEM)
	Pin    string // optional hex SHA-256 pin of the relay certificate
}

// DefaultTransport returns the built-in TransportProvider.
func DefaultTransport(o TransportOptions) TransportProvider {
	return defaultTransport{d: engine.TransportOptions(o).Dialer()}
}

type defaultTransport struct{ d engine.Dialer }

func (t defaultTransport) Dial(spec string) (net.Conn, error) { return t.d(spec) }
func (t defaultTransport) Label(spec string) string           { return engine.TransportLabel(spec) }

// StaticToken is an AuthProvider that always returns the same token.
type StaticToken string

func (s StaticToken) Token(context.Context) (string, error) { return string(s), nil }

type stateDiscoverer struct{ state string }

func (d stateDiscoverer) Devices(context.Context) ([]DeviceInfo, error) {
	ids, err := engine.PairedDevices(d.state)
	if err != nil {
		return nil, err
	}
	out := make([]DeviceInfo, 0, len(ids))
	for _, id := range ids {
		out = append(out, DeviceInfo{ID: id, Paired: true, Source: "state"})
	}
	return out, nil
}
