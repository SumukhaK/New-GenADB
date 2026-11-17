package engine

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// CLI runs one of the agent subcommands (keygen, relay, device, connect) with
// the historical flag set and JSON-lines events on stdout. It returns the
// process exit code.
func CLI(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: genadb <keygen|relay|device|connect> [flags]")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch args[0] {
	case "keygen":
		err = cliKeygen(args[1:])
	case "relay":
		err = cliRelay(ctx, args[1:])
	case "device":
		err = cliDevice(ctx, args[1:])
	case "connect":
		err = cliConnect(ctx, args[1:])
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		StdoutEvents("error", map[string]any{"reason": err.Error()})
		fmt.Fprintln(os.Stderr, "genadb:", err)
		return 1
	}
	return 0
}

func cliKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	state := fs.String("state", ".", "state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, err := Keygen(*state)
	if err != nil {
		return err
	}
	StdoutEvents("pubkey", map[string]any{"pubkey": pub})
	return nil
}

func cliRelay(ctx context.Context, args []string) error {
	var c RelayConfig
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	fs.StringVar(&c.Listen, "listen", "127.0.0.1:7000", "listen address")
	fs.StringVar(&c.Mode, "mode", "solo", "solo|corporate")
	fs.StringVar(&c.PolicyPath, "policy", "", "policy file (corporate)")
	fs.StringVar(&c.AuditPath, "audit", "", "hash-chained audit log path (JSONL)")
	fs.StringVar(&c.AdminListen, "admin", "", "admin listen address")
	fs.StringVar(&c.AdminToken, "admin-token", "", "admin bearer token")
	fs.StringVar(&c.WSListen, "ws-listen", "", "also accept clients over WebSocket on this address (ws://, or wss:// with --tls-cert)")
	fs.StringVar(&c.TLSCert, "tls-cert", "", "TLS certificate (PEM) for --ws-listen")
	fs.StringVar(&c.TLSKey, "tls-key", "", "TLS private key (PEM) for --ws-listen")
	fs.BoolVar(&c.TrustForwarded, "trust-forwarded", false, "take client IPs from CF-Connecting-IP / X-Forwarded-For on --ws-listen (only behind a reverse proxy or tunnel you control)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c.Events = StdoutEvents
	return RunRelay(ctx, c)
}

func cliDevice(ctx context.Context, args []string) error {
	var c DeviceConfig
	fs := flag.NewFlagSet("device", flag.ContinueOnError)
	fs.StringVar(&c.Relay, "relay", "", "relay address")
	fs.StringVar(&c.ADBD, "adbd", "127.0.0.1:5555", "adbd endpoint host:port, or 'auto' to discover Wireless debugging via mDNS (falls back to 127.0.0.1:5555), 'mdns' (strict) or 'auto-legacy' (_adb._tcp)")
	fs.StringVar(&c.State, "state", ".", "state directory")
	fs.StringVar(&c.Mode, "mode", "solo", "solo|corporate")
	fs.String("name", "", "device name")
	fs.StringVar(&c.Enroll, "enroll", "", "device enrollment JWT (corporate)")
	fs.StringVar(&c.PolicyPath, "policy", "", "policy file (corporate)")
	debugPolicy := fs.String("debug-policy", "allowed", "allowed|disallowed (MDM DISALLOW_DEBUGGING_FEATURES)")
	AddTransportFlags(fs, &c.Transport)
	fs.StringVar(&c.LANListen, "lan-listen", "", "LAN listen address (solo: direct path)")
	fs.StringVar(&c.LANAdvertise, "lan-advertise", "", "LAN address to advertise (default: lan-listen)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c.DebugAllowed = *debugPolicy == "allowed"
	c.Events = StdoutEvents
	return RunDevice(ctx, c)
}

func cliConnect(ctx context.Context, args []string) error {
	var c DesktopConfig
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.StringVar(&c.Relay, "relay", "", "relay address")
	fs.StringVar(&c.State, "state", ".", "state directory")
	fs.StringVar(&c.Listen, "listen", "127.0.0.1:0", "local adb endpoint to expose")
	fs.StringVar(&c.Mode, "mode", "solo", "solo|corporate")
	AddTransportFlags(fs, &c.Transport)
	fs.StringVar(&c.Code, "code", "", "pairing code shown on the phone (NNNN-SSSSSS)")
	fs.StringVar(&c.Device, "device", "", "previously paired device id")
	fs.StringVar(&c.Identity, "identity", "", "user identity JWT (corporate)")
	fs.StringVar(&c.PolicyPath, "policy", "", "policy file (corporate)")
	auditPath := fs.String("audit", "", "corporate: record sessions and adb operations to this hash-chained JSONL file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *auditPath != "" {
		s, err := openAuditFile(*auditPath)
		if err != nil {
			return err
		}
		defer s.Close()
		c.Audit = s
	}
	c.Events = StdoutEvents
	return RunDesktop(ctx, c)
}
