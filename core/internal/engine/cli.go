package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
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
	fs.StringVar(&c.AuditPath, "audit", "", "hash-chained audit log path (JSONL); corporate default <state>/relay-audit.jsonl, and cannot be turned off")
	fs.StringVar(&c.AuditKeyFile, "audit-anchor-key-file", "", "key that signs the audit log's anchor (default: audit-anchor.key next to the log)")
	state := fs.String("state", ".", "directory for the relay's persisted revocations (revocations.json) and default audit log")
	fs.StringVar(&c.AdminListen, "admin", "", "admin listen address")
	fs.StringVar(&c.AdminToken, "admin-token", "", "admin bearer token")
	fs.StringVar(&c.WSListen, "ws-listen", "", "also accept clients over WebSocket on this address (ws://, or wss:// with --tls-cert)")
	fs.StringVar(&c.TLSCert, "tls-cert", "", "TLS certificate (PEM) for --ws-listen")
	fs.StringVar(&c.TLSKey, "tls-key", "", "TLS private key (PEM) for --ws-listen")
	fs.BoolVar(&c.TrustForwarded, "trust-forwarded", false, "take client IPs from CF-Connecting-IP / X-Forwarded-For on --ws-listen (only behind a reverse proxy or tunnel you control)")
	wh := addWebhookFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	var err error
	if c.AuditPath, err = resolveAuditPath(c.AuditPath, c.Mode == "corporate", filepath.Join(*state, "relay-audit.jsonl")); err != nil {
		return err
	}
	hook, err := wh.sink()
	if err != nil {
		return err
	}
	if hook != nil {
		c.Audit = hook
	}
	if c.AuditPath != "" {
		logf("audit log: %s", c.AuditPath)
	}
	c.StateDir = *state // revocations.json survives restarts
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
	control := fs.Bool("control-stdin", false, `read JSON commands from stdin, one per line: {"cmd":"end_session","session_id":"..."}`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c.DebugAllowed = *debugPolicy == "allowed"
	c.Events = StdoutEvents
	if *control {
		c.Commands = readCommands(ctx, os.Stdin, StdoutEvents)
	}
	return RunDevice(ctx, c)
}

// readCommands turns JSON lines from r into device commands and reports
// each outcome as a command_result event.
func readCommands(ctx context.Context, r io.Reader, events EventFunc) <-chan DeviceCommand {
	out := make(chan DeviceCommand)
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			var m struct {
				Cmd       string `json:"cmd"`
				SessionID string `json:"session_id"`
			}
			if json.Unmarshal(sc.Bytes(), &m) != nil || m.Cmd == "" {
				continue
			}
			reply := make(chan error, 1)
			select {
			case out <- DeviceCommand{Op: m.Cmd, SessionID: m.SessionID, Reply: reply}:
			case <-ctx.Done():
				return
			}
			err := <-reply
			f := map[string]any{"cmd": m.Cmd, "session_id": m.SessionID, "ok": err == nil}
			if err != nil {
				f["error"] = err.Error()
			}
			events("command_result", f)
		}
	}()
	return out
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
	fs.StringVar(&c.Label, "label", "", "name shown for this computer in the phone's session list (v1.1.0)")
	fs.StringVar(&c.Identity, "identity", "", "user identity JWT (corporate)")
	fs.StringVar(&c.PolicyPath, "policy", "", "policy file (corporate)")
	auditPath := fs.String("audit", "", "record sessions and adb operations to this hash-chained JSONL file; corporate default <state>/audit.jsonl, and cannot be turned off")
	keyFile := fs.String("audit-anchor-key-file", "", "key that signs the audit log's anchor (default: audit-anchor.key next to the log)")
	wh := addWebhookFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	hook, err := wh.sink()
	if err != nil {
		return err
	}
	corporate := c.Mode == "corporate" || c.Identity != ""
	path, err := resolveAuditPath(*auditPath, corporate, filepath.Join(c.State, "audit.jsonl"))
	if err != nil {
		return err
	}
	s, err := combineAudit(path, *keyFile, hook)
	if err != nil {
		return err
	}
	if s != nil {
		defer s.Close()
		c.Audit = s
	}
	c.Events = StdoutEvents
	return RunDesktop(ctx, c)
}
