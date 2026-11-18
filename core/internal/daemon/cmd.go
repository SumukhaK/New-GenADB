package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/sumukhak/new-genadb/core/pkg/genadb"
)

// Main runs the daemon command (setu-daemon, or its pre-1.0.1 name
// genadb-daemon) and returns the process exit code. It exposes the SDK over
// JSON-RPC 2.0 (one JSON object per line) for IDE plugins and UIs, listening
// on loopback TCP with the token stored in <state>/daemon.token, or serving a
// single client over stdin/stdout with --stdio.
func Main(name string, args []string) int {
	if err := run(name, args); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, name+":", err)
		return 1
	}
	return 0
}

type stdio struct{}

func (stdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }

func run(name string, args []string) error {
	fl := flag.NewFlagSet(name, flag.ExitOnError)
	listen := fl.String("listen", "127.0.0.1:7605", "loopback address for JSON-RPC clients")
	useStdio := fl.Bool("stdio", false, "serve one client on stdin/stdout instead of TCP (no token)")
	state := fl.String("state", "", "state directory (default: user config dir/genadb, shared by setu and genadb)")
	relay := fl.String("relay", "", "relay address (host:port, ws:// or wss://)")
	mode := fl.String("mode", "solo", "solo|corporate")
	identityFile := fl.String("identity-file", "", "corporate: file holding the user identity JWT")
	policy := fl.String("policy", "", "corporate: policy file")
	auditMode := fl.String("audit", "auto", "auto (corporate only)|on|off")
	auditLog := fl.String("audit-log", "", "audit log path (default <state>/audit.jsonl)")
	hookURL := fl.String("audit-webhook-url", "", "also POST signed audit records here")
	hookSecretFile := fl.String("audit-webhook-secret-file", "", "webhook HMAC secret file (default $GENADB_AUDIT_WEBHOOK_SECRET)")
	anchorKey := fl.String("audit-anchor-key-file", "", "key that signs the audit log's anchor (default: audit-anchor.key next to the log)")
	adbPath := fl.String("adb", "", "adb executable for session.pair_adb (default: adb on PATH)")
	label := fl.String("label", "", "name shown for this computer in the phone's session list (default: none)")
	var t genadb.TransportOptions
	fl.StringVar(&t.Proxy, "proxy", "", "HTTP proxy for ws/wss relays")
	fl.StringVar(&t.CAFile, "relay-ca", "", "PEM CA/certificate to trust for wss relays")
	fl.StringVar(&t.Pin, "relay-pin", "", "hex SHA-256 relay certificate pin")
	fl.Parse(args)

	srv := &Server{}
	opts := []genadb.Option{genadb.WithRelayURL(*relay), genadb.WithTransportOptions(t),
		genadb.WithEventHandler(srv.Publish), genadb.WithLogger(func(l string) { fmt.Fprintln(os.Stderr, l) })}
	if *state != "" {
		opts = append(opts, genadb.WithStateDir(*state))
	}
	if *adbPath != "" {
		opts = append(opts, genadb.WithADBPath(*adbPath))
	}
	if *label != "" {
		opts = append(opts, genadb.WithDeviceLabel(*label))
	}
	ac := genadb.AuditConfig{Path: *auditLog, WebhookURL: *hookURL, AnchorKeyFile: *anchorKey}
	switch *auditMode {
	case "auto":
	case "on":
		ac.Mode = genadb.AuditOn
	case "off":
		ac.Mode = genadb.AuditOff
	default:
		return fmt.Errorf("--audit must be auto, on or off")
	}
	if ac.WebhookURL != "" {
		sec := os.Getenv("GENADB_AUDIT_WEBHOOK_SECRET")
		if *hookSecretFile != "" {
			b, err := os.ReadFile(*hookSecretFile)
			if err != nil {
				return err
			}
			sec = strings.TrimSpace(string(b))
		}
		if sec == "" {
			return fmt.Errorf("--audit-webhook-url needs a secret")
		}
		ac.WebhookSecret = []byte(sec)
	}
	opts = append(opts, genadb.WithAuditConfig(ac))
	switch *mode {
	case "solo":
	case "corporate":
		b, err := os.ReadFile(*identityFile)
		if err != nil {
			return fmt.Errorf("corporate mode: --identity-file: %w", err)
		}
		opts = append(opts, genadb.WithCorporateToken(strings.TrimSpace(string(b)), *policy))
	default:
		return fmt.Errorf("--mode must be solo or corporate")
	}
	c, err := genadb.New(opts...)
	if err != nil {
		return err
	}
	defer c.Close()
	srv.Client = c

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *useStdio {
		return srv.ServeConn(ctx, stdio{})
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("--listen must be a loopback address; the daemon controls adb access")
	}
	tok, path, err := loadOrCreateToken(c.StateDir())
	if err != nil {
		return err
	}
	srv.Token = tok
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s %s listening on %s (token in %s)\n", name, genadb.Version, ln.Addr(), path)
	return srv.Listen(ctx, ln)
}

func loadOrCreateToken(state string) (string, string, error) {
	p := filepath.Join(state, "daemon.token")
	b, err := os.ReadFile(p)
	if err == nil && len(strings.TrimSpace(string(b))) >= 32 {
		return strings.TrimSpace(string(b)), p, nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", "", err
	}
	r := make([]byte, 32)
	if _, err := rand.Read(r); err != nil {
		return "", "", err
	}
	tok := hex.EncodeToString(r)
	return tok, p, os.WriteFile(p, []byte(tok+"\n"), 0o600)
}
