package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sumukhak/new-genadb/core/pkg/genadb"
)

func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	state := fs.String("state", ".", "state directory")
	relay := fs.String("relay", "", "relay to test (host:port, ws:// or wss://)")
	auditLog := fs.String("audit-log", "", "audit log to verify (default <state>/audit.jsonl if present)")
	adb := fs.String("adb", "", "adb binary (default: from PATH)")
	asJSON := fs.Bool("json", false, "machine-readable output")
	var t genadb.TransportOptions
	fs.StringVar(&t.Proxy, "proxy", "", "HTTP proxy for ws/wss relays")
	fs.StringVar(&t.CAFile, "relay-ca", "", "PEM CA/certificate to trust for wss relays")
	fs.StringVar(&t.Pin, "relay-pin", "", "hex SHA-256 relay certificate pin")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *auditLog == "" {
		if p := filepath.Join(*state, "audit.jsonl"); fileExists(p) {
			*auditLog = p
		}
	}
	r := genadb.Diagnose(context.Background(), genadb.DoctorOptions{StateDir: *state, Relay: *relay,
		AuditPath: *auditLog, ADBPath: *adb, Transport: genadb.DefaultTransport(t)})
	if *asJSON {
		b, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Printf("%s %s (%s)\n", prog, r.Version, r.Platform)
		for _, c := range r.Checks {
			fmt.Printf("  [%-4s] %-15s %s\n", c.Status, c.Name, c.Detail)
			if c.Hint != "" && c.Status != genadb.CheckOK {
				fmt.Printf("  %6s %-15s hint: %s\n", "", "", c.Hint)
			}
		}
	}
	if !r.OK {
		return 1
	}
	return 0
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
