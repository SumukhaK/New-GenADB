package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sumukhak/new-genadb/core/internal/engine"
	"github.com/sumukhak/new-genadb/core/pkg/genadb"
)

// cmdADBPair runs `setu adb-pair`: Android 11+ Wireless-debugging pairing
// (adb pair) with a remote phone through the encrypted bridge.
func cmdADBPair(args []string) int {
	fs := flag.NewFlagSet("adb-pair", flag.ContinueOnError)
	relay := fs.String("relay", "", "relay address")
	state := fs.String("state", ".", "state directory")
	device := fs.String("device", "", "paired (solo) or granted (corporate) device id")
	port := fs.Int("port", 0, "port shown in the phone's \"Pair device with pairing code\" dialog (0 = discover on the phone)")
	code := fs.String("code", "", "six-digit Wi-Fi pairing code from the same dialog")
	adb := fs.String("adb", "", "adb executable (default: adb on PATH)")
	mode := fs.String("mode", "solo", "solo|corporate")
	identity := fs.String("identity", "", "user identity JWT (corporate)")
	policy := fs.String("policy", "", "policy file (corporate)")
	timeout := fs.Duration("timeout", 60*time.Second, "give up after this long")
	var t engine.TransportOptions
	engine.AddTransportFlags(fs, &t)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	opts := []genadb.Option{genadb.WithRelayURL(*relay), genadb.WithStateDir(*state),
		genadb.WithTransportOptions(genadb.TransportOptions(t)), genadb.WithADBPath(*adb)}
	if *mode == "corporate" || *identity != "" {
		opts = append(opts, genadb.WithCorporateToken(strings.TrimSpace(*identity), *policy))
	}
	c, err := genadb.New(opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, prog+":", err)
		return 1
	}
	defer c.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	res, err := c.PairADB(ctx, genadb.PairADBRequest{DeviceID: *device, PairingPort: *port, PairingCode: *code})
	if err != nil {
		engine.StdoutEvents("error", map[string]any{"reason": err.Error()})
		fmt.Fprintln(os.Stderr, prog+":", err)
		return 1
	}
	engine.StdoutEvents("adb_paired", map[string]any{"device_id": res.DeviceID, "transport": res.Transport})
	return 0
}
