package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/sumukhak/new-genadb/core/internal/engine"
)

// cmdPolicy runs `setu policy scope`: it prints the organisation policy
// reduced to one device's grants, the document to push to that phone
// through MDM (managed configuration key policy_json).
func cmdPolicy(args []string) int {
	if len(args) < 1 || args[0] != "scope" {
		fmt.Fprintf(os.Stderr, "usage: %s policy scope --policy org-policy.json --device <id> [--out file]\n", prog)
		return 2
	}
	fs := flag.NewFlagSet("policy scope", flag.ContinueOnError)
	in := fs.String("policy", "", "organisation policy file")
	device := fs.String("device", "", "device id (the enrollment token's subject)")
	out := fs.String("out", "", "write here instead of stdout (mode 0600)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, prog+":", err)
		return 1
	}
	b, err := engine.ScopePolicy(raw, *device)
	if err != nil {
		fmt.Fprintln(os.Stderr, prog+":", err)
		return 1
	}
	b = append(b, '\n')
	if *out == "" {
		os.Stdout.Write(b)
		return 0
	}
	if err := os.WriteFile(*out, b, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, prog+":", err)
		return 1
	}
	return 0
}
