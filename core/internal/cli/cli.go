// Package cli implements the setu command (and its pre-1.0.1 name, genadb):
// the rendezvous relay, the phone-side device agent, the desktop-side
// connect agent, diagnostics and audit reporting in one binary.
package cli

import (
	"fmt"

	"github.com/sumukhak/new-genadb/core/internal/engine"
)

// prog is the name the binary was invoked as, for usage and messages.
var prog = "setu"

// Main runs the command and returns the process exit code. name is the
// command's own name ("setu" or "genadb"); both accept the same subcommands,
// flags and output.
func Main(name string, args []string) int {
	prog = name
	if len(args) >= 1 {
		switch args[0] {
		case "audit":
			return cmdAudit(args[1:])
		case "doctor":
			return cmdDoctor(args[1:])
		case "adb-pair":
			return cmdADBPair(args[1:])
		case "policy":
			return cmdPolicy(args[1:])
		case "version", "--version":
			fmt.Println(engine.Version)
			return 0
		case "help", "-h", "--help":
			fmt.Printf("usage: %s <relay|device|connect|adb-pair|policy|keygen|doctor|audit|version> [flags]\n", prog)
			return 0
		}
	}
	return engine.CLI(args)
}
