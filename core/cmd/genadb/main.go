// Command genadb is the New-GenADB command-line tool: the rendezvous relay,
// the phone-side device agent, the desktop-side connect agent, diagnostics
// and audit reporting in one binary.
package main

import (
	"os"

	"github.com/sumukhak/new-genadb/core/internal/engine"
)

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "audit":
			os.Exit(cmdAudit(os.Args[2:]))
		case "doctor":
			os.Exit(cmdDoctor(os.Args[2:]))
		case "version", "--version":
			os.Stdout.WriteString(engine.Version + "\n")
			os.Exit(0)
		}
	}
	os.Exit(engine.CLI(os.Args[1:]))
}
