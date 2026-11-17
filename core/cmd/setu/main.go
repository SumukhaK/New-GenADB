// Command setu is the Setu command-line tool: the rendezvous relay, the
// phone-side device agent, the desktop-side connect agent, diagnostics and
// audit reporting in one binary.
package main

import (
	"os"

	"github.com/sumukhak/new-genadb/core/internal/cli"
)

func main() { os.Exit(cli.Main("setu", os.Args[1:])) }
