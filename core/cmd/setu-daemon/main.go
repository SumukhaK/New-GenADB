// Command setu-daemon serves the Setu SDK over JSON-RPC 2.0 for IDE plugins and UIs.
// setu-daemon and genadb-daemon (its pre-1.0.1 name) are identical apart
// from their name. See API_SPEC.md section 2.
package main

import (
	"os"

	"github.com/sumukhak/new-genadb/core/internal/daemon"
)

func main() { os.Exit(daemon.Main("setu-daemon", os.Args[1:])) }
