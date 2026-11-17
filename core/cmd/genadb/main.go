// Command genadb is the pre-1.0.1 name of the setu command, kept so that
// existing scripts, IDE integrations and the evaluation harness keep working.
// Both binaries are identical apart from their name.
package main

import (
	"os"

	"github.com/sumukhak/new-genadb/core/internal/cli"
)

func main() { os.Exit(cli.Main("genadb", os.Args[1:])) }
