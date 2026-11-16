// Command genadb is the New-GenADB connectivity core: one binary that acts as
// the rendezvous relay, the phone-side device agent and the desktop-side
// connect agent (CLI). See remote_adb_research_findings.md section 16.
//
// BASELINE (iteration 0): deliberately simple. Plain TCP to the relay, one
// relay connection per adb TCP connection, pairing code sent in clear,
// no end-to-end encryption and no corporate policy enforcement.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: genadb <keygen|relay|device|connect> [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "relay":
		err = cmdRelay(os.Args[2:])
	case "device":
		err = cmdDevice(os.Args[2:])
	case "connect":
		err = cmdConnect(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		emit("error", map[string]any{"reason": err.Error()})
		fmt.Fprintln(os.Stderr, "genadb:", err)
		os.Exit(1)
	}
}
