package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sumukhak/new-genadb/core/pkg/genadb/audit"
)

const auditUsage = `usage:
  genadb audit report [--log PATH | --state DIR] [--format json|csv|html] [--since T] [--until T] [--events] [--out FILE]
  genadb audit verify [--log PATH | --state DIR]

T is RFC 3339 (2026-01-02T15:04:05Z), a date (2026-01-02) or a duration ago (24h).`

func cmdAudit(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, auditUsage)
		return 2
	}
	var err error
	switch args[0] {
	case "report":
		err = auditReport(args[1:])
	case "verify":
		var ok bool
		ok, err = auditVerify(args[1:])
		if err == nil && !ok {
			return 1
		}
	case "-h", "--help", "help":
		fmt.Println(auditUsage)
		return 0
	default:
		err = fmt.Errorf("unknown audit command %q\n%s", args[0], auditUsage)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "genadb audit:", err)
		return 1
	}
	return 0
}

func logFlags(fs *flag.FlagSet) func() string {
	log := fs.String("log", "", "audit log (JSONL)")
	state := fs.String("state", ".", "state directory holding audit.jsonl (when --log is not given)")
	return func() string {
		if *log != "" {
			return *log
		}
		return filepath.Join(*state, "audit.jsonl")
	}
}

func parseWhen(s string, now time.Time) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return now.Add(-d), nil
	}
	for _, l := range []string{time.RFC3339Nano, "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.Parse(l, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse time %q", s)
}

func auditReport(args []string) error {
	fs := flag.NewFlagSet("audit report", flag.ContinueOnError)
	path := logFlags(fs)
	format := fs.String("format", "json", "json, csv or html")
	since := fs.String("since", "", "only records at or after this time")
	until := fs.String("until", "", "only records before this time")
	events := fs.Bool("events", false, "embed the raw records in a JSON report")
	out := fs.String("out", "", "write to FILE instead of stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	f, err := audit.ParseFormat(*format)
	if err != nil {
		return err
	}
	now := time.Now()
	var opt audit.Options
	if opt.Since, err = parseWhen(*since, now); err != nil {
		return err
	}
	if opt.Until, err = parseWhen(*until, now); err != nil {
		return err
	}
	opt.IncludeEvents, opt.Source = *events, path()
	evs, err := audit.ReadFile(path())
	if err != nil {
		return err
	}
	var w io.Writer = os.Stdout
	if *out != "" {
		file, err := os.OpenFile(*out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		w = file
	}
	return audit.Export(w, evs, f, opt)
}

func auditVerify(args []string) (bool, error) {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	path := logFlags(fs)
	if err := fs.Parse(args); err != nil {
		return false, err
	}
	evs, err := audit.ReadFile(path())
	if err != nil {
		return false, err
	}
	st := audit.Verify(evs)
	b, _ := json.MarshalIndent(st, "", "  ")
	fmt.Println(string(b))
	return st.Valid, nil
}
