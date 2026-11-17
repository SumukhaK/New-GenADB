package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sumukhak/new-genadb/core/pkg/genadb/audit"
)

// Issue #7: the CLI wrote no audit log in corporate mode unless --audit was
// passed, although the README promises corporate agents always log.
func TestCorporateCLIAuditDefaults(t *testing.T) {
	cases := []struct {
		flag      string
		corporate bool
		want      string
		wantErr   bool
	}{
		{"", false, "", false},               // solo: off unless asked
		{"x.jsonl", false, "x.jsonl", false}, // solo: on when asked
		{"off", false, "", false},
		{"", true, "def.jsonl", false},      // corporate: on by default
		{"x.jsonl", true, "x.jsonl", false}, // corporate: path can move
		{"off", true, "", true},             // corporate: cannot opt out
		{"none", true, "", true},
	}
	for _, c := range cases {
		got, err := resolveAuditPath(c.flag, c.corporate, "def.jsonl")
		if got != c.want || (err != nil) != c.wantErr {
			t.Errorf("resolveAuditPath(%q, corporate=%v) = %q, %v", c.flag, c.corporate, got, err)
		}
	}
}

func TestCorporateConnectWritesAuditLogWithoutFlag(t *testing.T) {
	dir := t.TempDir()
	base := []string{"--relay", "127.0.0.1:1", "--state", dir, "--mode", "corporate", "--device", "dev-A",
		"--identity", "header.payload.sig", "--listen", "127.0.0.1:0"}

	err := cliConnect(context.Background(), append(base, "--audit", "off"))
	if err == nil || !strings.Contains(err.Error(), "always keeps an audit log") {
		t.Fatalf("corporate --audit off must be refused, got %v", err)
	}

	// No --audit: the log and its anchor appear under the state directory
	// before the agent even reaches the (unreachable) relay.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	cliConnect(ctx, base)
	log := filepath.Join(dir, "audit.jsonl")
	if _, err := os.Stat(log); err != nil {
		t.Fatalf("corporate connect wrote no audit log: %v", err)
	}
	if _, err := os.Stat(audit.AnchorPath(log)); err != nil {
		t.Fatalf("corporate connect wrote no anchor: %v", err)
	}
	if st, err := audit.VerifyFile(log, audit.VerifyOptions{}); err != nil || !st.Valid {
		t.Fatalf("verify: %+v %v", st, err)
	}

	// Solo without --audit still writes nothing.
	solo := t.TempDir()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	cliConnect(ctx2, []string{"--relay", "127.0.0.1:1", "--state", solo, "--device", "x", "--listen", "127.0.0.1:0"})
	if _, err := os.Stat(filepath.Join(solo, "audit.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("solo connect must not log by default: %v", err)
	}
}
