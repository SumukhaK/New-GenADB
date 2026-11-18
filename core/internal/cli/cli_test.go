package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sumukhak/new-genadb/core/internal/engine"
)

// setu and genadb are the same command under two names.
func TestBothNamesRunTheSameCommands(t *testing.T) {
	for _, name := range []string{"setu", "genadb"} {
		if code := Main(name, []string{"version"}); code != 0 {
			t.Fatalf("%s version: exit %d", name, code)
		}
		if prog != name {
			t.Fatalf("messages would name %q, want %q", prog, name)
		}
		dir := t.TempDir()
		if code := Main(name, []string{"keygen", "--state", dir}); code != 0 {
			t.Fatalf("%s keygen: exit %d", name, code)
		}
		if _, err := os.Stat(filepath.Join(dir, "identity.key")); err != nil {
			t.Fatalf("%s keygen wrote no key: %v", name, err)
		}
		if code := Main(name, []string{"audit", "verify", "--log", filepath.Join(dir, "none.jsonl")}); code == 0 {
			t.Fatalf("%s audit verify of a missing log must fail", name)
		}
	}
	if engine.Version != "1.1.0" {
		t.Fatalf("version %s", engine.Version)
	}
}
