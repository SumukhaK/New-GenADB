package notices

import (
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite THIRD_PARTY_NOTICES.txt")

// known maps each module the binaries link to its licence files. A new
// dependency fails TestThirdPartyNotices until it is added here (and its
// licence is permissive, see CONTRIBUTING.md).
var known = map[string]struct {
	url, license string
	files        []string
}{
	"filippo.io/edwards25519":    {"https://github.com/FiloSottile/edwards25519", "BSD-3-Clause", []string{"LICENSE"}},
	"github.com/coder/websocket": {"https://github.com/coder/websocket", "ISC", []string{"LICENSE.txt"}},
	"golang.org/x/net":           {"https://go.googlesource.com/net", "BSD-3-Clause", []string{"LICENSE", "PATENTS"}},
}

func goCmd(t *testing.T, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = "../.."
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("go %v: %v (needs the module cache)", args, err)
	}
	return out
}

func components(t *testing.T) []Component {
	out := goCmd(t, "list", "-deps", "-json=Module", "./cmd/...")
	dec := json.NewDecoder(strings.NewReader(string(out)))
	dirs := map[string]string{}
	for dec.More() {
		var p struct {
			Module *struct {
				Path, Dir string
				Main      bool
			}
		}
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		if p.Module != nil && !p.Module.Main {
			dirs[p.Module.Path] = p.Module.Dir
		}
	}
	var mods []string
	for m := range dirs {
		mods = append(mods, m)
	}
	sort.Strings(mods)
	cs := []Component{{Name: "Go standard library and runtime", URL: "https://go.dev", License: "BSD-3-Clause",
		Dir: runtime.GOROOT(), Files: []string{"LICENSE", "PATENTS"}}}
	for _, m := range mods {
		k, ok := known[m]
		if !ok {
			t.Fatalf("binaries now link %s: add it (and its licence files) to notices_test.go", m)
		}
		if dirs[m] == "" {
			t.Skipf("%s is not in the module cache", m)
		}
		cs = append(cs, Component{Name: m, URL: k.url, License: k.license, Dir: dirs[m], Files: k.files})
	}
	return cs
}

// TestThirdPartyNotices fails when THIRD_PARTY_NOTICES.txt does not match
// the licence texts of what the binaries actually link (issue #6). Run with
// -update to regenerate it.
func TestThirdPartyNotices(t *testing.T) {
	want, err := Render(components(t))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "..", "THIRD_PARTY_NOTICES.txt")
	if *update {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (generate it with: go test ./internal/notices -update)", err)
	}
	if string(got) != want {
		t.Fatal("THIRD_PARTY_NOTICES.txt is out of date: go test ./internal/notices -update")
	}
}
