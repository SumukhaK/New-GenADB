// Package notices keeps THIRD_PARTY_NOTICES.txt (at the repository root) in
// step with the code that the setu and genadb binaries, and libgenadb.so in
// the Android AAR, statically link. See notices_test.go.
package notices

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Component is one statically linked third-party component.
type Component struct {
	Name, URL, License string
	Dir                string   // where its licence files are
	Files              []string // licence files, in order
}

// Render builds the notices file from the components' licence files.
func Render(components []Component) (string, error) {
	var b strings.Builder
	b.WriteString(`Setu (Setu-SDK) third-party notices
===================================

The setu, setu-daemon, genadb and genadb-daemon binaries, and libgenadb.so
inside the setu-android AAR, are built from the Setu sources (Apache License
2.0, see LICENSE and NOTICE) and statically include the components below.
Their licences require these notices to accompany binary distributions.

Components:
`)
	for _, c := range components {
		fmt.Fprintf(&b, "  - %s (%s), %s\n", c.Name, c.URL, c.License)
	}
	for _, c := range components {
		rule := strings.Repeat("=", 78)
		fmt.Fprintf(&b, "\n%s\n%s (%s)\n%s\n", rule, c.Name, c.License, rule)
		for _, f := range c.Files {
			t, err := os.ReadFile(filepath.Join(c.Dir, f))
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "\n--- %s ---\n\n%s", f, strings.TrimRight(strings.ReplaceAll(string(t), "\r\n", "\n"), "\n")+"\n")
		}
	}
	return b.String(), nil
}
