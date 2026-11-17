package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// specSection returns the text of a section of API_SPEC.md.
func specSection(t *testing.T, heading string) string {
	t.Helper()
	b, err := os.ReadFile("../../../../API_SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, heading)
	if i < 0 {
		t.Fatalf("API_SPEC.md has no %q", heading)
	}
	s = s[i+len(heading):]
	if j := strings.Index(s, "\n### "); j >= 0 {
		s = s[:j]
	}
	return s
}

func fence(t *testing.T, section, lang string) string {
	t.Helper()
	m := regexp.MustCompile("(?s)```" + lang + "\n(.*?)```").FindStringSubmatch(section)
	if m == nil {
		t.Fatalf("no ```%s block", lang)
	}
	return m[1]
}

// kind is the JSON kind of a value: object, array, string, number, bool.
func kind(v any) string {
	switch v.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case float64, json.Number:
		return "number"
	case bool:
		return "bool"
	}
	return "null"
}

// jsonPaths flattens a decoded JSON document to path -> kind. Array
// elements share the path "<array>[]".
func jsonPaths(prefix string, v any, out map[string]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			p := prefix + "." + k
			out[p] = kind(c)
			if p == ".events" { // raw records: free-form
				continue
			}
			jsonPaths(p, c, out)
		}
	case []any:
		for _, c := range x {
			out[prefix+"[]"] = kind(c)
			jsonPaths(prefix+"[]", c, out)
		}
	}
}

// typePaths flattens a Go type the same way, from its json tags.
func typePaths(prefix string, t reflect.Type, out map[string]string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "-" || !f.IsExported() {
				continue
			}
			if name == "" {
				name = f.Name
			}
			p := prefix + "." + name
			out[p] = goKind(f.Type)
			if p == ".events" {
				continue
			}
			typePaths(p, f.Type, out)
		}
	case reflect.Slice:
		out[prefix+"[]"] = goKind(t.Elem())
		typePaths(prefix+"[]", t.Elem(), out)
	}
}

func goKind(t reflect.Type) string {
	switch t.Kind() {
	case reflect.Struct, reflect.Map:
		return "object"
	case reflect.Slice:
		return "array"
	case reflect.String:
		return "string"
	case reflect.Int, reflect.Int64, reflect.Int32, reflect.Float64:
		return "number"
	case reflect.Bool:
		return "bool"
	}
	return t.Kind().String()
}

func diff(a, b map[string]string) []string {
	var d []string
	for k, v := range a {
		if w, ok := b[k]; !ok {
			d = append(d, "only in spec: "+k)
		} else if v != w {
			d = append(d, k+": spec "+v+", code "+w)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			d = append(d, "only in code: "+k)
		}
	}
	sort.Strings(d)
	return d
}

// TestReportMatchesAPISpec keeps API_SPEC.md section 3.2 and the Report type
// identical, field for field and kind for kind, and checks that a real
// report never emits a field the spec does not document.
func TestReportMatchesAPISpec(t *testing.T) {
	sec := specSection(t, "### 3.2 Report (JSON)")
	var example any
	if err := json.Unmarshal([]byte(fence(t, sec, "json")), &example); err != nil {
		t.Fatalf("spec example is not valid JSON: %v", err)
	}
	spec := map[string]string{}
	jsonPaths("", example, spec)
	code := map[string]string{}
	typePaths("", reflect.TypeOf(Report{}), code)
	if d := diff(spec, code); len(d) > 0 {
		t.Fatalf("API_SPEC 3.2 and audit.Report disagree:\n  %s", strings.Join(d, "\n  "))
	}

	// A real report over every record type emits only documented fields.
	evs := sampleLog(t)
	var buf bytes.Buffer
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := Export(&buf, evs, FormatJSON, Options{Since: since, Until: since.Add(24 * time.Hour), IncludeEvents: true, Source: "audit.jsonl"}); err != nil {
		t.Fatal(err)
	}
	var got any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	jsonPaths("", got, out)
	for p, k := range out {
		if sk, ok := spec[p]; !ok || sk != k {
			t.Errorf("report emits %s (%s), spec has %q", p, k, sk)
		}
	}
	for _, must := range []string{".totals.users", ".totals.denials", ".by_op", ".since", ".first_event", ".sessions[].end_reason", ".denials[].reason"} {
		if _, ok := out[must]; !ok {
			t.Errorf("report lacks %s", must)
		}
	}
	m := got.(map[string]any)
	tot := m["totals"].(map[string]any)
	if tot["users"].(float64) != 1 || tot["devices"].(float64) != 1 || tot["denials"].(float64) != 1 || tot["revocations"].(float64) != 1 {
		t.Errorf("totals = %v", tot)
	}
}

// TestCSVHeaderMatchesAPISpec keeps the CSV columns and the spec identical.
func TestCSVHeaderMatchesAPISpec(t *testing.T) {
	want := strings.TrimSpace(fence(t, specSection(t, "### 3.2 Report (JSON)"), "csv"))
	if got := strings.Join(CSVColumns, ","); got != want {
		t.Fatalf("CSV header\n code: %s\n spec: %s", got, want)
	}
	var buf bytes.Buffer
	if err := Export(&buf, sampleLog(t), FormatCSV, Options{}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if lines[0] != want {
		t.Fatalf("exported header %q", lines[0])
	}
	if !strings.Contains(buf.String(), ",failed,") {
		t.Fatal("failed operations must be visible in CSV (result column)")
	}
}

// TestChainStatusMatchesAPISpec checks section 3.3's field list.
func TestChainStatusMatchesAPISpec(t *testing.T) {
	sec := specSection(t, "### 3.3 Chain status")
	m := regexp.MustCompile("`\\{([^}]*)\\}`").FindStringSubmatch(sec)
	if m == nil {
		t.Fatal("no field list in 3.3")
	}
	var spec []string
	for _, f := range strings.Split(m[1], ",") {
		spec = append(spec, strings.TrimSuffix(strings.TrimSpace(f), "?"))
	}
	code := map[string]string{}
	typePaths("", reflect.TypeOf(ChainStatus{}), code)
	var names []string
	for p := range code {
		names = append(names, strings.TrimPrefix(p, "."))
	}
	sort.Strings(spec)
	sort.Strings(names)
	if strings.Join(spec, ",") != strings.Join(names, ",") {
		t.Fatalf("3.3 lists %v, ChainStatus has %v", spec, names)
	}
}

func sampleLog(t *testing.T) []Event {
	t.Helper()
	c := NewChain(0, "")
	raw := []Event{
		{"ts": "2026-01-01T08:00:00Z", "event": "session_start", "role": "desktop", "user": "alice", "token_id": "t1", "device": "dev-A", "session": "s1", "transport": "relay-wss"},
		{"ts": "2026-01-01T08:01:00Z", "event": "adb_op", "role": "desktop", "user": "alice", "device": "dev-A", "session": "s1", "op": "push", "path": "/sdcard/a", "sha256": "ab", "bytes_up": 10, "bytes_down": 0, "duration_ms": 5},
		{"ts": "2026-01-01T08:02:00Z", "event": "adb_op", "role": "desktop", "user": "alice", "device": "dev-A", "session": "s1", "op": "shell", "command": "=cmd", "bytes_up": 1, "bytes_down": 2, "duration_ms": 1, "result": "failed"},
		{"ts": "2026-01-01T08:03:00Z", "event": "session_end", "role": "desktop", "user": "alice", "device": "dev-A", "session": "s1", "transport": "relay-wss", "bytes_up": 11, "bytes_down": 2, "duration_ms": 180000, "reason": "closed"},
		{"ts": "2026-01-01T09:00:00Z", "event": "denied", "role": "relay", "user": "alice", "device": "dev-A", "reason": "no grant for device"},
		{"ts": "2026-01-01T10:00:00Z", "event": "revoked", "role": "relay", "user": "alice", "device": "dev-A"},
	}
	var out []Event
	for _, e := range raw {
		s, err := c.Seal(e)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}
