package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeLog(t *testing.T, path string, evs ...Event) {
	t.Helper()
	s, err := OpenFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if err := s.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
}

func sample() []Event {
	return []Event{
		{"event": "session_start", "user": "alice", "token_id": "j1", "device": "dev-A", "session": "s1", "transport": "relay-wss"},
		{"event": "adb_op", "user": "alice", "device": "dev-A", "session": "s1", "op": "push", "path": "/sdcard/a.bin", "bytes_up": 1048576, "bytes_down": 40, "duration_ms": 120, "sha256": strings.Repeat("ab", 32)},
		{"event": "adb_op", "user": "alice", "device": "dev-A", "session": "s1", "op": "shell", "command": "=cmd", "bytes_up": 10, "bytes_down": 200, "duration_ms": 5},
		{"event": "denied", "user": "bob", "device": "dev-A", "reason": "no grant for device"},
		{"event": "session_end", "user": "alice", "device": "dev-A", "session": "s1", "reason": "revoked"},
		{"event": "revoked", "user": "alice"},
	}
}

func TestChainVerifiesAndResumes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	ev := sample()
	writeLog(t, p, ev[:3]...)
	writeLog(t, p, ev[3:]...) // reopen: chain must continue
	got, err := ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	st := Verify(got)
	if !st.Valid || st.Records != 6 {
		t.Fatalf("chain: %+v", st)
	}
	if got[0]["prev_event_hash"] != GenesisHash {
		t.Fatalf("first record should link to genesis")
	}
	if s, _ := got[5]["seq"].(json.Number); s.String() != "6" {
		t.Fatalf("seq should continue across reopen, got %v", got[5]["seq"])
	}
}

func TestTamperDetected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	writeLog(t, p, sample()...)
	raw, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	cases := map[string][]string{
		"edit":    append(append([]string{}, lines[:1]...), append([]string{strings.Replace(lines[1], "1048576", "1048577", 1)}, lines[2:]...)...),
		"delete":  append(append([]string{}, lines[:2]...), lines[3:]...),
		"reorder": append([]string{lines[0], lines[2], lines[1]}, lines[3:]...),
	}
	for name, ls := range cases {
		ev, _ := Read(strings.NewReader(strings.Join(ls, "\n")))
		if st := Verify(ev); st.Valid {
			t.Errorf("%s: tampering not detected", name)
		}
	}
}

func TestReports(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	writeLog(t, p, sample()...)
	ev, _ := ReadFile(p)
	r := Build(ev, Options{})
	if !r.Chain.Valid || r.Totals.Operations != 2 || r.Totals.Denials != 1 || r.Totals.Sessions != 1 || r.Totals.BytesUp != 1048586 {
		t.Fatalf("totals: %+v chain %+v", r.Totals, r.Chain)
	}
	if len(r.Sessions) != 1 || r.Sessions[0].Operations != 2 || r.Sessions[0].Transport != "relay-wss" || r.Sessions[0].EndReason != "revoked" {
		t.Fatalf("sessions: %+v", r.Sessions)
	}
	for _, f := range []Format{FormatJSON, FormatCSV, FormatHTML} {
		var b bytes.Buffer
		if err := Export(&b, ev, f, Options{Source: "<script>x</script>"}); err != nil {
			t.Fatal(f, err)
		}
		out := b.String()
		switch f {
		case FormatJSON:
			var back Report
			if json.Unmarshal(b.Bytes(), &back) != nil || back.Totals.Operations != 2 {
				t.Fatalf("json report does not round-trip")
			}
		case FormatCSV:
			if n := strings.Count(out, "\n"); n != 7 {
				t.Fatalf("csv rows = %d, want header + 6", n)
			}
			if !strings.Contains(out, ",'=cmd,") {
				t.Fatalf("csv formula injection not neutralised: %s", out)
			}
		case FormatHTML:
			if strings.Contains(out, "<script>x") || !strings.Contains(out, "hash chain intact") {
				t.Fatalf("html report not escaped or missing integrity line")
			}
		}
	}
	if _, err := ParseFormat("pdf"); err == nil {
		t.Fatal("unknown format accepted")
	}
}

func TestWebhookSigned(t *testing.T) {
	secret := []byte("s3cret")
	var mu sync.Mutex
	var got []Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !VerifySignature(secret, r.Header.Get("X-GenADB-Timestamp"), r.Header.Get("X-GenADB-Signature"), body) {
			http.Error(w, "bad signature", 401)
			return
		}
		var e Event
		json.Unmarshal(body, &e)
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
	}))
	defer srv.Close()
	s, err := NewWebhookSink(srv.URL, secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range sample() {
		s.Write(e)
	}
	s.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 6 || got[0]["event"] != "session_start" {
		t.Fatalf("webhook received %d events", len(got))
	}
	if VerifySignature([]byte("wrong"), "1", Sign(secret, 1, []byte("x")), []byte("x")) {
		t.Fatal("signature accepted with the wrong secret")
	}
	if _, err := NewWebhookSink(srv.URL, nil, nil); err == nil {
		t.Fatal("webhook without secret accepted")
	}
}

func TestSinceFilter(t *testing.T) {
	ev := []Event{{"event": "denied", "ts": "2026-01-01T00:00:00Z"}, {"event": "denied", "ts": "2026-06-01T00:00:00Z"}}
	r := Build(ev, Options{Since: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)})
	if r.Totals.Denials != 1 {
		t.Fatalf("since filter: %+v", r.Totals)
	}
}

// Windows: a log held open by a writer must not block rotation, renaming
// the archive away, or deleting the directory (the v1.1.0 Windows fix; on
// Unix this always held). The writer follows the rotation to the new file.
func TestOpenWriterDoesNotBlockRenameOrDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	w, err := OpenFileWith(path, FileOptions{AnchorKey: []byte("k")})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.Write(Event{"event": "one"}); err != nil {
		t.Fatal(err)
	}
	// Rotate while w still holds the log open.
	archive := filepath.Join(dir, "audit-1.jsonl")
	if err := RotateFile(path, archive, FileOptions{AnchorKey: []byte("k")}); err != nil {
		t.Fatalf("rotate with an open writer: %v", err)
	}
	if err := w.Write(Event{"event": "two"}); err != nil {
		t.Fatalf("write after rotation: %v", err)
	}
	evs, err := ReadFile(path)
	if err != nil || len(evs) != 1 || evs[0]["event"] != "two" || seqOf(evs[0]) != 2 {
		t.Fatalf("new log %v %v", evs, err)
	}
	// RotateFile released its handle on the archive: it can be moved away.
	moved := filepath.Join(dir, "moved.jsonl")
	if err := os.Rename(archive, moved); err != nil {
		t.Fatalf("archive still held open: %v", err)
	}
	// The live log can be deleted while w still has it open.
	if err := os.Remove(path); err != nil {
		t.Fatalf("delete of an open log: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := w.Write(Event{"event": "late"}); err == nil {
		t.Fatal("write after Close succeeded")
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}
