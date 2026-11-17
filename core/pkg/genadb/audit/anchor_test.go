package audit

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeN(t *testing.T, s *FileSink, from, n int) {
	t.Helper()
	for i := from; i < from+n; i++ {
		if err := s.Write(Event{"event": "adb_op", "op": "shell", "n": i}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
}

func newLog(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := OpenFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	writeN(t, s, 0, n)
	s.Close()
	return path
}

func mustVerify(t *testing.T, path string) ChainStatus {
	t.Helper()
	st, err := VerifyFile(path, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func editLines(t *testing.T, path string, f func([]string) []string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	out := strings.Join(f(lines), "\n")
	if out != "" {
		out += "\n"
	}
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAnchoredLogVerifies(t *testing.T) {
	path := newLog(t, 5)
	st := mustVerify(t, path)
	if !st.Valid || st.Anchor != AnchorVerified || !st.StartsAtGenesis || st.FirstSeq != 1 || len(st.Warnings) != 0 {
		t.Fatalf("clean log: %+v", st)
	}
	if _, err := os.Stat(AnchorPath(path)); err != nil {
		t.Fatalf("no anchor written: %v", err)
	}
	if fi, err := os.Stat(DefaultAnchorKeyPath(path)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("anchor key: %v %v", fi, err)
	}
}

// Issue #8: removing the oldest records left a shorter chain that verified.
func TestDeletingOldestRecordsIsDetected(t *testing.T) {
	for _, drop := range []int{1, 3} {
		path := newLog(t, 6)
		// Without the anchor the shortened chain still verifies on its own.
		editLines(t, path, func(l []string) []string { return l[drop:] })
		evs, _ := ReadFile(path)
		if !Verify(evs).Valid {
			t.Fatal("precondition: the bare chain cannot see head truncation")
		}
		st := mustVerify(t, path)
		if st.Valid || !strings.Contains(st.Problem, "oldest records missing") {
			t.Fatalf("drop %d oldest: %+v", drop, st)
		}
		if _, err := OpenFile(path, false); !errors.Is(err, ErrAnchorMismatch) {
			t.Fatalf("a writer must refuse a truncated log, got %v", err)
		}
	}
}

func TestDeletingNewestRecordsIsDetected(t *testing.T) {
	path := newLog(t, 6)
	editLines(t, path, func(l []string) []string { return l[:4] })
	st := mustVerify(t, path)
	if st.Valid || !strings.Contains(st.Problem, "newest records missing") {
		t.Fatalf("tail truncation: %+v", st)
	}
}

func TestEmptiedOrDeletedLogIsDetected(t *testing.T) {
	path := newLog(t, 3)
	editLines(t, path, func([]string) []string { return nil })
	if st := mustVerify(t, path); st.Valid || !strings.Contains(st.Problem, "no records") {
		t.Fatalf("emptied log: %+v", st)
	}
	os.Remove(path)
	if st := mustVerify(t, path); st.Valid {
		t.Fatalf("deleted log with an anchor left behind: %+v", st)
	}
	if _, err := OpenFile(path, false); !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("recreating a deleted log must be refused, got %v", err)
	}
}

func TestForgedAnchorIsDetected(t *testing.T) {
	path := newLog(t, 6)
	// Truncate the head and rewrite the anchor to match, without the key.
	editLines(t, path, func(l []string) []string { return l[2:] })
	a, _ := ReadAnchor(AnchorPath(path))
	in, _ := scanLog(path, a.LastSeq)
	a.FirstSeq, a.FirstHash, a.FirstPrevHash = in.firstSeq, in.firstHash, in.firstPrev
	if err := writeAnchor(AnchorPath(path), a, []byte("not-the-key-not-the-key"), false); err != nil {
		t.Fatal(err)
	}
	st := mustVerify(t, path)
	if st.Valid || st.Anchor != AnchorInvalid {
		t.Fatalf("forged anchor accepted: %+v", st)
	}
	if _, err := OpenFile(path, false); !errors.Is(err, ErrAnchorSignature) {
		t.Fatalf("writer accepted a forged anchor: %v", err)
	}
}

func TestVerifyWithoutKeyStillChecksPositions(t *testing.T) {
	path := newLog(t, 4)
	os.Rename(DefaultAnchorKeyPath(path), DefaultAnchorKeyPath(path)+".elsewhere")
	st := mustVerify(t, path)
	if !st.Valid || st.Anchor != AnchorUnverified || len(st.Warnings) == 0 {
		t.Fatalf("no key: %+v", st)
	}
	editLines(t, path, func(l []string) []string { return l[1:] })
	if st := mustVerify(t, path); st.Valid {
		t.Fatalf("head truncation without the key: %+v", st)
	}
}

func TestUnanchoredLogWarnsWhenNotAtGenesis(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := OpenFileWith(path, FileOptions{NoAnchor: true})
	if err != nil {
		t.Fatal(err)
	}
	writeN(t, s, 0, 4)
	s.Close()
	if st := mustVerify(t, path); !st.Valid || st.Anchor != AnchorNone || len(st.Warnings) != 0 {
		t.Fatalf("unanchored genesis log: %+v", st)
	}
	editLines(t, path, func(l []string) []string { return l[2:] })
	st := mustVerify(t, path)
	if !st.Valid || st.StartsAtGenesis || st.FirstSeq != 3 || len(st.Warnings) != 1 {
		t.Fatalf("unanchored truncated log must verify with a warning: %+v", st)
	}
}

func TestLegacyLogIsAdoptedOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, _ := OpenFileWith(path, FileOptions{NoAnchor: true})
	writeN(t, s, 0, 3)
	s.Close()
	s, err := OpenFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	writeN(t, s, 3, 2)
	s.Close()
	if st := mustVerify(t, path); !st.Valid || st.Anchor != AnchorVerified || st.Records != 5 {
		t.Fatalf("adopted log: %+v", st)
	}
}

// Issue #8 (should-fix): a crash mid-write left a partial line that the next
// record was appended onto, corrupting both.
func TestPartialLastLineIsFinishedOnOpen(t *testing.T) {
	path := newLog(t, 2)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"seq":3,"event":"adb_op","prev_ev`)
	f.Close()
	s, err := OpenFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	writeN(t, s, 2, 1)
	s.Close()
	evs, _ := ReadFile(path)
	if len(evs) != 4 || evs[2]["event"] != "_unparseable" || evs[3]["event"] != "adb_op" {
		t.Fatalf("the new record must start on its own line: %v", evs)
	}
}

// Two writers on one log (two connect agents sharing a state directory) must
// keep one chain.
func TestConcurrentWritersKeepOneChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := OpenFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := OpenFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { writeN(t, a, 0, 50); close(done) }()
	writeN(t, b, 100, 50)
	<-done
	a.Close()
	b.Close()
	st := mustVerify(t, path)
	if !st.Valid || st.Records != 100 || st.Anchor != AnchorVerified {
		t.Fatalf("interleaved writers: %+v", st)
	}
}

func TestRotationContinuesTheChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	live, err := OpenFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	writeN(t, live, 0, 3)
	archive := filepath.Join(dir, "audit-2026-11.jsonl")
	if err := RotateFile(path, archive, FileOptions{}); err != nil {
		t.Fatal(err)
	}
	writeN(t, live, 3, 2) // the open writer follows the rotation
	live.Close()

	old := mustVerify(t, archive)
	if !old.Valid || old.Records != 3 || old.Anchor != AnchorVerified {
		t.Fatalf("archive: %+v", old)
	}
	cur := mustVerify(t, path)
	if !cur.Valid || cur.Records != 2 || cur.FirstSeq != 4 || cur.StartsAtGenesis || cur.Anchor != AnchorVerified || len(cur.Warnings) != 0 {
		t.Fatalf("rotated log: %+v", cur)
	}
	oldEvs, _ := ReadFile(archive)
	curEvs, _ := ReadFile(path)
	if curEvs[0]["prev_event_hash"] != oldEvs[2]["event_hash"] {
		t.Fatal("the new file must continue the archived chain")
	}
	// Dropping the first record of the rotated log is still caught.
	editLines(t, path, func(l []string) []string { return l[1:] })
	if st := mustVerify(t, path); st.Valid {
		t.Fatalf("head truncation after rotation: %+v", st)
	}
}

// Issue #8 (should-fix): Close waited for every retry (up to minutes) when
// the collector was down.
func TestWebhookCloseIsBounded(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(block)
	w, err := NewWebhookSink(srv.URL, []byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	w.CloseTimeout = 200 * time.Millisecond
	for i := 0; i < 3; i++ {
		w.Write(Event{"event": "adb_op", "n": i})
	}
	start := time.Now()
	w.Close()
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Close took %v with the collector hanging", d)
	}
	if _, failed := w.Stats(); failed != 3 {
		t.Fatalf("undelivered records must be counted as failed, got %d", failed)
	}
}
