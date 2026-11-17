// Package audit records tamper-evident session and operation events and
// turns them into admin reports.
//
// Every record is one JSON object per line (JSONL). Records are hash-chained:
// each carries the SHA-256 of the previous record ("prev_event_hash") and its
// own hash ("event_hash"), computed over the record's canonical JSON without
// the event_hash field. Editing, inserting, deleting or reordering any line
// breaks the chain, which Verify reports.
//
// Records never contain credentials, pairing codes or file contents. Callers
// pass identifiers (token IDs, device IDs), sizes, durations and content
// hashes only.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// GenesisHash is the prev_event_hash of the first record in a chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Event is one audit record. Well-known keys:
//
//	ts, seq, event, prev_event_hash, event_hash      (set by the chain)
//	user, token_id, device, session, role, reason    (who / why)
//	transport ("lan" | "relay-tcp" | "relay-ws" | "relay-wss")
//	op ("shell" | "exec" | "push" | "pull" | "install" | "forward" | "reverse" | "screencap" | "debug" | "other")
//	path, command, bytes_up, bytes_down, duration_ms, sha256
type Event map[string]any

// Sink receives audit events. Implementations must be safe for concurrent use.
type Sink interface {
	Write(e Event) error
	Close() error
}

// Chain stamps events with sequence numbers and hash links. It is safe for
// concurrent use; events are linked in the order Seal is called.
type Chain struct {
	mu   sync.Mutex
	seq  int64
	prev string
}

// NewChain starts a chain after the given record (or at genesis when prev is "").
func NewChain(lastSeq int64, prevHash string) *Chain {
	if prevHash == "" {
		prevHash = GenesisHash
	}
	return &Chain{seq: lastSeq, prev: prevHash}
}

// Seal returns a copy of e with ts (if missing), seq, prev_event_hash and
// event_hash set, and advances the chain.
func (c *Chain) Seal(e Event) (Event, error) {
	out := make(Event, len(e)+4)
	for k, v := range e {
		out[k] = v
	}
	if _, ok := out["ts"]; !ok {
		out["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out["seq"] = c.seq + 1
	out["prev_event_hash"] = c.prev
	delete(out, "event_hash")
	h, err := hashEvent(out)
	if err != nil {
		return nil, err
	}
	out["event_hash"] = h
	c.seq++
	c.prev = h
	return out, nil
}

// hashEvent hashes the canonical JSON encoding (sorted keys, no event_hash).
func hashEvent(e Event) (string, error) {
	m := make(map[string]any, len(e))
	for k, v := range e {
		if k != "event_hash" {
			m[k] = v
		}
	}
	b, err := canonicalJSON(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// canonicalJSON re-decodes through json.Number so that values hash the same
// whether they were produced in memory or read back from disk.
func canonicalJSON(m map[string]any) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// FileSink appends hash-chained records to a JSONL file, continuing an
// existing chain if the file already has records, and keeps the log's signed
// anchor (see Anchor) up to date.
//
// Several processes may append to one log: each record is written under an
// exclusive file lock (on Unix), and a writer that finds the file grown by
// someone else, or rotated by RotateFile, re-reads the tail and continues
// the chain from there.
type FileSink struct {
	mu         sync.Mutex
	f          *os.File
	path       string
	chain      *Chain
	sync       bool
	tees       []Sink
	anchorPath string // "" when anchoring is off
	key        []byte
	anchor     *Anchor
	size       int64 // file size after our last write or refresh
}

// FileOptions configures OpenFileWith.
type FileOptions struct {
	// Sync fsyncs every record (and its anchor) before Write returns.
	Sync bool
	// AnchorKey signs the anchor. When nil, the key is read from
	// AnchorKeyFile, which is created with a random key if missing.
	AnchorKey []byte
	// AnchorKeyFile defaults to DefaultAnchorKeyPath(path). Keep it on a
	// different volume from the log for stronger protection.
	AnchorKeyFile string
	// NoAnchor turns the anchor off (the chain alone then cannot reveal
	// records deleted from either end of the log).
	NoAnchor bool
}

// Tee forwards every record, after it is sealed and written, to the given
// sinks (webhooks, SIEM forwarders), so they see the same seq and hashes as
// the file. Call it before the first Write. Tees run while the record is
// being written, which may be on an ADB data path: they must not block
// (the built-in webhook sink and the SDK's event tap only enqueue).
func (s *FileSink) Tee(sinks ...Sink) { s.tees = append(s.tees, sinks...) }

// OpenFile opens (or creates) a chained, anchored audit log with the default
// anchor key. With syncEach, every record is fsynced before Write returns.
func OpenFile(path string, syncEach bool) (*FileSink, error) {
	return OpenFileWith(path, FileOptions{Sync: syncEach})
}

// OpenFileWith opens (or creates) a chained audit log. It refuses a log that
// no longer matches its anchor (ErrAnchorMismatch) or whose anchor fails its
// signature check (ErrAnchorSignature): appending would bury the evidence.
// A log without an anchor (new, or written by an older version) is anchored
// from its current first and last records.
func OpenFileWith(path string, opt FileOptions) (*FileSink, error) {
	s := &FileSink{path: path, sync: opt.Sync}
	if !opt.NoAnchor {
		s.anchorPath, s.key = AnchorPath(path), opt.AnchorKey
		if s.key == nil {
			kp := opt.AnchorKeyFile
			if kp == "" {
				kp = DefaultAnchorKeyPath(path)
			}
			k, err := LoadOrCreateAnchorKey(kp)
			if err != nil {
				return nil, err
			}
			s.key = k
		}
	}
	if err := s.open(); err != nil {
		return nil, err
	}
	return s, nil
}

// open opens s.path and loads its state under the file lock.
func (s *FileSink) open() error {
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return err
	}
	defer unlockFile(f)
	old := s.f
	s.f = f
	if err := s.refresh(); err != nil {
		s.f = old
		f.Close()
		return err
	}
	if old != nil {
		old.Close()
	}
	return nil
}

// refresh re-reads the log's tail and anchor. The caller holds the file lock.
func (s *FileSink) refresh() error {
	st, err := s.f.Stat()
	if err != nil {
		return err
	}
	size := st.Size()
	if size > 0 {
		// A writer that crashed mid-record leaves a partial last line;
		// finish it so the next record starts on a line of its own.
		last := make([]byte, 1)
		if _, err := s.f.ReadAt(last, size-1); err != nil {
			return err
		}
		if last[0] != '\n' {
			if _, err := s.f.Write([]byte{'\n'}); err != nil {
				return err
			}
			size++
		}
	}
	var a *Anchor
	if s.anchorPath != "" {
		if a, err = ReadAnchor(s.anchorPath); err != nil {
			return err
		}
		if a != nil && !a.Valid(s.key) {
			return fmt.Errorf("%w: %s", ErrAnchorSignature, s.anchorPath)
		}
	}
	var want int64
	if a != nil {
		want = a.LastSeq
	}
	in, err := scanLog(s.path, want)
	if err != nil {
		return err
	}
	if s.anchorPath != "" {
		if a == nil {
			a = &Anchor{FirstPrevHash: GenesisHash, LastHash: GenesisHash}
			if in.records > 0 {
				a = &Anchor{FirstSeq: in.firstSeq, FirstPrevHash: in.firstPrev, FirstHash: in.firstHash,
					LastSeq: in.lastSeq, LastHash: in.lastHash}
			}
			if err := writeAnchor(s.anchorPath, a, s.key, s.sync); err != nil {
				return err
			}
		} else if err := a.check(in); err != nil {
			return fmt.Errorf("%w (%s); preserve both files for investigation, or rotate them away to start a new log", err, s.path)
		}
	}
	switch {
	case in.records > 0:
		s.chain = NewChain(in.lastSeq, in.lastHash)
	case a != nil:
		s.chain = NewChain(a.LastSeq, a.LastHash)
	default:
		s.chain = NewChain(0, "")
	}
	s.anchor, s.size = a, size
	return nil
}

// catchUp re-reads state if another writer changed the log since our last
// write, or reopens it if it was rotated. The caller holds s.mu and the
// file lock on s.f, and must re-lock if this returns rotated == true.
func (s *FileSink) catchUp() (rotated bool, err error) {
	cur, err := os.Stat(s.path)
	if err == nil {
		mine, err := s.f.Stat()
		if err != nil {
			return false, err
		}
		if !os.SameFile(cur, mine) {
			return true, nil
		}
		if mine.Size() != s.size {
			return false, s.refresh()
		}
		return false, nil
	}
	if os.IsNotExist(err) {
		return true, nil
	}
	return false, err
}

func (s *FileSink) Write(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for tries := 0; ; tries++ {
		if err := lockFile(s.f); err != nil {
			return err
		}
		rotated, err := s.catchUp()
		if err == nil && !rotated {
			break
		}
		unlockFile(s.f)
		if err != nil {
			return err
		}
		if tries == 3 {
			return errorf("%s keeps changing underneath the writer", s.path)
		}
		if err := s.open(); err != nil { // rotated: continue in the new file
			return err
		}
	}
	defer unlockFile(s.f)
	sealed, err := s.chain.Seal(e)
	if err != nil {
		return err
	}
	b, err := json.Marshal(sealed)
	if err != nil {
		return err
	}
	n, err := s.f.Write(append(b, '\n'))
	s.size += int64(n)
	if err != nil {
		return err
	}
	if s.sync {
		if err := s.f.Sync(); err != nil {
			return err
		}
	}
	if a := s.anchor; a != nil {
		seq, hash := seqOf(sealed), sealed["event_hash"].(string)
		if a.FirstSeq == 0 {
			a.FirstSeq, a.FirstPrevHash, a.FirstHash = seq, sealed["prev_event_hash"].(string), hash
		}
		a.LastSeq, a.LastHash = seq, hash
		if err := writeAnchor(s.anchorPath, a, s.key, s.sync); err != nil {
			return err
		}
	}
	for _, t := range s.tees {
		t.Write(sealed)
	}
	return nil
}

// Close closes the file and every tee.
func (s *FileSink) Close() error {
	s.mu.Lock()
	err := s.f.Close()
	s.mu.Unlock()
	for _, t := range s.tees {
		t.Close()
	}
	return err
}

// MultiSink writes to every sink; the first error is returned after all
// sinks have been tried.
type MultiSink []Sink

func (m MultiSink) Write(e Event) error {
	var first error
	for _, s := range m {
		if err := s.Write(e); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (m MultiSink) Close() error {
	var first error
	for _, s := range m {
		if err := s.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Discard drops every event (solo mode default).
type Discard struct{}

func (Discard) Write(Event) error { return nil }
func (Discard) Close() error      { return nil }

// Read parses a JSONL audit log. Lines that are not JSON objects are kept as
// gaps so that Verify can report them.
func Read(r io.Reader) ([]Event, error) {
	var out []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		d := json.NewDecoder(bytes.NewReader(line))
		d.UseNumber()
		var e Event
		if err := d.Decode(&e); err != nil {
			out = append(out, Event{"event": "_unparseable"})
			continue
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// ReadFile reads a JSONL audit log from disk.
func ReadFile(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f)
}

// ChainStatus is the result of verifying a log.
type ChainStatus struct {
	Valid     bool   `json:"valid"`
	Records   int    `json:"records"`
	BrokenAt  int    `json:"broken_at,omitempty"` // 1-based record index of the first bad record
	Problem   string `json:"problem,omitempty"`
	LastHash  string `json:"last_hash,omitempty"`
	Unchained int    `json:"unchained,omitempty"` // records written without a chain (legacy)
	// FirstSeq is the seq of the oldest chained record, and StartsAtGenesis
	// whether it links to GenesisHash. A log that does not start at genesis
	// was rotated, or lost its oldest records; only an anchor tells which.
	FirstSeq        int64 `json:"first_seq,omitempty"`
	StartsAtGenesis bool  `json:"starts_at_genesis"`
	// Anchor is set by VerifyFile: verified, unverified (no key), invalid or none.
	Anchor   string   `json:"anchor,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// Verify checks every link in the chain. Records without event_hash (written
// by older versions) are counted but make the log invalid only if they occur
// after chained records.
//
// The first chained record may link to any hash, so that rotated logs
// verify; the chain therefore cannot show that records are missing from
// either end. VerifyFile adds that check using the log's anchor.
func Verify(events []Event) ChainStatus {
	st := ChainStatus{Valid: true, Records: len(events)}
	prev := ""
	for i, e := range events {
		h, _ := e["event_hash"].(string)
		if h == "" {
			if prev != "" {
				return st.broken(i, "record without a hash inside the chain")
			}
			st.Unchained++
			continue
		}
		p, _ := e["prev_event_hash"].(string)
		want := prev
		if want == "" {
			want = p // first chained record: accept whatever it links to (log rotation)
			st.FirstSeq, st.StartsAtGenesis = seqOf(e), p == GenesisHash
		}
		if p != want {
			return st.broken(i, "prev_event_hash does not match the previous record")
		}
		got, err := hashEvent(e)
		if err != nil || got != h {
			return st.broken(i, "record content does not match its event_hash")
		}
		prev = h
	}
	st.LastHash = prev
	return st
}

func (st ChainStatus) broken(i int, problem string) ChainStatus {
	st.Valid, st.BrokenAt, st.Problem, st.Unchained = false, i+1, problem, 0
	return st
}

func errorf(format string, args ...any) error { return fmt.Errorf("audit: "+format, args...) }

// Chained seals records with an in-memory chain (starting at genesis) before
// forwarding them, for sinks that have no file behind them.
func Chained(s Sink) Sink { return &chained{c: NewChain(0, ""), s: s} }

type chained struct {
	mu sync.Mutex
	c  *Chain
	s  Sink
}

func (c *chained) Write(e Event) error {
	c.mu.Lock() // keep forwarding order equal to chain order
	defer c.mu.Unlock()
	sealed, err := c.c.Seal(e)
	if err != nil {
		return err
	}
	return c.s.Write(sealed)
}

func (c *chained) Close() error { return c.s.Close() }
