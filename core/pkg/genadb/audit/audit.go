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
	"errors"
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
// existing chain if the file already has records.
type FileSink struct {
	mu    sync.Mutex
	f     *os.File
	chain *Chain
	sync  bool
	tees  []Sink
}

// Tee forwards every record, after it is sealed and written, to the given
// sinks (webhooks, SIEM forwarders), so they see the same seq and hashes as
// the file. Call it before the first Write. Tees run while the record is
// being written, which may be on an ADB data path: they must not block
// (the built-in webhook sink and the SDK's event tap only enqueue).
func (s *FileSink) Tee(sinks ...Sink) { s.tees = append(s.tees, sinks...) }

// OpenFile opens (or creates) a chained audit log. With syncEach, every
// record is fsynced before Write returns.
func OpenFile(path string, syncEach bool) (*FileSink, error) {
	seq, prev, err := lastLink(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &FileSink{f: f, chain: NewChain(seq, prev), sync: syncEach}, nil
}

func lastLink(path string) (int64, string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	var seq int64
	prev := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var e struct {
			Seq  int64  `json:"seq"`
			Hash string `json:"event_hash"`
		}
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.Hash != "" {
			seq, prev = e.Seq, e.Hash
		}
	}
	return seq, prev, sc.Err()
}

func (s *FileSink) Write(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sealed, err := s.chain.Seal(e)
	if err != nil {
		return err
	}
	b, err := json.Marshal(sealed)
	if err != nil {
		return err
	}
	if _, err := s.f.Write(append(b, '\n')); err != nil {
		return err
	}
	if s.sync {
		if err := s.f.Sync(); err != nil {
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
	err := s.f.Close()
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
}

// Verify checks every link in the chain. Records without event_hash (written
// by older versions) are counted but make the log invalid only if they occur
// after chained records.
func Verify(events []Event) ChainStatus {
	st := ChainStatus{Valid: true, Records: len(events)}
	prev := ""
	for i, e := range events {
		h, _ := e["event_hash"].(string)
		if h == "" {
			if prev != "" {
				return ChainStatus{Records: len(events), BrokenAt: i + 1, Problem: "record without a hash inside the chain"}
			}
			st.Unchained++
			continue
		}
		p, _ := e["prev_event_hash"].(string)
		want := prev
		if want == "" {
			want = p // first chained record: accept whatever it links to (log rotation)
		}
		if p != want {
			return ChainStatus{Records: len(events), BrokenAt: i + 1, Problem: "prev_event_hash does not match the previous record"}
		}
		got, err := hashEvent(e)
		if err != nil || got != h {
			return ChainStatus{Records: len(events), BrokenAt: i + 1, Problem: "record content does not match its event_hash"}
		}
		prev = h
	}
	st.LastHash = prev
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
