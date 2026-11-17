package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Anchor pins where a log starts and ends. It lives in its own file next to
// the log (audit.jsonl -> audit.anchor), is rewritten after every record and
// is signed with HMAC-SHA256 under a key kept outside the log.
//
// The hash chain alone proves that the records present are intact and in
// order, but not that none are missing at either end: dropping the oldest
// lines leaves a shorter chain that still verifies, and so does dropping the
// newest. The anchor closes both gaps for anyone who cannot forge its MAC.
// It does not stop someone who holds the key and can write both files; keep
// the key on another volume (FileOptions.AnchorKeyFile) and forward records
// to a webhook or SIEM for that threat.
type Anchor struct {
	Version int `json:"version"`
	// FirstSeq and FirstHash identify the oldest record in the log; FirstSeq
	// is 0 while the log has no records yet. FirstPrevHash is what that
	// record links to: GenesisHash for a new chain, or the last hash of the
	// previous file after a rotation.
	FirstSeq      int64  `json:"first_seq"`
	FirstPrevHash string `json:"first_prev_event_hash"`
	FirstHash     string `json:"first_event_hash,omitempty"`
	// LastSeq and LastHash identify the newest record written (or, before
	// the first record, the record the log continues from).
	LastSeq  int64  `json:"last_seq"`
	LastHash string `json:"last_event_hash"`
	Updated  string `json:"updated"`
	MAC      string `json:"mac,omitempty"`
}

const anchorVersion = 1

// AnchorKeyFileName is the default anchor key, in the log's directory.
const AnchorKeyFileName = "audit-anchor.key"

// Anchor problems reported by OpenFileWith and VerifyFile.
var (
	ErrAnchorSignature = errors.New("audit: anchor signature does not match (anchor edited, or wrong key)")
	ErrAnchorMismatch  = errors.New("audit: log does not match its anchor")
)

// AnchorPath returns the anchor file for a log: audit.jsonl -> audit.anchor.
func AnchorPath(log string) string {
	switch ext := filepath.Ext(log); ext {
	case ".jsonl", ".log", ".json":
		return strings.TrimSuffix(log, ext) + ".anchor"
	}
	return log + ".anchor"
}

// DefaultAnchorKeyPath returns the key file used when none is configured:
// audit-anchor.key in the log's directory, so rotated logs kept beside it
// verify with the same key.
func DefaultAnchorKeyPath(log string) string {
	return filepath.Join(filepath.Dir(log), AnchorKeyFileName)
}

// LoadAnchorKey reads a hex-encoded anchor key.
func LoadAnchorKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) < 16 {
		return nil, fmt.Errorf("audit: anchor key %s: want at least 16 hex-encoded bytes", path)
	}
	return k, nil
}

// LoadOrCreateAnchorKey reads the key at path, creating a random 32-byte key
// (mode 0600) if the file does not exist yet.
func LoadOrCreateAnchorKey(path string) ([]byte, error) {
	k, err := LoadAnchorKey(path)
	if !errors.Is(err, fs.ErrNotExist) {
		return k, err
	}
	k = make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, fs.ErrExist) { // another process created it first
		return LoadAnchorKey(path)
	}
	if err != nil {
		return nil, err
	}
	_, err = f.WriteString(hex.EncodeToString(k) + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return k, err
}

func (a Anchor) mac(key []byte) string {
	a.MAC = ""
	b, _ := json.Marshal(a)
	m := hmac.New(sha256.New, key)
	m.Write([]byte("setu-audit-anchor-v1\n"))
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil))
}

func (a *Anchor) sign(key []byte) { a.MAC = a.mac(key) }

// Valid reports whether the anchor's MAC matches key.
func (a *Anchor) Valid(key []byte) bool {
	return a.MAC != "" && hmac.Equal([]byte(a.MAC), []byte(a.mac(key)))
}

// ReadAnchor reads an anchor file; it returns (nil, nil) if there is none.
func ReadAnchor(path string) (*Anchor, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var a Anchor
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("%w: %s is not valid JSON", ErrAnchorSignature, path)
	}
	return &a, nil
}

// writeAnchor replaces the anchor atomically (temp file + rename).
func writeAnchor(path string, a *Anchor, key []byte, syncFile bool) error {
	a.Version = anchorVersion
	a.Updated = time.Now().UTC().Format(time.RFC3339Nano)
	a.sign(key)
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(append(b, '\n'))
	if err == nil && syncFile {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o600)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// logInfo summarises the chained records of a log.
type logInfo struct {
	records             int64 // chained records
	firstSeq, lastSeq   int64
	firstPrev           string
	firstHash, lastHash string
	hashAt              string // event_hash of the record with seq == want
}

type linkScanner struct {
	want int64
	info logInfo
}

func (l *linkScanner) add(seq int64, prev, hash string) {
	if hash == "" {
		return
	}
	in := &l.info
	if in.records == 0 {
		in.firstSeq, in.firstPrev, in.firstHash = seq, prev, hash
	}
	in.records++
	in.lastSeq, in.lastHash = seq, hash
	if seq == l.want && l.want > 0 {
		in.hashAt = hash
	}
}

// scanLog streams a log file, collecting its first and last links and the
// hash of the record with seq == want.
func scanLog(path string, want int64) (logInfo, error) {
	ls := linkScanner{want: want}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return ls.info, nil
	}
	if err != nil {
		return ls.info, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var e struct {
			Seq  int64  `json:"seq"`
			Prev string `json:"prev_event_hash"`
			Hash string `json:"event_hash"`
		}
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			ls.add(e.Seq, e.Prev, e.Hash)
		}
	}
	return ls.info, sc.Err()
}

func infoFromEvents(events []Event, want int64) logInfo {
	ls := linkScanner{want: want}
	for _, e := range events {
		h, _ := e["event_hash"].(string)
		p, _ := e["prev_event_hash"].(string)
		ls.add(seqOf(e), p, h)
	}
	return ls.info
}

func seqOf(e Event) int64 {
	switch v := e["seq"].(type) {
	case json.Number:
		n, _ := v.Int64()
		return n
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	}
	return 0
}

// check compares a log with its anchor and describes the first mismatch.
func (a *Anchor) check(in logInfo) error {
	if a.FirstSeq == 0 {
		// Anchored before its first record. Records written since (a crash
		// can land between the record and the anchor update) must continue
		// from the anchored point.
		if in.records > 0 && (in.firstSeq != a.LastSeq+1 || in.firstPrev != a.LastHash) {
			return fmt.Errorf("%w: the anchor expects the log to start at seq %d, but it starts at seq %d",
				ErrAnchorMismatch, a.LastSeq+1, in.firstSeq)
		}
		return nil
	}
	switch {
	case in.records == 0:
		return fmt.Errorf("%w: the log has no records, but its anchor covers seq %d to %d (log deleted or emptied)",
			ErrAnchorMismatch, a.FirstSeq, a.LastSeq)
	case in.firstSeq != a.FirstSeq || in.firstHash != a.FirstHash:
		return fmt.Errorf("%w: oldest records missing or replaced: the log starts at seq %d, the anchor at seq %d",
			ErrAnchorMismatch, in.firstSeq, a.FirstSeq)
	case in.lastSeq < a.LastSeq:
		return fmt.Errorf("%w: newest records missing: the log ends at seq %d, the anchor at seq %d",
			ErrAnchorMismatch, in.lastSeq, a.LastSeq)
	case in.hashAt != a.LastHash:
		return fmt.Errorf("%w: record seq %d is not the one the anchor recorded", ErrAnchorMismatch, a.LastSeq)
	}
	return nil
}

// VerifyOptions configures VerifyFile.
type VerifyOptions struct {
	AnchorKey     []byte // key to check the anchor's MAC; nil loads AnchorKeyFile
	AnchorKeyFile string // "" means DefaultAnchorKeyPath(log)
}

// VerifyFile verifies a log on disk: every hash link (as Verify does), plus
// its anchor, which catches records deleted from either end of the log.
// Without an anchor, a log that does not start at genesis gets a warning,
// since its oldest records may have been removed.
func VerifyFile(path string, opt VerifyOptions) (ChainStatus, error) {
	evs, err := ReadFile(path)
	missing := errors.Is(err, fs.ErrNotExist)
	if err != nil && !missing {
		return ChainStatus{}, err
	}
	st := Verify(evs)
	a, aerr := ReadAnchor(AnchorPath(path))
	if a == nil && aerr == nil {
		if missing {
			return st, err
		}
		st.Anchor = AnchorNone
		if st.Records > 0 && !st.StartsAtGenesis {
			st.Warnings = append(st.Warnings, fmt.Sprintf(
				"log starts at seq %d, not at genesis, and has no anchor: older records may have been removed (rotation also does this)", st.FirstSeq))
		}
		return st, nil
	}
	fail := func(problem string) (ChainStatus, error) {
		st.Valid, st.Problem = false, problem
		return st, nil
	}
	if aerr != nil {
		st.Anchor = AnchorInvalid
		return fail(aerr.Error())
	}
	key := opt.AnchorKey
	if key == nil {
		kp := opt.AnchorKeyFile
		if kp == "" {
			kp = DefaultAnchorKeyPath(path)
		}
		if key, err = LoadAnchorKey(kp); err != nil {
			st.Anchor = AnchorUnverified
			st.Warnings = append(st.Warnings, fmt.Sprintf("anchor key not available (%v): anchor positions checked, signature not", err))
		}
	}
	if key != nil {
		if !a.Valid(key) {
			st.Anchor = AnchorInvalid
			return fail(ErrAnchorSignature.Error())
		}
		st.Anchor = AnchorVerified
	}
	if !st.Valid {
		return st, nil
	}
	in := infoFromEvents(evs, a.LastSeq)
	if err := a.check(in); err != nil {
		return fail(err.Error())
	}
	if in.records > 0 && in.lastSeq > a.LastSeq && a.FirstSeq != 0 {
		st.Warnings = append(st.Warnings, fmt.Sprintf(
			"%d record(s) after the anchor (a writer stopped between the record and the anchor update)", in.lastSeq-a.LastSeq))
	}
	return st, nil
}

// Anchor states reported in ChainStatus.Anchor.
const (
	AnchorVerified   = "verified"   // anchor present, MAC checked, positions match
	AnchorUnverified = "unverified" // anchor present, key unavailable
	AnchorInvalid    = "invalid"    // anchor present but forged, edited or unreadable
	AnchorNone       = "none"       // no anchor file
)

// RotateFile moves a log and its anchor to archive (and AnchorPath(archive))
// and starts an empty log at path whose chain continues from the archived
// one. Writers that have the log open, in this or other processes, notice
// the rotation on their next record and switch to the new file.
func RotateFile(path, archive string, opt FileOptions) error {
	if opt.NoAnchor {
		return errorf("rotate: rotation keeps the chain continuous through the anchor, which NoAnchor turns off")
	}
	s, err := OpenFileWith(path, opt)
	if err != nil {
		return err
	}
	defer s.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := lockFile(s.f); err != nil {
		return err
	}
	defer unlockFile(s.f)
	if err := s.refresh(); err != nil {
		return err
	}
	if _, err := os.Stat(archive); err == nil {
		return fmt.Errorf("audit: rotate: %s already exists", archive)
	}
	last := *s.anchor
	if err := os.Rename(path, archive); err != nil {
		return err
	}
	if err := os.Rename(s.anchorPath, AnchorPath(archive)); err != nil {
		return err
	}
	nf, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	nf.Close()
	next := &Anchor{FirstPrevHash: last.LastHash, LastSeq: last.LastSeq, LastHash: last.LastHash}
	return writeAnchor(s.anchorPath, next, s.key, true)
}
