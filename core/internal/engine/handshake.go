package engine

import (
	"fmt"

	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

// Authenticated key exchange run end to end between desktop agent (initiator)
// and device agent (responder) over the relayed byte stream. The relay only
// sees public values.
//
//   M1 desktop->device: mode, eph(X25519), id(ed25519), pake(Y)?, token?
//   M2 device->desktop: eph, id, pake(X)?, token?, sig_dev(th1), mac_dev?
//   M3 desktop->device: sig_desk(th2), mac_desk?
//
// Session keys = HKDF(DH(eph,eph) || K_pake?, transcript).

type hsMsg struct {
	Mode  string `json:"mode,omitempty"`
	Eph   []byte `json:"eph,omitempty"`
	ID    []byte `json:"id,omitempty"`
	Pake  []byte `json:"pake,omitempty"`
	Token string `json:"token,omitempty"`
	Sig   []byte `json:"sig,omitempty"`
	MAC   []byte `json:"mac,omitempty"`
	Err   string `json:"err,omitempty"`
	// Caps (v1.1.0+) lists optional features. A desktop announces its own in
	// M1; a device answers with its capabilities in M2 only when M1 carried
	// some, so a v1.0.x desktop (which re-encodes M2 for the transcript)
	// never sees a field it would drop.
	Caps []string `json:"caps,omitempty"`
	// Meta (v1.1.0+, M3) is the AEAD-sealed handshakeMeta: what the
	// desktop wants this stream for, and its display label. It is sealed
	// under a key derived from the session secret, so the relay learns
	// neither.
	Meta []byte `json:"meta,omitempty"`
}

// Capabilities exchanged in hsMsg.Caps.
const (
	capV11     = "v1.1"     // desktop: understands device capabilities
	capADBPair = "adb-pair" // device: tunnels Wireless-debugging pairing
	capClose   = "close"    // both: understands the graceful close record
)

var deviceCaps = []string{capV11, capADBPair, capClose}

func hasCap(caps []string, c string) bool {
	for _, x := range caps {
		if x == c {
			return true
		}
	}
	return false
}

// handshakeMeta travels sealed in M3.
type handshakeMeta struct {
	// Target is "" (adbd) or "adb-pair:<port>" (Android 11+ Wireless
	// debugging pairing service; port 0 = discover it on the device).
	Target string `json:"target,omitempty"`
	// Label is the desktop's display name for the phone's session list.
	Label string `json:"label,omitempty"`
}

func metaAEADKey(k keys) []byte {
	mk, _ := hkdf.Key(sha256.New, k.confirm, nil, "genadb handshake meta v1", 32)
	return mk
}

// sealMeta / openMeta use a key used for exactly one message, so a fixed
// nonce is safe.
func sealMeta(k keys, m handshakeMeta) []byte {
	b, _ := json.Marshal(m)
	return newAEAD(metaAEADKey(k)).Seal(nil, make([]byte, 12), b, []byte("meta"))
}

func openMeta(k keys, ct []byte) (handshakeMeta, error) {
	var m handshakeMeta
	if len(ct) == 0 {
		return m, nil
	}
	pt, err := newAEAD(metaAEADKey(k)).Open(nil, make([]byte, 12), ct, []byte("meta"))
	if err != nil {
		return m, errors.New("handshake metadata failed authentication")
	}
	if err := json.Unmarshal(pt, &m); err != nil {
		return m, errors.New("bad handshake metadata")
	}
	return m, nil
}

func writeMsg(w io.Writer, m any) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	_, err = w.Write(append(hdr[:], b...))
	return b, err
}

func readMsg(r io.Reader, m any) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > 64*1024 {
		return nil, errors.New("handshake message too large")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, json.Unmarshal(b, m)
}

func thash(parts ...[]byte) []byte {
	h := sha256.New()
	h.Write([]byte("genadb-transcript-v1"))
	for _, p := range parts {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		h.Write(l[:])
		h.Write(p)
	}
	return h.Sum(nil)
}

func mac(key []byte, label string, th []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(label))
	m.Write(th)
	return m.Sum(nil)
}

type keys struct{ i2r, r2i, confirm, resume, sid []byte }

func deriveKeys(dh, pakeK, th []byte) keys {
	secret := append(append([]byte{}, dh...), pakeK...)
	k, _ := hkdf.Key(sha256.New, secret, th, "genadb session keys v1", 144)
	return keys{k[:32], k[32:64], k[64:96], k[96:128], k[128:144]}
}

func makeSecure(c net.Conn, r io.Reader, k keys, initiator bool) *secureConn {
	s := &secureConn{Conn: c, r: r, sid: k.sid, resumeKey: k.resume}
	if initiator {
		s.sendA, s.recvA = newAEAD(k.i2r), newAEAD(k.r2i)
	} else {
		s.sendA, s.recvA = newAEAD(k.r2i), newAEAD(k.i2r)
	}
	return s
}

// initiatorParams describes what the desktop knows going in.
type initiatorParams struct {
	id         ed25519.PrivateKey
	mode       string // "pair" | "resume"
	secret     string // pairing secret (pair mode)
	nameplate  string
	pinnedPeer ed25519.PublicKey // resume mode: expected device key
	token      string            // corporate user token
	verifyPeer func(peerID ed25519.PublicKey, token string) error
	tokenFn    func() string // current corporate token (live rotation); overrides token
	target     string        // "" = adbd, "adb-pair:<port>" = pairing service
	label      string        // display label shown on the phone
}

func (p initiatorParams) currentToken() string {
	if p.tokenFn != nil {
		return p.tokenFn()
	}
	return p.token
}

// clientHandshake runs the desktop side. Returns the secure channel and the
// device's identity key.
func clientHandshake(c net.Conn, r io.Reader, p initiatorParams) (*secureConn, ed25519.PublicKey, error) {
	c.SetDeadline(time.Now().Add(15 * time.Second))
	defer c.SetDeadline(time.Time{})
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	m1 := hsMsg{Mode: p.mode, Eph: eph.PublicKey().Bytes(), ID: p.id.Public().(ed25519.PublicKey), Token: p.currentToken(),
		Caps: []string{capV11, capClose}}
	var sp *spake
	if p.mode == "pair" {
		sp = newSpake("B", p.secret, p.nameplate)
		m1.Pake = sp.msg
	}
	b1, err := writeMsg(c, m1)
	if err != nil {
		return nil, nil, err
	}
	var m2 hsMsg
	if _, err := readMsg(r, &m2); err != nil {
		return nil, nil, err
	}
	if m2.Err != "" {
		return nil, nil, errors.New(m2.Err)
	}
	if len(m2.ID) != ed25519.PublicKeySize {
		return nil, nil, errors.New("bad peer identity")
	}
	peerID := ed25519.PublicKey(m2.ID)
	core2 := m2
	core2.Sig, core2.MAC = nil, nil
	b2, _ := json.Marshal(core2)
	th1 := thash(b1, b2)
	pk, err := ecdh.X25519().NewPublicKey(m2.Eph)
	if err != nil {
		return nil, nil, err
	}
	dh, err := eph.ECDH(pk)
	if err != nil {
		return nil, nil, err
	}
	var pakeK []byte
	if sp != nil {
		if pakeK, err = sp.finish(m2.Pake); err != nil {
			return nil, nil, err
		}
	} else if p.pinnedPeer != nil && !peerID.Equal(p.pinnedPeer) {
		return nil, nil, errors.New("device identity does not match pinned key")
	}
	k := deriveKeys(dh, pakeK, th1)
	if sp != nil && !hmac.Equal(m2.MAC, mac(k.confirm, "device", th1)) {
		return nil, nil, ErrBadCode
	}
	if !ed25519.Verify(peerID, append([]byte("genadb-dev-sig"), th1...), m2.Sig) {
		return nil, nil, errors.New("device signature invalid")
	}
	if p.verifyPeer != nil {
		if err := p.verifyPeer(peerID, m2.Token); err != nil {
			return nil, nil, err
		}
	}
	if p.target != "" && !hasCap(m2.Caps, capADBPair) {
		return nil, nil, fmt.Errorf("%w: %w: adb pairing needs Setu-SDK 1.1.0 or later on the device", errDenied, ErrUnsupported)
	}
	th2 := thash(th1, m2.Sig)
	m3 := hsMsg{Sig: ed25519.Sign(p.id, append([]byte("genadb-desk-sig"), th2...))}
	if sp != nil {
		m3.MAC = mac(k.confirm, "desktop", th2)
	}
	if p.target != "" || p.label != "" {
		m3.Meta = sealMeta(k, handshakeMeta{Target: p.target, Label: p.label})
	}
	if _, err := writeMsg(c, m3); err != nil {
		return nil, nil, err
	}
	// final ack from device so failures are reported before we claim success
	var ack hsMsg
	if _, err := readMsg(r, &ack); err != nil {
		return nil, nil, err
	}
	if ack.Err != "" {
		return nil, nil, errors.New(ack.Err)
	}
	sc := makeSecure(c, r, k, true)
	sc.peerCaps = m2.Caps
	return sc, peerID, nil
}

// responderPolicy lets the device decide per handshake.
type responderPolicy struct {
	id ed25519.PrivateKey
	// pairing returns (secret, nameplate, ok) when a pairing code is active.
	pairing func() (string, string, bool)
	// pairResult reports a pairing attempt outcome.
	pairResult func(ok bool, peer ed25519.PublicKey)
	// authorize decides whether a resume/corporate peer is allowed.
	authorize func(peer ed25519.PublicKey, token string) error
	token     string // device's own token (corporate)
}

// handshakeResult is what the device learns about an authenticated peer.
type handshakeResult struct {
	peer  ed25519.PublicKey
	token string // the peer's corporate token (already checked by authorize)
	caps  []string
	meta  handshakeMeta
}

func serverHandshake(c net.Conn, r io.Reader, p responderPolicy, b1 []byte, m1 hsMsg) (*secureConn, handshakeResult, error) {
	var res handshakeResult
	c.SetDeadline(time.Now().Add(15 * time.Second))
	defer c.SetDeadline(time.Time{})
	var err error
	if len(m1.ID) != ed25519.PublicKeySize {
		return nil, res, errors.New("bad peer identity")
	}
	peerID := ed25519.PublicKey(m1.ID)
	var sp *spake
	switch m1.Mode {
	case "pair":
		secret, nameplate, ok := p.pairing()
		if !ok {
			writeMsg(c, hsMsg{Err: "no active pairing code"})
			return nil, res, errors.New("pairing not active")
		}
		sp = newSpake("A", secret, nameplate)
	default:
		if err := p.authorize(peerID, m1.Token); err != nil {
			writeMsg(c, hsMsg{Err: "not authorized"})
			return nil, res, err
		}
	}
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	m2 := hsMsg{Eph: eph.PublicKey().Bytes(), ID: p.id.Public().(ed25519.PublicKey), Token: p.token}
	if sp != nil {
		m2.Pake = sp.msg
	}
	if len(m1.Caps) > 0 {
		m2.Caps = deviceCaps // only to desktops that announced their own (see hsMsg.Caps)
	}
	b2, _ := json.Marshal(m2)
	th1 := thash(b1, b2)
	pk, err := ecdh.X25519().NewPublicKey(m1.Eph)
	if err != nil {
		return nil, res, err
	}
	dh, err := eph.ECDH(pk)
	if err != nil {
		return nil, res, err
	}
	var pakeK []byte
	if sp != nil {
		if pakeK, err = sp.finish(m1.Pake); err != nil {
			p.pairResult(false, nil)
			return nil, res, err
		}
	}
	k := deriveKeys(dh, pakeK, th1)
	m2.Sig = ed25519.Sign(p.id, append([]byte("genadb-dev-sig"), th1...))
	if sp != nil {
		m2.MAC = mac(k.confirm, "device", th1)
	}
	if _, err := writeMsg(c, m2); err != nil {
		return nil, res, err
	}
	var m3 hsMsg
	_, err = readMsg(r, &m3)
	th2 := thash(th1, m2.Sig)
	ok := err == nil && ed25519.Verify(peerID, append([]byte("genadb-desk-sig"), th2...), m3.Sig)
	if sp != nil {
		ok = ok && hmac.Equal(m3.MAC, mac(k.confirm, "desktop", th2))
		p.pairResult(ok, peerID)
	}
	var meta handshakeMeta
	if ok {
		if meta, err = openMeta(k, m3.Meta); err != nil {
			ok = false
		}
	}
	if !ok {
		writeMsg(c, hsMsg{Err: "handshake failed"})
		return nil, res, errors.New("peer failed to authenticate")
	}
	if _, err := writeMsg(c, hsMsg{Mode: "ok"}); err != nil {
		return nil, res, err
	}
	sc := makeSecure(c, r, k, false)
	sc.peerCaps = m1.Caps
	return sc, handshakeResult{peer: peerID, token: m1.Token, caps: m1.Caps, meta: meta}, nil
}
