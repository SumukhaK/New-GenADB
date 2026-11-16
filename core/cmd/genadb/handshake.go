package main

import (
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
}

// clientHandshake runs the desktop side. Returns the secure channel and the
// device's identity key.
func clientHandshake(c net.Conn, r io.Reader, p initiatorParams) (*secureConn, ed25519.PublicKey, error) {
	c.SetDeadline(time.Now().Add(15 * time.Second))
	defer c.SetDeadline(time.Time{})
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	m1 := hsMsg{Mode: p.mode, Eph: eph.PublicKey().Bytes(), ID: p.id.Public().(ed25519.PublicKey), Token: p.token}
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
		return nil, nil, errors.New("pairing code rejected")
	}
	if !ed25519.Verify(peerID, append([]byte("genadb-dev-sig"), th1...), m2.Sig) {
		return nil, nil, errors.New("device signature invalid")
	}
	if p.verifyPeer != nil {
		if err := p.verifyPeer(peerID, m2.Token); err != nil {
			return nil, nil, err
		}
	}
	th2 := thash(th1, m2.Sig)
	m3 := hsMsg{Sig: ed25519.Sign(p.id, append([]byte("genadb-desk-sig"), th2...))}
	if sp != nil {
		m3.MAC = mac(k.confirm, "desktop", th2)
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
	return makeSecure(c, r, k, true), peerID, nil
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

func serverHandshake(c net.Conn, r io.Reader, p responderPolicy, b1 []byte, m1 hsMsg) (*secureConn, ed25519.PublicKey, error) {
	c.SetDeadline(time.Now().Add(15 * time.Second))
	defer c.SetDeadline(time.Time{})
	var err error
	if len(m1.ID) != ed25519.PublicKeySize {
		return nil, nil, errors.New("bad peer identity")
	}
	peerID := ed25519.PublicKey(m1.ID)
	var sp *spake
	switch m1.Mode {
	case "pair":
		secret, nameplate, ok := p.pairing()
		if !ok {
			writeMsg(c, hsMsg{Err: "no active pairing code"})
			return nil, nil, errors.New("pairing not active")
		}
		sp = newSpake("A", secret, nameplate)
	default:
		if err := p.authorize(peerID, m1.Token); err != nil {
			writeMsg(c, hsMsg{Err: "not authorized"})
			return nil, nil, err
		}
	}
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	m2 := hsMsg{Eph: eph.PublicKey().Bytes(), ID: p.id.Public().(ed25519.PublicKey), Token: p.token}
	if sp != nil {
		m2.Pake = sp.msg
	}
	b2, _ := json.Marshal(m2)
	th1 := thash(b1, b2)
	pk, err := ecdh.X25519().NewPublicKey(m1.Eph)
	if err != nil {
		return nil, nil, err
	}
	dh, err := eph.ECDH(pk)
	if err != nil {
		return nil, nil, err
	}
	var pakeK []byte
	if sp != nil {
		if pakeK, err = sp.finish(m1.Pake); err != nil {
			p.pairResult(false, nil)
			return nil, nil, err
		}
	}
	k := deriveKeys(dh, pakeK, th1)
	m2.Sig = ed25519.Sign(p.id, append([]byte("genadb-dev-sig"), th1...))
	if sp != nil {
		m2.MAC = mac(k.confirm, "device", th1)
	}
	if _, err := writeMsg(c, m2); err != nil {
		return nil, nil, err
	}
	var m3 hsMsg
	_, err = readMsg(r, &m3)
	th2 := thash(th1, m2.Sig)
	ok := err == nil && ed25519.Verify(peerID, append([]byte("genadb-desk-sig"), th2...), m3.Sig)
	if sp != nil {
		ok = ok && hmac.Equal(m3.MAC, mac(k.confirm, "desktop", th2))
		p.pairResult(ok, peerID)
	}
	if !ok {
		writeMsg(c, hsMsg{Err: "handshake failed"})
		return nil, nil, errors.New("peer failed to authenticate")
	}
	if _, err := writeMsg(c, hsMsg{Mode: "ok"}); err != nil {
		return nil, nil, err
	}
	return makeSecure(c, r, k, false), peerID, nil
}
