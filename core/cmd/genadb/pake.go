package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"

	"filippo.io/edwards25519"
)

// SPAKE2 over edwards25519. The pairing secret never leaves either endpoint
// and an eavesdropper or the relay cannot test guesses offline; each online
// guess costs the attacker one of the device's (three) attempts.

var spakeM, spakeN = hashToPoint("genadb SPAKE2 M v1"), hashToPoint("genadb SPAKE2 N v1")

func hashToPoint(label string) *edwards25519.Point {
	for ctr := byte(0); ; ctr++ {
		h := sha512.Sum512(append([]byte(label), ctr))
		p, err := new(edwards25519.Point).SetBytes(h[:32])
		if err != nil {
			continue
		}
		p.MultByCofactor(p)
		if p.Equal(edwards25519.NewIdentityPoint()) == 1 {
			continue
		}
		return p
	}
}

func passwordScalar(secret, nameplate string) *edwards25519.Scalar {
	h := sha512.Sum512([]byte("genadb-pw-v1|" + nameplate + "|" + secret))
	s, _ := new(edwards25519.Scalar).SetUniformBytes(h[:])
	return s
}

func randScalar() *edwards25519.Scalar {
	var b [64]byte
	rand.Read(b[:])
	s, _ := new(edwards25519.Scalar).SetUniformBytes(b[:])
	return s
}

type spake struct {
	w, x   *edwards25519.Scalar
	mine   *edwards25519.Point // blinding point for my role
	theirs *edwards25519.Point // blinding point for peer role
	msg    []byte
}

// newSpake: role "A" (device, uses M) or "B" (desktop, uses N).
func newSpake(role, secret, nameplate string) *spake {
	s := &spake{w: passwordScalar(secret, nameplate), x: randScalar()}
	if role == "A" {
		s.mine, s.theirs = spakeM, spakeN
	} else {
		s.mine, s.theirs = spakeN, spakeM
	}
	X := new(edwards25519.Point).ScalarBaseMult(s.x)
	X.Add(X, new(edwards25519.Point).ScalarMult(s.w, s.mine))
	s.msg = X.Bytes()
	return s
}

func (s *spake) finish(peer []byte) ([]byte, error) {
	Y, err := new(edwards25519.Point).SetBytes(peer)
	if err != nil {
		return nil, errors.New("bad pake message")
	}
	t := new(edwards25519.Point).ScalarMult(s.w, s.theirs)
	t.Subtract(Y, t)
	K := new(edwards25519.Point).ScalarMult(s.x, t)
	K.MultByCofactor(K)
	if K.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, errors.New("degenerate pake")
	}
	h := sha256.New()
	h.Write([]byte("genadb-spake2-v1"))
	h.Write(K.Bytes())
	h.Write(s.w.Bytes())
	return h.Sum(nil), nil
}
