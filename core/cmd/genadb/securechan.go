package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

const maxFrame = 64 * 1024

// secureConn is an AEAD-framed channel (AES-256-GCM, per-direction keys and
// counters). Any authentication failure tears the connection down, so a
// tampered byte can never be delivered to adb.
type secureConn struct {
	net.Conn
	r       io.Reader
	sendA   cipher.AEAD
	recvA   cipher.AEAD
	sendCtr uint64
	recvCtr uint64
	wmu     sync.Mutex
	rbuf    []byte
}

func newAEAD(key []byte) cipher.AEAD {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		panic(err)
	}
	return a
}

func nonce(ctr uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n
}

func (s *secureConn) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxFrame {
			n = maxFrame
		}
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(n+s.sendA.Overhead()))
		out := make([]byte, 4, 4+n+s.sendA.Overhead())
		copy(out, hdr[:])
		out = s.sendA.Seal(out, nonce(s.sendCtr), p[:n], hdr[:])
		s.sendCtr++
		if _, err := s.Conn.Write(out); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (s *secureConn) Read(p []byte) (int, error) {
	if len(s.rbuf) == 0 {
		var hdr [4]byte
		if _, err := io.ReadFull(s.r, hdr[:]); err != nil {
			return 0, err
		}
		ln := binary.BigEndian.Uint32(hdr[:])
		if ln > maxFrame+64 || ln < uint32(s.recvA.Overhead()) {
			return 0, errors.New("bad frame length")
		}
		ct := make([]byte, ln)
		if _, err := io.ReadFull(s.r, ct); err != nil {
			return 0, err
		}
		pt, err := s.recvA.Open(ct[:0], nonce(s.recvCtr), ct, hdr[:])
		if err != nil {
			s.Conn.Close()
			return 0, errors.New("frame authentication failed")
		}
		s.recvCtr++
		s.rbuf = pt
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}

// handshake runs an ephemeral X25519 exchange over the relayed stream and
// derives per-direction AEAD keys bound to the transcript.
func handshake(c net.Conn, r io.Reader, initiator bool) (*secureConn, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	mine := priv.PublicKey().Bytes()
	if _, err := c.Write(mine); err != nil {
		return nil, err
	}
	theirs := make([]byte, 32)
	if _, err := io.ReadFull(r, theirs); err != nil {
		return nil, err
	}
	pk, err := ecdh.X25519().NewPublicKey(theirs)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(pk)
	if err != nil {
		return nil, err
	}
	var ti, tr []byte
	if initiator {
		ti, tr = mine, theirs
	} else {
		ti, tr = theirs, mine
	}
	th := sha256.Sum256(append(append([]byte("genadb-hs-v1"), ti...), tr...))
	keys, err := hkdf.Key(sha256.New, shared, th[:], "genadb session keys", 64)
	if err != nil {
		return nil, err
	}
	i2r, r2i := newAEAD(keys[:32]), newAEAD(keys[32:])
	s := &secureConn{Conn: c, r: r}
	if initiator {
		s.sendA, s.recvA = i2r, r2i
	} else {
		s.sendA, s.recvA = r2i, i2r
	}
	return s, nil
}
