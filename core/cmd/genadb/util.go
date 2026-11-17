package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var emitMu sync.Mutex

// emit writes one JSON event line to stdout (the harness/UI contract).
func emit(event string, fields map[string]any) {
	m := map[string]any{"event": event}
	for k, v := range fields {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	emitMu.Lock()
	os.Stdout.Write(append(b, '\n'))
	emitMu.Unlock()
}

// loadOrCreateKey returns the persistent ed25519 identity key in dir.
func loadOrCreateKey(dir string) (ed25519.PrivateKey, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, "identity.key")
	if b, err := os.ReadFile(p); err == nil && len(b) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(b), nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, priv.Seed(), 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

func pubString(k ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
}

// writeHello / readHello exchange one JSON control line on a raw connection.
func writeHello(c net.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.Write(append(b, '\n'))
	return err
}

func readHello(r *bufio.Reader, v any) error {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return err
	}
	return json.Unmarshal(line, v)
}

// splice copies in both directions until either side closes.
func splice(a net.Conn, ar io.Reader, b net.Conn, br io.Reader) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(b, ar); closeWrite(b); done <- struct{}{} }()
	go func() { io.Copy(a, br); closeWrite(a); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
	<-done
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
}

func dial(addr string) (net.Conn, error) { return dialTimeout(addr, 5*time.Second) }

func dialTimeout(addr string, d time.Duration) (net.Conn, error) {
	// Aggressive TCP keepalive: a silently dead path (radio loss without a
	// reset) is noticed in ~25 s instead of the OS default of minutes.
	dl := net.Dialer{Timeout: d, KeepAliveConfig: net.KeepAliveConfig{Enable: true,
		Idle: 10 * time.Second, Interval: 5 * time.Second, Count: 3}}
	c, err := dl.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	return c, nil
}

var errDenied = errors.New("denied")

// relayHello sends a hello to the relay and completes the corporate
// proof-of-possession challenge if the relay asks for one.
func relayHello(c net.Conn, br *bufio.Reader, h hello, key ed25519.PrivateKey) (reply, error) {
	if h.Identity != "" {
		h.Pub = pubString(key)
	}
	if err := writeHello(c, h); err != nil {
		return reply{}, err
	}
	var rep reply
	if err := readHello(br, &rep); err != nil {
		return reply{}, err
	}
	if rep.OK && len(rep.Challenge) > 0 {
		sig := ed25519.Sign(key, popMessage(rep.Challenge, h.Identity))
		if err := writeHello(c, hello{Sig: sig}); err != nil {
			return reply{}, err
		}
		rep = reply{}
		if err := readHello(br, &rep); err != nil {
			return reply{}, err
		}
	}
	return rep, nil
}

// logf writes a timestamped diagnostic line to stderr. Events for machines go
// to stdout via emit; this is for humans debugging a field failure.
func logf(format string, args ...any) {
	emitMu.Lock()
	fmt.Fprintf(os.Stderr, "%s genadb: %s\n", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, args...))
	emitMu.Unlock()
}
