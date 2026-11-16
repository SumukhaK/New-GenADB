package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type desktopAgent struct {
	relayAddr, state, token string
	key                     ed25519.PrivateKey
}

func cmdConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	relayAddr := fs.String("relay", "", "relay address")
	state := fs.String("state", ".", "state directory")
	listen := fs.String("listen", "127.0.0.1:0", "local adb endpoint to expose")
	mode := fs.String("mode", "solo", "solo|corporate")
	code := fs.String("code", "", "pairing code shown on the phone (NNNN-SSSSSS)")
	device := fs.String("device", "", "previously paired device id")
	identity := fs.String("identity", "", "user identity JWT (corporate)")
	policyPath := fs.String("policy", "", "policy file (corporate)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := loadOrCreateKey(*state)
	if err != nil {
		return err
	}
	a := &desktopAgent{relayAddr: *relayAddr, state: *state, key: key, token: *identity}
	params := initiatorParams{id: key, mode: "resume", token: *identity}
	if *mode == "corporate" {
		if *identity == "" {
			return fmt.Errorf("%w: corporate mode requires --identity", errDenied)
		}
		pol, err := loadPolicy(*policyPath)
		if err != nil {
			return err
		}
		if *device == "" {
			return fmt.Errorf("corporate mode requires --device")
		}
		want := *device
		// the device must prove an MDM enrollment bound to the key it uses
		params.verifyPeer = func(peer ed25519.PublicKey, tok string) error {
			cl, err := pol.verifyToken(tok, "device", peer)
			if err != nil {
				return fmt.Errorf("device enrollment: %w", err)
			}
			if cl.Sub != want {
				return fmt.Errorf("device enrollment is for %q, not %q", cl.Sub, want)
			}
			return nil
		}
	}
	id := *device
	if *code != "" {
		np, secret, ok := strings.Cut(*code, "-")
		if !ok {
			return fmt.Errorf("pairing code must look like NNNN-SSSSSS")
		}
		c, br, did, err := a.openSession(hello{Role: "desktop", Code: np})
		if err != nil {
			return err
		}
		_, peer, err := clientHandshake(c, br, initiatorParams{id: key, mode: "pair", secret: secret, nameplate: np})
		c.Close()
		if err != nil {
			return fmt.Errorf("%w: %v", errDenied, err)
		}
		if err := savePeer(*state, did, peer); err != nil {
			return err
		}
		id = did
	}
	if *mode != "corporate" {
		pinned, err := loadPeer(*state, id)
		if err != nil {
			return fmt.Errorf("%w: device %q is not paired with this computer", errDenied, id)
		}
		params.pinnedPeer = pinned
	}
	// verify the device is reachable and still trusts us before exposing a port
	c, br, _, err := a.openSession(hello{Role: "desktop", DeviceID: id})
	if err != nil {
		return err
	}
	_, _, err = clientHandshake(c, br, params)
	c.Close()
	if err != nil {
		return fmt.Errorf("%w: %v", errDenied, err)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	emit("listening", map[string]any{"addr": ln.Addr().String(), "device_id": id})
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(conn net.Conn) {
			c, br, _, err := a.openSession(hello{Role: "desktop", DeviceID: id})
			if err != nil {
				conn.Close()
				return
			}
			sc, _, err := clientHandshake(c, br, params)
			if err != nil {
				conn.Close()
				c.Close()
				return
			}
			splice(conn, conn, sc, sc)
		}(conn)
	}
}

// openSession asks the relay for a spliced stream to the device.
func (a *desktopAgent) openSession(h hello) (net.Conn, *bufio.Reader, string, error) {
	c, err := dial(a.relayAddr)
	if err != nil {
		return nil, nil, "", err
	}
	br := bufio.NewReader(c)
	h.Identity = a.token
	rep, err := relayHello(c, br, h, a.key)
	if err != nil {
		c.Close()
		return nil, nil, "", err
	}
	if !rep.OK {
		c.Close()
		return nil, nil, "", fmt.Errorf("%w: %s", errDenied, rep.Reason)
	}
	return c, br, rep.DeviceID, nil
}

func peerPath(state, id string) string {
	return filepath.Join(state, "peers", base64.RawURLEncoding.EncodeToString([]byte(id)))
}

func savePeer(state, id string, k ed25519.PublicKey) error {
	if err := os.MkdirAll(filepath.Join(state, "peers"), 0o700); err != nil {
		return err
	}
	return os.WriteFile(peerPath(state, id), []byte(base64.RawURLEncoding.EncodeToString(k)), 0o600)
}

func loadPeer(state, id string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(peerPath(state, id))
	if err != nil {
		return nil, err
	}
	k, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("corrupt pin")
	}
	return ed25519.PublicKey(k), nil
}
