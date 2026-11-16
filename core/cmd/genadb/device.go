package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func cmdDevice(args []string) error {
	fs := flag.NewFlagSet("device", flag.ContinueOnError)
	relayAddr := fs.String("relay", "", "relay address")
	adbd := fs.String("adbd", "127.0.0.1:5555", "local adbd endpoint")
	state := fs.String("state", ".", "state directory")
	mode := fs.String("mode", "solo", "solo|corporate")
	fs.String("name", "", "device name")
	enroll := fs.String("enroll", "", "device enrollment JWT (corporate)")
	fs.String("policy", "", "policy file (corporate)")
	fs.String("debug-policy", "allowed", "allowed|disallowed (MDM DISALLOW_DEBUGGING_FEATURES)")
	fs.String("lan-listen", "", "LAN listen address")
	fs.String("lan-advertise", "", "LAN advertised address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := loadOrCreateKey(*state); err != nil {
		return err
	}
	id, err := deviceID(*state, *mode, *enroll)
	if err != nil {
		return err
	}
	code := ""
	if *mode == "solo" {
		code = newCode()
	}
	announced := false
	for {
		err := deviceSession(*relayAddr, *adbd, id, code, &announced)
		fmt.Fprintln(os.Stderr, "device session ended:", err)
		time.Sleep(time.Second)
	}
}

func deviceSession(relayAddr, adbd, id, code string, announced *bool) error {
	c, err := dial(relayAddr)
	if err != nil {
		return err
	}
	defer c.Close()
	br := bufio.NewReader(c)
	if err := writeHello(c, hello{Role: "device", DeviceID: id, Code: code}); err != nil {
		return err
	}
	var rep reply
	if err := readHello(br, &rep); err != nil {
		return err
	}
	if !*announced {
		emit("online", map[string]any{"device_id": id})
		if code != "" {
			emit("pairing_code", map[string]any{"code": code, "device_id": id})
		}
		*announced = true
	}
	for {
		var m reply
		if err := readHello(br, &m); err != nil {
			return err
		}
		if m.Open != "" {
			go openData(relayAddr, adbd, m.Open)
		}
	}
}

func openData(relayAddr, adbd, sid string) {
	a, err := dial(adbd)
	if err != nil {
		return
	}
	c, err := dial(relayAddr)
	if err != nil {
		a.Close()
		return
	}
	if err := writeHello(c, hello{Role: "data", SID: sid}); err != nil {
		a.Close()
		c.Close()
		return
	}
	splice(c, c, a, a)
}

func deviceID(state, mode, enroll string) (string, error) {
	if mode == "corporate" && enroll != "" {
		parts := strings.Split(enroll, ".")
		if len(parts) == 3 {
			if b, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				var cl struct {
					Sub string `json:"sub"`
				}
				if json.Unmarshal(b, &cl) == nil && cl.Sub != "" {
					return cl.Sub, nil
				}
			}
		}
	}
	p := filepath.Join(state, "device_id")
	if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
		return strings.TrimSpace(string(b)), nil
	}
	b := make([]byte, 6)
	rand.Read(b)
	id := "dev-" + base64.RawURLEncoding.EncodeToString(b)
	return id, os.WriteFile(p, []byte(id), 0o600)
}

func newCode() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1_000_000))
	return fmt.Sprintf("%06d", n.Int64())
}
