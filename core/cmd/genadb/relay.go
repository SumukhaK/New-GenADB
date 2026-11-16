package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"net"
	"sync"
	"time"
)

type hello struct {
	Role     string `json:"role"`
	DeviceID string `json:"device_id,omitempty"`
	Code     string `json:"code,omitempty"`
	SID      string `json:"sid,omitempty"`
	Probe    bool   `json:"probe,omitempty"`
	Identity string `json:"identity,omitempty"`
}

type reply struct {
	OK       bool   `json:"ok"`
	DeviceID string `json:"device_id,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Open     string `json:"open,omitempty"`
}

type deviceEntry struct {
	conn net.Conn
	code string
	wmu  sync.Mutex
}

type relay struct {
	mu      sync.Mutex
	devices map[string]*deviceEntry
	pending map[string]chan net.Conn // sid -> data conn from device
	pendR   map[string]*bufio.Reader
}

func cmdRelay(args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:7000", "listen address")
	fs.String("mode", "solo", "solo|corporate")
	fs.String("policy", "", "policy file (corporate)")
	fs.String("audit", "", "audit log path")
	fs.String("admin", "", "admin listen address")
	fs.String("admin-token", "", "admin bearer token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	r := &relay{devices: map[string]*deviceEntry{}, pending: map[string]chan net.Conn{}, pendR: map[string]*bufio.Reader{}}
	emit("ready", map[string]any{"addr": ln.Addr().String()})
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go r.handle(c)
	}
}

func (r *relay) handle(c net.Conn) {
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	var h hello
	if err := readHello(br, &h); err != nil {
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})
	switch h.Role {
	case "device":
		e := &deviceEntry{conn: c, code: h.Code}
		r.mu.Lock()
		r.devices[h.DeviceID] = e
		r.mu.Unlock()
		writeHello(c, reply{OK: true})
		// control connection: block until closed
		buf := make([]byte, 1)
		for {
			if _, err := br.Read(buf); err != nil {
				break
			}
		}
		r.mu.Lock()
		if r.devices[h.DeviceID] == e {
			delete(r.devices, h.DeviceID)
		}
		r.mu.Unlock()
		c.Close()
	case "data":
		r.mu.Lock()
		ch := r.pending[h.SID]
		r.pendR[h.SID] = br
		r.mu.Unlock()
		if ch == nil {
			c.Close()
			return
		}
		ch <- c
	case "desktop":
		r.mu.Lock()
		id := h.DeviceID
		if h.Code != "" {
			id = ""
			for did, e := range r.devices {
				if e.code == h.Code {
					id = did
				}
			}
		}
		e := r.devices[id]
		r.mu.Unlock()
		if e == nil {
			writeHello(c, reply{OK: false, Reason: "unknown device or code"})
			c.Close()
			return
		}
		if h.Probe {
			writeHello(c, reply{OK: true, DeviceID: id})
			c.Close()
			return
		}
		sidb := make([]byte, 8)
		rand.Read(sidb)
		sid := hex.EncodeToString(sidb)
		ch := make(chan net.Conn, 1)
		r.mu.Lock()
		r.pending[sid] = ch
		r.mu.Unlock()
		e.wmu.Lock()
		err := writeHello(e.conn, reply{OK: true, Open: sid})
		e.wmu.Unlock()
		var dc net.Conn
		if err == nil {
			select {
			case dc = <-ch:
			case <-time.After(10 * time.Second):
			}
		}
		r.mu.Lock()
		dbr := r.pendR[sid]
		delete(r.pending, sid)
		delete(r.pendR, sid)
		r.mu.Unlock()
		if dc == nil {
			writeHello(c, reply{OK: false, Reason: "device did not answer"})
			c.Close()
			return
		}
		writeHello(c, reply{OK: true, DeviceID: id})
		splice(c, br, dc, dbr)
	default:
		c.Close()
	}
}
