package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
)

func cmdConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	relayAddr := fs.String("relay", "", "relay address")
	state := fs.String("state", ".", "state directory")
	listen := fs.String("listen", "127.0.0.1:0", "local adb endpoint to expose")
	fs.String("mode", "solo", "solo|corporate")
	code := fs.String("code", "", "pairing code shown on the phone")
	device := fs.String("device", "", "previously paired device id")
	fs.String("identity", "", "user identity JWT (corporate)")
	fs.String("policy", "", "policy file (corporate)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := loadOrCreateKey(*state); err != nil {
		return err
	}
	// resolve the device once (probe), then expose a local listener
	c, err := dial(*relayAddr)
	if err != nil {
		return err
	}
	br := bufio.NewReader(c)
	if err := writeHello(c, hello{Role: "desktop", Code: *code, DeviceID: *device, Probe: true}); err != nil {
		return err
	}
	var rep reply
	if err := readHello(br, &rep); err != nil {
		return err
	}
	c.Close()
	if !rep.OK {
		return fmt.Errorf("%w: %s", errDenied, rep.Reason)
	}
	id := rep.DeviceID
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	emit("listening", map[string]any{"addr": ln.Addr().String(), "device_id": id})
	for {
		a, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(a net.Conn) {
			c, err := dial(*relayAddr)
			if err != nil {
				a.Close()
				return
			}
			br := bufio.NewReader(c)
			if writeHello(c, hello{Role: "desktop", DeviceID: id}) != nil {
				a.Close()
				c.Close()
				return
			}
			var rep reply
			if readHello(br, &rep) != nil || !rep.OK {
				a.Close()
				c.Close()
				return
			}
			splice(a, a, c, br)
		}(a)
	}
}
