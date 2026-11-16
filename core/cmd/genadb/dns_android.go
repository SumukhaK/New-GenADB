package main

import (
	"context"
	"net"
	"os"
	"strings"
	"time"
)

// A statically linked Go binary on Android has no usable system resolver:
// there is no /etc/resolv.conf, so the pure-Go resolver falls back to
// localhost:53 and every hostname lookup fails. When the agent runs as a
// plain executable (adb shell, Termux, or the companion app's native process)
// resolve relay hostnames through explicit DNS servers instead.
//
// GENADB_DNS overrides the servers (comma-separated host[:port]); the
// companion app passes the active network's DNS servers this way.
func init() {
	if _, err := os.Stat("/etc/resolv.conf"); err == nil {
		return
	}
	servers := []string{"8.8.8.8:53", "1.1.1.1:53", "[2001:4860:4860::8888]:53"}
	if env := os.Getenv("GENADB_DNS"); env != "" {
		servers = nil
		for _, s := range strings.Split(env, ",") {
			if s = strings.TrimSpace(s); s == "" {
				continue
			}
			if _, _, err := net.SplitHostPort(s); err != nil {
				s = net.JoinHostPort(s, "53")
			}
			servers = append(servers, s)
		}
	}
	if len(servers) == 0 {
		return
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			var last error
			for _, s := range servers {
				c, err := d.DialContext(ctx, network, s)
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		},
	}
}
