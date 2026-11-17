package engine

import (
	"context"
	"net"
	"os"
	"strings"
	"sync/atomic"
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
	var next atomic.Uint32
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// The resolver retries by dialling again; rotate so a server that
			// is slow or unreachable on this network is not asked every time
			// (a UDP "dial" always succeeds, so errors alone cannot rotate).
			d := net.Dialer{Timeout: 2 * time.Second}
			start := int(next.Add(1)-1) % len(servers)
			var last error
			for i := range servers {
				c, err := d.DialContext(ctx, network, servers[(start+i)%len(servers)])
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		},
	}
}
