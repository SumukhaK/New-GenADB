package engine

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Relay transports.
//
//   host:port        raw TCP (lowest overhead; LAN / permissive networks)
//   ws://host/path   WebSocket over TCP (works through HTTP proxies that
//                    allow upgrades)
//   wss://host/path  WebSocket over TLS on 443: indistinguishable from normal
//                    HTTPS to corporate firewalls, works through HTTP CONNECT
//                    proxies (--proxy or HTTPS_PROXY) and TLS-terminating
//                    reverse proxies / load balancers.
//
// The relay transport only carries the hello/routing exchange and our own
// end-to-end encrypted session, so TLS here protects metadata (device ids,
// tokens on the relay hop) rather than adb payloads, which are already E2E.

// TransportOptions configures how agents reach the relay.
type TransportOptions struct {
	Proxy  string // http://host:port (CONNECT) ; "" = environment
	CAFile string // extra trusted CA / self-signed relay cert (PEM)
	Pin    string // optional hex SHA-256 pin of the relay leaf certificate
}

// AddTransportFlags registers --proxy, --relay-ca and --relay-pin.
func AddTransportFlags(fs *flag.FlagSet, o *TransportOptions) {
	fs.StringVar(&o.Proxy, "proxy", "", "HTTP proxy for ws/wss relay URLs (default: HTTPS_PROXY/HTTP_PROXY)")
	fs.StringVar(&o.CAFile, "relay-ca", "", "PEM file with a CA or certificate to trust for wss relays")
	fs.StringVar(&o.Pin, "relay-pin", "", "hex SHA-256 of the relay TLS certificate to pin")
}

// Dialer opens a byte stream to the relay named by spec.
type Dialer func(spec string) (net.Conn, error)

// Dialer returns the default relay dialer for these options.
func (o TransportOptions) Dialer() Dialer {
	return func(spec string) (net.Conn, error) { return o.dialRelay(spec) }
}

// TransportLabel classifies a relay spec for audit records.
func TransportLabel(spec string) string {
	switch {
	case strings.HasPrefix(spec, "wss://"):
		return "relay-wss"
	case strings.HasPrefix(spec, "ws://"):
		return "relay-ws"
	}
	return "relay-tcp"
}

func (o TransportOptions) dialRelay(spec string) (net.Conn, error) {
	if !strings.Contains(spec, "://") {
		return dial(spec)
	}
	u, err := url.Parse(spec)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return nil, fmt.Errorf("unsupported relay scheme %q", u.Scheme)
	}
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: false,
		TLSHandshakeTimeout: 10 * time.Second, DialContext: relayDialContext}
	if o.Proxy != "" {
		pu, err := url.Parse(o.Proxy)
		if err != nil {
			return nil, fmt.Errorf("bad --proxy: %w", err)
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	tcfg, err := o.relayTLSConfig()
	if err != nil {
		return nil, err
	}
	tr.TLSClientConfig = tcfg
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, resp, err := websocket.Dial(ctx, spec, &websocket.DialOptions{HTTPClient: &http.Client{Transport: tr}})
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("relay websocket: %s: %w", resp.Status, err)
		}
		return nil, fmt.Errorf("relay websocket: %w", err)
	}
	c.SetReadLimit(-1)
	go wsKeepalive(c)
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
}

// wsKeepalive pings an otherwise idle WebSocket. Reverse proxies and tunnels
// (and carrier NATs) drop connections that carry nothing for a minute or two,
// which would bounce the device's control channel every couple of minutes.
// Pongs are only seen while someone reads the connection; relay clients
// always keep a reader running, so a missing pong means the path is dead.
func wsKeepalive(c *websocket.Conn) {
	tk := time.NewTicker(25 * time.Second)
	defer tk.Stop()
	for range tk.C {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := c.Ping(ctx)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				// No pong within 10 s while the reader is running: the
				// path is dead (e.g. a phone that lost its radio without a
				// reset). Close so both sides reconnect instead of hanging.
				c.Close(websocket.StatusGoingAway, "keepalive timeout")
			}
			return
		}
	}
}

// relayDialContext dials the relay (or proxy) host, remembering the addresses
// of the last successful lookup. Agents reconnect exactly when the network is
// misbehaving, which is also when DNS is slowest; falling back to the last
// known addresses keeps a flaky resolver from stretching every reconnect.
var relayAddrs, dnsFallbackWarned sync.Map // host -> []string, host -> bool

func relayDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host) != nil {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
	}
	lctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	ips, lerr := net.DefaultResolver.LookupHost(lctx, host)
	cancel()
	if lerr == nil && len(ips) > 0 {
		relayAddrs.Store(host, ips)
		dnsFallbackWarned.Delete(host)
	} else if v, ok := relayAddrs.Load(host); ok {
		if _, warned := dnsFallbackWarned.LoadOrStore(host, true); !warned {
			logf("DNS lookup for %s failed (%v); using last known addresses", host, lerr)
		}
		ips = v.([]string)
	} else {
		return nil, lerr
	}
	// IPv4 first, then IPv6, each with a short timeout: cellular networks
	// often advertise an IPv6 path that black-holes.
	sort.SliceStable(ips, func(i, j int) bool { return !strings.Contains(ips[i], ":") && strings.Contains(ips[j], ":") })
	var last error
	for _, ip := range ips {
		c, err := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

func (o TransportOptions) relayTLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("--relay-ca: no certificates found")
		}
		cfg.RootCAs = pool
	}
	if pin := strings.ToLower(strings.ReplaceAll(o.Pin, ":", "")); pin != "" {
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("relay presented no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if hex.EncodeToString(sum[:]) != pin {
				return errors.New("relay certificate does not match --relay-pin")
			}
			return nil
		}
	}
	return cfg, nil
}

// serveWebSocket accepts relay clients over ws:// (or wss:// when a
// certificate is given) and hands each upgraded stream to the relay.
func (r *relay) serveWebSocket(addr, certFile, keyFile string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		remote := req.RemoteAddr
		if r.trustForwarded {
			// Behind a reverse proxy / tunnel every client shares the proxy's
			// address; rate-limit and audit by the address it reports instead.
			if ip := forwardedIP(req); ip != "" {
				remote = net.JoinHostPort(ip, "0")
			}
		}
		if !r.allow(clientIP(remote), "ws-accept") {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		c, err := websocket.Accept(w, req, &websocket.AcceptOptions{})
		if err != nil {
			return
		}
		c.SetReadLimit(-1)
		go wsKeepalive(c)
		nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
		r.handle(&wsConn{Conn: nc, remote: remote})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if certFile != "" {
			srv.ServeTLS(ln, certFile, keyFile)
		} else {
			srv.Serve(ln)
		}
	}()
	return ln, nil
}

// wsConn reports the HTTP client address (useful for rate limiting/audit).
type wsConn struct {
	net.Conn
	remote string
}

func (w *wsConn) RemoteAddr() net.Addr { return wsAddr(w.remote) }

type wsAddr string

func (a wsAddr) Network() string { return "ws" }
func (a wsAddr) String() string  { return string(a) }

// forwardedIP returns the client address reported by a trusted reverse proxy.
func forwardedIP(req *http.Request) string {
	for _, h := range []string{"CF-Connecting-IP", "X-Real-IP"} {
		if ip := net.ParseIP(strings.TrimSpace(req.Header.Get(h))); ip != nil {
			return ip.String()
		}
	}
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		if ip := net.ParseIP(strings.TrimSpace(first)); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func clientIP(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}
