package main

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
	"strings"
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

type transportOpts struct {
	proxy       string // http://host:port (CONNECT) ; "" = environment
	caFile      string // extra trusted CA / self-signed relay cert (PEM)
	fingerprint string // optional SHA-256 pin of the relay leaf certificate
}

var relayTransport transportOpts

func addTransportFlags(fs *flag.FlagSet) {
	fs.StringVar(&relayTransport.proxy, "proxy", "", "HTTP proxy for ws/wss relay URLs (default: HTTPS_PROXY/HTTP_PROXY)")
	fs.StringVar(&relayTransport.caFile, "relay-ca", "", "PEM file with a CA or certificate to trust for wss relays")
	fs.StringVar(&relayTransport.fingerprint, "relay-pin", "", "hex SHA-256 of the relay TLS certificate to pin")
}

func dialRelay(spec string) (net.Conn, error) {
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
		TLSHandshakeTimeout: 10 * time.Second, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}
	if relayTransport.proxy != "" {
		pu, err := url.Parse(relayTransport.proxy)
		if err != nil {
			return nil, fmt.Errorf("bad --proxy: %w", err)
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	tcfg, err := relayTLSConfig()
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
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
}

func relayTLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if relayTransport.caFile != "" {
		pem, err := os.ReadFile(relayTransport.caFile)
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
	if pin := strings.ToLower(strings.ReplaceAll(relayTransport.fingerprint, ":", "")); pin != "" {
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
func (r *relay) serveWebSocket(addr, certFile, keyFile string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
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
	return nil
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
