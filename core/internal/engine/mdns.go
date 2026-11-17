package engine

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Dynamic adbd endpoint discovery.
//
// Android's Wireless debugging listens on a random TLS port that changes
// every time it is toggled or the phone changes network. adbd advertises it
// over mDNS as _adb-tls-connect._tcp (pairing: _adb-tls-pairing._tcp; legacy
// tcpip: _adb._tcp). With --adbd auto the device agent resolves the endpoint
// by DNS-SD and re-resolves whenever a dial fails, so a port change never
// requires user action. (In the Android app this maps onto NsdManager.)
//
// Queries are sent as "legacy unicast" (source port != 5353), which RFC 6762
// section 6.7 requires responders to answer by unicast to the querier, so no
// multicast listener or port-5353 binding is needed.

var mdnsServer = "224.0.0.251:5353" // overridable for tests

type adbdResolver struct {
	static   string
	service  string // e.g. _adb-tls-connect._tcp.local.
	prefer   func(net.IP) bool
	fallback string // used when discovery finds nothing but this endpoint accepts a connection
	events   EventFunc

	mu   sync.Mutex
	last string
}

func newAdbdResolver(spec string) *adbdResolver {
	switch spec {
	case "auto":
		// Android 10 has no Wireless debugging: fall back to legacy `adb tcpip` adbd on loopback.
		return &adbdResolver{service: "_adb-tls-connect._tcp.local.", prefer: isLocalIP, fallback: "127.0.0.1:5555"}
	case "mdns":
		return &adbdResolver{service: "_adb-tls-connect._tcp.local.", prefer: isLocalIP}
	case "auto-legacy":
		return &adbdResolver{service: "_adb._tcp.local.", prefer: isLocalIP}
	}
	return &adbdResolver{static: spec}
}

// current returns the last known endpoint, resolving if needed.
func (r *adbdResolver) current() (string, error) {
	if r.static != "" {
		return r.static, nil
	}
	r.mu.Lock()
	last := r.last
	r.mu.Unlock()
	if last != "" {
		return last, nil
	}
	return r.refresh()
}

// refresh re-runs discovery (called after a failed dial).
func (r *adbdResolver) refresh() (string, error) {
	if r.static != "" {
		return r.static, nil
	}
	eps, err := browse(r.service, 1500*time.Millisecond)
	if err != nil && r.fallback == "" {
		return "", err
	}
	var pick string
	for _, ep := range eps {
		host, _, _ := net.SplitHostPort(ep)
		if pick == "" || (r.prefer != nil && r.prefer(net.ParseIP(host))) {
			pick = ep
		}
	}
	if pick == "" && r.fallback != "" {
		if c, derr := net.DialTimeout("tcp", r.fallback, 500*time.Millisecond); derr == nil {
			c.Close()
			pick = r.fallback
		}
	}
	if pick == "" {
		return "", fmt.Errorf("no %s service found (is Wireless debugging on?)", strings.TrimSuffix(r.service, ".local."))
	}
	r.mu.Lock()
	changed := pick != r.last
	r.last = pick
	r.mu.Unlock()
	if changed {
		if r.events != nil {
			r.events("adbd_endpoint", map[string]any{"addr": pick, "service": r.service})
		}
	}
	return pick, nil
}

func isLocalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// browse sends a DNS-SD PTR query and collects host:port endpoints from the
// PTR/SRV/A/AAAA records in the responses.
func browse(service string, wait time.Duration) ([]string, error) {
	dst, err := net.ResolveUDPAddr("udp", mdnsServer)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	name, err := dnsmessage.NewName(service)
	if err != nil {
		return nil, err
	}
	q := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: uint16(rand.IntN(65536))},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}},
	}
	pkt, err := q.Pack()
	if err != nil {
		return nil, err
	}
	srv := map[string]dnsmessage.SRVResource{} // instance -> SRV
	hosts := map[string][]net.IP{}             // target -> addrs
	instances := map[string]bool{}
	deadline := time.Now().Add(wait)
	for attempt := 0; attempt < 2; attempt++ {
		c.WriteToUDP(pkt, dst)
		c.SetReadDeadline(time.Now().Add(wait / 2))
		buf := make([]byte, 9000)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				break
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil {
				continue
			}
			for _, rr := range append(append(m.Answers, m.Additionals...), m.Authorities...) {
				nm := strings.ToLower(rr.Header.Name.String())
				switch b := rr.Body.(type) {
				case *dnsmessage.PTRResource:
					if strings.EqualFold(nm, service) {
						instances[strings.ToLower(b.PTR.String())] = true
					}
				case *dnsmessage.SRVResource:
					srv[nm] = *b
				case *dnsmessage.AResource:
					hosts[nm] = append(hosts[nm], net.IP(b.A[:]))
				case *dnsmessage.AAAAResource:
					hosts[nm] = append(hosts[nm], net.IP(b.AAAA[:]))
				}
			}
			_ = from
		}
		if len(instances) > 0 || time.Now().After(deadline) {
			break
		}
	}
	var out []string
	for inst := range instances {
		s, ok := srv[inst]
		if !ok {
			continue
		}
		for _, ip := range hosts[strings.ToLower(s.Target.String())] {
			out = append(out, net.JoinHostPort(ip.String(), fmt.Sprint(s.Port)))
		}
	}
	if len(out) == 0 && len(instances) > 0 {
		return nil, errors.New("mDNS: service found but no SRV/address records")
	}
	return out, nil
}
