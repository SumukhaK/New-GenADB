package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestSpakeAgreesOnlyWithSameCode(t *testing.T) {
	a := newSpake("A", "123456", "4242")
	b := newSpake("B", "123456", "4242")
	ka, err := a.finish(b.msg)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := b.finish(a.msg)
	if !bytes.Equal(ka, kb) {
		t.Fatal("same code must agree")
	}
	c := newSpake("B", "123457", "4242")
	kc, _ := c.finish(a.msg)
	ka2, _ := a.finish(c.msg)
	if bytes.Equal(kc, ka2) {
		t.Fatal("different codes must not agree")
	}
}

func TestLimiterBurstAndRefill(t *testing.T) {
	l := newLimiter()
	n := 0
	for l.take("1.2.3.4", "auth-fail", false) {
		n++
		if n > 1000 {
			t.Fatal("no limit")
		}
	}
	if n != int(relayRules["auth-fail"].burst) {
		t.Fatalf("burst %d", n)
	}
	if !l.take("5.6.7.8", "auth-fail", false) {
		t.Fatal("other IPs must be unaffected")
	}
}

func mkToken(t *testing.T, priv ed25519.PrivateKey, claims map[string]any) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	b, _ := json.Marshal(claims)
	p := base64.RawURLEncoding.EncodeToString(b)
	sig := ed25519.Sign(priv, []byte(h+"."+p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerifyToken(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	kpub, _, _ := ed25519.GenerateKey(rand.Reader)
	p := &policy{RelayID: "r1", Issuer: "iss", idp: pub}
	now := time.Now().Unix()
	base := func() map[string]any {
		return map[string]any{"iss": "iss", "aud": "r1", "sub": "alice", "typ": "user", "exp": now + 60,
			"cnf": map[string]any{"key": pubString64(kpub)}}
	}
	if _, err := p.verifyToken(mkToken(t, priv, base()), "user", kpub); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(m map[string]any){
		"expired": func(m map[string]any) { m["exp"] = now - 3600 },
		"aud":     func(m map[string]any) { m["aud"] = "other" },
		"typ":     func(m map[string]any) { m["typ"] = "device" },
		"iss":     func(m map[string]any) { m["iss"] = "evil" },
		"cnf":     func(m map[string]any) { m["cnf"] = map[string]any{"key": "x"} },
	}
	for name, f := range cases {
		m := base()
		f(m)
		if _, err := p.verifyToken(mkToken(t, priv, m), "user", kpub); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := p.verifyToken(mkToken(t, other, base()), "user", kpub); err == nil {
		t.Error("forged signature accepted")
	}
}

// fake mDNS responder answering legacy-unicast PTR queries
func fakeMDNS(t *testing.T, port uint16) string {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil || len(q.Questions) == 0 {
				continue
			}
			svc := q.Questions[0].Name
			inst := dnsmessage.MustNewName("adb-POCO-xyz." + svc.String())
			host := dnsmessage.MustNewName("Android.local.")
			hdr := func(nm dnsmessage.Name, typ dnsmessage.Type) dnsmessage.ResourceHeader {
				return dnsmessage.ResourceHeader{Name: nm, Type: typ, Class: dnsmessage.ClassINET, TTL: 120}
			}
			m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true},
				Questions: q.Questions,
				Answers:   []dnsmessage.Resource{{Header: hdr(svc, dnsmessage.TypePTR), Body: &dnsmessage.PTRResource{PTR: inst}}},
				Additionals: []dnsmessage.Resource{
					{Header: hdr(inst, dnsmessage.TypeSRV), Body: &dnsmessage.SRVResource{Port: port, Target: host}},
					{Header: hdr(host, dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}},
				}}
			b, _ := m.Pack()
			c.WriteToUDP(b, from)
		}
	}()
	return c.LocalAddr().String()
}

func TestAdbdDiscoveryFollowsPortChange(t *testing.T) {
	// two "adbd" listeners; the advertised one changes like a Wireless-debugging toggle
	l1, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l1.Close()
	p1 := uint16(l1.Addr().(*net.TCPAddr).Port)
	old := mdnsServer
	defer func() { mdnsServer = old }()
	mdnsServer = fakeMDNS(t, p1)
	d := &deviceAgent{adbd: newAdbdResolver("auto")}
	c, err := d.dialAdbd()
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// toggle: old port closes, a new one is advertised
	l1.Close()
	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l2.Close()
	mdnsServer = fakeMDNS(t, uint16(l2.Addr().(*net.TCPAddr).Port))
	c, err = d.dialAdbd()
	if err != nil {
		t.Fatalf("did not follow port change: %v", err)
	}
	c.Close()
	if got, _ := d.adbd.current(); got != l2.Addr().String() {
		t.Fatalf("resolver at %s, want %s", got, l2.Addr())
	}
}

func TestPinsPersist(t *testing.T) {
	dir := t.TempDir()
	k, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := savePeer(dir, "dev-1", k); err != nil {
		t.Fatal(err)
	}
	got, err := loadPeer(dir, "dev-1")
	if err != nil || !got.Equal(k) {
		t.Fatal("pin round trip failed")
	}
	if _, err := os.Stat(filepath.Join(dir, "peers")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPeer(dir, "dev-2"); err == nil || !os.IsNotExist(err) {
		t.Fatal("unknown device must not be pinned")
	}
}

// Android 10 has no Wireless debugging: --adbd auto must fall back to legacy tcpip adbd.
func TestAdbdAutoFallsBackToLegacy(t *testing.T) {
	old := mdnsServer
	defer func() { mdnsServer = old }()
	u, err := net.ListenPacket("udp", "127.0.0.1:0") // silent mDNS: nothing advertised
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	mdnsServer = u.LocalAddr().String()
	l, err := net.Listen("tcp", "127.0.0.1:0") // stands in for legacy adbd
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	r := newAdbdResolver("auto")
	r.fallback = l.Addr().String()
	if got, err := r.refresh(); err != nil || got != l.Addr().String() {
		t.Fatalf("got %q, %v; want fallback %s", got, err, l.Addr())
	}
	r = newAdbdResolver("mdns") // explicit mdns: no fallback
	if _, err := r.refresh(); err == nil {
		t.Fatal("mdns mode must not fall back")
	}
}
