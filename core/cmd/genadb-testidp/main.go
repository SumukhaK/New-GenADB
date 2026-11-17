// genadb-testidp is a TEST-ONLY identity provider for exercising corporate
// mode on real devices. It plays the part an organisation's IdP / MDM would:
// it holds an Ed25519 signing key, writes the policy file that the relay and
// the agents load, and issues short-lived EdDSA JWTs bound to an agent key.
//
// It is deliberately a separate binary: nothing in genadb can mint tokens.
//
//	genadb-testidp init  --dir D --relay-id R --grant alice:dev-A,dev-B [--grant bob:]
//	genadb-testidp issue --dir D --sub alice --typ user   --key <agent pubkey> [--ttl 600]
//	genadb-testidp issue --dir D --sub dev-A --typ device --key <agent pubkey>
//	genadb-testidp issue ... --rogue        (signed by a fresh key the policy does not trust)
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const issuer = "https://idp.genadb.test"

var b64 = base64.RawURLEncoding

type grant struct {
	User    string   `json:"user"`
	Devices []string `json:"devices"`
}

type grantFlag []grant

func (g *grantFlag) String() string { return fmt.Sprint(*g) }
func (g *grantFlag) Set(v string) error {
	user, devs, ok := strings.Cut(v, ":")
	if !ok || user == "" {
		return fmt.Errorf("grant must be user:dev1,dev2")
	}
	gr := grant{User: user, Devices: []string{}}
	for _, d := range strings.Split(devs, ",") {
		if d != "" {
			gr.Devices = append(gr.Devices, d)
		}
	}
	*g = append(*g, gr)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: genadb-testidp init|issue ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "issue":
		err = cmdIssue(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "genadb-testidp:", err)
		os.Exit(1)
	}
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := fs.String("dir", ".", "directory for idp.key and policy.json")
	relayID := fs.String("relay-id", "", "relay id (token audience); random if empty")
	maxSess := fs.Int("max-session-seconds", 900, "maximum session length")
	var grants grantFlag
	fs.Var(&grants, "grant", "user:dev1,dev2 (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if *relayID == "" {
		b := make([]byte, 4)
		rand.Read(b)
		*relayID = "relay-" + hex.EncodeToString(b)
	}
	if grants == nil {
		grants = grantFlag{}
	}
	pol := map[string]any{"relay_id": *relayID, "issuer": issuer, "idp_ed25519_public_key": b64.EncodeToString(pub),
		"grants": []grant(grants), "max_session_seconds": *maxSess}
	pb, _ := json.MarshalIndent(pol, "", "  ")
	if err := os.WriteFile(filepath.Join(*dir, "idp.key"), []byte(b64.EncodeToString(priv.Seed())), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dir, "policy.json"), append(pb, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Println(*relayID)
	return nil
}

func cmdIssue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	dir := fs.String("dir", ".", "directory holding idp.key and policy.json")
	sub := fs.String("sub", "", "subject: user name or device id")
	typ := fs.String("typ", "user", "user|device")
	key := fs.String("key", "", "agent public key to bind (from `genadb keygen`)")
	ttl := fs.Int("ttl", 600, "lifetime in seconds (negative = already expired)")
	aud := fs.String("aud", "", "audience override (default: the policy's relay_id)")
	rogue := fs.Bool("rogue", false, "sign with a fresh key the policy does not trust")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sub == "" {
		return fmt.Errorf("--sub is required")
	}
	pb, err := os.ReadFile(filepath.Join(*dir, "policy.json"))
	if err != nil {
		return err
	}
	var pol struct {
		RelayID string `json:"relay_id"`
		Issuer  string `json:"issuer"`
	}
	if err := json.Unmarshal(pb, &pol); err != nil {
		return err
	}
	var priv ed25519.PrivateKey
	if *rogue {
		_, priv, _ = ed25519.GenerateKey(rand.Reader)
	} else {
		sb, err := os.ReadFile(filepath.Join(*dir, "idp.key"))
		if err != nil {
			return err
		}
		seed, err := b64.DecodeString(strings.TrimSpace(string(sb)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return fmt.Errorf("bad idp.key")
		}
		priv = ed25519.NewKeyFromSeed(seed)
	}
	if *aud == "" {
		*aud = pol.RelayID
	}
	now := time.Now().Unix()
	iat := now
	if *ttl < 0 {
		iat = now - 700
	}
	jti := make([]byte, 16)
	rand.Read(jti)
	claims := map[string]any{"iss": pol.Issuer, "sub": *sub, "aud": *aud, "typ": *typ, "iat": iat,
		"nbf": iat - 5, "exp": now + int64(*ttl), "jti": hex.EncodeToString(jti)}
	if *key != "" {
		claims["cnf"] = map[string]string{"key": *key}
	}
	hb, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	cb, _ := json.Marshal(claims)
	signing := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	fmt.Println(signing + "." + b64.EncodeToString(ed25519.Sign(priv, []byte(signing))))
	return nil
}
