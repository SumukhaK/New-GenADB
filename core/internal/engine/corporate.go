package engine

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// policy is the corporate configuration pushed by the organisation (relay)
// or by MDM (device / desktop).
type policy struct {
	RelayID string `json:"relay_id"`
	Issuer  string `json:"issuer"`
	IdPKey  string `json:"idp_ed25519_public_key"`
	Grants  []struct {
		User    string   `json:"user"`
		Devices []string `json:"devices"`
	} `json:"grants"`
	MaxSessionSeconds int `json:"max_session_seconds"`

	idp ed25519.PublicKey
}

func loadPolicy(path string) (*policy, error) {
	if path == "" {
		return nil, errors.New("corporate mode requires --policy")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := &policy{}
	if err := json.Unmarshal(b, p); err != nil {
		return nil, err
	}
	k, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(p.IdPKey, "="))
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, errors.New("policy: bad idp_ed25519_public_key")
	}
	p.idp = k
	return p, nil
}

func (p *policy) granted(user, device string) bool {
	for _, g := range p.Grants {
		if g.User == user {
			for _, d := range g.Devices {
				if d == device {
					return true
				}
			}
		}
	}
	return false
}

// devicesFor lists the devices granted to user, sorted and de-duplicated.
func (p *policy) devicesFor(user string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, g := range p.Grants {
		if g.User != user {
			continue
		}
		for _, d := range g.Devices {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	sort.Strings(out)
	return out
}

type claims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud any    `json:"aud"`
	Typ string `json:"typ"`
	Iat int64  `json:"iat"`
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`
	Cnf struct {
		Key string `json:"key"`
	} `json:"cnf"`
}

func (c *claims) hasAud(want string) bool {
	switch a := c.Aud.(type) {
	case string:
		return a == want
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// verifyToken checks an EdDSA JWT against the policy: signature, issuer,
// audience, validity window, token type and (optionally) the bound key.
func (p *policy) verifyToken(tok, typ string, boundKey ed25519.PublicKey) (*claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("malformed token header")
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(hb, &hdr) != nil || hdr.Alg != "EdDSA" {
		return nil, errors.New("unsupported token algorithm")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(p.idp, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, errors.New("token signature invalid")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed token payload")
	}
	c := &claims{}
	if err := json.Unmarshal(pb, c); err != nil {
		return nil, errors.New("malformed token claims")
	}
	now := time.Now().Unix()
	const skew = 30
	switch {
	case c.Iss != p.Issuer:
		return nil, errors.New("token issuer mismatch")
	case !c.hasAud(p.RelayID):
		return nil, errors.New("token audience mismatch")
	case c.Exp == 0 || now > c.Exp+skew:
		return nil, errors.New("token expired")
	case c.Nbf != 0 && now+skew < c.Nbf:
		return nil, errors.New("token not yet valid")
	case c.Typ != typ:
		return nil, fmt.Errorf("token type %q, want %q", c.Typ, typ)
	case c.Sub == "":
		return nil, errors.New("token has no subject")
	}
	if boundKey != nil && c.Cnf.Key != pubString64(boundKey) {
		return nil, errors.New("token is not bound to this key")
	}
	return c, nil
}

func pubString64(k ed25519.PublicKey) string { return base64.RawURLEncoding.EncodeToString(k) }

func popMessage(challenge []byte, token string) []byte {
	th := sha256.Sum256([]byte(token))
	return append(append([]byte("genadb-relay-pop-v1"), challenge...), th[:]...)
}

// TokenInfo is what a verified user token says (never the token itself).
type TokenInfo struct {
	Subject string
	TokenID string
	Expires time.Time
}

// VerifyUserToken checks a corporate user token the way the relay and the
// device will: signature, issuer, audience, validity, type "user", and its
// binding to this machine's identity key in state. Failures wrap ErrDenied
// and ErrTokenExpired or ErrTokenInvalid.
func VerifyUserToken(policyPath, state, token string) (TokenInfo, error) {
	pol, err := loadPolicy(policyPath)
	if err != nil {
		return TokenInfo{}, err
	}
	key, err := loadOrCreateKey(state)
	if err != nil {
		return TokenInfo{}, err
	}
	cl, err := pol.verifyToken(token, "user", key.Public().(ed25519.PublicKey))
	if err != nil {
		return TokenInfo{}, deniedError("token: " + err.Error())
	}
	return TokenInfo{Subject: cl.Sub, TokenID: cl.Jti, Expires: time.Unix(cl.Exp, 0).UTC()}, nil
}
