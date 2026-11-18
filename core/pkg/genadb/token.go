package genadb

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sumukhak/new-genadb/core/internal/engine"
	"github.com/sumukhak/new-genadb/core/pkg/genadb/audit"
)

// TokenInfo describes a corporate identity token (never the token itself).
type TokenInfo struct {
	Subject   string    `json:"subject"`
	TokenID   string    `json:"token_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SetToken rotates the corporate identity token live. The token is verified
// first (signature, issuer, audience, expiry, type and binding to this
// machine's key) and rejected, keeping the current one, if it fails. Once
// accepted, every new adb connection, rejoin and reconnect of every live
// session presents it; nothing is restarted and no session drops.
//
// While sessions are live the new token must name the same subject: a
// different user would silently inherit another user's sessions. Stop the
// sessions first to switch users.
func (c *SetuClient) SetToken(token string) (TokenInfo, error) {
	token = strings.TrimSpace(token)
	if c.cfg.mode != ModeCorporate {
		return TokenInfo{}, fmt.Errorf("%w: identity tokens are only used in corporate mode", ErrDenied)
	}
	ti, err := engine.VerifyUserToken(c.cfg.policyPath, c.cfg.state, token)
	if err != nil {
		return TokenInfo{}, err
	}
	info := TokenInfo{Subject: ti.Subject, TokenID: ti.TokenID, ExpiresAt: ti.Expires}
	c.tokMu.Lock()
	prev := c.tokSubject
	if prev == "" {
		if cur, err := c.cfg.auth.Token(context.Background()); err == nil {
			if pi, err := engine.VerifyUserToken(c.cfg.policyPath, c.cfg.state, cur); err == nil {
				prev = pi.Subject
			}
		}
	}
	if prev != "" && prev != info.Subject && len(c.Sessions()) > 0 {
		c.tokMu.Unlock()
		return TokenInfo{}, fmt.Errorf("%w: %w: token is for %q but live sessions belong to %q; stop them first",
			ErrDenied, ErrTokenInvalid, info.Subject, prev)
	}
	c.tokOverride.Store(&token)
	c.tokSubject = info.Subject
	c.tokMu.Unlock()
	if c.sink != nil {
		c.sink.Write(audit.Event{"event": "token_rotated", "role": "desktop", "user": info.Subject,
			"token_id": info.TokenID, "expires_at": info.ExpiresAt.Format(time.RFC3339)})
	}
	c.emit(Event{Type: EventTokenUpdated, Fields: map[string]any{"subject": info.Subject, "token_id": info.TokenID,
		"expires_at": info.ExpiresAt.Format(time.RFC3339)}})
	return info, nil
}

// currentToken is the token to use now: the last one given to SetToken,
// else the AuthProvider's.
func (c *SetuClient) currentToken(ctx context.Context) (string, error) {
	if t := c.tokOverride.Load(); t != nil {
		return *t, nil
	}
	return c.cfg.auth.Token(ctx)
}

// WatchIdentityFile re-reads path every interval (default 2s) until ctx
// ends and hands changed contents to SetToken, so a corporate agent that
// rewrites the file (an SSO helper, a cron job) rotates the token without
// restarting anything. A rejected token is reported once as an EventError
// with Fields["source"]="identity_file" and the current token stays.
func (c *SetuClient) WatchIdentityFile(ctx context.Context, path string, interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	last := ""
	if b, err := os.ReadFile(path); err == nil {
		last = strings.TrimSpace(string(b))
	}
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
		b, err := os.ReadFile(path)
		if err != nil {
			continue // missing while a writer replaces it: try again next tick
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" || tok == last {
			continue
		}
		last = tok
		if _, err := c.SetToken(tok); err != nil {
			c.emit(Event{Type: EventError, Fields: map[string]any{"source": "identity_file", "path": path, "error": errText(err)}})
		}
	}
}
