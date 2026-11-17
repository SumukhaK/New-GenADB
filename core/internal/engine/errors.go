package engine

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors. Every refusal wraps ErrDenied, plus a more specific
// sentinel when the reason is known, so callers can use errors.Is at either
// level. Transient conditions wrap ErrUnavailable and are retried internally.
var (
	ErrDenied       = errors.New("denied")
	ErrUnavailable  = errors.New("device unavailable")
	ErrNotPaired    = errors.New("device not paired with this computer")
	ErrBadCode      = errors.New("pairing code rejected")
	ErrRevoked      = errors.New("access revoked")
	ErrTokenInvalid = errors.New("identity token invalid")
	ErrTokenExpired = errors.New("identity token expired")
	ErrNoGrant      = errors.New("no grant for this device")
	ErrBlocked      = errors.New("debugging disallowed by device policy")
)

var errDenied = ErrDenied

// deniedError maps a relay refusal reason to a typed error.
func deniedError(reason string) error {
	var specific error
	switch {
	case reason == "revoked":
		specific = ErrRevoked
	case strings.Contains(reason, "expired"):
		specific = ErrTokenExpired
	case strings.Contains(reason, "no grant"):
		specific = ErrNoGrant
	case strings.Contains(reason, "token"):
		specific = ErrTokenInvalid
	}
	if specific == nil {
		return fmt.Errorf("%w: %s", ErrDenied, reason)
	}
	return fmt.Errorf("%w: %w: %s", ErrDenied, specific, reason)
}
