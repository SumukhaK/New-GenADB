package genadb

import "github.com/sumukhak/new-genadb/core/internal/engine"

// Sentinel errors. Errors returned by this package wrap one of these where
// the cause is known; test with errors.Is.
var (
	// ErrDenied: the relay, the device or policy refused the session.
	ErrDenied = engine.ErrDenied
	// ErrUnavailable: the device is offline, busy, or the relay is unreachable.
	ErrUnavailable = engine.ErrUnavailable
	// ErrNotPaired: no pin exists for the requested device; pair first.
	ErrNotPaired = engine.ErrNotPaired
	// ErrBadCode: the pairing code was wrong, expired or malformed.
	ErrBadCode = engine.ErrBadCode
	// ErrRevoked: the user or device credential has been revoked.
	ErrRevoked = engine.ErrRevoked
	// ErrTokenInvalid: a corporate token failed verification.
	ErrTokenInvalid = engine.ErrTokenInvalid
	// ErrTokenExpired: a corporate token is past its expiry.
	ErrTokenExpired = engine.ErrTokenExpired
	// ErrNoGrant: the corporate policy does not grant this user the device.
	ErrNoGrant = engine.ErrNoGrant
	// ErrBlocked: device management disallows debugging on the device.
	ErrBlocked = engine.ErrBlocked
	// ErrUnsupported: the device runs an agent without this capability
	// (for example adb pairing needs Setu-SDK 1.1.0 on the phone).
	ErrUnsupported = engine.ErrUnsupported
	// ErrADBPairFailed: adb pair through the bridge did not succeed.
	ErrADBPairFailed = engine.ErrADBPairFailed
	// ErrSessionExpired: the corporate max_session_seconds cap ended the
	// session. It is not retried: Connect again to re-authenticate.
	ErrSessionExpired = engine.ErrSessionExpired
	// ErrPeerClosed: the device ended the session on purpose (for example
	// SetuManager.endSession on the phone). It is not retried.
	ErrPeerClosed = engine.ErrPeerClosed
)

// Errors raised by the Client itself.
var (
	ErrClosed        = errorString("genadb: client closed")
	ErrNoRelay       = errorString("genadb: no relay configured (WithRelayURL)")
	ErrNoDevice      = errorString("genadb: a device id or a pairing code is required")
	ErrNoSession     = errorString("genadb: no such session")
	ErrAuditDisabled = errorString("genadb: audit logging is not enabled")
)

type errorString string

func (e errorString) Error() string { return string(e) }
