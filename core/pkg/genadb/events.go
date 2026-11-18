package genadb

import "time"

// Event types emitted by a Client.
const (
	EventPaired       = "paired"        // a new device was paired; Fields["device_id"]
	EventListening    = "listening"     // a session's local adb endpoint is up; Fields["addr"]
	EventSessionUp    = "session_up"    // Connect returned a live session
	EventSessionDown  = "session_down"  // a session ended; Fields["error"] if abnormal
	EventRetrying     = "retrying"      // a session is being restarted; Fields["attempt"], ["error"]
	EventAudit        = "audit"         // an audit record was written; Fields is the record
	EventError        = "error"         // a non-fatal error; Fields["error"]
	EventTokenUpdated = "token_updated" // SetToken accepted a token; Fields["subject"], ["token_id"], ["expires_at"]
	EventADBPair      = "adb_pair"      // PairADB finished; Fields["device_id"], ["paired"], ["transport"] or ["error"]

	// Path events (v1.1.0). Fields["session_id"] is the tunnel id, shared by
	// both ends; Fields["transport"] is lan | relay-tcp | relay-ws | relay-wss.
	EventPathDown = "path_down" // the tunnel's path broke and it is rejoining; ["reason"], ["transport"]
	EventPathUp   = "path_up"   // the tunnel rejoined; ["transport"] (possibly new), ["outage_ms"]
	EventPathLost = "path_lost" // rejoin gave up; the tunnel and its adb stream are gone; ["reason"], ["outage_ms"]

	// Session termination (v1.1.0), followed by session_down.
	EventSessionExpired = "session_expired" // corporate max_session_seconds reached; re-authenticate to reconnect
	EventPeerClosed     = "peer_closed"     // the device ended the session; ["peer_reason"], e.g. ended_on_device
)

// Event is a structured notification from the client or one of its sessions.
type Event struct {
	Time    time.Time      `json:"time"`
	Type    string         `json:"type"`
	Session string         `json:"session,omitempty"`
	Fields  map[string]any `json:"fields,omitempty"`
}
