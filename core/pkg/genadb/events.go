package genadb

import "time"

// Event types emitted by a Client.
const (
	EventPaired      = "paired"       // a new device was paired; Fields["device_id"]
	EventListening   = "listening"    // a session's local adb endpoint is up; Fields["addr"]
	EventSessionUp   = "session_up"   // Connect returned a live session
	EventSessionDown = "session_down" // a session ended; Fields["error"] if abnormal
	EventRetrying    = "retrying"     // a session is being restarted; Fields["attempt"], ["error"]
	EventAudit       = "audit"        // an audit record was written; Fields is the record
	EventError       = "error"        // a non-fatal error; Fields["error"]
	EventADBPair     = "adb_pair"     // PairADB finished; Fields["device_id"], ["paired"], ["transport"] or ["error"]
)

// Event is a structured notification from the client or one of its sessions.
type Event struct {
	Time    time.Time      `json:"time"`
	Type    string         `json:"type"`
	Session string         `json:"session,omitempty"`
	Fields  map[string]any `json:"fields,omitempty"`
}
