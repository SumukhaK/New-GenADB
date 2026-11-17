# Setu (Setu-SDK) API specification

Version 1.0.1. Setu is an encrypted bridge between your IDE and any Android device, anywhere. This document is the contract for front ends, including the separate `genadb-ui` repository, IDE plugins and device-lab tooling. It covers four surfaces:

1. [Go SDK](#1-go-sdk-pkggenadb): `github.com/sumukhak/new-genadb/core/pkg/genadb`
2. [Daemon JSON-RPC protocol](#2-daemon-json-rpc-20-protocol): `setu-daemon`
3. [Audit record and report schema](#3-audit-record-and-report-schema)
4. [Android SDK](#4-android-sdk-setu-android): `dev.genadb.sdk.SetuManager`

The CLI's JSON-lines events (`setu device` and `setu connect` print one JSON object per line on stdout) use the same event names as section 1.4.

Compatibility: within 0.x, fields and methods may be added, never renamed or removed without a minor version bump. Clients must ignore unknown fields and event types.

---

**Names before v1.0.1.** The project was called New-GenADB until v1.0.1. Every old name still works, and new code should use the Setu names:

| Before 1.0.1 | Since 1.0.1 | Compatibility |
|---|---|---|
| `genadb`, `genadb-daemon` | `setu`, `setu-daemon` | Same programs: identical flags, output and exit codes |
| `genadb.Client`, `genadb.Session` | `genadb.SetuClient`, `genadb.SetuSession` | Type aliases: the same types |
| `GenAdbManager` | `SetuManager` | Deprecated subclass with the same Builder and companion, sharing the process-wide instance |
| `GenAdbConfig` | `SetuConfig` | Deprecated typealias |

The Go module path, the Kotlin package `dev.genadb.sdk`, the state directories, the `GENADB_*` environment variables, the `X-GenADB-*` webhook headers and the wire protocol are unchanged.

## 1. Go SDK (`pkg/genadb`)

### 1.1 SetuClient

```go
func New(opts ...Option) (*SetuClient, error)

func (c *SetuClient) Connect(ctx context.Context, req ConnectRequest) (*SetuSession, error)
func (c *SetuClient) Session(id string) (*SetuSession, bool)
func (c *SetuClient) Sessions() []*SetuSession                       // live sessions, oldest first
func (c *SetuClient) Devices(ctx context.Context) ([]DeviceInfo, error)
func (c *SetuClient) Forget(deviceID string) error               // drop a pairing
func (c *SetuClient) PublicKey() (string, error)                 // identity key that token issuers bind to
func (c *SetuClient) ExportAuditReport(w io.Writer, f audit.Format, opt audit.Options) error
func (c *SetuClient) Doctor(ctx context.Context) DoctorReport
func (c *SetuClient) HostDevice(ctx context.Context, h HostConfig) error   // device side
func (c *SetuClient) Events() <-chan Event
func (c *SetuClient) Mode() Mode
func (c *SetuClient) StateDir() string
func (c *SetuClient) AuditPath() string                          // "" when audit is off
func (c *SetuClient) Close() error                               // stops sessions, closes audit
```

`ConnectRequest`:

| Field | Meaning |
|---|---|
| `DeviceID` | A paired (solo) or granted (corporate) device |
| `PairingCode` | The code shown on the phone, `NNNN-XXXXXX`. Pairs first, then connects (solo only) |
| `Listen` | Local adb endpoint. The default is `127.0.0.1:0`, which picks any free port |

`Connect` returns once the local endpoint is listening, or with the first error; it never retries before the session is up. A mistyped, expired or burned pairing code fails fast with `ErrBadCode`, and a relay that does not answer within 20 s fails with `ErrUnavailable`. If `ctx` ends first, the error wraps `ctx.Err()` and the last session error.

### 1.2 SetuSession

```go
func (s *SetuSession) ID() string            // "s1", "s2", … unique per SetuClient
func (s *SetuSession) ADBAddr() string       // pass to `adb connect`
func (s *SetuSession) DeviceID() string
func (s *SetuSession) Started() time.Time
func (s *SetuSession) Done() <-chan struct{}
func (s *SetuSession) Err() error            // blocks until done; nil after Stop
func (s *SetuSession) Stop()                 // ends the session and waits
```

When a session is restarted under its reconnect policy, it keeps the same `ADBAddr`, so IDEs keep working.

### 1.3 Options

| Option | Default | Notes |
|---|---|---|
| `WithRelayURL(url)` | none (required for Connect) | `host:port`, `ws://…` or `wss://…` |
| `WithStateDir(dir)` | user config dir + `/genadb` | `~/` is expanded. Holds the identity key, device pins and audit log |
| `WithMode(ModeSolo \| ModeCorporate)` | solo | |
| `WithCorporateToken(token, policyPath)` | n/a | Implies corporate mode |
| `WithAuthProvider(p, policyPath)` | n/a | Corporate mode with a refreshing token source |
| `WithAuditConfig(AuditConfig)` | `AuditAuto` | See below |
| `WithReconnectPolicy(ReconnectPolicy)` | `DefaultReconnectPolicy` (forever, 1 s to 30 s backoff) | Restarts a session that was up and then failed. `NoReconnect` ends it instead. Denials are never retried |
| `WithTransportOptions(TransportOptions{Proxy, CAFile, Pin})` | environment proxy | For ws and wss relays |
| `WithTransport(TransportProvider)` | built-in | Replaces the relay dialer |
| `WithDeviceDiscoverer(DeviceDiscoverer)` | paired devices in the state directory | |
| `WithEventHandler(func(Event))` | none | Synchronous, lossless; must not block |
| `WithEventBuffer(n)` | 256 | Capacity of `Events()`. Events are dropped when it is full |
| `WithLogger(func(string))` | stderr | Process-wide |

`AuditConfig`:

| Field | Meaning |
|---|---|
| `Mode` | `AuditAuto` (default: on in corporate mode only), `AuditOn` or `AuditOff`. `AuditOff` is rejected in corporate mode |
| `Path` | Log file. The default is `<state>/audit.jsonl` |
| `WebhookURL`, `WebhookSecret` | Forward every sealed record, signed (section 3.4) |
| `Sinks` | Extra `AuditSink`s; each receives the sealed records |
| `AnchorKeyFile` | Key that signs the log's anchor (section 3.3.1). The default is `audit-anchor.key` next to the log, created on first use |

The command line follows the same rule: in corporate mode (or whenever `--identity` is given), `setu connect` logs to `<state>/audit.jsonl` and `setu relay` to `<state>/relay-audit.jsonl` unless `--audit PATH` names another file, and `--audit=off` is refused. Both take `--audit-anchor-key-file`. `setu audit verify|report|rotate` accept `--anchor-key-file`.

### 1.4 Interfaces

```go
type TransportProvider interface {
    Dial(spec string) (net.Conn, error)
    Label(spec string) string          // "relay-tcp" | "relay-ws" | "relay-wss"
}
type AuthProvider interface { Token(ctx context.Context) (string, error) }
type AuditSink = audit.Sink           // Write(audit.Event) error; Close() error
type DeviceDiscoverer interface { Devices(ctx context.Context) ([]DeviceInfo, error) }

type DeviceInfo struct { ID string; Paired bool; Source string }
```

### 1.5 Events

```go
type Event struct {
    Time    time.Time
    Type    string
    Session string          // client session id, "device" for HostDevice, or empty
    Fields  map[string]any
}
```

| Type | Fields | When |
|---|---|---|
| `paired` | `device_id` | A pairing code was accepted |
| `listening` | `addr`, `device_id` | A session's local endpoint is up |
| `session_up` | `addr`, `device_id` | `Connect` returned |
| `retrying` | `attempt`, `error`, `delay_ms` | A session is being restarted |
| `session_down` | `error` (if abnormal) | A session ended |
| `audit` | the sealed audit record | Audit on: every record written |
| `pairing_code` | `code`, `device_id` | Device side: show this code to the user |
| `online` | `device_id` | Device side: registered with the relay |
| `blocked` | `reason` | Device side: debugging disallowed by device management |
| `adbd_endpoint` | `addr` | Device side: adbd discovered |
| `adbd_unreachable` | `reason` | Device side: Wireless debugging is off or unreachable |
| `error` | `reason` | CLI only: fatal error before exit |

### 1.6 Errors

Use `errors.Is`. Denials wrap both `ErrDenied` and the specific cause.

| Sentinel | Meaning | Retried by the reconnect policy |
|---|---|---|
| `ErrDenied` | Refused by relay, device or policy (parent of the next six) | no |
| `ErrBadCode` | Wrong, expired or malformed pairing code | no |
| `ErrNotPaired` | No pairing exists for this device | no |
| `ErrRevoked` | User or device credential revoked | no |
| `ErrTokenInvalid` / `ErrTokenExpired` | Corporate token failed verification or has expired | no |
| `ErrNoGrant` | Policy does not grant this user the device | no |
| `ErrBlocked` | Device management disallows debugging | no |
| `ErrUnavailable` | Device offline or busy, or relay unreachable | yes |
| `ErrNoRelay`, `ErrNoDevice`, `ErrNoSession`, `ErrClosed`, `ErrAuditDisabled` | Misuse of the client | n/a |

### 1.7 Diagnostics

```go
func Diagnose(ctx context.Context, o DoctorOptions) DoctorReport
type DoctorReport struct { Version, Platform string; OK bool; Checks []Check }
type Check struct { Name string; Status CheckStatus; Detail, Hint string }  // ok | warn | fail | skip
```

The checks are `adb`, `state`, `paired_devices`, `proxy_env`, `relay_dns`, `relay_reach` and `audit_log`. They never send credentials. Proxy credentials are not printed. `setu doctor [--json]` prints the same report.

---

## 2. Daemon JSON-RPC 2.0 protocol

`setu-daemon` (or `genadb-daemon`) wraps one `SetuClient`. Transport:

- **TCP (default)**: `127.0.0.1:7605`. Only loopback addresses are accepted. The first call on each connection must be `auth` with the token from `<state>/daemon.token`, a file with mode 0600 created on first start.
- **stdio** (`--stdio`): a single client on stdin and stdout, with no token. Use it when the daemon is a child process of the UI.

Framing: one JSON-RPC 2.0 object per line, UTF-8, newline-terminated, at most 1 MiB. Requests without `id` are notifications and get no response. Batches are not supported.

Startup flags mirror the CLI:

```
--relay, --state, --mode solo|corporate, --identity-file, --policy,
--audit auto|on|off, --audit-log, --audit-anchor-key-file, --audit-webhook-url, --audit-webhook-secret-file,
--proxy, --relay-ca, --relay-pin, --listen, --stdio
```

The webhook secret can also be supplied in `$GENADB_AUDIT_WEBHOOK_SECRET`.

### 2.1 Methods

| Method | Params | Result |
|---|---|---|
| `auth` | `{token}` | `{ok: true}` |
| `version` | none | `{version, mode, audit: bool}` |
| `doctor` | none | `DoctorReport` (section 1.7, JSON field names in lower snake case) |
| `identity.public_key` | none | `{public_key}` |
| `devices.list` | none | `{devices: [{id, paired, source}]}` |
| `devices.forget` | `{device_id}` | `{}` |
| `session.connect` | `{device_id?, pairing_code?, listen?, timeout_ms?}` (default timeout 60000) | `SessionInfo` |
| `session.list` | none | `{sessions: [SessionInfo]}` |
| `session.stop` | `{session_id}` | `{}` |
| `events.subscribe` | none | `{subscribed: true}`. This connection then receives `event` notifications |
| `events.unsubscribe` | none | `{subscribed: false}` |
| `audit.report` | `{format: "json"\|"csv"\|"html", since?, until?, include_events?}` (RFC 3339 times) | JSON: `{format, report: Report}`. CSV and HTML: `{format, content: string}` |
| `audit.verify` | none | `ChainStatus` (section 3.3) |

`SessionInfo` is `{session_id, adb_addr, device_id, started}`.

Unknown params fields are rejected with `-32602`.

### 2.2 Notifications

```json
{"jsonrpc":"2.0","method":"event","params":{"time":"2026-11-17T09:12:03.1Z","type":"session_up","session":"s1","fields":{"addr":"127.0.0.1:41377","device_id":"pixel-7"}}}
```

`params` is an Event (section 1.5).

### 2.3 Errors

| Code | `data.kind` | Meaning |
|---|---|---|
| -32700 | | Parse error |
| -32600 | | Invalid request |
| -32601 | | Method not found |
| -32602 | | Invalid params |
| -32603 | | Internal error |
| -32001 | | Unauthorized (call `auth`) |
| -32010 | `denied` | |
| -32011 | `unavailable` | |
| -32012 | `not_paired` | |
| -32013 | `bad_code` | |
| -32014 | `revoked` | |
| -32015 | `token_invalid` | |
| -32016 | `token_expired` | |
| -32017 | `no_grant` | |
| -32018 | `blocked` | |
| -32020 | `no_session` | |
| -32021 | `audit_disabled` | |

The most specific code wins. For example, a wrong pairing code returns -32013 rather than -32010.

### 2.4 Example

```
→ {"jsonrpc":"2.0","id":1,"method":"auth","params":{"token":"…"}}
← {"jsonrpc":"2.0","id":1,"result":{"ok":true}}
→ {"jsonrpc":"2.0","id":2,"method":"events.subscribe"}
← {"jsonrpc":"2.0","id":2,"result":{"subscribed":true}}
→ {"jsonrpc":"2.0","id":3,"method":"session.connect","params":{"pairing_code":"4821-K7QZPM"}}
← {"jsonrpc":"2.0","method":"event","params":{"type":"paired",…}}
← {"jsonrpc":"2.0","id":3,"result":{"session_id":"s1","adb_addr":"127.0.0.1:41377","device_id":"pixel-7","started":"…"}}
```

---

## 3. Audit record and report schema

### 3.1 Record

Records are stored one JSON object per line. Every record has these fields:

| Field | Type | Meaning |
|---|---|---|
| `seq` | int | 1-based position in this log |
| `ts` | string | RFC 3339 UTC |
| `event` | string | See below |
| `prev_event_hash` | hex string | `event_hash` of the previous record; 64 zeros for the first |
| `event_hash` | hex string | SHA-256 of the record's canonical JSON without `event_hash` |

Canonical JSON means compact JSON, object keys sorted, and Go `encoding/json` string escaping: `<`, `>` and `&` are written as `\u003c`, `\u003e` and `\u0026`. Integers are written as plain numbers. The Go and Kotlin implementations produce identical bytes.

Common optional fields are `role` (`relay`, `desktop` or `device`), `user` (token subject), `token_id` (token ID claim; never the token), `device`, `session` (opaque tunnel ID) and `ip`.

| `event` | Writer | Extra fields |
|---|---|---|
| `session_start` | desktop, relay | `transport`: `lan`, `relay-tcp`, `relay-ws` or `relay-wss` |
| `session_end` | desktop, relay | `transport`, `bytes_up`, `bytes_down`, `duration_ms`, `reason` |
| `adb_op` | desktop | `op`, `path?`, `command?`, `sha256?`, `bytes_up`, `bytes_down`, `duration_ms`, `result?` (`failed`) |
| `denied` | relay | `user?`, `device?`, `reason` |
| `revoked` | relay (admin API) | `user?`, `device?`, `sessions_killed` |
| `rate_limited`, `device_online`, `device_offline` | relay | `role`, `kind`, `device` |
| `agent_start`, `online`, `pairing_code_issued`, `adbd_endpoint`, `adbd_unreachable`, `blocked`, `policy_missing`, `agent_error`, `agent_exit`, `agent_stop` | device (Android SDK) | `mode`, `transport`, `reason`, `addr`, `exit_code`, `missing` |

`op` values:

| `op` | Meaning |
|---|---|
| `push`, `pull` | File transfer; carries `path` and `sha256` |
| `install` | Package install stream; `sha256` of the uploaded bytes |
| `shell` | `command` is the first word only, or `(interactive)` |
| `exec` | |
| `forward` | `path` is `tcp:…`, `localabstract:…` and so on |
| `reverse` | |
| `debug` | JDWP |
| `screencap`, `screenrecord` | |
| `other` | |

`sha256` is omitted for compressed transfers and failed operations.

Never recorded: tokens, pairing codes, passwords, command arguments, environment variables and file contents.

### 3.2 Report (JSON)

`setu audit report --format json`, `SetuClient.ExportAuditReport(…, audit.FormatJSON, …)` and the daemon's `audit.report` all produce this object. The example below is checked field for field against the code by `TestReportMatchesAPISpec` (`core/pkg/genadb/audit`), so it is the contract.

```json
{
  "generated_at": "2026-11-17T09:00:00Z",
  "source": "audit.jsonl",
  "since": "2026-11-10T00:00:00Z",
  "until": "2026-11-17T00:00:00Z",
  "first_event": "2026-11-10T08:00:00Z",
  "last_event": "2026-11-16T18:30:00Z",
  "chain": { "valid": true, "records": 812, "broken_at": 0, "problem": "", "last_hash": "9f2c…", "unchained": 0,
             "first_seq": 1, "starts_at_genesis": true, "anchor": "verified",
             "warnings": ["1 record(s) after the anchor (a writer stopped between the record and the anchor update)"] },
  "totals": { "records": 812, "sessions": 40, "operations": 655, "denials": 3, "revocations": 1,
              "bytes_up": 734003200, "bytes_down": 52428800, "users": 4, "devices": 6 },
  "by_user":   [ { "key": "alice", "sessions": 10, "operations": 200, "denials": 0, "bytes_up": 1048576, "bytes_down": 2048 } ],
  "by_device": [ { "key": "pixel-7", "sessions": 10, "operations": 200, "denials": 1, "bytes_up": 1048576, "bytes_down": 2048 } ],
  "by_op":     [ { "key": "push", "sessions": 0, "operations": 120, "denials": 0, "bytes_up": 1048576, "bytes_down": 0 } ],
  "sessions":  [ { "session": "4be1c0d2a9f37e11", "user": "alice", "device": "pixel-7", "transport": "relay-wss",
                   "start": "2026-11-16T09:00:00Z", "end": "2026-11-16T09:45:00Z", "end_reason": "closed",
                   "operations": 12, "bytes_up": 1048576, "bytes_down": 2048 } ],
  "denials":   [ { "ts": "2026-11-16T10:00:00Z", "user": "bob", "device": "pixel-7", "reason": "no grant for device" } ],
  "events":    [ { "seq": 1, "ts": "2026-11-10T08:00:00Z", "event": "session_start", "prev_event_hash": "0000…", "event_hash": "ab12…" } ]
}
```

Field notes:

- `since` and `until` echo the filter and are omitted when it is unbounded. `first_event` and `last_event` are the timestamps of the first and last records included.
- `chain` is the chain status (section 3.3). Fields that are zero or empty are omitted.
- `totals.bytes_up` and `totals.bytes_down` add up `adb_op` records. `totals.users` and `totals.devices` count distinct named users and devices.
- `by_user`, `by_device` and `by_op` are sorted by `key`. Records without a user or device are grouped under `(unknown)`.
- In `sessions`, `user`, `device`, `transport`, `start`, `end` and `end_reason` are omitted when unknown. Byte totals come from the `session_end` record when it carries them.
- In `denials`, `user`, `device` and `reason` are omitted when unknown.
- `events` is present only with `include_events`.

The CSV format has one row per record (not the summary), with this fixed header:

```csv
seq,ts,event,role,user,token_id,device,session,transport,op,path,command,sha256,bytes_up,bytes_down,duration_ms,result,reason,prev_event_hash,event_hash
```

Cells that a spreadsheet would treat as formulas are neutralised with a leading `'`. HTML is a self-contained page with summary tiles (records, sessions, operations, denials, revocations, bytes) and the same tables as the JSON.

### 3.3 Chain status

`{valid, records, broken_at?, problem?, last_hash?, unchained?, first_seq?, starts_at_genesis, anchor?, warnings?}`. `broken_at` is the 1-based index of the first record that fails verification. `first_seq` is the seq of the oldest chained record, and `starts_at_genesis` says whether it links to the all-zero genesis hash.

`anchor` is reported when the log is verified from disk (`audit verify`, the daemon's `audit.verify`, `doctor`): `verified`, `unverified` (the anchor key is not available, so positions are checked but not the signature), `invalid` or `none`.

### 3.3.1 Anchor file

The hash chain shows that the records present are intact and in order, but not that none are missing at either end: removing the oldest or newest lines leaves a shorter chain that still verifies. Every log therefore has an anchor next to it (`audit.jsonl` → `audit.anchor`), rewritten after each record:

```json
{ "version": 1, "first_seq": 1, "first_prev_event_hash": "0000…", "first_event_hash": "ab12…",
  "last_seq": 812, "last_event_hash": "9f2c…", "updated": "2026-11-17T10:00:00Z", "mac": "<hex>" }
```

`mac` is HMAC-SHA256 over `"setu-audit-anchor-v1\n"` followed by the anchor's JSON without `mac`. The key is 32 random bytes, hex-encoded, in `audit-anchor.key` in the log's directory (mode 0600, created on first use), or a file of your choice. Verification fails when the log's first record is not the anchored one (the oldest records were deleted), when it ends before the anchored last record (the newest records were deleted), when the log is empty or missing but its anchor is not, or when the MAC does not match. Writers refuse to append to such a log. A log written by an older version is anchored from its current contents the first time it is opened.

The anchor defeats anyone who cannot forge its MAC. Someone who holds the key and can write both files can still rewrite history, so keep the key on another volume, and use the webhook (3.4) or a SIEM copy as the record of last resort. `audit rotate` moves a log and its anchor aside and starts a new log whose chain continues from the old one.

### 3.4 Webhook delivery

Each sealed record is sent as `POST <audit_webhook_url>` with `Content-Type: application/json` and the record as the body. Headers:

```
X-GenADB-Timestamp: <unix seconds>
X-GenADB-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + body)>
```

Delivery is asynchronous, in order, and retried with backoff. Collectors should verify the signature with a constant-time comparison, reject timestamps more than a few minutes old, and de-duplicate on `event_hash`.

---

## 4. Android SDK (`setu-android`)

Artifact: `setu-android-1.0.1.aar` (Gradle module `:genadb-android`). Package: `dev.genadb.sdk`. The minimum SDK is 29. The AAR carries `LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES.txt` under `assets/setu-sdk/`, so apps that embed it ship the required notices. The library is built in Kotlin explicit-API mode, so everything not listed here is internal.

Consuming apps must keep native libraries extracted, because the agent runs as an executable: set `packaging { jniLibs { useLegacyPackaging = true } }`. Run the agent from a foreground service.

### 4.1 SetuManager

```kotlin
open class SetuManager {
    val connectionState: StateFlow<ConnectionState>
    val policyStatus: StateFlow<PolicyStatus>
    val auditEvents: StateFlow<AuditEvent?>          // latest record
    val recentAuditEvents: StateFlow<List<AuditEvent>>  // last 200
    val auditLogFile: File?

    fun start(config: SetuConfig? = null)            // throws GenAdbException.NotConfigured
    suspend fun pair(timeoutMs: Long = 30_000): String
    fun stop()
    fun status(): GenAdbStatus
    fun refreshPolicy(): PolicyStatus                // on ACTION_APPLICATION_RESTRICTIONS_CHANGED

    open class Builder(context: Context) {
        fun config(SetuConfig); fun agentLauncher(AgentLauncher)
        fun policyProvider(PolicyProvider); fun networkInfoProvider(NetworkInfoProvider)
        fun auditSink(AuditSink); fun stateDir(File); fun scope(CoroutineScope)
        fun build(): SetuManager
    }
    companion object {
        fun initialize(builder: Builder): SetuManager     // process-wide instance
        fun getInstance(context: Context): SetuManager    // defaults on first use
    }
}

@Deprecated class GenAdbManager : SetuManager        // pre-1.0.1 name; GenAdbManager.Builder builds one
@Deprecated typealias GenAdbConfig = SetuConfig
```

`pair()` can throw `GenAdbException.PairingUnavailable` (corporate mode), `GenAdbException.PolicyMissing`, `GenAdbException.Blocked` or `GenAdbException.Timeout`.

Corporate configuration that is incomplete (an enrollment token without a policy, or the reverse) never throws from `start()` and never launches the agent. The state becomes `ConnectionState.PolicyMissing(missing)`, `policyStatus.missing` names the absent item, and a `policy_missing` audit record is written. Call `start()` again on `ACTION_APPLICATION_RESTRICTIONS_CHANGED`. Errors inside the agent supervisor are reported as `Reconnecting`, never thrown into the host app.

### 4.2 Models

```kotlin
data class SetuConfig(relayUrl: String, mode: Mode = SOLO, adbd: String = "auto",
    lanListen: String? = "0.0.0.0:47100", enrollmentToken: String? = null,
    policyJson: String? = null, relayPin: String? = null, proxy: String? = null,
    audit: AuditMode = AUTO)

sealed interface ConnectionState {
    object Idle; object Starting
    data class Online(deviceId, pairingCode: String?, adbdEndpoint: String?, warning: String?)
    data class Reconnecting(attempt: Int, reason: String?, retryInMs: Long)
    data class Blocked(reason: String)
    data class PolicyMissing(missing: String)   // "policy_json" | "enroll_token"
}
data class PolicyStatus(mode, debuggingAllowed, managed, auditEnabled, missing: String?)
data class AuditEvent(seq, timestamp, type, deviceId, fields: Map<String,String>, eventHash, prevEventHash)
data class GenAdbStatus(connection, policy, running, auditLogPath)
enum class Mode { SOLO, CORPORATE };  enum class AuditMode { AUTO, ON, OFF }
```

Managed configuration takes precedence over `SetuConfig`. The EMM keys are:

| Key | Effect |
|---|---|
| `relay_url` | Relay to use |
| `enroll_token` | Switches to corporate mode |
| `policy_json` | Organisation policy |
| `relay_pin` | Relay certificate pin |

`UserManager.DISALLOW_DEBUGGING_FEATURES` produces `ConnectionState.Blocked`. In corporate mode, audit is always on. The device log at `auditLogFile` uses the schema in section 3, and `setu audit verify` and `setu audit report` read it.

### 4.3 Injection points

| Interface | Default | Purpose |
|---|---|---|
| `AgentLauncher` | `ProcessAgentLauncher(nativeLibraryDir/libgenadb.so)` | Start the agent process |
| `PolicyProvider` | `AndroidPolicyProvider` | Supply managed configuration and user restrictions |
| `NetworkInfoProvider` | `AndroidNetworkInfo` | Supply DNS servers of the active network |
| `AuditSink` | `HashChainedAuditLog(<state>/audit.jsonl)` | Seal and store records |
