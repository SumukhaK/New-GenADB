<p align="center">
  <img src="assets/logo.svg" width="112" height="112" alt="Setu logo: an encrypted bridge between an Android phone and a developer terminal">
</p>

<h1 align="center">Setu</h1>

<p align="center"><b>Setu-SDK</b>: an encrypted bridge between your IDE and any Android device, anywhere.</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-3B82F6?style=flat-square"></a>
  <a href="API_SPEC.md"><img alt="Go SDK" src="https://img.shields.io/badge/Go_SDK-1.24%2B-10B981?style=flat-square&logo=go&logoColor=white"></a>
  <a href="android/genadb-android"><img alt="Android AAR" src="https://img.shields.io/badge/Android_AAR-API_29%2B-059669?style=flat-square&logo=android&logoColor=white"></a>
  <a href="results.tsv"><img alt="Eval score: 98.97/100" src="https://img.shields.io/badge/eval_score-98.97%2F100-0F172A?style=flat-square"></a>
</p>

**Use a real Android phone from anywhere as if it were plugged into your computer.** Setu (Sanskrit for "bridge") connects Android Studio, any IDE, or plain `adb` to a physical device on another network: across the office, across the country, or behind a carrier NAT. You can deploy APKs and AABs, stream logcat, debug, push and pull files, and take screenshots.

```
$ setu connect --relay wss://relay.example.com/ --code 4821-093357
{"event":"listening","addr":"127.0.0.1:41377","device_id":"pixel-7-…"}
$ adb connect 127.0.0.1:41377
$ adb install app-debug.apk      # Android Studio sees the device too
```

## The problem

`adb` assumes the device is within reach of a USB cable or the same Wi-Fi network. Real teams don't work that way:

- **Remote and hybrid developers** keep test phones at home, in the office or in a lab, and need to reach them from elsewhere.
- **QA and device labs** share a small pool of physical devices across many people and time zones.
- **Field and customer issues** happen on hardware, carriers and networks that an emulator can't reproduce.

The usual workarounds each fall short. `adb tcpip` exposed through a port forward is unauthenticated and unencrypted. A VPN gives everyone access to everything. Commercial device clouds are expensive and keep your builds on someone else's hardware. Screen-sharing tools can't install an APK from your IDE.

## Why it matters

Setu makes a remote device look local to `adb`, and therefore to every tool built on it. It does this without asking you to trust the network in between:

- **End-to-end encrypted and mutually authenticated.** The relay that connects the two sides only forwards opaque bytes. It never sees ADB traffic, files, or the pairing code.
- **Zero-config for individuals.** Install the companion app, read a one-time code off the phone, and connect. Pairing is remembered.
- **Governed for organisations.** In corporate mode, identity tokens, per-device grants, revocation, device-management restrictions and a tamper-evident audit trail decide who may debug which device.
- **Built for bad networks.** Sessions survive Wi-Fi to cellular handovers and short outages without `adb` noticing. When both sides share a network, traffic takes a direct LAN path automatically.
- **Embeddable.** A Go SDK, a local JSON-RPC daemon and an Android library (AAR) let you build it into IDE plugins, device-lab tooling and your own apps.

## Architecture

```mermaid
flowchart LR
    subgraph Dev["Developer computer"]
        IDE["Android Studio / IDE / adb"] -->|"adb connect 127.0.0.1:PORT"| CA["setu connect<br/>(Go SDK / daemon)"]
    end
    subgraph Net["Internet"]
        R["setu relay<br/>(rendezvous, policy, admin)"]
    end
    subgraph Phone["Android device"]
        DA["setu-android SDK<br/>(device agent)"] --> ADBD["system adbd<br/>(Wireless debugging)"]
    end
    CA <-->|"TCP / WebSocket / WSS"| R
    R <-->|"TCP / WebSocket / WSS"| DA
    CA <-.->|"direct LAN path when available"| DA
    CA ==>|"end-to-end encrypted tunnel"| DA

    classDef dev fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#1E3A8A
    classDef relay fill:#FFFBEB,stroke:#D97706,stroke-width:1.5px,color:#78350F
    classDef phone fill:#ECFDF5,stroke:#059669,stroke-width:1.5px,color:#064E3B
    class IDE,CA dev
    class R relay
    class DA,ADBD phone
    style Dev fill:#2563EB12,stroke:#2563EB,stroke-width:1px,color:#3B82F6
    style Net fill:#D9770612,stroke:#D97706,stroke-width:1px,color:#F59E0B
    style Phone fill:#05966912,stroke:#059669,stroke-width:1px,color:#10B981
    linkStyle 5 stroke:#059669,stroke-width:3px
```

Each side connects outbound to the relay, so neither the phone nor the computer needs an open port. The relay matches the two sides and splices their connections. The two agents then establish their own encrypted, authenticated session through that splice. In solo mode the relay forwards only and learns nothing about what you do.

```mermaid
sequenceDiagram
    box rgba(5,150,105,0.10) Android device
        participant P as Phone (device agent)
    end
    box rgba(217,119,6,0.10) Internet
        participant R as Relay
    end
    box rgba(37,99,235,0.10) Developer computer
        participant D as Desktop (connect agent)
        participant A as adb / IDE
    end
    P->>R: register (outbound)
    Note over P: shows a one-time pairing code
    D->>R: connect with code (solo) or identity token (corporate)
    R-->>D: rendezvous
    D->>P: authenticate both ends, end-to-end (via the relay splice)
    Note over D,P: the device is pinned, later connects need no code
    A->>D: adb connect 127.0.0.1:PORT
    D->>P: ADB stream (encrypted, resumable)
    P->>P: forward to system adbd
```

```mermaid
flowchart TB
    subgraph Go["core/ (Go)"]
        CLI["cmd/setu (and genadb)<br/>relay · device · connect · doctor · audit"]
        DMN["cmd/setu-daemon<br/>JSON-RPC 2.0"]
        SDK["pkg/genadb<br/>SetuClient · SetuSession · options · interfaces"]
        AUD["pkg/genadb/audit<br/>hash chain · signed anchor · reports · webhook"]
        ENG["internal/engine<br/>transport · tunnel · policy (unexported)"]
        CLI --> ENG
        CLI --> SDK
        DMN --> SDK
        SDK --> ENG
        SDK --> AUD
        ENG --> AUD
    end
    subgraph Android["android/ (Kotlin)"]
        LIB["setu-android (AAR)<br/>SetuManager"]
        APP["companion app"]
        APP --> LIB
    end
    LIB -->|"runs as libgenadb.so"| CLI

    classDef dev fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#1E3A8A
    classDef relay fill:#FFFBEB,stroke:#D97706,stroke-width:1.5px,color:#78350F
    classDef phone fill:#ECFDF5,stroke:#059669,stroke-width:1.5px,color:#064E3B
    classDef engine fill:#F1F5F9,stroke:#475569,stroke-width:1.5px,color:#0F172A
    class CLI,DMN,SDK dev
    class AUD relay
    class ENG engine
    class LIB,APP phone
    style Go fill:#2563EB12,stroke:#2563EB,stroke-width:1px,color:#3B82F6
    style Android fill:#05966912,stroke:#059669,stroke-width:1px,color:#10B981
```

The wire protocol, framing and session security live in `internal/engine` and are deliberately not part of any public API.

**Names before v1.0.1.** The project was called New-GenADB until v1.0.1. The old names keep working:
- **Commands:** `genadb` and `genadb-daemon` are the same programs as `setu` and `setu-daemon`.
- **Go SDK:** `Client` and `Session` are aliases of `SetuClient` and `SetuSession`.
- **Android SDK:** `GenAdbManager` and `GenAdbConfig` are deprecated names for `SetuManager` and `SetuConfig`.
- **Unchanged:** the Go module path, the Kotlin package `dev.genadb.sdk`, the state directories and the wire protocol.

### Modes

| | Solo | Corporate |
|---|---|---|
| Trust | One-time pairing code, then the device is pinned | Identity token per user, enrollment token per device, organisation policy |
| Who may connect | Whoever paired | Users granted the device by policy; revocation takes effect immediately |
| Device management | n/a | Respects `DISALLOW_DEBUGGING_FEATURES`; relay URL and enrollment come from EMM managed configuration |
| Audit | Off by default (opt in) | Always on: relay and desktop write hash-chained logs, with an optional signed webhook |
| Direct LAN path | Yes | Relay only |

## Quickstart: CLI

```bash
cd core && go build -o setu ./cmd/setu

# 1. A relay somewhere both sides can reach (a small VM, or a tunnel to your laptop)
./setu relay --listen 0.0.0.0:7000 --ws-listen 0.0.0.0:8443 --tls-cert cert.pem --tls-key key.pem

# 2. On the phone: the companion app (android/) or the agent itself
./setu device --relay wss://relay.example.com:8443/ --adbd auto
#   -> {"event":"pairing_code","code":"4821-093357",...}

# 3. On your computer
./setu connect --relay wss://relay.example.com:8443/ --code 4821-093357
adb connect 127.0.0.1:<port from the "listening" event>

# Later: no code needed
./setu connect --relay wss://relay.example.com:8443/ --device <device id> --label "$(hostname)"

# Android 11+ Wireless debugging (TLS adbd): pair this computer's adb through the tunnel once.
# On the phone: Wireless debugging > "Pair device with pairing code" shows a port and a 6-digit code.
./setu adb-pair --relay wss://relay.example.com:8443/ --device <device id> --port 37099 --code 482913

# Something wrong? Check adb, state, proxy settings and relay reachability
./setu doctor --relay wss://relay.example.com:8443/
```

The pairing code the phone shows is 10 digits, `NNNN-NNNNNN`: a 4-digit nameplate that finds the device on the relay and a 6-digit secret that never leaves the two ends (it feeds a SPAKE2 exchange). It is single-use, expires, and is burned after a few wrong guesses. The six-digit code in Android's own *Pair device with pairing code* dialog is a different code; it goes to `setu adb-pair`.

## Quickstart: Go SDK

The module path is `github.com/sumukhak/new-genadb/core` (see `core/go.mod`). It is unchanged by the Setu rename and by the repository moving on GitHub, so keep that import path; inside this repository use a `replace` directive or `go.work` pointing at `core/`.

```go
import (
    "context"
    "errors"
    "fmt"
    "os"

    "github.com/sumukhak/new-genadb/core/pkg/genadb"
    "github.com/sumukhak/new-genadb/core/pkg/genadb/audit"
)

func main() {
    ctx := context.Background()
    c, err := genadb.New(
        genadb.WithRelayURL("wss://relay.example.com:8443/"),
        genadb.WithStateDir("~/.setu"),
        genadb.WithReconnectPolicy(genadb.DefaultReconnectPolicy),
        genadb.WithEventHandler(func(e genadb.Event) { fmt.Println(e.Type, e.Fields) }),
    )
    if err != nil {
        panic(err)
    }
    defer c.Close()

    sess, err := c.Connect(ctx, genadb.ConnectRequest{PairingCode: "4821-093357"})
    switch {
    case errors.Is(err, genadb.ErrBadCode):
        // ask the user to re-enter the code
    case err != nil:
        panic(err)
    }
    fmt.Println("adb connect", sess.ADBAddr())

    // Android 11+: pair adb once through the tunnel (port and code from the phone's dialog).
    c.PairADB(ctx, genadb.PairADBRequest{DeviceID: sess.DeviceID(), PairingPort: 37099, PairingCode: "482913"})

    // Corporate: rotate the identity token without dropping sessions.
    //   c.SetToken(newJWT)  or  go c.WatchIdentityFile(ctx, "/run/setu/identity.jwt", 2*time.Second)

    // Corporate deployments: genadb.WithCorporateToken(token, policyPath) turns on
    // policy checks and a hash-chained audit log. Export it at any time:
    c.ExportAuditReport(os.Stdout, audit.FormatHTML, audit.Options{})
}
```

Other languages can use `setu-daemon`, which offers the same operations over JSON-RPC 2.0 on loopback. See [API_SPEC.md](API_SPEC.md).

## Quickstart: Android (Kotlin)

```kotlin
// settings.gradle.kts: include(":genadb-android"), or depend on setu-android-1.1.0.aar
// app/build.gradle.kts: packaging { jniLibs { useLegacyPackaging = true } }

val setu = SetuManager.initialize(
    SetuManager.Builder(context)
        .config(SetuConfig(relayUrl = "wss://relay.example.com:8443/"))
)

setu.start()                         // call from a foreground service
lifecycleScope.launch {
    setu.connectionState.collect { state ->
        when (state) {
            is ConnectionState.Online -> showCode(state.pairingCode)
            is ConnectionState.Blocked -> showPolicyMessage(state.reason)
            is ConnectionState.Reconnecting -> showRetry(state.attempt)
            else -> Unit
        }
    }
}
val code = setu.pair()               // suspend; solo mode

// Who is debugging this phone right now, and an "End" button for each session
lifecycleScope.launch {
    setu.sessions.collect { list -> list.forEach { show(it.peerLabel, it.transport, it.path) } }
}
setu.endSession(sessionId)           // the desktop sees a graceful peer_closed
setu.stop()
```

Show the pairing code with `SetuNotifications.content(state, sessions)`: it returns the full text for the unlocked phone and a `publicText` without the code for the lock screen (post with `VISIBILITY_PRIVATE` and `setPublicVersion`).

In corporate mode, the relay URL, enrollment token and policy come from EMM managed configuration. Device-side audit records then appear on `setu.auditEvents`.

Build the library with `./gradlew :genadb-android:assembleRelease`, which writes `genadb-android/build/outputs/aar/setu-android-1.1.0.aar`. The AAR carries `LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES.txt` under `assets/setu-sdk/`. The build cross-compiles the Go core, so Go 1.24+ must be on `PATH`.

## What's new in 1.1.0

- **Android 11+ pairing over the tunnel:** `setu adb-pair`, `SetuClient.PairADB` and the daemon's `session.pair_adb` run `adb pair` against the phone's `_adb-tls-pairing._tcp` service through the encrypted tunnel, so TLS adbd accepts the computer without being on the same Wi-Fi.
- **Live token rotation:** `auth.set_token`, `SetuClient.SetToken` and an automatic watch on `--identity-file`. Sessions keep running, and the audit trail records `token_rotated`.
- **Daemon for UIs:** requests run concurrently, `session.cancel` stops a pending connect, a `{"event":"daemon_ready","listen":"127.0.0.1:PORT"}` line on stdout announces the port, and `events.dropped` tells slow subscribers what they missed.
- **Relay state:** revocations survive relay restarts (`revocations.json` in `--state`), and `GET /v1/devices` / `devices.presence` show which devices are online.
- **Path events:** `path_down`, `path_up` (with `transport` `lan|relay-tcp|relay-ws|relay-wss`) and `path_lost`, on the Go SDK and the CLI, and on Android through `ConnectionState.Online.path` and `SetuManager.sessions`.
- **Corporate controls:** `max_session_seconds` is a hard cap that requires re-authentication (rejoining cannot extend it), and `setu policy scope` / `GET /v1/policy?device=` give each phone only its own grants.
- **On the phone:** `SetuManager.sessions` (who is connected, `peer_label`, `transport`), `SetuManager.endSession(id)`, and a lock-screen notification that never shows the pairing code.

All of it interoperates with 1.0 peers; features the other side lacks fail with `ErrUnsupported`. See [API_SPEC.md](API_SPEC.md) for the full contract.

## Audit and reports

In corporate mode every session and ADB operation is recorded. Each record names:

- the user (token subject and token ID) and the device
- the transport: LAN, or relay over TCP, WS or WSS
- the operation: shell (command name only), push, pull, install, forward, reverse, debug or screencap
- bytes in each direction and the duration
- the SHA-256 of pushed and pulled files

Records never contain passwords, tokens, pairing codes, command arguments or file contents. The log is append-only JSONL, and each record carries the hash of the previous one, so editing, inserting or reordering records breaks the chain. A signed anchor file next to the log (`audit.anchor`, keyed by `audit-anchor.key`) pins its first and last records, so deleting records from either end is detected too. Someone who holds the anchor key and can rewrite both files could still forge history: keep the key on another volume (`--audit-anchor-key-file`) and forward records to a collector as the copy of last resort.

```bash
setu audit verify --log audit.jsonl
setu audit report --log audit.jsonl --format html --since 168h --out weekly.html
setu audit report --log audit.jsonl --format csv   # one row per record, spreadsheet-safe
setu audit rotate --log audit.jsonl --to audit-2026-11.jsonl   # archive; the chain continues
```

Records can also be forwarded to a SIEM or collector as they happen (`--audit-webhook-url`), with each delivery signed with HMAC-SHA256.

Operation-level records need the ADB stream to be visible to the desktop agent, which is the case with classic `adb tcpip`. When adbd upgrades the connection to TLS (Android 11+ Wireless debugging pairing), the stream is opaque, and sessions are recorded with byte counts and duration only.

## Benchmarks

These figures come from the locked evaluation harness (`eval.py`, a simulated WAN with a fake adbd) and from hardware runs on a Pixel 7 and a POCO F1.

| Metric | Result |
|---|---|
| Overall eval score | 98.97 / 100 |
| Time from `connect` to `adb`-ready | 0.9 s |
| Push throughput through the relay (simulated WAN) | 11 MB/s, up from 5.7 MB/s before ADB-aware flow control |
| Logcat line latency (median) | 44 ms, down from 86 ms |
| JDWP round trip, direct LAN path vs relay | 3 ms vs about 250 ms |
| Recovery after a network outage, `adb` session kept | about 4 s (simulated); 2.9 s after a 40 s radio loss on a Pixel 7 |
| Corporate revocation, live session killed | under 0.1 s |
| 10 MiB push over Wi-Fi, tunnel vs direct `adb` (Pixel 7) | 669 ms vs 587 ms |
| Tampered or replayed traffic | always detected; never delivered silently |

## Repository layout

| Path | What |
|---|---|
| `core/cmd/setu`, `core/cmd/genadb` | CLI: `relay`, `device`, `connect`, `adb-pair`, `keygen`, `doctor`, `audit`, `policy`, `version` (two names, one program) |
| `core/cmd/setu-daemon`, `core/cmd/genadb-daemon` | JSON-RPC 2.0 daemon for IDE plugins and UIs |
| `core/pkg/genadb` | Public Go SDK |
| `core/pkg/genadb/audit` | Hash-chained audit log, reports, webhook sink |
| `core/internal/…` | Engine: transport, tunnel, policy (not public API) |
| `android/genadb-android` | Android SDK (`setu-android` AAR) |
| `android/agent-protocol` | Platform-neutral Kotlin half of the SDK, JVM-tested |
| `android/app` | Companion app built on the SDK |
| `eval.py`, `harness/` | Locked evaluation harness |
| `docs/research/` | Research findings, notes and reports behind the design (locked record) |

## Building and testing

```bash
cd core && go vet ./... && go test -race ./... # Go SDK, engine, daemon, audit, notices
python3 eval.py                               # end-to-end evaluation (builds via solution.py)
python3 tests/repo_hygiene.py                 # no compiled binaries tracked in git
cd android && ./gradlew :agent-protocol:test  # Kotlin SDK logic, no Android SDK needed
cd android && ./gradlew :genadb-android:assembleRelease :app:assembleDebug
```

## Security

If you believe you have found a security issue, please do not open a public issue. Report it privately through GitHub's "Report a vulnerability" (security advisories) on this repository.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md).
