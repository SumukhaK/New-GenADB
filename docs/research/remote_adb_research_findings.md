# Remote ADB for Android: Research Findings and Existing Attempts

**Research snapshot:** 16 November 2026  
**Scope:** Android Debug Bridge (ADB), remote debugging without laptop USB access, WAN / carrier-NAT connectivity, relay architectures, device-farm systems, enterprise policy and relevant GitHub implementations.  
**Prepared for:** New-GenADB research

---

## Executive summary

Remote ADB is **not a new or impossible idea**. Android already supports ADB over a network through Wireless Debugging, and multiple independent projects have built remote ADB gateways, tunnels, browser clients, device farms and WebSocket relays.

The most important additional finding from the deeper GitHub review is a three-part open-source project family from **AndroidGradleTools**:

1. [android-ide-extension](https://github.com/AndroidGradleTools/android-ide-extension) — a VS Code Android development extension whose current README says it can connect to a configured remote ADB relay.
2. [adb-relay-android](https://github.com/AndroidGradleTools/adb-relay-android) — an Android companion app that opens an outbound WebSocket to a relay and forwards multiplexed traffic to the phone's existing `adbd` endpoint.
3. [adb-relay-jvm](https://github.com/AndroidGradleTools/adb-relay-jvm) — a Kotlin/JVM WebSocket relay that pairs the developer side and phone side using a shared session token and forwards binary frames.

A related implementation, [aioue/adb-relay-python](https://github.com/aioue/adb-relay-python), implements the same published relay protocol and adds token allow-listing, handshake/message/buffer limits, ping handling and conformance tests.

This is the closest open-source architecture I found to the requirement in this research: **a phone-originated Internet connection, a relay in the middle, and an ADB-compatible connection on the developer side**. The repository documentation and selected source files were inspected, but I did not deploy the stack or independently verify its full end-to-end operation, security or enterprise suitability. Treat it as a concrete implementation to evaluate, not a production certification.

A second strong proof of feasibility is [BigBIueWhale/samsung_a56_remote_usb_debugging](https://github.com/BigBIueWhale/samsung_a56_remote_usb_debugging). Its author documents a non-rooted Galaxy A56 controlled from an Ubuntu workstation over 5G using Termux and a phone-initiated reverse SSH tunnel. The documented path switches the phone to legacy ADB TCP mode on port 5555, then carries that traffic through SSH. The README contains session logs and subsequent self-healing/recovery updates. This is persuasive evidence of feasibility, but its legacy TCP mode and device-specific operational assumptions are not a recommended default for an enterprise product.

Other substantial projects include:

- [DarkRide](https://github.com/DarkRideApp/DarkRide), with an implemented ADB proxy, remote ADB-key approval and revocation. Its own documentation explicitly says the proxy transport is unencrypted and recommends VPN/WireGuard on untrusted networks.
- [DeviceFarmer/stf](https://github.com/DeviceFarmer/stf), a remote device-farm web application with device sharing and remote ADB connection support.
- [enginefuture/tauri-android-remote](https://github.com/enginefuture/tauri-android-remote), an Alpha Tailscale + native Wireless ADB + scrcpy companion/CLI project.
- [nisargjhaveri/remote-adb](https://github.com/nisargjhaveri/remote-adb), a WebUSB-based way to share a USB-attached phone from one host to a remote browser or CLI client.

Commercial device streaming also exists. Google's [Android Device Streaming](https://developer.android.com/studio/run/android-device-streaming) exposes provider-hosted physical devices over ADB over SSL and integrates with Android Studio. It does **not** turn a developer's own phone into a remote device endpoint. BrowserStack and AWS Device Farm offer remote testing/control features, but their documented workflows are service-oriented rather than an arbitrary stock ADB bridge to a personally owned phone.

### Updated conclusion

The earlier conversational conclusion that no complete open-source approach had surfaced needs a qualification: **the AndroidGradleTools WebSocket bridge family is a direct implementation attempt of the phone-agent + relay + developer-bridge architecture**. It is a significant candidate and should be studied before designing a competing protocol.

What remains unproven is whether any of these implementations is mature enough for broad enterprise deployment with strong identity, authorization, tenant isolation, audit, key lifecycle, policy enforcement, operational recovery and security review.

---

## 1. Define the problem precisely

“Remote debugging” can mean several different things. Many search results use the phrase while solving a different problem.

| Category | What it does | Does it solve the no-USB-on-developer-laptop use case? |
|---|---|---|
| USB ADB | The phone is physically connected to the workstation. | No, if laptop USB data access is blocked. |
| Android Wireless Debugging | The workstation pairs with the phone and connects to `adbd` over Wi-Fi using Android's native pairing/TLS flow. | Sometimes. It removes the cable, but Google's documented workflow expects the workstation and phone on the same wireless network. |
| ADB over VPN / overlay | ADB connects to the phone's reachable Wireless Debugging endpoint through a VPN such as Tailscale. | Yes, when the organisation permits the overlay and the phone keeps Wireless Debugging available. |
| Phone-originated reverse tunnel | A phone-side process initiates an outbound tunnel to a host; the workstation connects to a local forwarded port. | Yes, including carrier-NAT cases, provided the phone-side agent and ADB endpoint remain alive. |
| WebSocket ADB relay | A phone-side agent and a developer-side bridge both connect outbound to a relay; the relay pairs them and forwards the ADB transport. | Yes in principle, and there are public implementations to inspect. |
| ADB proxy / device farm | A server already connected to phones exposes them to authorized remote clients. | Yes for a managed lab, but not necessarily for a developer's own phone. |
| Browser remote control | A browser can view/tap/control a remote device, often through a vendor console. | Not necessarily. A web shell or control panel is not equivalent to exposing a stock ADB transport to Android Studio or local tools. |
| Cloud device streaming | A provider reserves and streams devices hosted in its data centre. | Yes for provider-hosted devices; not for the user's own remote phone. |

The target use case assumed throughout this report is:

> A developer uses their normal ADB-compatible tools on a corporate workstation. The workstation's USB data ports are blocked or unavailable. The Android phone is physically elsewhere or on a different network. A secure, approved network path connects the developer to that phone without exposing an unrestricted ADB endpoint to the Internet.

Two corporate situations must be separated:

- **Laptop policy only:** the workstation blocks USB data but the phone and debugging features are permitted. A network bridge may be viable.
- **Phone/MDM policy:** the managed phone has debugging features disabled by its administrator. A bridge must not be used to bypass that policy. Android exposes the `DISALLOW_DEBUGGING_FEATURES` restriction, which can disable debugging features including USB debugging. `DISALLOW_USB_FILE_TRANSFER` is a narrower restriction on file transfer over USB and is not the same thing as disabling ADB.

Sources: [Android ADB documentation](https://developer.android.com/tools/adb), [UserManager.DISALLOW_DEBUGGING_FEATURES](https://developer.android.com/reference/android/os/UserManager#DISALLOW_DEBUGGING_FEATURES), [UserManager.DISALLOW_USB_FILE_TRANSFER](https://developer.android.com/reference/android/os/UserManager#DISALLOW_USB_FILE_TRANSFER).

---

## 2. The most important GitHub finding: AndroidGradleTools' remote ADB bridge

### Repositories

- [AndroidGradleTools/android-ide-extension](https://github.com/AndroidGradleTools/android-ide-extension)
- [AndroidGradleTools/adb-relay-android](https://github.com/AndroidGradleTools/adb-relay-android)
- [AndroidGradleTools/adb-relay-jvm](https://github.com/AndroidGradleTools/adb-relay-jvm)
- Compatible relay implementation: [aioue/adb-relay-python](https://github.com/aioue/adb-relay-python)

### What the repositories say they do

The Android Gradle Tools VS Code extension describes itself as an Android Gradle build/run/debug extension for VS Code. Its README says a device can be paired with Wireless ADB or connected through a configured remote ADB relay when USB is inconvenient. Its changelog records an optional **Remote ADB over WebSocket** feature with a developer-side mux bridge, relay settings, relay/agent components and an “Internet relay” setup flow. A later changelog entry says the relay host was moved from a bundled Node implementation to the standalone `adb-relay-jvm` project.

The Android companion README says the app acts as the **device side** of the bridge:

1. Enable Android Wireless Debugging on the phone.
2. Enter the host and port for the local `adbd` endpoint shown in Wireless Debugging (the app's default fields are `127.0.0.1` and `5555`, but the README directs users to enter the actual endpoint from the phone's settings screen).
3. Enter the relay WebSocket URL and session token shown by the developer-side workflow.
4. Tap Connect. A foreground notification stays active while the tunnel is up.
5. The app forwards relay data to the phone's local `adbd` endpoint. It does not replace Android's own Wireless Debugging pairing flow.

The relay JVM README describes a standalone Kotlin/JVM WebSocket server. A `dev` client and a `device` client connect to `/`, send a JSON handshake with a shared session token, and then exchange binary frames. The relay forwards those binary frames byte-for-byte; it does not parse the ADB multiplexing protocol.

### Architecture reconstructed from the README, protocol and selected Android source

```text
Developer tools / adb client
          |
          v
Developer-side bridge in IDE extension
  - accepts/uses a local ADB-side TCP connection
  - multiplexes TCP channels into ADBM frames
          |
          | outbound WebSocket (dev role)
          v
WebSocket relay / broker
  - matches dev + device by shared session token
  - forwards binary payloads without interpreting ADB
          ^
          | outbound WebSocket (device role)
          |
Android companion foreground service
  - connects to the relay
  - demultiplexes ADBM frames
  - opens TCP sockets to local adbd endpoint
          |
          v
Android system adbd
  - retains Android's debugging/authorization model
```

This is an important distinction: the companion app is not claiming to create a privileged new `adbd` daemon. It forwards traffic to the system ADB endpoint after debugging is enabled. The phone creates an outbound WebSocket connection, which is the useful property for phones behind carrier NAT or restrictive inbound firewall rules.

### Protocol details inspected

The relay specification published at [adb-relay-jvm/prompts/specs.md](https://github.com/AndroidGradleTools/adb-relay-jvm/blob/main/prompts/specs.md) defines:

- WebSocket on `/`; transport may be `ws://` or `wss://`.
- First message is UTF-8 JSON with `v: 1`, `role: "dev"` or `role: "device"`, and a non-empty `token`.
- One `dev` and one `device` with the same token are paired.
- Binary frames received before the peer arrives are buffered and flushed FIFO once paired.
- After pairing, binary frames are forwarded unchanged.
- Closing one side closes the peer.
- The relay does not inspect the ADBM mux payload.
- ADBM frames contain a magic string, version, message type, channel ID and payload length. The message types are DATA, OPEN and CLOSE.

The JVM relay README says it listens on `0.0.0.0:18765` by default and expects a reverse proxy or other deployment layer when TLS is required. The Android app README explicitly says cleartext `ws://` is enabled for LAN testing and recommends `wss://` on the public Internet.

### Security strengths visible in the inspected design

- The Android companion stores relay URL, token, host and port using `EncryptedSharedPreferences`.
- The companion is a foreground service and its code contains reconnect handling with backoff.
- The relay does not expose its own ADB command API in the described protocol; it forwards binary data between two already-paired roles.
- Android's native Wireless Debugging and ADB authorization flow remains in the path. The companion README states that the app does not replace the pairing process.
- The relay protocol explicitly says that the session token is a secret, should have high entropy, and should be rotated or single-use on untrusted networks.
- The Python implementation adds token-file allow-listing, handshake timeouts, ping/pong timeouts, maximum message and buffer sizes, a cap on waiting sessions, and tests.

### Open security / maturity questions

These are not claims that the project is vulnerable; they are the questions that require a real deployment review:

1. **TLS is not automatic in the default relay configuration.** The JVM relay is a plain WebSocket listener by default. A production deployment needs `wss://` or a properly secured tunnel/reverse proxy.
2. **The shared token is the relay's pairing credential.** The published relay spec describes matching by token; it does not itself define corporate SSO, per-user authorization, multi-tenant roles, device ownership checks, approval workflow, or a complete audit model.
3. **Token issuance and lifecycle need an owner.** The operator must ensure high-entropy tokens, expiry, rotation, revocation, non-reuse and secure delivery to the correct phone and developer endpoint.
4. **The relay protocol does not itself specify end-to-end encryption between the developer and phone.** `wss://` secures each WebSocket connection to the relay. Whether the inner ADB stream is separately protected depends on the `adbd` endpoint being forwarded (native Wireless Debugging TLS versus legacy TCP mode) and must be verified with the actual configuration and a packet-level test. Do not assume that WSS alone means the relay cannot see or alter the forwarded ADB bytes.
5. **The relay is deliberately transport-transparent.** It does not parse ADB commands and cannot enforce command-level permissions from the published v1 relay specification alone.
6. **The phone must have Wireless Debugging enabled and the correct `adbd` endpoint configured.** The app does not silently enable debugging, and does not override organisation policy.
7. **Operational recovery is not the same as production reliability.** Reconnect logic exists in the Android service, but the actual lifecycle across vendor battery management, Wi-Fi/cellular transitions, OS upgrades and reboot must be tested across OEMs.
8. **Licensing must be checked before reuse.** GitHub repository metadata for the Android relay and JVM relay did not show a recognised licence in the repository metadata inspected. The VS Code extension says it is MIT-licensed; the Python relay says MIT. Do not assume all three components share a licence.
9. **The public footprint is small.** The relay repositories are small projects, not evidence of broad enterprise deployment. GitHub stars/issues are snapshots, not a quality metric; no independent security audit was found in the reviewed documentation.
10. **The protocol documentation has some version drift.** The JVM spec still references the earlier Node relay path in the IDE extension, while the extension changelog says the bundled Node relay was removed in favour of the standalone JVM relay. Inspect the current source tree before copying any paths or integration instructions.

### Assessment

**High relevance.** This is the closest architecture to a remote ADB bridge without laptop USB that was found in the search. It deserves a hands-on proof-of-concept and a security review before New-GenADB designs another relay protocol.

Primary sources:

- [VS Code extension README](https://github.com/AndroidGradleTools/android-ide-extension/blob/main/README.md)
- [VS Code extension changelog](https://github.com/AndroidGradleTools/android-ide-extension/blob/main/CHANGELOG.md)
- [Android relay README](https://github.com/AndroidGradleTools/adb-relay-android/blob/main/README.md)
- [Android service source](https://github.com/AndroidGradleTools/adb-relay-android/blob/main/app/src/main/java/org/androidgradletools/adbrelayandroid/AdbProxyService.kt)
- [Android mux codec source](https://github.com/AndroidGradleTools/adb-relay-android/blob/main/app/src/main/java/org/androidgradletools/adbrelayandroid/MuxCodec.kt)
- [Encrypted preference storage source](https://github.com/AndroidGradleTools/adb-relay-android/blob/main/app/src/main/java/org/androidgradletools/adbrelayandroid/Prefs.kt)
- [JVM relay README](https://github.com/AndroidGradleTools/adb-relay-jvm/blob/main/README.md)
- [Normative relay protocol / ADBM spec](https://github.com/AndroidGradleTools/adb-relay-jvm/blob/main/prompts/specs.md)
- [Python compatible relay README](https://github.com/aioue/adb-relay-python/blob/main/README.md)

---

## 3. Strong end-to-end feasibility demonstration: reverse SSH over 5G

**Repository:** [BigBIueWhale/samsung_a56_remote_usb_debugging](https://github.com/BigBIueWhale/samsung_a56_remote_usb_debugging)

The repository documents a non-rooted Samsung Galaxy A56 5G controlled from an Ubuntu workstation while the phone is on mobile data. The initial proof is dated 28 September 2026. The repository includes terminal outputs and logs showing the workstation attaching to `127.0.0.1:7555` and executing commands such as `adb shell`, `getprop` and `screencap` over the tunnel.

### Architecture

1. The phone runs Termux with `adb` and OpenSSH.
2. The phone's `adbd` is switched into legacy TCP mode on port `5555`.
3. Termux initiates an outbound SSH connection to the workstation and requests a reverse port forward: workstation loopback port `7555` forwards to phone loopback port `5555`.
4. The workstation runs `adb connect 127.0.0.1:7555`.
5. The ADB client sees a normal device transport and can run shell commands, capture screenshots and use scrcpy.

The phone initiates the SSH connection, so the design can work around carrier NAT that blocks unsolicited inbound connections to a phone.

### Updates recorded by the author

- An October 5 update adds a reconnect loop, phone-only restricted SSH key, five-minute silence tolerance and workstation-side ADB reattachment.
- A November 9 update documents Termux being killed by Android even while the phone remains powered on, and a recovery card to bring the tunnel back. The author notes that a separate Wi-Fi bootstrap step is needed after a reboot.

### Security and operational caveats

- The phone uses legacy `adb tcpip 5555`, not Android's TLS Wireless Debugging endpoint, for the tunneled ADB leg.
- Legacy ADB TCP mode is not encrypted by itself. SSH is the layer protecting the traffic in this example.
- The repository documents that port 5555 listens on all phone interfaces while legacy TCP mode is active, until reboot or explicit shutdown. That is a meaningful exposure risk if the device joins hostile Wi-Fi or has an inbound-reachable IPv6 address.
- The author reports a Termux background-process termination issue and provides recovery steps.
- The documented setup includes host networking/SSH configuration which is specific to the author's environment.
- The README documents a working example, but I did not independently reproduce it.

### Assessment

**Very high relevance as a proof of feasibility; not a production blueprint.** It proves that a non-rooted phone can originate the tunnel and appear as a normal ADB device on a separate workstation over mobile data. Its legacy TCP-mode step should not be copied into a general enterprise design without a careful threat model.

Sources: [Repository README and evidence](https://github.com/BigBIueWhale/samsung_a56_remote_usb_debugging), [author's self-healing tunnel notes](https://github.com/BigBIueWhale/samsung_a56_remote_usb_debugging/tree/master/docs), [author's Android research notes](https://github.com/BigBIueWhale/samsung_a56_remote_usb_debugging/blob/master/docs/android-research.md).

---

## 4. DarkRide: ADB-compatible proxy with key approval and revocation

**Repository:** [DarkRideApp/DarkRide](https://github.com/DarkRideApp/DarkRide)

DarkRide includes an ADB proxy that allows another machine to run `adb` against Android devices attached to the DarkRide host. The remote machine uses stock `adb connect <host>:<port>` and then can run device commands such as `adb shell`, `adb push`, `adb pull` and `adb forward` within the supported service policy.

### Architecture and controls

- Each online Android device receives a dedicated TCP listener/port on the DarkRide host.
- The remote ADB client presents its normal ADB public key.
- A previously unknown key appears as a pending request in the DarkRide UI.
- An administrator can approve, deny, forget or revoke a machine.
- Revocation closes that machine's live sessions immediately.
- The proxy forwards per-device ADB services to DarkRide's local ADB server.
- Host-level ADB services are deliberately refused by the proxy.

The design document says the feature is implemented and records tests for unknown-key denial, approval and revocation.

### Important limitations stated by DarkRide itself

- The proxy connection is **not encrypted**. The project's documentation recommends putting it behind a VPN or WireGuard on an untrusted network.
- Approval of one key can grant shell access to every proxied device unless the device allow-list is configured.
- It does not support every ADB service. The docs list unsupported operations including `adb pair`, `adb reverse`, `adb tcpip`, `adb usb` and the unauthenticated host-protocol form `adb -H host -P port`.
- It is designed around devices already visible to the DarkRide host's ADB server. It is not itself the phone-originated agent needed for a phone behind carrier NAT.

### Assessment

**High relevance for a central ADB gateway, device-scoped listeners, approval and revocation.** Not a complete secure Internet bridge by itself because the project's own docs say the proxy transport is plaintext; combine only with an approved encrypted network layer or redesign its transport security.

Sources: [ADB proxy guide](https://github.com/DarkRideApp/DarkRide/blob/main/docs/adb-proxy.md), [ADB proxy design specification](https://github.com/DarkRideApp/DarkRide/blob/main/docs/specs/2026-10-11-adb-proxy-design.md), [repository](https://github.com/DarkRideApp/DarkRide).

---

## 5. DeviceFarmer / OpenSTF: remote device farm infrastructure

### Repositories

- [DeviceFarmer/stf](https://github.com/DeviceFarmer/stf)
- [openstf/stf](https://github.com/openstf/stf)
- [f4samurai/device-farm](https://github.com/f4samurai/device-farm) — another search result with substantially overlapping STF documentation.

STF (Smartphone Test Farm) is a browser application for remotely controlling and managing Android devices. The DeviceFarmer README describes real-time screen view, touch/typing, APK installation, shell commands, log streaming, file management, device inventory, user groups, booking and reverse port forwarding. It also documents an `adb connect` workflow for connecting to a remote device as if it were plugged into the developer's machine.

This is a mature architectural reference for:

- host/worker separation;
- device inventory and health;
- user/device allocation and booking;
- browser-based control;
- remote ADB connection flows;
- exposing selected remote devices to developers.

The original `openstf/stf` README warns that the original project was no longer under active development and points users to DeviceFarmer. DeviceFarmer's README contains an explicit security caveat: the project's historical internal-network assumptions meant there was little or no encryption between some processes, and devices were not completely reset between uses. Do not treat the old internal deployment assumptions as acceptable for a modern multi-tenant enterprise environment.

**Assessment:** Best reference for the remote device-lab / fleet-management category. It expects a fleet connected to worker hosts; it is not a phone companion designed to create an Internet uplink from a single user's phone.

Sources: [DeviceFarmer repository](https://github.com/DeviceFarmer/stf), [DeviceFarmer README](https://github.com/DeviceFarmer/stf/blob/master/README.md), [original OpenSTF repository](https://github.com/openstf/stf), [STF API documentation](https://github.com/DeviceFarmer/stf/blob/master/doc/API.md).

---

## 6. Tailscale + native Wireless ADB

### [enginefuture/tauri-android-remote](https://github.com/enginefuture/tauri-android-remote)

A Tauri 2 + Rust Android companion and Mac CLI for connecting an authorized Mac to an Android phone using Tailscale, ADB and scrcpy. The README labels the project **Alpha**. It says the app guides setup and generates commands; Android's own `adbd` executes the commands. It does not implement an ADB server, grant itself shell access or enable debugging automatically.

The documented sequence is:

1. Install/sign in to Tailscale on phone and Mac.
2. Enable Android Wireless Debugging and complete Android's pairing-code flow.
3. Use `adb pair` to pair, then `adb connect` to the phone's Tailscale IP and the dynamic Wireless Debugging connection port.
4. Use normal ADB and scrcpy over the overlay network.

The project calls out important limitations: Tailscale does not enable ADB automatically; OEM behaviour may differ; cellular-only use needs explicit device testing; some phones disable Wireless Debugging when Wi-Fi disconnects; no unattended reboot recovery is promised. Its optional USB fallback uses legacy `adb tcpip 5555`, which the README itself warns may listen on LAN interfaces and recommends avoiding in favour of Wireless Debugging TLS pairing.

**Assessment:** Useful and relatively clean where Tailscale is approved and Wireless Debugging remains available. This is a routed overlay approach, not a relay protocol and not a fit for organisations that prohibit third-party VPN/overlay clients.

### [andrew-malitchuk/tailscale-deploy-adb](https://github.com/andrew-malitchuk/tailscale-deploy-adb)

A Claude Code skill that automates a deploy/debug loop over Tailscale and ADB: device resolution, `adb connect`, Gradle installation, launch, logcat and a suspended debug launch mode. Its README also documents a USB bootstrap path using `adb tcpip 5555` and native Wireless Debugging pairing. Treat it as automation around existing connectivity, not a new bridge daemon.

Sources: [Android Remote](https://github.com/enginefuture/tauri-android-remote), [Tailscale Deploy ADB](https://github.com/andrew-malitchuk/tailscale-deploy-adb).

---

## 7. Other open-source projects inspected

### [nisargjhaveri/remote-adb](https://github.com/nisargjhaveri/remote-adb)

A WebUSB-based browser and CLI tool for sharing Android devices attached by USB to a remote host. The host starts a `remote-adb` server; another machine opens the HTTPS web client or uses the command-line client to connect the device. The remote side can debug the shared device.

Important distinction: it still requires a different machine with USB access to the physical phone. It helps when the developer's laptop cannot use USB, but it does not eliminate the need for a USB-connected host somewhere. Its `package.json` has a test script that explicitly exits with “no test specified”; this is not evidence that the project is broken, but it means the repository does not define an npm test suite through that script.

Source: [README](https://github.com/nisargjhaveri/remote-adb), [package metadata](https://github.com/nisargjhaveri/remote-adb/blob/main/package.json).

### [devapro/adb-master](https://github.com/devapro/adb-master)

A browser-based Android device-management tool with a local ADB host and optional VPS relay. It advertises a web UI for shell, logcat, install, app management, files, screen stream, input control and a relay mode for remote browser sessions. It is primarily a remote web-control product; its README does not establish a transparent native ADB endpoint for every tool on the developer laptop. Its documented basic device setup includes USB ADB or legacy `adb tcpip 5555`.

Source: [README](https://github.com/devapro/adb-master).

### [thusexistence/remote-adb-magisk](https://github.com/thusexistence/remote-adb-magisk)

A Magisk service module for Android 11+ that restores Wi-Fi and starts Android's native TLS Wireless Debugging after boot, and can report the dynamic ADB endpoint to a host on the same LAN. Requires root/Magisk and one successful native pairing. It does not present itself as a general Internet relay.

Source: [README](https://github.com/thusexistence/remote-adb-magisk).

### [SangbitDas/DroidBridge](https://github.com/SangbitDas/DroidBridge)

A Windows desktop UI for Android Wireless Debugging. It handles QR/code pairing, local mDNS discovery, connect/disconnect, device details and local saved profiles. Its documented requirement is phone and PC on the same Wi-Fi. Useful UX reference for Wireless ADB, not a WAN bridge.

Source: [README](https://github.com/SangbitDas/DroidBridge).

### [wsrscx/cloudphone](https://github.com/wsrscx/cloudphone)

A remote Android control project with a Windows server, Android client and Remote IME. It uses ADB from the server to manage the controlled phone, then streams video and sends control messages over separate TLS WebSockets. Its usage instructions still require the controlled phone to be connected to the server through USB or an already-controlled ADB channel and authorized on that server. It provides an interesting secure video/control architecture, but not a phone-to-developer ADB transport replacement.

Source: [README](https://github.com/wsrscx/cloudphone), [usage guide](https://github.com/wsrscx/cloudphone/blob/main/docs/%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E.md).

### [yume-chan/ya-webadb](https://github.com/yume-chan/ya-webadb)

A TypeScript reimplementation of the ADB client that works in Chromium-based browsers, Node.js and Electron. The repository brands the project Tango / “ADB in your browser.” It is important for ADB protocol/client implementation and browser tooling, but it is not itself a phone-originated remote relay.

Source: [README](https://github.com/yume-chan/ya-webadb).

### [labgrid-project/labgrid](https://github.com/labgrid-project/labgrid)

A general embedded-board control/testing framework with a remote client-exporter-coordinator model. It supports remote hardware control and testing infrastructure, but is not Android ADB-specific. It is a useful architecture reference for a device-lab control plane rather than a direct implementation of the user's Android requirement.

Source: [README](https://github.com/labgrid-project/labgrid).

### [borankux/android-remote-control](https://github.com/borankux/android-remote-control)

An Android remote-control stack for rooted devices and cloud phones. Its README describes a Kotlin app, token-protected Node relay, React console, device diagnostics, screenshots, UI dumps, whitelisted control commands and an optional ADB bridge over WebSocket. It explicitly targets rooted Android/cloud-phone use cases, so it is not proof that the same design works on ordinary unrooted corporate phones.

Source: [README](https://github.com/borankux/android-remote-control).

### [Anirudh-pandit-466/android-adb-tunnel-vantage](https://github.com/Anirudh-pandit-466/android-adb-tunnel-vantage)

The README describes a cross-platform desktop/mobile development hub using SSH reverse tunnels from remote device hosts, with device inventory, CLI and ADB actions. It is a host-agent/SSH-tunnel model rather than a phone-side companion. I inspected the README but did not validate the claimed build, functionality or security implementation.

Source: [README](https://github.com/Anirudh-pandit-466/android-adb-tunnel-vantage).

### [t0mer/adb-api](https://github.com/t0mer/adb-api)

A FastAPI application for managing Android TV devices reachable over ADB/TCP. It generates/stores an ADB key and exposes device control through a REST API and browser remote. It is a home-automation / Android TV API layer, not a transparent remote ADB bridge for a developer workstation.

Source: [README](https://github.com/t0mer/adb-api).

### [MoTechOrbit/ADB-WEB](https://github.com/MoTechOrbit/ADB-WEB)

A Flask-based browser UI for local ADB/scrcpy operations, with app/file/log/shell/screen controls. The README tells operators not to expose it directly to the Internet and recommends firewall/HTTPS for deployment. It is a web dashboard for an ADB host, not a phone-originated remote ADB transport.

Source: [README](https://github.com/MoTechOrbit/ADB-WEB).

### [MajeurAndroid/java-adb-remote-screen](https://github.com/MajeurAndroid/java-adb-remote-screen)

A local Java GUI for viewing and controlling an Android screen through ADB. The README dates the project lineage to 2015–2020. It is not a remote bridge.

Source: [README](https://github.com/MajeurAndroid/java-adb-remote-screen).

---

## 8. Additional GitHub repositories and search leads

This inventory preserves additional repository links found during the search. Inspection levels vary: some READMEs were inspected, while others are search-only leads. Do not infer implementation quality, security or maintenance status from a repository name or search result alone.

| Repository | Why it surfaced / caution |
|---|---|
| [CoryCharlton/Remote.Adb](https://github.com/CoryCharlton/Remote.Adb) | A remote ADB / tunnel-related project surfaced in search. A readable README fetch failed during this review, so the exact implementation remains unverified. |
| [AndroidGradleTools/adb-relay-android-upstream](https://github.com/aioue/adb-relay-android-upstream) | README is near-identical to AndroidGradleTools' Android device-side relay companion; appears to be an upstream/mirror/fork of the same approach, not an independent architecture. |
| [aioue/adb-relay-jvm](https://github.com/aioue/adb-relay-jvm) | A fork/mirror of the Kotlin/JVM relay implementation; inspected README is effectively the same relay approach. |
| [aioue/adb-relay-python](https://github.com/aioue/adb-relay-python) | README and protocol compatibility were inspected; see Section 2. |
| [AndroidGradleTools/adb-relay-jvm](https://github.com/AndroidGradleTools/adb-relay-jvm) | README and protocol specification were inspected; see Section 2. |
| [AndroidGradleTools/android-ide-extension](https://github.com/AndroidGradleTools/android-ide-extension) | README and changelog were inspected; see Section 2. |
| [AndroidGradleTools/adb-relay-android](https://github.com/AndroidGradleTools/adb-relay-android) | README and selected Kotlin source files were inspected; see Section 2. |
| [Anirudh-pandit-466/android-adb-tunnel-vantage](https://github.com/Anirudh-pandit-466/android-adb-tunnel-vantage) | README inspected; implementation not validated. |
| [borankux/android-remote-control](https://github.com/borankux/android-remote-control) | README inspected; rooted/cloud-phone target; implementation not validated. |
| [MajeurAndroid/java-adb-remote-screen](https://github.com/MajeurAndroid/java-adb-remote-screen) | README inspected; local screen controller rather than remote bridge. |
| [MoTechOrbit/ADB-WEB](https://github.com/MoTechOrbit/ADB-WEB) | README inspected; local web UI around an ADB host. |
| [t0mer/adb-api](https://github.com/t0mer/adb-api) | README inspected; Android TV ADB/TCP REST wrapper. |
| [applicaster/adb-remote](https://github.com/applicaster/adb-remote) | Search result only; not inspected. |
| [oberien/adb-remote-control](https://github.com/oberien/adb-remote-control) | Search result only; not inspected. |
| [nladuo/PyAndroidControl](https://github.com/nladuo/PyAndroidControl) | Search result only; not inspected. |
| [scvjx/PhoneRemoteControlPlatform](https://github.com/scvjx/PhoneRemoteControlPlatform) | Search result only; not inspected. |
| [maxired/android-remote-electron](https://github.com/maxired/android-remote-electron) | Search result only; not inspected. |
| [mobi-nex/adborc](https://github.com/mobi-nex/adborc) | Search result only; not inspected. |
| [sleekweasel/CgiAdbRemote](https://github.com/sleekweasel/CgiAdbRemote) | Search result only; not inspected. |
| [ns130291/MonkeyRemote](https://github.com/ns130291/MonkeyRemote) | Search result only; not inspected. |
| [ppareit/AdbConnect](https://github.com/ppareit/AdbConnect) | Search result only; not inspected. |
| [maxrd2/DivvyDroid](https://github.com/maxrd2/DivvyDroid) | Search result only; not inspected. |
| [firerpa/lamda](https://github.com/firerpa/lamda) | Search result only; not inspected. |
| [kasuganosoras/RemoteAndroid](https://github.com/kasuganosoras/RemoteAndroid) | Search result only; not inspected. |
| [Anirudh-pandit-466/android-adb-tunnel-vantage](https://github.com/Anirudh-pandit-466/android-adb-tunnel-vantage) | README inspected; not executed. |
| [f4samurai/device-farm](https://github.com/f4samurai/device-farm) | Search result with overlapping DeviceFarmer/STF-style documentation; not treated as a distinct architecture. |

Some broad search results also returned repositories with names such as `ghost`, `worm`, `RAT`, exploit/pentest tools or unrelated Android TV remotes. They were not included as recommended implementations because the search result alone did not establish a legitimate, relevant remote ADB bridge use case.

---

## 9. Commercial and official offerings

### Google's Android Device Streaming

[Android Device Streaming, powered by Firebase](https://developer.android.com/studio/run/android-device-streaming) allows developers to reserve and connect to remote physical Android devices hosted in Google's secure data centres and Android Partner Device Labs. Google's docs state that the connection uses **ADB over SSL**, allowing ADB-compatible tools to work after reservation, and that devices are factory-reset and wiped when the session ends. The Android CLI also offers `android device remote` commands to reserve and connect remote devices to ADB.

This is a strong example that remote ADB is accepted as a product capability. Its limitation is the device source: it is a provider-hosted device, not a tunnel to the developer's personal or company-issued phone wherever it happens to be.

Sources: [Android Device Streaming](https://developer.android.com/studio/run/android-device-streaming), [Android CLI `device remote`](https://developer.android.com/tools/agents/android-cli/commands/device_remote), [Google Cloud Device Streaming API overview](https://docs.cloud.google.com/device-streaming/docs/overview).

### BrowserStack App Live

BrowserStack App Live documents an ADB Shell panel with supported ADB commands inside its remote testing session. This is useful remote debugging/test functionality, but the documented workflow is a vendor-provided command interface, not necessarily a general-purpose ADB transport to arbitrary local IDEs.

Sources: [Using ADB commands in App Live](https://www.browserstack.com/docs/app-live/adb-commands), [App Live DevTools](https://www.browserstack.com/docs/app-live/get-started/toolbar).

### AWS Device Farm

AWS Device Farm's Remote Access feature provides browser-based manual interaction with physical devices hosted by AWS, app upload, screenshots, video and logs, plus an Appium endpoint. Its documentation does not describe a general-purpose stock ADB bridge to any arbitrary personal phone.

Sources: [AWS Device Farm Remote Access](https://docs.aws.amazon.com/devicefarm/latest/developerguide/remote-access.html), [What is AWS Device Farm?](https://docs.aws.amazon.com/devicefarm/latest/developerguide/welcome.html).

### WiDE-R (unverified lead)

[wide-r.net](https://wide-r.net) was mentioned in the earlier search as a product claiming Android Studio integration for remote phones using a session PIN and companion app. In this review I could not retrieve the site or independently inspect a source repository, protocol, security model or current release. It should remain an unverified lead and should not carry weight in the technical conclusion until tested directly.

---

## 10. Why a universal remote ADB bridge is not already a standard Android feature

These are architectural explanations, not claims about Google's internal product strategy.

### 10.1 ADB is a high-privilege interface

ADB can install applications, execute shell commands, move files, inspect logs and interact with debugging services. Exposing it remotely gives substantial control over the device. A remote gateway needs a stronger access-control story than “the TCP port is reachable.”

### 10.2 The ADB host server is not safe to expose as-is

The official scrcpy tunnel documentation shows that a local ADB client can be pointed at a remote ADB server using `ADB_SERVER_SOCKET`, but it explicitly warns that communication between the client and ADB server is unencrypted and recommends an SSH tunnel for secure remote access.

That is one reason a product should not just publish port `5037` to the Internet. ADB server access and device-side `adbd` access are different protocol surfaces, and an exposed host server is not an enterprise gateway.

Source: [scrcpy remote ADB and SSH tunnels](https://github.com/Genymobile/scrcpy/blob/master/doc/tunnels.md).

### 10.3 Android Wireless Debugging is deliberately a paired local workflow

Google documents Wireless Debugging as a pairing-code/QR process where the workstation and device must be on the same wireless network. Pairing is remembered until the user forgets the workstation or revokes debugging authorizations. This is good for local development, but it does not automatically solve carrier NAT, dynamic network paths or a phone that must connect from outside the enterprise LAN.

Source: [Android ADB — wireless debugging](https://developer.android.com/tools/adb).

### 10.4 NAT and firewall direction matter

A phone on mobile data is often behind carrier NAT; an unsolicited inbound connection from a developer workstation may not reach it. A phone-initiated channel (SSH reverse tunnel, WebSocket relay or overlay VPN) solves the directionality problem because the phone can make outbound connections. The BigBlueWhale and AndroidGradleTools projects demonstrate these two families.

### 10.5 Android applications cannot silently replace system debugging authority

A regular APK cannot simply grant itself system-level shell access. The viable implementations use the system's existing Wireless Debugging / `adbd`, a previously authorized connection, root/Magisk, or a host already trusted to control the phone. The AndroidGradleTools companion README explicitly says it does not replace Wireless Debugging pairing or automatically enable debugging.

### 10.6 Enterprise policy may prohibit debugging itself

If MDM/EMM has set `DISALLOW_DEBUGGING_FEATURES`, the bridge should not restore debugging through a side path. A compliant enterprise product needs an administrator-controlled enablement and revocation model. A laptop USB block alone is a different situation from a phone policy that disables debugging.

Source: [Android `DISALLOW_DEBUGGING_FEATURES`](https://developer.android.com/reference/android/os/UserManager#DISALLOW_DEBUGGING_FEATURES).

### 10.7 The ecosystem is fragmented around different network and trust assumptions

The projects found use several non-interchangeable approaches:

- direct Wireless ADB over same Wi-Fi;
- ADB over Tailscale/overlay network;
- reverse SSH tunnel from a phone or host;
- a per-device ADB proxy;
- a WebSocket relay pairing two endpoints with a shared token;
- USB device sharing via WebUSB;
- web-based device-farm control.

There is no single, widely adopted bridge standard across these repositories. The AndroidGradleTools protocol is an attempt to standardize one relay approach, but its adoption and enterprise maturity have not been established in this review.

---

## 11. What an enterprise-grade remote ADB bridge would need

The research suggests the most promising design is to preserve Android's existing `adbd` and ADB key authorisation while building a secure transport and policy layer around it.

### Recommended high-level architecture

```text
Android phone
  - Android Wireless Debugging / system adbd
  - approved phone-side companion
  - outbound WSS connection
        |
        v
Relay / broker
  - TLS termination
  - one-time session pairing
  - identity and policy checks
  - device/user mapping
  - expiry and revocation
  - rate/connection limits
  - audit events
        ^
        |
Developer workstation
  - approved local helper / IDE bridge
  - local loopback ADB endpoint
  - stock ADB / Android Studio / VS Code / scrcpy
```

### Requirements checklist

| Requirement | Reason |
|---|---|
| Phone-initiated outbound connection | Supports devices behind carrier NAT and strict inbound firewalls. |
| TLS/WSS with certificate validation | Protects the transport and session credential in transit. |
| Preserve Android's own ADB pairing/authentication | Do not invent a weaker substitute for device trust. |
| Separate user identity from relay token | A bearer token alone is not corporate user identity or SSO. |
| One device and one user per session by default | Prevents a shared credential from granting unintended fleet-wide access. |
| Short-lived, high-entropy, single-use session tokens | Limits exposure if a token leaks. |
| Explicit consent and policy approval | Makes remote access visible and compliant. |
| Immediate revoke/kill | Ends active sessions, not merely future connections. |
| MDM/EMM policy integration | Must respect `DISALLOW_DEBUGGING_FEATURES` and enterprise device ownership. |
| Audit trail | Record who accessed which device, when, and for how long; avoid logging secrets or command output by default. |
| No public `5037` / `5555` listener | Avoids publishing raw ADB services to untrusted networks. |
| Network/battery lifecycle recovery | Handle Wi-Fi/cellular transitions, vendor background limits, sleep and reboot. |
| Device identity binding | Bind the session to a stable device identity, not just an IP address or self-reported name. |
| Resource limits and backpressure | Prevent relay memory growth and one peer monopolising the server. |
| Session isolation | Ensure one developer cannot attach to another developer's active phone session. |
| Enterprise deployment modes | Self-hosted relay, proxy-compatible outbound ports, SSO, customer-managed keys and retention controls. |

### What not to do

- Do not expose ADB server port `5037` publicly.
- Do not expose legacy `adbd` TCP port `5555` directly to the Internet.
- Do not use cleartext `ws://` for public relay traffic.
- Do not treat an IP address, hostname or device-reported model as authentication.
- Do not let an application silently turn on debugging or override MDM policy.
- Do not treat a shared session token as a complete enterprise identity and authorization system.
- Do not claim Android Studio compatibility merely because a web UI can execute shell commands.

---

## 12. New-GenADB implications

The earlier review of [SumukhaK/New-GenADB](https://github.com/SumukhaK/New-GenADB) found four Markdown research documents and no Android application implementation, Gradle project, Android manifest or tests at that point. Those documents already separate build tooling, ADB device control, wireless debugging and LocalSend-style file transfer.

The remote ADB research adds a fourth architectural concern that should be researched independently:

1. **Build/deploy pipeline** — Gradle/Android SDK, APK build and install.
2. **Device debugging/control** — ADB commands, logcat, shell and debugger.
3. **Remote transport / session broker** — how the developer reaches an authorised phone across networks.
4. **File transfer** — a distinct file-sharing path, not a replacement for ADB.

Before implementing a custom bridge, New-GenADB should do a hands-on comparison of:

- AndroidGradleTools' WebSocket relay family;
- DarkRide's ADB proxy design and approval model;
- BigBlueWhale's reverse-SSH lifecycle and NAT handling;
- direct Tailscale + Wireless Debugging.

A productive initial experiment would be to build and test the AndroidGradleTools stack in a controlled lab, then write a threat model and compare the result against DarkRide's per-key approval/revocation approach. That will reveal whether the missing piece is the transport, the enterprise identity/policy layer, or operational reliability.

---

## 13. Bottom-line findings

| Question | Finding |
|---|---|
| Is remote ADB technically possible? | **Yes.** Android Wireless Debugging, SSH, VPNs, ADB proxies and WebSocket relays demonstrate it. |
| Has anyone documented a non-rooted phone over mobile data? | **Yes.** BigBIueWhale documents a Galaxy A56 on 5G using a phone-originated reverse SSH tunnel. |
| Is there an open-source phone-side companion + Internet relay + developer bridge? | **Yes, at least one public project family:** AndroidGradleTools' VS Code extension + Android companion + JVM/Python relay. |
| Is there a separate ADB-compatible proxy with approval/revocation? | **Yes:** DarkRide. Its own docs state that the proxy traffic is unencrypted without an outer VPN/tunnel. |
| Are there remote device farms? | **Yes:** DeviceFarmer/STF and commercial options such as Google's Android Device Streaming, BrowserStack and AWS Device Farm. |
| Did I establish a mature, widely adopted enterprise-ready open-source product that solves all constraints? | **No.** Public implementations exist, but the reviewed evidence does not establish broad enterprise adoption, independent security audits or complete MDM/SSO/policy integration. |
| Is there still meaningful work for New-GenADB? | **Yes, if the contribution is the enterprise security/policy/lifecycle layer or a demonstrably better operational product—not merely another raw TCP tunnel.** |

---

## 14. Research method, verification level and limitations

This report reflects research performed through **16 November 2026**. It combines:

- official Android developer documentation;
- Android Enterprise API documentation;
- GitHub repository and code search;
- direct reads of README/changelog/design/protocol documents for selected repositories;
- direct reads of selected Android companion source files for the AndroidGradleTools relay;
- official documentation for Google, BrowserStack and AWS device streaming/testing services.

### Verification labels used

- **Inspected:** README, design document, protocol specification or selected source files were read directly.
- **Author-documented working:** the repository includes a detailed claimed successful run, logs or test evidence, but I did not independently reproduce it.
- **Search-only:** a repository surfaced in GitHub search, but its implementation was not inspected enough to make a confident technical classification.
- **Unverified product lead:** a product was mentioned in the earlier research, but I could not independently retrieve and verify its implementation during this review.

### What was not done

- I did not literally scrape every public website or GitHub repository. That is not a verifiable claim anyone can make from a finite search.
- I did not inspect private repositories or all forks of every candidate.
- I did not build or run the AndroidGradleTools relay stack, DarkRide, DeviceFarmer, Tailscale projects or the reverse-SSH setup.
- I did not conduct penetration testing, cryptographic review, dependency audit or Android OEM compatibility testing.
- I did not verify enterprise customer deployments or adoption claims.
- Repository READMEs are author statements, not independent proof. A feature described in a README is not automatically a secure, reliable, maintained or production-ready implementation.

The most honest conclusion is therefore not “nobody has solved this.” It is: **several people have built meaningful parts of it, and one especially relevant open-source WebSocket bridge family exists; what remains uncertain is whether any of these projects already meets enterprise requirements without substantial additional engineering and verification.**

---

## 15. Source catalogue

The links below are included so every major technical claim and every named repository can be checked directly.

### Official Android / platform documentation

1. [Android Debug Bridge (ADB)](https://developer.android.com/tools/adb) — ADB architecture, client/server/device model and Wireless Debugging workflow.
2. [Android `UserManager.DISALLOW_DEBUGGING_FEATURES`](https://developer.android.com/reference/android/os/UserManager#DISALLOW_DEBUGGING_FEATURES) — device/profile-owner restriction for debugging features.
3. [Android `UserManager.DISALLOW_USB_FILE_TRANSFER`](https://developer.android.com/reference/android/os/UserManager#DISALLOW_USB_FILE_TRANSFER) — narrower USB file-transfer restriction.
4. [Android Device Streaming](https://developer.android.com/studio/run/android-device-streaming) — provider-hosted remote physical devices, ADB over SSL and Android Studio integration.
5. [Android CLI `android device remote`](https://developer.android.com/tools/agents/android-cli/commands/device_remote) — reserve and connect to remote Google-hosted devices through ADB.
6. [Google Cloud Device Streaming API overview](https://docs.cloud.google.com/device-streaming/docs/overview) — secure remote ADB access to data-centre-hosted physical devices.

### Key remote ADB and relay implementations

7. [BigBIueWhale/samsung_a56_remote_usb_debugging](https://github.com/BigBIueWhale/samsung_a56_remote_usb_debugging) — documented reverse SSH ADB over 5G.
8. [AndroidGradleTools/android-ide-extension](https://github.com/AndroidGradleTools/android-ide-extension) — VS Code Android tooling and remote ADB bridge integration.
9. [AndroidGradleTools extension changelog](https://github.com/AndroidGradleTools/android-ide-extension/blob/main/CHANGELOG.md) — records the Remote ADB over WebSocket feature and relay-host move.
10. [AndroidGradleTools/adb-relay-android](https://github.com/AndroidGradleTools/adb-relay-android) — phone-side WebSocket agent.
11. [Android companion `AdbProxyService.kt`](https://github.com/AndroidGradleTools/adb-relay-android/blob/main/app/src/main/java/org/androidgradletools/adbrelayandroid/AdbProxyService.kt) — foreground WebSocket tunnel service and reconnect handling.
12. [Android companion `MuxCodec.kt`](https://github.com/AndroidGradleTools/adb-relay-android/blob/main/app/src/main/java/org/androidgradletools/adbrelayandroid/MuxCodec.kt) — ADBM mux framing.
13. [Android companion `Prefs.kt`](https://github.com/AndroidGradleTools/adb-relay-android/blob/main/app/src/main/java/org/androidgradletools/adbrelayandroid/Prefs.kt) — encrypted preferences.
14. [AndroidGradleTools/adb-relay-jvm](https://github.com/AndroidGradleTools/adb-relay-jvm) — Kotlin/JVM WebSocket relay.
15. [ADB relay v1 protocol specification](https://github.com/AndroidGradleTools/adb-relay-jvm/blob/main/prompts/specs.md) — handshake, token pairing, binary forwarding and ADBM frame layout.
16. [aioue/adb-relay-python](https://github.com/aioue/adb-relay-python) — Python implementation of the same relay protocol with additional limits and tests.
17. [aioue/adb-relay-android-upstream](https://github.com/aioue/adb-relay-android-upstream) — related Android companion fork/mirror.
18. [DarkRide ADB proxy guide](https://github.com/DarkRideApp/DarkRide/blob/main/docs/adb-proxy.md) — key approval, revocation and security caveats.
19. [DarkRide ADB proxy design spec](https://github.com/DarkRideApp/DarkRide/blob/main/docs/specs/2026-10-11-adb-proxy-design.md) — implementation design and stated test goals.
20. [DeviceFarmer/stf](https://github.com/DeviceFarmer/stf) — remote device farm.
21. [DeviceFarmer STF README](https://github.com/DeviceFarmer/stf/blob/master/README.md) — capabilities and security notes.
22. [openstf/stf](https://github.com/openstf/stf) — original STF project; README points to DeviceFarmer for continued development.
23. [nisargjhaveri/remote-adb](https://github.com/nisargjhaveri/remote-adb) — WebUSB-based USB device sharing.
24. [devapro/adb-master](https://github.com/devapro/adb-master) — browser device console and optional relay.
25. [enginefuture/tauri-android-remote](https://github.com/enginefuture/tauri-android-remote) — Tailscale + Wireless ADB companion and CLI.
26. [andrew-malitchuk/tailscale-deploy-adb](https://github.com/andrew-malitchuk/tailscale-deploy-adb) — automation for deploy/debug over Tailscale and ADB.
27. [thusexistence/remote-adb-magisk](https://github.com/thusexistence/remote-adb-magisk) — root/Magisk Wireless Debugging bootstrap.
28. [SangbitDas/DroidBridge](https://github.com/SangbitDas/DroidBridge) — local Windows Wireless Debugging UI.
29. [wsrscx/cloudphone](https://github.com/wsrscx/cloudphone) — remote screen/control stack that uses a server-side ADB connection.
30. [yume-chan/ya-webadb](https://github.com/yume-chan/ya-webadb) — browser/TypeScript ADB client implementation.
31. [labgrid-project/labgrid](https://github.com/labgrid-project/labgrid) — general remote embedded device-control framework.
32. [borankux/android-remote-control](https://github.com/borankux/android-remote-control) — rooted/cloud-phone remote control with optional ADB tunnel.
33. [Anirudh-pandit-466/android-adb-tunnel-vantage](https://github.com/Anirudh-pandit-466/android-adb-tunnel-vantage) — README-described SSH tunnel / remote device hub.
34. [t0mer/adb-api](https://github.com/t0mer/adb-api) — Android TV ADB/TCP REST API.
35. [MoTechOrbit/ADB-WEB](https://github.com/MoTechOrbit/ADB-WEB) — local browser UI around ADB and scrcpy.
36. [MajeurAndroid/java-adb-remote-screen](https://github.com/MajeurAndroid/java-adb-remote-screen) — local ADB-based remote-screen utility.
37. [CoryCharlton/Remote.Adb](https://github.com/CoryCharlton/Remote.Adb) — repository surfaced in search; README was not readable during this review.

### Remote tunnelling / device streaming references

38. [scrcpy remote ADB and tunnels documentation](https://github.com/Genymobile/scrcpy/blob/master/doc/tunnels.md) — remote ADB server setup, plaintext warning and SSH tunnel examples.
39. [BrowserStack ADB commands in App Live](https://www.browserstack.com/docs/app-live/adb-commands) — vendor-provided ADB Shell feature.
40. [BrowserStack App Live DevTools](https://www.browserstack.com/docs/app-live/get-started/toolbar) — logs, UI inspector, ADB shell and other tools.
41. [AWS Device Farm Remote Access](https://docs.aws.amazon.com/devicefarm/latest/developerguide/remote-access.html) — browser remote access and Appium endpoint.
42. [AWS Device Farm overview](https://docs.aws.amazon.com/devicefarm/latest/developerguide/welcome.html) — remote testing of hosted physical devices.
43. [WiDE-R website](https://wide-r.net) — unverified lead only; current technical claims were not independently verified.

---

---

## 16. New-GenADB problem statement, design hypothesis and evaluation specification

*Added 16 November 2026. This section is the research specification for the autoresearch loop: `program.md` refers to it in place of a separate `research_draft.md`.*

### 16.1 Problem statement

We are building a tool with three parts: a **desktop app with a CLI**, a **mobile companion app**, and a **connectivity core** that they share. With it, a developer can deploy to and debug their own physical Android phone from any IDE without a USB cable to the computer. The connectivity core comes first. The front end is out of scope for now.

The tool has two modes.

| | Solo / developer mode | Corporate mode |
|---|---|---|
| Who | Indie developers, freelancers, hobby projects on their own network and hardware | Organisations with USB data blocked, VPNs, MDM, security review |
| Phone network | Same Wi-Fi as the computer, or mobile data (carrier NAT) | Anywhere. Corporate egress may allow only outbound HTTPS. |
| Trust bootstrap | Short pairing code shown on the phone (cf. Wireless debugging) | IdP/SSO identity for users, MDM-issued enrollment for devices |
| Security posture | Relaxed UX, but still encrypted end to end and resistant to brute force | Least privilege, no bearer-token-only access, revocation, audit, respects `DISALLOW_DEBUGGING_FEATURES` |

Required capabilities:

- Deploy APKs, and AABs via `bundletool install-apks`, which uses split install sessions (`install-multiple`).
- Stream the deployed app's logs into the IDE's Logcat console.
- Attach a debugger (JDWP).
- Bonus: screenshots (`screencap`) and short screen recordings (`screenrecord`).

### 16.2 Core design hypothesis: make the remote phone look like a local `adb connect` target

Android Studio, the IntelliJ/VS Code Android tooling, Gradle `installDebug`, `bundletool` and scrcpy all talk to the **local adb server (port 5037)**. If the desktop agent exposes a loopback TCP endpoint that behaves like a phone's adbd, then `adb connect 127.0.0.1:<port>` registers the remote phone as an ordinary device. Every IDE feature then works unchanged: install, Logcat, debugger, screen capture and file transfer.

So the connectivity core is a **secure, resilient byte tunnel for one long-lived adb transport stream**. adb multiplexes all of its services over that single TCP connection. The core does not need to re-implement any IDE feature. This is the same shape as the AndroidGradleTools relay family (§2) and the BigBlueWhale reverse tunnel (§3). It adds the policy, identity, integrity and lifecycle layer that §11 found missing.

```text
IDE / Gradle / bundletool / scrcpy
        │ (adb client protocol, localhost:5037)
local adb server ──adb connect 127.0.0.1:P──► genadb connect (desktop agent, loopback-only listener)
                                                   │ outbound, end-to-end encrypted session
                                                   ▼
                                            genadb relay (rendezvous + policy + audit; sees ciphertext only)
                                                   ▲ outbound (works behind carrier NAT)
                                                   │
                                   genadb device (inside the companion app on the phone)
                                                   │ only after an authorised session exists
                                                   ▼
                                   phone adbd (Wireless debugging TLS port or legacy tcpip)
```

There is also an optional **direct LAN path**. When the phone and computer can reach each other, as in the solo same-Wi-Fi case, the agents should use a direct connection with the same end-to-end authentication, and fall back to the relay.

### 16.3 Hard phone-side constraint (to verify on real hardware)

A non-root app cannot create debugging authority. It can only forward to the system adbd. The options for reaching adbd are:

1. **Wireless debugging TLS endpoint**, used as `127.0.0.1:<dynamic port>` from the companion. This is the cleanest option, because adb's own TLS and key pinning stay end to end between the developer's adb and the phone. It requires the phone to be associated with *some* Wi-Fi. Stock Android turns Wireless debugging off without Wi-Fi, and Android 17's "trusted networks" behaviour (§ report 2) can turn it off on unapproved networks. Because the port is dynamic, the companion must discover it (local mDNS `_adb-tls-connect._tcp`) and follow it when it changes. First-time `adb pair` can be carried through the tunnel to the pairing port.
2. **Legacy `adb tcpip`**, bootstrapped once over USB, or Shizuku/LADB-style by having the companion pair with its own adbd. This survives Wi-Fi loss until reboot, so it is the only known non-root route for **mobile-data-only** solo use. adbd then listens in plaintext on all interfaces. That is acceptable only as an explicit solo-mode opt-in, with the tunnel providing the encryption and an automatic `usb:`/disable afterwards.
3. **ADB-aware proxy**: the companion is itself an authorised adb client of its own adbd and proxies services. This is more complex and is a possible future research direction.

None of these behaviours can be confirmed without physical devices across OEMs. Each is listed in §16.7 as unverified.

### 16.4 Security design targets

- **Solo mode:**
  - Pairing uses a short code with a PAKE-style handshake, so neither the relay nor a network observer learns the code or can brute-force it offline.
  - The code is burned after 3 failures.
  - Long-term keys are pinned for later reconnects without a code.
  - Traffic is encrypted and authenticated end to end, so the relay is blind and tampering is detected.
- **Corporate mode:**
  - Users present IdP-signed JWTs (EdDSA in the test IdP). The relay checks issuer, audience, expiry and signature, and the token must carry a `cnf.key` bound to the desktop agent's key (proof of possession), so a stolen token is useless.
  - Devices enroll with MDM-signed tokens that also bind their key.
  - The relay enforces per-user, per-device grants and supports admin revocation that kills live sessions.
  - The relay writes an audit log without secrets.
  - The device agent refuses to run when MDM disallows debugging, and touches adbd only for an authorised session.
  - The desktop listener is loopback-only.

### 16.5 Process contract (what eval.py drives)

All roles are subcommands of one binary built from `core/` by `solution.py`. Each prints JSON-lines events on stdout.

| Command | Required behaviour / events |
|---|---|
| `genadb keygen --state DIR` | Create (idempotent) the identity key and print `{"event":"pubkey","pubkey":S}`. `S` is opaque. It is placed in JWT `cnf.key`. |
| `genadb relay --listen H:P --mode solo\|corporate [--policy F] [--audit F] [--admin H:P --admin-token T]` | Print `{"event":"ready"}`. The admin endpoint takes `POST /v1/revoke` with `{"user":U}` or `{"device":D}` and `Authorization: Bearer T`. It kills live sessions and denies new ones. The audit log is JSONL with `event`, `user`, `device`, and no secrets. |
| `genadb device --relay H:P --adbd H:P --state DIR --mode M [--enroll JWT --policy F] [--debug-policy allowed\|disallowed] [--lan-listen H:P --lan-advertise H:P]` | Print `{"event":"online","device_id":D}`. In solo mode also print `{"event":"pairing_code","code":C,"device_id":D}`, and print a fresh code after a code is burned. If debugging is disallowed, print `{"event":"blocked",...}` and never contact adbd. |
| `genadb connect --relay H:P --state DIR --listen 127.0.0.1:0 --mode M (--code C \| --device D) [--identity JWT] [--policy F]` | Print `{"event":"listening","addr":"127.0.0.1:N","device_id":D}` when ready. The harness then runs `adb connect`. On denial, print `{"event":"error"}` and exit non-zero. Printing `listening` and then refusing the adb connection is also accepted. |

The policy file (corporate) contains `relay_id` (the expected JWT `aud`), `issuer`, `idp_ed25519_public_key` (raw, base64url), `grants: [{user, devices[]}]` and `max_session_seconds`. JWT claims are `iss`, `sub`, `aud`, `typ` (`user`|`device`), `iat`, `nbf`, `exp`, `jti` and `cnf.key`.

### 16.6 Evaluation: test bed, scenarios and metric

**Test bed.**

- **Real adb host:** the **real AOSP `adb` host binary** (Ubuntu `adb` 34.0.4), one isolated server per scenario.
- **Simulated phone:** `harness/fake_adbd.py`, a simulated phone adbd that speaks the real ADB wire protocol in two modes: Wireless-debugging TLS (STLS, TLS 1.3, client-key pinning) and legacy RSA AUTH. It implements shell/exec, sync push/pull, streamed install, split install sessions (`install-create/write/commit`, the bundletool/AAB path), logcat, screencap, a screenrecord stream and JDWP echo. It records everything it receives, so integrity is checked by hash.
- **Network simulator:** `harness/netsim.py` sits on every agent↔relay leg. It adds latency and bandwidth caps and records all bytes. It can kill connections, black out the network, and flip one bit (active tampering).
- **NAT model:** the agents can only dial out, which models NAT.

**Scenarios** run in parallel, about 16 s in total:

| ID | Setting | Checks (weight) |
|---|---|---|
| S | Solo, legacy adbd, 20 ms per leg one-way, 200 Mbit/s | pair+connect (3), shell (2), 8 MiB push+pull integrity (5), `adb install` (4), `install-multiple` / AAB path (3), screencap (3), logcat stream (3), screenrecord stream (2), JDWP debugger (2), reconnect without code (1); canary/file/shell output absent from the wire (4), pairing code absent from the wire (2), pushing zeros yields incompressible wire bytes (1) |
| W | Solo, pairing abuse | 3 wrong codes rejected without touching adbd (2), correct code refused after 3 failures (4), freshly issued code works (1) |
| T | Solo, legacy adbd, 10 ms per leg | a bit flip mid-pull is never accepted silently (8), a 12 MiB push survives a mid-transfer connection drop (5, or 0.4 if it only recovers), recovery time after a 4 s blackout (5) |
| C | Corporate, TLS adbd, IdP + policy + audit + admin | authorised session works: shell, push, logcat (6, and gates the rest); deny unauthorised user / expired / forged / wrong audience / stolen token (other key) / no identity (2 each); `debug-policy disallowed` blocks without touching adbd (3); revoke kills the live session within seconds (2) and blocks new ones (2); audit log has start/deny/end and no secrets (3); loopback-only listeners and no adbd contact before authorisation (2) |
| P | Measured inside S | push throughput, log-scaled 0.5→60 MB/s (3); time to ready (2); logcat median latency (2) |
| L | Solo, relay legs 60 ms one-way, LAN path 1 ms available | JDWP median round-trip time, 250 ms → 20 ms scaled (3) |

**SCORE** = Σ weight × fraction, with a range of 0 to 100 where higher is better. A denial only scores if the authorised session in the same scenario works, so "deny everything" earns nothing. A "denied" result requires both that adb never reaches `device` state and that the simulated adbd sees no new connection. The canary, payloads and seeds are random on every run. Measured run-to-run noise on the baseline is about ±0.05.

**Anti-gaming rules**, enforced in `program.md` and by review:

- The solution must not read `harness/` or `eval.py`, and must not detect the test environment.
- Keys must not be derivable from data the relay sees.
- The pairing code must not reach the relay in any encoding.
- No hard-coded keys.

### 16.7 What this evaluation can and cannot verify

**Verified here:**

- Real adb host behaviour (connect, TLS client authentication, install, split install, sync, logcat, exec-out, forward to JDWP) through the tunnel.
- Protocol correctness and integrity under latency, drops, blackouts and bit flips.
- Relay blindness against passive capture.
- Corporate authorisation logic, revocation and audit.
- Behaviour of the CLI process contract.

**Not verified here. This needs physical devices and real networks:**

- Real phone adbd behaviour: dynamic-port changes, Wireless debugging turning off when Wi-Fi drops, Android 17 trusted networks, OEM differences, and whether legacy tcpip mode survives on mobile data.
- `adb pair` (SPAKE2) through the tunnel.
- Android background-execution and battery limits on the companion's foreground service.
- Real carrier NAT and IPv6 exposure.
- Corporate egress proxies, i.e. WSS over 443.
- MDM integration (reading `DISALLOW_DEBUGGING_FEATURES` from DevicePolicyManager).
- The Android Studio UI itself.
- `bundletool` with a real AAB. The eval tests the split-install path that bundletool uses.
- Real screenrecord and H.264.

Passive-capture checks cannot prove the absence of a weak cipher. Code review must confirm that standard AEAD and key exchange are used.

---

*End of report.*
