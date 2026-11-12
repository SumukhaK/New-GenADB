# LocalSend discovery and transfer

Research checked on 2026-11-12. The current project pages list v1.18.2 as the latest stable release; the project protocol repository labels its current document LocalSend Protocol v2.2. Those are different versioning surfaces, so the report should avoid assuming the app release's exact protocol revision without checking the tagged source. [Releases](https://github.com/localsend/localsend/releases) · [Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md)

## How LocalSend discovers devices and transfers files

### Takeaway

LocalSend is a direct local-network file/message exchange: peers discover one another, establish a direct HTTP(S) connection, present transfer metadata, then transfer bytes after the receiver's decision. "Serverless" here means there is no central relay or account service in the documented flow; a peer still runs an HTTP server to receive data. [Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md) · [Project README](https://github.com/localsend/localsend)

### Cited Findings

#### Plain-English lens

- The project says devices can share files and messages over their local network without an internet connection, without accounts or logins, and without a third-party server. Its published client platforms include Android, iOS, Windows, macOS, and Linux. [Project README](https://github.com/localsend/localsend) · [LocalSend website FAQ](https://localsend.org/)
- At a high level, the sender selects a nearby device and files; the receiver gets a chance to accept, partially accept, or reject the request before file bytes are sent. The protocol separates the metadata/approval request from the subsequent binary upload. [Protocol v2.2, file-transfer sections](https://github.com/localsend/protocol/blob/main/README.md)

#### Senior-architect lens

- The published protocol defaults to UDP multicast at IPv4 `224.0.0.167:53317` and an HTTP/TCP service at port `53317`; these addresses/ports can be changed in app settings. Discovery announcements carry fields such as alias, protocol version, device type/model, certificate fingerprint, service port, HTTP/HTTPS mode, and capability flags. [Protocol v2.2, defaults and discovery](https://github.com/localsend/protocol/blob/main/README.md)
- Default discovery is a custom JSON announcement over UDP multicast, not mDNS/DNS-SD: on receiving an announcement, a peer first sends `POST /api/localsend/v2/register` to the announcer over TCP; multicast reply is a fallback. When multicast discovery fails, the documented legacy method probes local IP addresses using the same `/register` API. [Protocol v2.2, discovery](https://github.com/localsend/protocol/blob/main/README.md)
- The default upload flow is receiver-server/sender-client: `POST /prepare-upload` sends a manifest (name, size, MIME type, optional SHA-256, preview and metadata). The receiver returns a session ID and per-file tokens if it accepts the transfer; the sender posts each file's raw bytes to `/upload`, with uploads allowed in parallel, and can call `/cancel`. [Protocol v2.2, upload API](https://github.com/localsend/protocol/blob/main/README.md)
- The protocol describes optional PIN submission on prepare-upload, receiver decisions including rejection or partial acceptance, and `422` for a checksum mismatch if a SHA-256 digest was supplied and verified. [Protocol v2.2, upload API](https://github.com/localsend/protocol/blob/main/README.md)
- LocalSend also specifies a reverse/browser flow: the sender exposes a URL and the other device uses a browser to fetch files. The protocol expressly says this flow uses unencrypted HTTP because browsers reject the app's self-signed certificates. [Protocol v2.2, reverse transfer](https://github.com/localsend/protocol/blob/main/README.md)
- The main app repository describes the application as cross-platform and uses Flutter; release v1.18.0 says the Rust rewrite of core networking and file-I/O logic was complete and introduced the CLI on the same Rust library. [Project README](https://github.com/localsend/localsend) · [v1.18.0 release notes](https://github.com/localsend/localsend/releases/tag/v1.18.0)

#### Academic / protocol lens

- The LocalSend protocol separates discovery, transfer negotiation, and data transfer into distinct application-level stages. This permits a receiver decision before bulk data begins and makes the service capability advertisement explicit. This is an architectural interpretation of the protocol's published message/endpoint sequence. [Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md)
- LocalSend's default discovery is its own multicast JSON protocol; it should not be described as mDNS. In the standards-based alternative, DNS-SD specifies service-instance PTR/SRV/TXT record conventions, and mDNS transports DNS-like queries/replies over IP multicast for zero-configuration link-local discovery. [LocalSend Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md) · [RFC 6763, DNS-Based Service Discovery](https://www.rfc-editor.org/rfc/rfc6763) · [RFC 6762, Multicast DNS](https://www.rfc-editor.org/rfc/rfc6762)
- RFC 6763 explains that multicast DNS-SD is suitable for ad-hoc networks but that high-volume enterprise-wide multicast can be undesirable, motivating directory/registration approaches for larger networks. Applied to LocalSend, this suggests its multicast-plus-local-IP-scan design targets small local networks; that scalability conclusion is an inference, not a measured LocalSend benchmark. [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763) · [Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md)

### Inferences

- For a developer tool, LocalSend offers a useful UX reference for selecting a nearby target and transferring a build artifact over a direct network path. Its published API has file/message transfer endpoints, not Android package-install, shell, debugger, or log-streaming endpoints; treating it as a complete ADB replacement would therefore be a category error based on the documented protocol surface. [Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md)
- A split design is feasible: reuse a LAN transfer experience for artifact delivery while retaining a separate, explicitly authorized device-control channel for install/launch/debug operations. This is a product/architecture inference from LocalSend's transfer protocol and the distinct requirements of device control.

### Gaps

- The project protocol README is living documentation and currently says v2.2; the v1.18.2 release notes do not state which exact protocol revision the shipped app implements. Verify against the tagged app code before implementing wire compatibility. [Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md) · [v1.18.2 release notes](https://github.com/localsend/localsend/releases/tag/v1.18.2)
- The protocol docs provide no controlled throughput, discovery-latency, power-use, or maximum-peer-count measurements. The project's "maximum Wi-Fi speed" statement is a product claim, not a benchmark. [LocalSend website](https://localsend.org/) · [Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md)

## Security, trust, and operational limits

### Takeaway

HTTPS protects the ordinary app-to-app data path, but a secure channel is only as trustworthy as peer identity and the discovery-to-certificate binding. A published LocalSend security advisory reports a serious discovery-spoofing issue for versions through 1.17.0 and currently lists no patched version, while the project has since released v1.18.2; the advisory and later release history do not by themselves establish whether current builds are vulnerable or fixed. [Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md) · [Security advisory CVE-2025-54792](https://github.com/localsend/localsend/security/advisories/GHSA-424h-5f6m-x63f) · [v1.18.2 release](https://github.com/localsend/localsend/releases/tag/v1.18.2)

### Cited Findings

#### Plain-English lens

- LocalSend says its normal transfers use HTTPS and offers optional PIN verification; it also says it works without an internet connection. These are project claims and describe the normal local-network model, not every protocol path. [LocalSend website FAQ](https://localsend.org/) · [Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md)
- Devices still need to be reachable on the same usable local network. LocalSend's troubleshooting material identifies router access-point isolation, public Windows network profile/firewall restrictions, OS local-network permissions, and VPNs that block LAN traffic as reasons discovery or communication can fail. [Project troubleshooting and setup](https://github.com/localsend/localsend)
- The default firewall guidance is incoming TCP and UDP on port `53317`; the project says AP/client isolation must be disabled for peer connections. Users can manually send to an IP when automatic discovery fails. [Project setup and troubleshooting](https://github.com/localsend/localsend)

#### Senior-architect lens

- When encryption is enabled, the protocol defines the device fingerprint as SHA-256 of its certificate; when encryption is disabled it is a random string. The app README says certificates are generated on each device. A certificate fingerprint is an identity pin only if a client actually binds and verifies that expected fingerprint during its TLS connection; protocol prose alone is not a complete implementation audit. [Protocol v2.2, fingerprint](https://github.com/localsend/protocol/blob/main/README.md) · [Project README](https://github.com/localsend/localsend)
- The protocol announcement itself is UDP multicast. GitHub's LocalSend advisory, published by a project maintainer on 2025-08-01 and assigned CVE-2025-54792, alleges unauthenticated devices on the same LAN can spoof announcements, poison peer lists, and intercept transfers; it lists affected `<=1.17.0` and patched versions `None`. Its remediation proposes TCP IP-address verification. Treat this as a specific reported vulnerability, not proof that every version or network is exploitable. [GHSA-424h-5f6m-x63f / CVE-2025-54792](https://github.com/localsend/localsend/security/advisories/GHSA-424h-5f6m-x63f)
- The official project subsequently released v1.18.0 (2026-08-10) and v1.18.2 (2026-08-21); the v1.18.2 notes mention redirect hardening and compatibility fixes but do not name CVE-2025-54792. The public advisory still says “Patched versions: None” in the reviewed source. This leaves current remediation status unresolved from the available official pages. [v1.18.0 release](https://github.com/localsend/localsend/releases/tag/v1.18.0) · [v1.18.2 release](https://github.com/localsend/localsend/releases/tag/v1.18.2) · [Security advisory](https://github.com/localsend/localsend/security/advisories/GHSA-424h-5f6m-x63f)
- The documented browser/reverse-download flow uses plain HTTP. That is an explicit protocol exception to the homepage's broad statement that all transfers are HTTPS; users should not infer that the browser link flow has HTTPS transport protection. [Protocol v2.2, reverse transfer](https://github.com/localsend/protocol/blob/main/README.md) · [LocalSend website FAQ](https://localsend.org/)
- The project's troubleshooting page suggests disabling encryption on both devices to improve slow transfer speed. This trades away transport encryption and should not be presented as a routine performance setting in a product handling source builds or credentials. [Project troubleshooting](https://github.com/localsend/localsend)
- LocalSend's protocol supports optional sender-provided SHA-256 and receiver-side checksum verification, but the manifest field is nullable; the protocol does not make a checksum mandatory in every transfer. [Protocol v2.2, upload API](https://github.com/localsend/protocol/blob/main/README.md)
- AP isolation, network profile/firewall rules, active VPN policy, and OS local-network permission can block discovery or the direct TCP connection. Manual IP entry can bypass the discovery phase, but it cannot fix a blocked TCP port or an unreachable route. The second sentence is an engineering inference from the distinct discovery and transfer paths. [Project setup/troubleshooting](https://github.com/localsend/localsend) · [Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md)

#### Academic / protocol lens

- UDP multicast discovery and TLS-protected HTTP transfer are different trust layers: confidentiality on the transfer link does not, by itself, establish that the peer selected from an unauthenticated discovery message is the intended device. This is a protocol-security inference consistent with the discovery flow and the reported CVE. [Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md) · [CVE-2025-54792 advisory](https://github.com/localsend/localsend/security/advisories/GHSA-424h-5f6m-x63f)
- RFC 8446 specifies TLS 1.3, but LocalSend's protocol documentation does not state a minimum TLS version, negotiated cipher suite, exact certificate lifetime, public-key algorithm, or whether every client pins/validates the peer certificate exactly as its fingerprint field suggests. Therefore do not attribute particular TLS 1.3 properties to LocalSend without measuring or inspecting the tagged implementation. [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) · [LocalSend Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md)
- RFC 6762/6763 define mDNS/DNS-SD, including service-record conventions; LocalSend's custom announcement format has different semantics and should receive a distinct spoofing/privacy review rather than inheriting security assumptions from mDNS/DNS-SD. This is an analysis recommendation, not a claim that either standard authenticates peers. [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) · [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763) · [LocalSend Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md)

### Inferences

- For an app that might receive APKs, source archives, or debugging artifacts, avoid treating a friendly alias, local-network presence, favorite marker, or successful TLS handshake as user identity unless the product verifies a stable peer identity. Offer an explicit first-contact confirmation/pairing path and clear identity changes; this recommendation follows from the reported spoofing issue and the separation between discovery and transport.
- The 2025 advisory/release discrepancy is a real evidence gap, so a product adopting LocalSend protocol code should inspect and test the actual tagged versions it intends to interoperate with, with tests for spoofed discovery, TLS certificate changes, HTTP fallback, PIN, and checksum failures. This is a verification recommendation based on the unresolved source status, not a claim that all those issues are present.

### Gaps

- The reviewed official security advisory has no patched-version field despite official releases after the vulnerable range. The available release notes do not explain the advisory's current disposition; source inspection and a maintainer clarification would be needed before making a current-version security claim. [Security advisory](https://github.com/localsend/localsend/security/advisories/GHSA-424h-5f6m-x63f) · [Releases](https://github.com/localsend/localsend/releases)
- No independent protocol audit, security evaluation, or performance measurement specific to LocalSend was identified in the primary sources reviewed. The advisory is a public project security report, not a peer-reviewed academic paper.
- The protocol docs do not specify a stable cryptographic device identity across app reinstalls, certificate rotation behavior, session-token entropy, or rate limits in enough detail to independently evaluate all attacks. [Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md)

## Alternatives and implications for a developer tool

### Takeaway

LocalSend is one point in the design space: cross-platform, direct IP networking on a shared LAN with project-defined discovery and an open file-transfer protocol. AirDrop and Quick Share use different discovery, identity, and connectivity models, so their user experiences are useful references but their protocols are not interchangeable with LocalSend. [LocalSend Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md) · [Apple AirDrop security](https://support.apple.com/en-ca/guide/security/sec2261183f4/web) · [Google Quick Share help](https://support.google.com/android/answer/13801258?hl=en)

### Cited Findings

#### Plain-English lens

- LocalSend's appeal is broad platform support and file transfer without a cloud account or internet connection; the project itself calls it an open-source AirDrop alternative. [Project README](https://github.com/localsend/localsend)
- AirDrop is Apple-device sharing and uses Bluetooth Low Energy (BLE) plus Apple's peer-to-peer Wi-Fi technology; Apple says that peer-to-peer link does not require an internet connection or wireless access point and is encrypted with TLS. Apple also says iCloud services help authenticate AirDrop users. [Apple Platform Security: AirDrop security](https://support.apple.com/en-ca/guide/security/sec2261183f4/web)
- Quick Share's Android-to-Windows instructions require Bluetooth, Wi-Fi or Ethernet, both devices on the same network, and device visibility settings; Google warns that some office Wi-Fi networks do not permit device-to-device sharing. [Google Android Help: Quick Share between Android and Windows](https://support.google.com/android/answer/13801258?hl=en)

#### Senior-architect lens

- LocalSend's open protocol documents a custom UDP multicast discovery plane and direct HTTP(S) REST transfer plane with configurable port/address and fallback discovery. The project repository lists platform compatibility and offers a CLI built on protocol v2. [Protocol repository](https://github.com/localsend/protocol) · [Project README/CLI](https://github.com/localsend/localsend)
- Apple documents BLE advertisement/discovery, peer-to-peer Wi-Fi connection, TLS encryption, and iCloud-assisted identity checks for AirDrop. Google documents OS-level Quick Share availability/visibility and Bluetooth plus shared-network requirements for Android-Windows. Those are materially different connection and identity stacks from LocalSend's documented custom LAN protocol. [Apple Platform Security](https://support.apple.com/en-ca/guide/security/sec2261183f4/web) · [Google Android Help](https://support.google.com/android/answer/13801258?hl=en)
- LocalSend's website and protocol are open/public, but its endpoints implement LocalSend's own schema. Compatibility therefore requires implementing LocalSend discovery/API semantics; it does not follow merely from being able to use Wi-Fi, HTTPS, AirDrop, or Quick Share. This is a protocol interoperability inference. [LocalSend Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md) · [Apple Platform Security](https://support.apple.com/en-ca/guide/security/sec2261183f4/web) · [Google Android Help](https://support.google.com/android/answer/13801258?hl=en)

#### Academic / protocol lens

- These approaches occupy different layers: LocalSend advertises services on a shared IP LAN and sends via HTTP(S); AirDrop combines BLE proximity discovery with a peer-to-peer Wi-Fi path; Quick Share's user documentation requires Bluetooth and a shared network for the Android-Windows scenario. Comparing them as if they were simply “Wi-Fi file transfer” hides meaningful discovery, identity, and reachability differences. [LocalSend Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md) · [Apple Platform Security](https://support.apple.com/en-ca/guide/security/sec2261183f4/web) · [Google Android Help](https://support.google.com/android/answer/13801258?hl=en)
- DNS-SD/mDNS is a standardized alternative discovery architecture with defined DNS record semantics and local-link zero-configuration operation; LocalSend instead specifies custom multicast JSON and HTTP probing. A project choosing between these patterns should evaluate network reachability, metadata exposure, spoof resistance, implementation burden, and behavior across subnets separately. The evaluation dimensions are analysis, grounded in the standards and LocalSend's documented fallback paths. [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) · [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763) · [LocalSend Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md)
- Google's troubleshooting documentation itself states that some enterprise/office networks block device-to-device sharing. This is evidence that local-device transfer is partly a network-policy problem, not only an app feature problem. [Google Android Help](https://support.google.com/android/answer/13801258?hl=en)

### Inferences

- Borrow LocalSend's concise target-selection and artifact-transfer flow as a UX reference, while keeping the lifecycle explicit: identify authorized device → transfer APK → install via an authorized Android debugging channel → launch and stream logs. The final install/launch/debug actions are outside LocalSend's published file-transfer API. [LocalSend Protocol v2.2](https://github.com/localsend/protocol/blob/main/README.md)
- For a developer product, LAN-only transfer is convenient but will predictably fail in guest Wi-Fi, AP-isolated, VPN-restricted, or enterprise networks; manual IP or QR bootstrap can reduce discovery friction but still depends on a permitted direct route/port. The networking implication is supported by LocalSend and Google troubleshooting docs; the QR suggestion is a product-design inference. [LocalSend troubleshooting](https://github.com/localsend/localsend) · [Google Quick Share help](https://support.google.com/android/answer/13801258?hl=en)
- A cross-platform product can keep its transport modular: LAN direct as the low-latency path, USB/ADB as a fallback or control path, and any remote relay as a separate explicitly disclosed mode. This is a design inference from the differing reachability models documented by LocalSend, AirDrop, and Quick Share.

### Gaps

- Official Apple and Google user-facing documentation establishes broad operational behavior but does not expose enough protocol details to produce a wire-level interoperability comparison with LocalSend; use vendor platform-security or protocol documents for that depth.
- No controlled apples-to-apples throughput, reliability, power, or privacy comparison across LocalSend, AirDrop, and Quick Share was found in the sources reviewed. The sources support architectural differences, not a winner on performance.
- No file-sharing benchmark supports LocalSend's homepage claim that it runs at maximum Wi-Fi speed; this should be treated as marketing language until tested with representative hardware/network conditions. [LocalSend website](https://localsend.org/)
