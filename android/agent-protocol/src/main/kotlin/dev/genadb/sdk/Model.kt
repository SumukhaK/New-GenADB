package dev.genadb.sdk

/** Solo: a developer's own phone, trusted by pairing code. Corporate: MDM-enrolled, policy-governed. */
public enum class Mode(internal val flag: String) { SOLO("solo"), CORPORATE("corporate") }

/** Whether the device-side audit log is written. */
public enum class AuditMode {
    /** Off in solo mode, on in corporate mode (default). */
    AUTO,
    ON,
    /** Ignored in corporate mode, where audit is mandatory. */
    OFF,
}

/**
 * What the device agent should do. Values pushed by device management
 * (see [ManagedPolicy]) override these.
 */
public data class GenAdbConfig(
    /** Relay: host:port, ws://host/path or wss://host/path. */
    val relayUrl: String,
    val mode: Mode = Mode.SOLO,
    /** "auto" discovers Wireless debugging over mDNS; or host:port for legacy `adb tcpip`. */
    val adbd: String = "auto",
    /** Solo: also accept direct connections from desktops on the same network. Null = relay only. */
    val lanListen: String? = "0.0.0.0:47100",
    /** Corporate: device enrollment token issued by the organisation. */
    val enrollmentToken: String? = null,
    /** Corporate: organisation policy document (JSON). */
    val policyJson: String? = null,
    /** Optional hex SHA-256 pin of the relay's TLS certificate. */
    val relayPin: String? = null,
    /** Optional HTTP proxy for ws/wss relays. */
    val proxy: String? = null,
    val audit: AuditMode = AuditMode.AUTO,
)

/** Connection lifecycle of the device agent. */
public sealed interface ConnectionState {
    /** Not started, or stopped. */
    public data object Idle : ConnectionState

    /** The agent is starting. */
    public data object Starting : ConnectionState

    /**
     * Registered with the relay. In solo mode [pairingCode] is what a desktop
     * enters (`genadb connect --code …`); it is null in corporate mode.
     */
    public data class Online(
        val deviceId: String,
        val pairingCode: String? = null,
        val adbdEndpoint: String? = null,
        /** A non-fatal problem, e.g. Wireless debugging is switched off. */
        val warning: String? = null,
    ) : ConnectionState

    /** The agent stopped unexpectedly and will be restarted. */
    public data class Reconnecting(val attempt: Int, val reason: String?, val retryInMs: Long) : ConnectionState

    /** Device management forbids debugging; the agent will not tunnel. */
    public data class Blocked(val reason: String) : ConnectionState

    /**
     * Corporate mode is configured but incomplete (for example the EMM pushed
     * the enrollment token before the policy). The agent is not started;
     * call start() again once managed configuration changes.
     * [missing] names what is absent: "policy_json" or "enroll_token".
     */
    public data class PolicyMissing(val missing: String) : ConnectionState
}

/** Effective policy after merging the app config with device management. */
public data class PolicyStatus(
    val mode: Mode = Mode.SOLO,
    /** False when the device owner set DISALLOW_DEBUGGING_FEATURES. */
    val debuggingAllowed: Boolean = true,
    /** True when relay / enrollment / policy came from device management. */
    val managed: Boolean = false,
    val auditEnabled: Boolean = false,
    /** Corporate configuration item that is missing ("policy_json", "enroll_token"), or null. */
    val missing: String? = null,
)

/** One sealed record of the device-side audit log. */
public data class AuditEvent(
    val seq: Long,
    /** RFC 3339 UTC. */
    val timestamp: String,
    /** agent_start, pairing_code_issued, online, adbd_endpoint, adbd_unreachable, blocked, policy_missing, agent_error, agent_exit, agent_stop. */
    val type: String,
    val deviceId: String?,
    /** Extra fields (never secrets, tokens or pairing codes). */
    val fields: Map<String, String>,
    /** SHA-256 over the canonical record; links to the previous record's hash. */
    val eventHash: String,
    val prevEventHash: String,
)

/** Point-in-time snapshot returned by `status()`. */
public data class GenAdbStatus(
    val connection: ConnectionState,
    val policy: PolicyStatus,
    val running: Boolean,
    /** Absolute path of the audit log, or null when auditing is off. */
    val auditLogPath: String?,
)

/** Typed failures. */
public sealed class GenAdbException(message: String) : Exception(message) {
    public class NotConfigured : GenAdbException("start() needs a GenAdbConfig with a relay URL")
    public class Blocked(public val reason: String) : GenAdbException("debugging is disallowed by device policy: $reason")
    public class PairingUnavailable : GenAdbException("pairing codes exist only in solo mode")
    public class PolicyMissing(public val missing: String) : GenAdbException("corporate configuration incomplete: $missing is missing")
    public class Timeout(what: String) : GenAdbException("timed out waiting for $what")
}
