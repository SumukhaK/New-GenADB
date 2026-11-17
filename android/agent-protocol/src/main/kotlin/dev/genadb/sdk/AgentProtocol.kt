package dev.genadb.sdk

import org.json.JSONObject

/** Effective agent settings after merging [GenAdbConfig] with [ManagedPolicy]. */
internal data class EffectiveConfig(
    val config: GenAdbConfig,
    val policy: PolicyStatus,
    val relayPin: String?,
    val enrollmentToken: String?,
    val policyJson: String?,
)

internal fun effective(cfg: GenAdbConfig, managed: ManagedPolicy): EffectiveConfig {
    val enroll = managed.enrollmentToken?.takeIf { it.isNotBlank() } ?: cfg.enrollmentToken
    val mode = if (!managed.enrollmentToken.isNullOrBlank()) Mode.CORPORATE else cfg.mode
    val relay = managed.relayUrl?.takeIf { it.isNotBlank() } ?: cfg.relayUrl
    val audit = when {
        mode == Mode.CORPORATE -> true
        cfg.audit == AuditMode.ON -> true
        else -> false
    }
    val isManaged = listOf(managed.relayUrl, managed.enrollmentToken, managed.policyJson).any { !it.isNullOrBlank() }
    val policyJson = managed.policyJson?.takeIf { it.isNotBlank() } ?: cfg.policyJson?.takeIf { it.isNotBlank() }
    val missing = when {
        mode != Mode.CORPORATE -> null
        enroll.isNullOrBlank() -> "enroll_token"
        policyJson == null -> "policy_json"
        else -> null
    }
    return EffectiveConfig(
        config = cfg.copy(relayUrl = relay, mode = mode),
        policy = PolicyStatus(mode, managed.debuggingAllowed, isManaged, audit, missing),
        relayPin = managed.relayPin?.takeIf { it.isNotBlank() } ?: cfg.relayPin,
        enrollmentToken = enroll?.takeIf { it.isNotBlank() },
        policyJson = policyJson,
    )
}

/** Command line for `genadb device`. [policyFile] holds [EffectiveConfig.policyJson]. */
internal fun agentArgs(e: EffectiveConfig, stateDir: String, policyFile: String?): List<String> = buildList {
    val c = e.config
    require(c.relayUrl.isNotBlank()) { "relay URL is empty" }
    add("device")
    add("--relay"); add(c.relayUrl)
    add("--adbd"); add(c.adbd)
    add("--state"); add(stateDir)
    add("--mode"); add(c.mode.flag)
    if (!e.policy.debuggingAllowed) { add("--debug-policy"); add("disallowed") }
    if (c.mode == Mode.CORPORATE) {
        add("--enroll"); add(requireNotNull(e.enrollmentToken) { "corporate mode needs an enrollment token" })
        add("--policy"); add(requireNotNull(policyFile) { "corporate mode needs a policy" })
    } else if (c.lanListen != null) {
        add("--lan-listen"); add(c.lanListen)
    }
    e.relayPin?.let { add("--relay-pin"); add(it) }
    c.proxy?.let { add("--proxy"); add(it) }
}

/** Classifies a relay spec the way the Go core does for audit records. */
internal fun transportLabel(relay: String): String = when {
    relay.startsWith("wss://") -> "relay-wss"
    relay.startsWith("ws://") -> "relay-ws"
    else -> "relay-tcp"
}

/** Events the agent prints as JSON lines on stdout. */
internal sealed interface AgentEvent {
    data class Online(val deviceId: String) : AgentEvent
    data class PairingCode(val code: String, val deviceId: String) : AgentEvent
    data class Blocked(val reason: String) : AgentEvent
    data class AdbdEndpoint(val addr: String) : AgentEvent
    data class AdbdUnreachable(val reason: String) : AgentEvent
    data class Error(val reason: String) : AgentEvent
    data class Other(val name: String) : AgentEvent

    companion object {
        fun parse(line: String): AgentEvent? {
            val o = runCatching { JSONObject(line.trim()) }.getOrNull() ?: return null
            return when (val e = o.optString("event")) {
                "online" -> Online(o.optString("device_id"))
                "pairing_code" -> PairingCode(o.optString("code"), o.optString("device_id"))
                "blocked" -> Blocked(o.optString("reason"))
                "adbd_endpoint" -> AdbdEndpoint(o.optString("addr"))
                "adbd_unreachable" -> AdbdUnreachable(o.optString("reason"))
                "error" -> Error(o.optString("reason"))
                "" -> null
                else -> Other(e)
            }
        }
    }
}

/** Folds agent events into the public connection state. */
internal data class AgentView(
    val online: Boolean = false,
    val deviceId: String? = null,
    val pairingCode: String? = null,
    val adbdEndpoint: String? = null,
    val warning: String? = null,
    val blocked: String? = null,
    val lastError: String? = null,
) {
    fun reduce(e: AgentEvent): AgentView = when (e) {
        is AgentEvent.Online -> copy(online = true, deviceId = e.deviceId, lastError = null)
        is AgentEvent.PairingCode -> copy(pairingCode = e.code, deviceId = e.deviceId)
        is AgentEvent.Blocked -> copy(online = false, blocked = e.reason)
        is AgentEvent.AdbdEndpoint -> copy(adbdEndpoint = e.addr, warning = null)
        is AgentEvent.AdbdUnreachable -> copy(warning = "Wireless debugging unreachable: ${e.reason}")
        is AgentEvent.Error -> copy(online = false, lastError = e.reason)
        is AgentEvent.Other -> this
    }

    fun state(): ConnectionState = when {
        blocked != null -> ConnectionState.Blocked(blocked)
        online && deviceId != null -> ConnectionState.Online(deviceId, pairingCode, adbdEndpoint, warning)
        else -> ConnectionState.Starting
    }
}

/** Audit record for an agent event; never includes the pairing code. */
internal fun auditFor(e: AgentEvent): Pair<String, Map<String, String>>? = when (e) {
    is AgentEvent.Online -> "online" to emptyMap()
    is AgentEvent.PairingCode -> "pairing_code_issued" to emptyMap()
    is AgentEvent.Blocked -> "blocked" to mapOf("reason" to e.reason)
    is AgentEvent.AdbdEndpoint -> "adbd_endpoint" to mapOf("addr" to e.addr)
    is AgentEvent.AdbdUnreachable -> "adbd_unreachable" to mapOf("reason" to e.reason)
    is AgentEvent.Error -> "agent_error" to mapOf("reason" to e.reason)
    is AgentEvent.Other -> null
}
