package dev.genadb.sdk

import org.json.JSONObject

/** Effective agent settings after merging [SetuConfig] with [ManagedPolicy]. */
internal data class EffectiveConfig(
    val config: SetuConfig,
    val policy: PolicyStatus,
    val relayPin: String?,
    val enrollmentToken: String?,
    val policyJson: String?,
)

internal fun effective(cfg: SetuConfig, managed: ManagedPolicy): EffectiveConfig {
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
    // The phone keeps only its own grants, even if device management pushed
    // the organisation's whole user-to-device map (v1.1.0).
    val deviceId = enroll?.let(::tokenSubject)
    val scoped = if (policyJson != null && deviceId != null) scopePolicyJson(policyJson, deviceId) ?: policyJson else policyJson
    return EffectiveConfig(
        config = cfg.copy(relayUrl = relay, mode = mode),
        policy = PolicyStatus(mode, managed.debuggingAllowed, isManaged, audit, missing),
        relayPin = managed.relayPin?.takeIf { it.isNotBlank() } ?: cfg.relayPin,
        enrollmentToken = enroll?.takeIf { it.isNotBlank() },
        policyJson = scoped,
    )
}

/** The `sub` claim of a JWT (not verified: the agent verifies the token). */
internal fun tokenSubject(token: String): String? = runCatching {
    val parts = token.trim().split(".")
    if (parts.size != 3) return null
    val json = String(java.util.Base64.getUrlDecoder().decode(parts[1].trimEnd('=')), Charsets.UTF_8)
    JSONObject(json).optString("sub").takeIf { it.isNotEmpty() }
}.getOrNull()

/**
 * Reduces an organisation policy to what [deviceId] needs: every top-level
 * setting is kept, and `grants` only keeps users granted this device, each
 * listing just this device. Returns null when the policy is not valid JSON
 * (the agent will then report the error itself).
 */
public fun scopePolicyJson(policyJson: String, deviceId: String): String? = runCatching {
    val o = JSONObject(policyJson)
    val grants = o.optJSONArray("grants") ?: org.json.JSONArray()
    val out = org.json.JSONArray()
    val seen = HashSet<String>()
    for (i in 0 until grants.length()) {
        val g = grants.optJSONObject(i) ?: continue
        val user = g.optString("user")
        val devices = g.optJSONArray("devices") ?: continue
        val hit = (0 until devices.length()).any { devices.optString(it) == deviceId }
        if (hit && seen.add(user)) {
            out.put(JSONObject().put("user", user).put("devices", org.json.JSONArray().put(deviceId)))
        }
    }
    o.put("grants", out)
    o.toString()
}.getOrNull()

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
    add("--control-stdin") // SetuManager.endSession
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
    data class Path(val status: PathStatus) : AgentEvent
    data class SessionOpen(val sessionId: String, val peerLabel: String, val transport: String, val kind: String) : AgentEvent
    data class SessionClose(val sessionId: String, val reason: String) : AgentEvent
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
                "session_open" -> SessionOpen(o.optString("session_id"), o.optString("peer_label"),
                    o.optString("transport"), o.optString("kind", "adb"))
                "session_close" -> SessionClose(o.optString("session_id"), o.optString("reason"))
                "path_down", "path_up", "path_lost" -> Path(
                    PathStatus(
                        sessionId = o.optString("session_id"),
                        state = when (e) {
                            "path_down" -> PathState.DOWN
                            "path_up" -> PathState.UP
                            else -> PathState.LOST
                        },
                        transport = o.optString("transport").takeIf { it.isNotEmpty() },
                        reason = o.optString("reason").takeIf { it.isNotEmpty() },
                        outageMs = if (o.has("outage_ms")) o.optLong("outage_ms") else null,
                    ),
                )
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
    val path: PathStatus? = null,
) {
    fun reduce(e: AgentEvent): AgentView = when (e) {
        is AgentEvent.Online -> copy(online = true, deviceId = e.deviceId, lastError = null)
        is AgentEvent.PairingCode -> copy(pairingCode = e.code, deviceId = e.deviceId)
        is AgentEvent.Blocked -> copy(online = false, blocked = e.reason)
        is AgentEvent.AdbdEndpoint -> copy(adbdEndpoint = e.addr, warning = null)
        is AgentEvent.AdbdUnreachable -> copy(warning = "Wireless debugging unreachable: ${e.reason}")
        is AgentEvent.Error -> copy(online = false, lastError = e.reason)
        is AgentEvent.Path -> copy(path = e.status)
        is AgentEvent.SessionOpen, is AgentEvent.SessionClose, is AgentEvent.Other -> this
    }

    fun state(): ConnectionState = when {
        blocked != null -> ConnectionState.Blocked(blocked)
        online && deviceId != null -> ConnectionState.Online(deviceId, pairingCode, adbdEndpoint, warning, path)
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
    is AgentEvent.Path -> "path_" + e.status.state.name.lowercase() to buildMap {
        put("session_id", e.status.sessionId)
        e.status.transport?.let { put("transport", it) }
        e.status.reason?.let { put("reason", it) }
        e.status.outageMs?.let { put("outage_ms", it.toString()) }
    }
    is AgentEvent.SessionOpen -> "session_open" to mapOf("session_id" to e.sessionId, "peer_label" to e.peerLabel,
        "transport" to e.transport, "kind" to e.kind)
    is AgentEvent.SessionClose -> "session_close" to mapOf("session_id" to e.sessionId, "reason" to e.reason)
    is AgentEvent.Other -> null
}

/** Folds session and path events into the list of open sessions. */
internal fun List<DeviceSession>.apply(e: AgentEvent, nowMs: Long): List<DeviceSession> = when (e) {
    is AgentEvent.SessionOpen -> filterNot { it.id == e.sessionId } +
        DeviceSession(e.sessionId, e.peerLabel, e.transport, e.kind, nowMs)
    is AgentEvent.SessionClose -> filterNot { it.id == e.sessionId }
    is AgentEvent.Path -> map {
        if (it.id != e.status.sessionId) it
        else it.copy(path = e.status.state, transport = e.status.transport ?: it.transport)
    }
    else -> this
}

/** The command line asking the agent to end a session. */
internal fun endSessionCommand(id: String): String =
    JSONObject().put("cmd", "end_session").put("session_id", id).toString()
