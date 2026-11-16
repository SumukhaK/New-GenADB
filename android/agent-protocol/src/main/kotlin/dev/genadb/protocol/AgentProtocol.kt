package dev.genadb.protocol

import org.json.JSONObject

/**
 * Bridge between the Android companion app and the `genadb device` agent
 * (the Go connectivity core, shipped in the APK as libgenadb.so).
 * The contract is the one specified in remote_adb_research_findings.md §16.5.
 */
enum class Mode(val flag: String) { SOLO("solo"), CORPORATE("corporate") }

data class DeviceAgentConfig(
    val relay: String,                    // host:port, ws://… or wss://…
    val stateDir: String,                 // app-private files dir
    val mode: Mode = Mode.SOLO,
    /** "auto" = discover Wireless debugging via mDNS; or host:port (legacy tcpip). */
    val adbd: String = "auto",
    val enrollToken: String? = null,      // corporate: MDM-issued device token
    val policyFile: String? = null,       // corporate: policy pushed via managed config
    val debuggingAllowed: Boolean = true, // !DISALLOW_DEBUGGING_FEATURES
    val lanListen: String? = null,        // solo: direct LAN path, e.g. "0.0.0.0:47100"
    val relayCaFile: String? = null,
    val relayPin: String? = null,
    val proxy: String? = null,
) {
    fun toArgs(): List<String> = buildList {
        add("device")
        add("--relay"); add(relay)
        add("--adbd"); add(adbd)
        add("--state"); add(stateDir)
        add("--mode"); add(mode.flag)
        if (!debuggingAllowed) { add("--debug-policy"); add("disallowed") }
        if (mode == Mode.CORPORATE) {
            requireNotNull(enrollToken) { "corporate mode needs an enrollment token" }
            requireNotNull(policyFile) { "corporate mode needs a policy file" }
            add("--enroll"); add(enrollToken)
            add("--policy"); add(policyFile)
        } else if (lanListen != null) {
            add("--lan-listen"); add(lanListen)
        }
        relayCaFile?.let { add("--relay-ca"); add(it) }
        relayPin?.let { add("--relay-pin"); add(it) }
        proxy?.let { add("--proxy"); add(it) }
    }
}

/** Events the agent prints as JSON lines on stdout. */
sealed interface AgentEvent {
    data class Online(val deviceId: String) : AgentEvent
    data class PairingCode(val code: String, val deviceId: String) : AgentEvent
    data class Blocked(val reason: String) : AgentEvent
    data class AdbdEndpoint(val addr: String) : AgentEvent
    data class AdbdUnreachable(val reason: String) : AgentEvent
    data class Error(val reason: String) : AgentEvent
    data class Other(val name: String, val raw: JSONObject) : AgentEvent

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
                else -> Other(e, o)
            }
        }
    }
}

/** UI state folded from the event stream. */
data class AgentState(
    val online: Boolean = false,
    val deviceId: String? = null,
    val pairingCode: String? = null,
    val blockedReason: String? = null,
    val adbdEndpoint: String? = null,
    val lastError: String? = null,
) {
    fun reduce(e: AgentEvent): AgentState = when (e) {
        is AgentEvent.Online -> copy(online = true, deviceId = e.deviceId, lastError = null)
        is AgentEvent.PairingCode -> copy(pairingCode = e.code, deviceId = e.deviceId)
        is AgentEvent.Blocked -> copy(online = false, blockedReason = e.reason)
        is AgentEvent.AdbdEndpoint -> copy(adbdEndpoint = e.addr, lastError = null)
        is AgentEvent.AdbdUnreachable -> copy(lastError = "Wireless debugging unreachable: ${e.reason}")
        is AgentEvent.Error -> copy(online = false, lastError = e.reason)
        is AgentEvent.Other -> this
    }
}
