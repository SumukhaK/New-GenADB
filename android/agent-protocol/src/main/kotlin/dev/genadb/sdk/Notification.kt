package dev.genadb.sdk

/**
 * What a foreground-service notification should say for the agent's state
 * (v1.1.0+). [text] is for the unlocked device and may contain the pairing
 * code; [publicText] is the redacted version for the lock screen and never
 * does. Post the notification with VISIBILITY_PRIVATE and [publicText] as
 * its public version (or VISIBILITY_SECRET when [containsSecret]), so the
 * 10-digit code is never readable on a locked phone.
 */
public data class NotificationContent(
    val title: String,
    val text: String,
    val publicText: String,
    /** True when [text] shows the pairing code. */
    val containsSecret: Boolean,
)

public object SetuNotifications {
    /** Builds the notification text for [state] and the open [sessions]. */
    @JvmStatic
    public fun content(state: ConnectionState, sessions: List<DeviceSession> = emptyList()): NotificationContent {
        val who = when (sessions.size) {
            0 -> null
            1 -> "Debugging session: ${sessions[0].peerLabel}"
            else -> "${sessions.size} debugging sessions"
        }
        val reconnecting = sessions.any { it.path == PathState.DOWN }
        val (text, public) = when (state) {
            is ConnectionState.Blocked -> "Blocked by device policy" to "Blocked by device policy"
            is ConnectionState.PolicyMissing -> "Waiting for device management (${state.missing} missing)" to "Waiting for device management"
            is ConnectionState.Online -> {
                val base = when {
                    reconnecting -> "Online · reconnecting a session…"
                    who != null -> "Online · $who"
                    else -> "Online"
                }
                (state.pairingCode?.let { "$base · pairing code $it" } ?: base) to
                    (if (who != null || reconnecting) base else "Online")
            }
            is ConnectionState.Reconnecting -> (state.reason ?: "Reconnecting…") to "Reconnecting…"
            ConnectionState.Starting -> "Starting…" to "Starting…"
            ConnectionState.Idle -> "Stopped" to "Stopped"
        }
        val secret = (state as? ConnectionState.Online)?.pairingCode != null
        return NotificationContent("Setu remote debugging", text, redact(public, state), secret)
    }

    // Defence in depth: whatever the wording, the public text never carries the code.
    private fun redact(public: String, state: ConnectionState): String {
        val code = (state as? ConnectionState.Online)?.pairingCode ?: return public
        return public.replace(code, "••••-••••••")
    }
}
