package dev.genadb.companion

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.RestrictionsManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.wifi.WifiManager
import android.os.IBinder
import android.os.UserManager
import dev.genadb.protocol.AgentEvent
import dev.genadb.protocol.AgentState
import dev.genadb.protocol.DeviceAgentConfig
import dev.genadb.protocol.Mode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.File

/**
 * Foreground service that runs the Go device agent (libgenadb.so) and keeps
 * it alive. The agent only ever talks to the *system* adbd; it cannot enable
 * debugging itself, and it refuses to run when the device owner has set
 * DISALLOW_DEBUGGING_FEATURES.
 */
class AgentService : Service() {
    companion object {
        val state: StateFlow<AgentState> get() = _state
        private val _state = MutableStateFlow(AgentState())
        const val EXTRA_RELAY = "relay"

        fun start(ctx: Context, relay: String) =
            ctx.startForegroundService(Intent(ctx, AgentService::class.java).putExtra(EXTRA_RELAY, relay))

        fun stop(ctx: Context) = ctx.stopService(Intent(ctx, AgentService::class.java))
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var job: Job? = null
    private var proc: Process? = null
    private var multicastLock: WifiManager.MulticastLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(1, notification("Starting…"), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        val cfg = buildConfig(intent?.getStringExtra(EXTRA_RELAY))
        multicastLock = (applicationContext.getSystemService(WIFI_SERVICE) as WifiManager)
            .createMulticastLock("genadb-mdns").apply { setReferenceCounted(false); acquire() }
        job?.cancel()
        job = scope.launch { superviseAgent(cfg) }
        return START_STICKY
    }

    private fun buildConfig(relayExtra: String?): DeviceAgentConfig {
        val um = getSystemService(USER_SERVICE) as UserManager
        val debuggingAllowed = !um.hasUserRestriction(UserManager.DISALLOW_DEBUGGING_FEATURES)
        val managed = (getSystemService(RESTRICTIONS_SERVICE) as RestrictionsManager).applicationRestrictions
        val enroll = managed.getString("enroll_token").orEmpty()
        val corporate = enroll.isNotEmpty()
        val policyFile = managed.getString("policy_json")?.takeIf { it.isNotEmpty() }?.let {
            File(filesDir, "policy.json").apply { writeText(it) }.absolutePath
        }
        return DeviceAgentConfig(
            relay = managed.getString("relay_url")?.takeIf { it.isNotEmpty() } ?: relayExtra.orEmpty(),
            stateDir = File(filesDir, "agent").apply { mkdirs() }.absolutePath,
            mode = if (corporate) Mode.CORPORATE else Mode.SOLO,
            adbd = "auto",
            enrollToken = enroll.takeIf { corporate },
            policyFile = policyFile,
            debuggingAllowed = debuggingAllowed,
            lanListen = if (corporate) null else "0.0.0.0:47100",
            relayPin = managed.getString("relay_pin")?.takeIf { it.isNotEmpty() },
        )
    }

    private fun activeDnsServers(): List<String> {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val lp = cm.getLinkProperties(cm.activeNetwork ?: return emptyList()) ?: return emptyList()
        return lp.dnsServers.mapNotNull { it.hostAddress }
    }

    /** Runs the agent, restarting it with backoff if it exits (e.g. killed by OEM battery savers). */
    private suspend fun superviseAgent(cfg: DeviceAgentConfig) {
        val exe = File(applicationInfo.nativeLibraryDir, "libgenadb.so")
        var backoff = 1000L
        while (scope.isActive) {
            val pb = ProcessBuilder(listOf(exe.absolutePath) + cfg.toArgs())
                .redirectError(File(cacheDir, "agent.log"))
            // The native agent has no system resolver; hand it the active network's DNS servers.
            activeDnsServers().takeIf { it.isNotEmpty() }?.let { pb.environment()["GENADB_DNS"] = it.joinToString(",") }
            val p = pb.start()
            proc = p
            p.inputStream.bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    AgentEvent.parse(line)?.let { e ->
                        _state.value = _state.value.reduce(e)
                        updateNotification()
                    }
                }
            }
            p.waitFor()
            _state.value = _state.value.copy(online = false)
            updateNotification()
            delay(backoff)
            backoff = (backoff * 2).coerceAtMost(30_000)
        }
    }

    private fun updateNotification() {
        val s = _state.value
        val text = when {
            s.blockedReason != null -> "Blocked by device policy"
            s.pairingCode != null && s.online -> "Online · pairing code ${s.pairingCode}"
            s.online -> "Online"
            else -> s.lastError ?: "Reconnecting…"
        }
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).notify(1, notification(text))
    }

    private fun notification(text: String): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(NotificationChannel("agent", "Remote debugging", NotificationManager.IMPORTANCE_LOW))
        return Notification.Builder(this, "agent")
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setContentTitle("GenADB remote debugging")
            .setContentText(text)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        job?.cancel()
        proc?.destroy()
        multicastLock?.release()
        scope.coroutineContext[Job]?.cancel()
        _state.value = AgentState()
        super.onDestroy()
    }
}
