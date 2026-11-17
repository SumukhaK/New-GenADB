package dev.genadb.companion

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import dev.genadb.sdk.ConnectionState
import dev.genadb.sdk.SetuConfig
import dev.genadb.sdk.SetuManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Foreground service that keeps the Setu agent alive. All agent logic lives
 * in the Setu Android SDK (setu-android); this service only owns the notification.
 */
class AgentService : Service() {
    companion object {
        const val EXTRA_RELAY = "relay"

        fun start(ctx: Context, relay: String) =
            ctx.startForegroundService(Intent(ctx, AgentService::class.java).putExtra(EXTRA_RELAY, relay))

        fun stop(ctx: Context) = ctx.stopService(Intent(ctx, AgentService::class.java))
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val setu by lazy { SetuManager.getInstance(this) }
    private val restrictionsChanged = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) {
            // Re-read managed relay / enrollment / policy. Never let a bad
            // EMM payload crash the app: the state flow reports what is wrong.
            runCatching {
                setu.refreshPolicy()
                setu.start()
            }.onFailure { notify("Not started: ${it.message}") }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        val filter = IntentFilter(Intent.ACTION_APPLICATION_RESTRICTIONS_CHANGED)
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(restrictionsChanged, filter, RECEIVER_NOT_EXPORTED)
        else registerReceiver(restrictionsChanged, filter)
        scope.launch { setu.connectionState.collect { notify(text(it)) } }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(1, notification("Starting…"), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        // A sticky restart has no intent: reuse the last relay the user entered.
        val prefs = getSharedPreferences("agent", MODE_PRIVATE)
        val relay = intent?.getStringExtra(EXTRA_RELAY)?.also { prefs.edit().putString(EXTRA_RELAY, it).apply() }
            ?: prefs.getString(EXTRA_RELAY, "").orEmpty()
        runCatching { setu.start(SetuConfig(relayUrl = relay)) }
            .onFailure { notify("Not started: ${it.message}") }
        return START_STICKY
    }

    private fun text(s: ConnectionState): String = when (s) {
        is ConnectionState.Blocked -> "Blocked by device policy"
        is ConnectionState.PolicyMissing -> "Waiting for device management (${s.missing} missing)"
        is ConnectionState.Online -> s.pairingCode?.let { "Online · pairing code $it" } ?: "Online"
        is ConnectionState.Reconnecting -> s.reason ?: "Reconnecting…"
        ConnectionState.Starting -> "Starting…"
        ConnectionState.Idle -> "Stopped"
    }

    private fun notify(text: String) =
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).notify(1, notification(text))

    private fun notification(text: String): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(NotificationChannel("agent", "Remote debugging", NotificationManager.IMPORTANCE_LOW))
        return Notification.Builder(this, "agent")
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setContentTitle("Setu remote debugging")
            .setContentText(text)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        unregisterReceiver(restrictionsChanged)
        setu.stop()
        scope.cancel()
        super.onDestroy()
    }
}
