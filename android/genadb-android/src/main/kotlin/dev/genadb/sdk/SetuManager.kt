package dev.genadb.sdk

import android.content.Context
import android.content.RestrictionsManager
import android.net.ConnectivityManager
import android.net.wifi.WifiManager
import android.os.UserManager
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.StateFlow
import java.io.File

/**
 * Entry point of the Setu Android SDK (Setu-SDK): an encrypted bridge between
 * your IDE and any Android device, anywhere. It runs the connectivity agent
 * that makes this device reachable by `adb` on a developer's computer, and
 * exposes its state as [StateFlow]s.
 *
 * ```
 * val setu = SetuManager.initialize(
 *     SetuManager.Builder(context).config(SetuConfig(relayUrl = "wss://relay.example.com/"))
 * )
 * setu.start()
 * val code = setu.pair()                 // show to the user (solo mode)
 * setu.connectionState.collect { … }
 * ```
 *
 * The agent keeps running while the process lives; host it in a foreground
 * service so the system does not stop it. The SDK never enables debugging
 * itself and refuses to tunnel when device management disallows debugging.
 */
public open class SetuManager internal constructor(
    internal val core: ManagerCore,
) {
    /** Agent lifecycle: Idle, Starting, Online (with pairing code in solo mode), Reconnecting, Blocked, PolicyMissing. */
    public val connectionState: StateFlow<ConnectionState> get() = core.connectionState

    /** Effective mode and device-management restrictions. */
    public val policyStatus: StateFlow<PolicyStatus> get() = core.policyStatus

    /** The most recent audit record (null when auditing is off or nothing happened yet). */
    public val auditEvents: StateFlow<AuditEvent?> get() = core.lastAuditEvent

    /** The last 200 audit records of this process, oldest first. */
    public val recentAuditEvents: StateFlow<List<AuditEvent>> get() = core.recentAuditEvents

    /**
     * Live debugging sessions on this device: who is connected ([DeviceSession.peerLabel]),
     * over which transport, and whether the path is currently up. Updated from the
     * agent's `session_open` / `session_close` / `path_*` events.
     */
    public val sessions: StateFlow<List<DeviceSession>> get() = core.sessions

    /**
     * Ends one session from the device side. The desktop receives a graceful
     * `peer_closed` (reason `ended_on_device`) instead of a reconnect loop.
     * Returns false if no such session is live.
     */
    public fun endSession(id: String): Boolean = core.endSession(id)

    /**
     * Starts (or restarts) the agent; [config] replaces the builder's configuration.
     * Incomplete corporate configuration does not throw: it sets
     * [ConnectionState.PolicyMissing] and waits for the next start().
     * @throws GenAdbException.NotConfigured when no relay URL is known
     */
    public fun start(config: SetuConfig? = null) {
        core.start(config)
    }

    /**
     * Starts the agent if needed and returns the pairing code a desktop uses
     * (`setu connect --code …`). Solo mode only.
     * @throws GenAdbException.PairingUnavailable in corporate mode
     * @throws GenAdbException.PolicyMissing when corporate configuration is incomplete
     * @throws GenAdbException.Blocked when debugging is disallowed
     * @throws GenAdbException.Timeout when the relay cannot be reached in time
     */
    public suspend fun pair(timeoutMs: Long = 30_000): String = core.pair(timeoutMs)

    /** Stops the agent. Paired desktops can reconnect after the next start(). */
    public fun stop() {
        core.stop()
    }

    /** Snapshot of connection, policy and audit configuration. */
    public fun status(): GenAdbStatus = core.status()

    /** Re-reads device-management restrictions (call on ACTION_APPLICATION_RESTRICTIONS_CHANGED). */
    public fun refreshPolicy(): PolicyStatus = core.refreshPolicy()

    /** The hash-chained JSONL audit log; `setu audit verify|report` read it. Null when auditing is off. */
    public val auditLogFile: File? get() = core.status().auditLogPath?.let(::File)

    /** Configures a [SetuManager]. Every collaborator can be replaced (tests, custom hosting). */
    public open class Builder(context: Context) {
        private val app = context.applicationContext
        private var config: SetuConfig? = null
        private var launcher: AgentLauncher? = null
        private var policy: PolicyProvider? = null
        private var network: NetworkInfoProvider? = null
        private var audit: AuditSink? = null
        private var stateDir: File? = null
        private var scope: CoroutineScope? = null

        public open fun config(config: SetuConfig): Builder = apply { this.config = config }
        public open fun agentLauncher(launcher: AgentLauncher): Builder = apply { this.launcher = launcher }
        public open fun policyProvider(provider: PolicyProvider): Builder = apply { this.policy = provider }
        public open fun networkInfoProvider(provider: NetworkInfoProvider): Builder = apply { this.network = provider }
        /** Replaces the default file audit log (e.g. to forward records to a collector). */
        public open fun auditSink(sink: AuditSink): Builder = apply { this.audit = sink }
        public open fun stateDir(dir: File): Builder = apply { this.stateDir = dir }
        public open fun scope(scope: CoroutineScope): Builder = apply { this.scope = scope }

        public open fun build(): SetuManager = SetuManager(buildCore())

        internal fun buildCore(): ManagerCore {
            // The state directory keeps its pre-rename name so paired desktops,
            // keys and audit logs survive the upgrade.
            val dir = stateDir ?: File(app.filesDir, "genadb")
            dir.mkdirs()
            val lock = MulticastHold(app)
            val core = ManagerCore(
                launcher = launcher ?: defaultLauncher(app),
                policyProvider = policy ?: AndroidPolicyProvider(app),
                network = network ?: AndroidNetworkInfo(app),
                stateDir = dir,
                scope = scope ?: CoroutineScope(SupervisorJob() + Dispatchers.IO + CoroutineExceptionHandler { _, t ->
                    android.util.Log.e("Setu", "agent supervisor failed", t) // never crash the host app
                }),
                auditSinkOverride = audit,
                onRunning = lock::set,
            )
            config?.let(core::configure)
            core.refreshPolicy()
            return core
        }
    }

    public companion object {
        @Volatile
        private var instance: SetuManager? = null

        /** Builds the process-wide instance (replacing a previous, stopped one). */
        @JvmStatic
        public fun initialize(builder: Builder): SetuManager = synchronized(this) {
            instance?.stop()
            builder.build().also { instance = it }
        }

        /** The process-wide instance, created with defaults on first use. */
        @JvmStatic
        public fun getInstance(context: Context): SetuManager =
            instance ?: synchronized(this) { instance ?: Builder(context).build().also { instance = it } }
    }
}

/**
 * The pre-1.0.1 name of [SetuManager], kept so existing apps compile
 * unchanged (Kotlin and Java). It shares the process-wide instance and agent
 * with [SetuManager].
 */
@Deprecated("Renamed to SetuManager", ReplaceWith("SetuManager", "dev.genadb.sdk.SetuManager"))
public class GenAdbManager internal constructor(core: ManagerCore) : SetuManager(core) {

    @Deprecated("Renamed to SetuManager.Builder", ReplaceWith("SetuManager.Builder", "dev.genadb.sdk.SetuManager"))
    public class Builder(context: Context) : SetuManager.Builder(context) {
        override fun config(config: SetuConfig): Builder = apply { super.config(config) }
        override fun agentLauncher(launcher: AgentLauncher): Builder = apply { super.agentLauncher(launcher) }
        override fun policyProvider(provider: PolicyProvider): Builder = apply { super.policyProvider(provider) }
        override fun networkInfoProvider(provider: NetworkInfoProvider): Builder = apply { super.networkInfoProvider(provider) }
        override fun auditSink(sink: AuditSink): Builder = apply { super.auditSink(sink) }
        override fun stateDir(dir: File): Builder = apply { super.stateDir(dir) }
        override fun scope(scope: CoroutineScope): Builder = apply { super.scope(scope) }
        override fun build(): GenAdbManager = GenAdbManager(buildCore())
    }

    public companion object {
        @JvmStatic
        public fun initialize(builder: Builder): GenAdbManager = SetuManager.initialize(builder) as GenAdbManager

        @JvmStatic
        public fun getInstance(context: Context): GenAdbManager =
            SetuManager.getInstance(context).let { it as? GenAdbManager ?: GenAdbManager(it.core) }
    }
}

internal fun defaultLauncher(ctx: Context): AgentLauncher {
    val exe = File(ctx.applicationInfo.nativeLibraryDir, "libgenadb.so")
    val launcher = ProcessAgentLauncher(exe, File(ctx.cacheDir, "genadb-agent.log"))
    return AgentLauncher { args, env ->
        check(exe.canExecute()) {
            "libgenadb.so is not extracted; set packaging { jniLibs { useLegacyPackaging = true } } in the app"
        }
        launcher.launch(args, env)
    }
}

/**
 * Reads EMM managed configuration (keys relay_url, enroll_token, policy_json,
 * relay_pin) and the DISALLOW_DEBUGGING_FEATURES user restriction.
 */
public class AndroidPolicyProvider(context: Context) : PolicyProvider {
    private val app = context.applicationContext

    override fun current(): ManagedPolicy {
        val um = app.getSystemService(Context.USER_SERVICE) as UserManager
        val rm = app.getSystemService(Context.RESTRICTIONS_SERVICE) as RestrictionsManager
        val b = rm.applicationRestrictions
        return ManagedPolicy(
            relayUrl = b.getString("relay_url"),
            enrollmentToken = b.getString("enroll_token"),
            policyJson = b.getString("policy_json"),
            relayPin = b.getString("relay_pin"),
            debuggingAllowed = !um.hasUserRestriction(UserManager.DISALLOW_DEBUGGING_FEATURES),
        )
    }
}

/** DNS servers of the active network (the statically linked agent has no system resolver). */
public class AndroidNetworkInfo(context: Context) : NetworkInfoProvider {
    private val app = context.applicationContext

    override fun dnsServers(): List<String> {
        val cm = app.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val lp = cm.getLinkProperties(cm.activeNetwork ?: return emptyList()) ?: return emptyList()
        return lp.dnsServers.mapNotNull { it.hostAddress }
    }
}

/** Holds a Wi-Fi multicast lock while the agent runs (mDNS discovery of adbd). */
internal class MulticastHold(ctx: Context) {
    private val lock: WifiManager.MulticastLock? = runCatching {
        (ctx.getSystemService(Context.WIFI_SERVICE) as WifiManager)
            .createMulticastLock("genadb-mdns").apply { setReferenceCounted(false) }
    }.getOrNull()

    fun set(running: Boolean) {
        runCatching { if (running) lock?.acquire() else if (lock?.isHeld == true) lock.release() }
    }
}
