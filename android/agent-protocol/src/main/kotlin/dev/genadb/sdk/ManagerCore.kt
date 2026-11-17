package dev.genadb.sdk

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File

/** Restart backoff for the agent process. */
internal data class Backoff(val initialMs: Long = 1_000, val maxMs: Long = 30_000)

/**
 * Platform-neutral engine behind GenAdbManager: supervises the agent
 * process, folds its events into state flows and writes the audit log.
 */
internal class ManagerCore(
    private val launcher: AgentLauncher,
    private val policyProvider: PolicyProvider,
    private val network: NetworkInfoProvider,
    private val stateDir: File,
    private val scope: CoroutineScope,
    private val auditSinkOverride: AuditSink? = null,
    private val io: CoroutineDispatcher = Dispatchers.IO,
    private val backoff: Backoff = Backoff(),
    private val onRunning: (Boolean) -> Unit = {},
) {
    private val _connection = MutableStateFlow<ConnectionState>(ConnectionState.Idle)
    private val _policy = MutableStateFlow(PolicyStatus())
    private val _lastAudit = MutableStateFlow<AuditEvent?>(null)
    private val _recentAudit = MutableStateFlow<List<AuditEvent>>(emptyList())

    val connectionState: StateFlow<ConnectionState> = _connection.asStateFlow()
    val policyStatus: StateFlow<PolicyStatus> = _policy.asStateFlow()
    val lastAuditEvent: StateFlow<AuditEvent?> = _lastAudit.asStateFlow()
    val recentAuditEvents: StateFlow<List<AuditEvent>> = _recentAudit.asStateFlow()

    private val lock = Any()
    private var job: Job? = null
    private var proc: AgentProcess? = null
    private var config: GenAdbConfig? = null
    private var audit: AuditSink? = null
    private var deviceId: String? = null

    val auditFile: File get() = File(stateDir, "audit.jsonl")

    fun configure(cfg: GenAdbConfig) = synchronized(lock) { config = cfg }

    fun refreshPolicy(): PolicyStatus {
        val cfg = synchronized(lock) { config } ?: GenAdbConfig(relayUrl = "")
        return effective(cfg, policyProvider.current()).policy.also { _policy.value = it }
    }

    fun start(cfg: GenAdbConfig?) {
        synchronized(lock) {
            if (cfg != null) config = cfg
            // Managed configuration alone (relay from EMM) is enough to start.
            val c = config ?: GenAdbConfig(relayUrl = "")
            val eff = effective(c, policyProvider.current())
            if (eff.config.relayUrl.isBlank()) throw GenAdbException.NotConfigured()
            stopLocked(record = false)
            _policy.value = eff.policy
            audit = if (eff.policy.auditEnabled) auditSinkOverride ?: HashChainedAuditLog(auditFile) else null
            eff.policy.missing?.let { missing ->
                // Restrictive default: never launch a half-configured corporate agent.
                recordAudit("policy_missing", mapOf("missing" to missing))
                _connection.value = ConnectionState.PolicyMissing(missing)
                return
            }
            _connection.value = ConnectionState.Starting
            onRunning(true)
            job = scope.launch(io) {
                try {
                    supervise(eff)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    // Never let a configuration or I/O error escape into the
                    // host app's coroutine scope (on Android that kills the process).
                    recordAudit("agent_error", mapOf("reason" to (e.message ?: e.javaClass.simpleName)))
                    if (currentJobActive()) _connection.value = ConnectionState.Reconnecting(0, e.message, -1)
                }
            }
        }
    }

    fun stop() = synchronized(lock) { stopLocked(record = true) }

    private fun stopLocked(record: Boolean) {
        if (_connection.value is ConnectionState.PolicyMissing) _connection.value = ConnectionState.Idle
        val j = job ?: return
        job = null
        j.cancel()
        proc?.destroy()
        proc = null
        if (record) recordAudit("agent_stop", emptyMap())
        if (auditSinkOverride == null) audit?.close()
        audit = null
        _connection.value = ConnectionState.Idle
        onRunning(false)
    }

    fun isRunning(): Boolean = synchronized(lock) { job?.isActive == true }

    fun status(): GenAdbStatus = GenAdbStatus(
        connection = _connection.value,
        policy = _policy.value,
        running = isRunning(),
        auditLogPath = if (_policy.value.auditEnabled) auditFile.absolutePath else null,
    )

    suspend fun pair(timeoutMs: Long): String {
        if (!isRunning()) start(null)
        (connectionState.value as? ConnectionState.PolicyMissing)?.let { throw GenAdbException.PolicyMissing(it.missing) }
        if (_policy.value.mode == Mode.CORPORATE) throw GenAdbException.PairingUnavailable()
        val s = withTimeoutOrNull(timeoutMs) {
            connectionState.first { it is ConnectionState.Blocked || (it is ConnectionState.Online && it.pairingCode != null) }
        } ?: throw GenAdbException.Timeout("a pairing code")
        return when (s) {
            is ConnectionState.Blocked -> throw GenAdbException.Blocked(s.reason)
            is ConnectionState.Online -> s.pairingCode!!
            else -> error("unreachable")
        }
    }

    private fun recordAudit(type: String, fields: Map<String, String>) {
        val sink = audit ?: return
        val ev = runCatching { sink.record(type, deviceId, fields) }.getOrNull() ?: return
        _lastAudit.value = ev
        _recentAudit.value = (_recentAudit.value + ev).takeLast(RECENT_AUDIT)
    }

    private suspend fun supervise(eff: EffectiveConfig) {
        val state = File(stateDir, "agent").apply { mkdirs() }
        val policyFile = eff.policyJson?.let { File(stateDir, "policy.json").apply { writeText(it) }.absolutePath }
        val args = agentArgs(eff, state.absolutePath, policyFile)
        var delayMs = backoff.initialMs
        var attempt = 0
        while (scope.isActive && currentJobActive()) {
            val env = network.dnsServers().takeIf { it.isNotEmpty() }
                ?.let { mapOf("GENADB_DNS" to it.joinToString(",")) } ?: emptyMap()
            recordAudit("agent_start", mapOf("mode" to eff.config.mode.flag, "transport" to transportLabel(eff.config.relayUrl)))
            val p = try {
                launcher.launch(args, env)
            } catch (t: Throwable) {
                null
            }
            var view = AgentView()
            var lastError: String? = if (p == null) "agent failed to start" else null
            if (p != null) {
                synchronized(lock) { proc = p }
                while (true) {
                    val line = runInterruptible { p.readLine() } ?: break
                    val ev = AgentEvent.parse(line) ?: continue
                    view = view.reduce(ev)
                    if (view.deviceId != null) deviceId = view.deviceId
                    auditFor(ev)?.let { (t, f) -> recordAudit(t, f) }
                    if (ev is AgentEvent.Online) {
                        delayMs = backoff.initialMs
                        attempt = 0
                    }
                    if (currentJobActive()) _connection.value = view.state()
                }
                val code = runInterruptible { p.waitFor() }
                lastError = view.lastError ?: "agent exited with code $code"
                recordAudit("agent_exit", mapOf("exit_code" to code.toString()))
            }
            if (!currentJobActive()) return
            attempt++
            _connection.value = if (view.blocked != null) ConnectionState.Blocked(view.blocked!!)
            else ConnectionState.Reconnecting(attempt, lastError, delayMs)
            delay(delayMs)
            delayMs = (delayMs * 2).coerceAtMost(backoff.maxMs)
        }
    }

    private suspend fun currentJobActive(): Boolean =
        kotlin.coroutines.coroutineContext[Job]?.isActive == true

    companion object {
        const val RECENT_AUDIT = 200
    }
}
