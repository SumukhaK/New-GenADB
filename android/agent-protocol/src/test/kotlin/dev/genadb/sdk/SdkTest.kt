package dev.genadb.sdk

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import java.io.File
import java.nio.file.Files
import java.time.Instant
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CanonicalJsonTest {
    // Vectors produced by the Go SDK (pkg/genadb/audit Chain.Seal).
    private val goRecords = javaClass.getResource("/go-audit-vectors.jsonl")!!.readText().lines().filter { it.isNotBlank() }

    @Test
    fun matchesGoEncodingAndHashes() {
        for (line in goRecords) {
            val o = JSONObject(line)
            assertEquals(line, CanonicalJson.encode(o), "re-encoding must be byte-identical to Go")
            val m = o.keys().asSequence().filter { it != "event_hash" }.associateWith { o.get(it) }
            assertEquals(o.getString("event_hash"), HashChainedAuditLog.sha256Hex(CanonicalJson.encode(m)))
        }
        val f = Files.createTempFile("go", ".jsonl").toFile()
        f.writeText(goRecords.joinToString("\n") + "\n")
        assertEquals(0, HashChainedAuditLog.verify(f))
    }
}

class AuditLogTest {
    private val dir = Files.createTempDirectory("audit").toFile()

    @Test
    fun chainsResumesAndDetectsTampering() {
        val f = File(dir, "audit.jsonl")
        var t = Instant.parse("2026-03-01T10:00:00Z")
        val log = HashChainedAuditLog(f) { t.also { t = t.plusSeconds(1) } }
        val a = log.record("agent_start", null, mapOf("mode" to "corporate", "transport" to "relay-wss"))
        val b = log.record("online", "dev-1", emptyMap())
        assertEquals(HashChainedAuditLog.GENESIS, a.prevEventHash)
        assertEquals(a.eventHash, b.prevEventHash)
        // a new instance continues the same chain
        val c = HashChainedAuditLog(f).record("agent_stop", "dev-1", emptyMap())
        assertEquals(3, c.seq)
        assertEquals(b.eventHash, c.prevEventHash)
        assertEquals(0, HashChainedAuditLog.verify(f))
        // sample for the Go cross-check (genadb audit verify)
        File("build").mkdirs()
        f.copyTo(File("build/kotlin-audit-sample.jsonl"), overwrite = true)

        val lines = f.readLines().toMutableList()
        lines[1] = lines[1].replace("dev-1", "dev-2")
        f.writeText(lines.joinToString("\n") + "\n")
        assertEquals(2, HashChainedAuditLog.verify(f))
        lines.removeAt(1)
        f.writeText(lines.joinToString("\n") + "\n")
        assertTrue(HashChainedAuditLog.verify(f) != 0, "deleting a record must break the chain")
    }
}

class ProtocolTest {
    @Test
    fun soloArgs() {
        val e = effective(GenAdbConfig("wss://relay.example/"), ManagedPolicy())
        val args = agentArgs(e, "/data/state", null)
        assertEquals(listOf("device", "--relay", "wss://relay.example/", "--adbd", "auto", "--state", "/data/state",
            "--mode", "solo", "--lan-listen", "0.0.0.0:47100"), args)
        assertFalse(e.policy.auditEnabled, "solo audit is off by default")
    }

    @Test
    fun managedConfigWinsAndForcesCorporateAudit() {
        val e = effective(
            GenAdbConfig("wss://user.example/", audit = AuditMode.OFF),
            ManagedPolicy(relayUrl = "wss://corp.example/", enrollmentToken = "ENROLL", policyJson = "{}", debuggingAllowed = false),
        )
        assertEquals(Mode.CORPORATE, e.policy.mode)
        assertTrue(e.policy.auditEnabled && e.policy.managed)
        val args = agentArgs(e, "/s", "/s/policy.json")
        assertTrue(args.containsAll(listOf("wss://corp.example/", "--enroll", "ENROLL", "--policy", "/s/policy.json", "--debug-policy", "disallowed")))
        assertFalse("--lan-listen" in args, "no direct LAN path in corporate mode")
    }

    @Test
    fun auditNeverCarriesPairingCode() {
        val (type, fields) = auditFor(AgentEvent.PairingCode("1234-ABCDEF", "dev"))!!
        assertEquals("pairing_code_issued", type)
        assertTrue(fields.isEmpty())
    }
}

/** A scripted agent: tests push stdout lines and exit codes. */
class FakeAgent : AgentLauncher {
    val launches = LinkedBlockingQueue<List<String>>()
    val envs = LinkedBlockingQueue<Map<String, String>>()
    @Volatile var current: Proc? = null

    inner class Proc : AgentProcess {
        val lines = LinkedBlockingQueue<String>()
        @Volatile var exit: Int? = null
        @Volatile var destroyed = false
        override fun readLine(): String? {
            while (true) {
                if (destroyed) return null
                val l = lines.poll(20, TimeUnit.MILLISECONDS)
                if (l == EOF) return null
                if (l != null) return l
            }
        }
        override fun waitFor(): Int = exit ?: if (destroyed) 143 else 0
        override fun destroy() { destroyed = true }
        fun emit(json: String) = lines.put(json)
        fun exit(code: Int) { exit = code; lines.put(EOF) }
    }

    override fun launch(args: List<String>, env: Map<String, String>): AgentProcess {
        val p = Proc()
        current = p
        envs.put(env)
        launches.put(args)
        return p
    }

    fun awaitLaunch(): Proc {
        launches.poll(5, TimeUnit.SECONDS) ?: error("agent not launched")
        return current!!
    }

    companion object { const val EOF = "\u0000EOF" }
}

class ManagerCoreTest {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val dir = Files.createTempDirectory("mgr").toFile()

    @AfterTest
    fun done() = scope.cancel()

    private fun core(fake: FakeAgent, policy: ManagedPolicy = ManagedPolicy()) = ManagerCore(
        launcher = fake, policyProvider = { policy }, network = { listOf("10.0.0.53") }, stateDir = dir,
        scope = scope, backoff = Backoff(initialMs = 50, maxMs = 100),
    )

    @Test
    fun soloLifecyclePairAuditAndRestart() = runBlocking {
        val fake = FakeAgent()
        val m = core(fake)
        m.start(GenAdbConfig("ws://relay:7000/", audit = AuditMode.ON))
        val p = fake.awaitLaunch()
        assertEquals("10.0.0.53", fake.envs.take()["GENADB_DNS"])
        p.emit("""{"event":"pairing_code","code":"4321-QWERTY","device_id":"dev-9"}""")
        p.emit("""{"event":"online","device_id":"dev-9"}""")
        assertEquals("4321-QWERTY", withTimeout(5000) { m.pair(5000) })
        val online = m.connectionState.value
        assertIs<ConnectionState.Online>(online)
        assertEquals("dev-9", online.deviceId)

        // the agent dies: Reconnecting, then a fresh launch
        p.exit(1)
        withTimeout(5000) { m.connectionState.first { it is ConnectionState.Reconnecting } }
        val p2 = fake.awaitLaunch()
        p2.emit("""{"event":"online","device_id":"dev-9"}""")
        withTimeout(5000) { m.connectionState.first { it is ConnectionState.Online } }

        m.stop()
        assertEquals(ConnectionState.Idle, m.connectionState.value)
        assertTrue(p2.destroyed)
        val types = m.recentAuditEvents.value.map { it.type }
        assertEquals(listOf("agent_start", "pairing_code_issued", "online", "agent_exit", "agent_start", "online", "agent_stop"), types)
        val log = m.auditFile.readText()
        assertFalse("4321-QWERTY" in log, "pairing code must never reach the audit log")
        assertEquals(0, HashChainedAuditLog.verify(m.auditFile))
        assertEquals(m.auditFile.absolutePath, m.status().auditLogPath)
    }

    @Test
    fun soloAuditOffByDefault() = runBlocking {
        val fake = FakeAgent()
        val m = core(fake)
        m.start(GenAdbConfig("ws://relay:7000/"))
        fake.awaitLaunch().emit("""{"event":"online","device_id":"d"}""")
        withTimeout(5000) { m.connectionState.first { it is ConnectionState.Online } }
        m.stop()
        assertFalse(m.auditFile.exists())
        assertNull(m.lastAuditEvent.value)
        assertNull(m.status().auditLogPath)
    }

    @Test
    fun corporateBlockedAndNoPairing() = runBlocking {
        val fake = FakeAgent()
        val m = core(fake, ManagedPolicy(relayUrl = "wss://corp/", enrollmentToken = "E", policyJson = "{}", debuggingAllowed = false))
        m.start(GenAdbConfig(""))
        val p = fake.awaitLaunch()
        p.emit("""{"event":"blocked","reason":"debugging_disallowed"}""")
        withTimeout(5000) { m.connectionState.first { it is ConnectionState.Blocked } }
        assertFailsWith<GenAdbException.PairingUnavailable> { m.pair(1000) }
        assertTrue(m.policyStatus.value.auditEnabled)
        assertEquals("blocked", m.lastAuditEvent.value?.type)
        assertTrue(File(dir, "policy.json").exists())
        m.stop()
    }

    // Regression: an EMM that pushes the enrollment token before the policy
    // must give a clean PolicyMissing state, never an exception that kills
    // the app, and the agent must not be launched half-configured.
    @Test
    fun corporateTokenWithoutPolicyIsPolicyMissing() = runBlocking {
        val fake = FakeAgent()
        var managed = ManagedPolicy(relayUrl = "wss://corp/", enrollmentToken = "ENROLL", policyJson = null)
        val m = ManagerCore(
            launcher = fake, policyProvider = { managed }, network = { emptyList() }, stateDir = dir,
            scope = scope, backoff = Backoff(initialMs = 50, maxMs = 100),
        )
        m.start(null) // no app config at all: everything comes from EMM
        assertEquals(ConnectionState.PolicyMissing("policy_json"), m.connectionState.value)
        assertEquals("policy_json", m.policyStatus.value.missing)
        assertEquals(Mode.CORPORATE, m.policyStatus.value.mode)
        assertFalse(m.isRunning())
        assertNull(fake.launches.poll(200, TimeUnit.MILLISECONDS), "agent must not launch without a policy")
        assertEquals("policy_missing", m.lastAuditEvent.value?.type, "corporate audit records the misconfiguration")
        val e = assertFailsWith<GenAdbException.PolicyMissing> { m.pair(1000) }
        assertEquals("policy_json", e.missing)

        // Blank policy is the same as missing; so is a policy without a token.
        managed = managed.copy(policyJson = "   ")
        m.start(null)
        assertIs<ConnectionState.PolicyMissing>(m.connectionState.value)
        m.stop()
        assertEquals(ConnectionState.Idle, m.connectionState.value)

        // The policy arrives (EMM update): the agent starts normally.
        managed = managed.copy(policyJson = """{"version":1}""")
        m.start(null)
        val args = fake.launches.poll(5, TimeUnit.SECONDS) ?: error("agent not launched")
        assertTrue("--policy" in args && "ENROLL" in args)
        assertTrue(File(dir, "policy.json").readText().contains("version"))
        assertNull(m.policyStatus.value.missing)
        m.stop()
    }

    @Test
    fun agentArgsErrorsNeverEscapeTheScope() = runBlocking {
        val crashed = java.util.concurrent.atomic.AtomicReference<Throwable?>(null)
        val guarded = CoroutineScope(SupervisorJob() + Dispatchers.Default +
            kotlinx.coroutines.CoroutineExceptionHandler { _, t -> crashed.set(t) })
        val m = ManagerCore(
            launcher = { _, _ -> throw IllegalStateException("exec failed") }, policyProvider = { ManagedPolicy() },
            network = { emptyList() }, stateDir = dir, scope = guarded, backoff = Backoff(50, 100),
        )
        m.start(GenAdbConfig("ws://relay:7000/"))
        withTimeout(5000) { m.connectionState.first { it is ConnectionState.Reconnecting } }
        m.stop()
        guarded.cancel()
        assertNull(crashed.get())
    }

    @Test
    fun notConfigured() {
        assertFailsWith<GenAdbException.NotConfigured> { core(FakeAgent()).start(null) }
    }
}
