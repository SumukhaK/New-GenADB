package dev.genadb.sdk

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import java.nio.file.Files
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SessionsTest {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val dir = Files.createTempDirectory("sessions").toFile()

    @AfterTest
    fun done() = scope.cancel()

    /** A FakeAgent whose processes record the commands written to them. */
    class CommandAgent : AgentLauncher {
        val inner = FakeAgent()
        val commands = LinkedBlockingQueue<String>()
        override fun launch(args: List<String>, env: Map<String, String>): AgentProcess {
            val p = inner.launch(args, env)
            return object : AgentProcess by p {
                override fun writeLine(line: String): Boolean { commands.put(line); return true }
            }
        }
    }

    @Test
    fun sessionsFollowAgentEventsAndEndSessionSendsTheCommand() = runBlocking {
        val agent = CommandAgent()
        val m = ManagerCore(
            launcher = agent, policyProvider = { ManagedPolicy() }, network = { emptyList() }, stateDir = dir,
            scope = scope, backoff = Backoff(50, 100),
        )
        m.start(SetuConfig("ws://relay:7000/", audit = AuditMode.ON))
        val args = agent.inner.launches.poll(5, TimeUnit.SECONDS)!!
        assertTrue("--control-stdin" in args)
        val p = agent.inner.current!!
        p.emit("""{"event":"online","device_id":"dev-1"}""")
        p.emit("""{"event":"session_open","session_id":"a1","peer_label":"ci-laptop","transport":"relay-wss","kind":"adb"}""")
        p.emit("""{"event":"session_open","session_id":"b2","peer_label":"alice","transport":"lan","kind":"adb-pair"}""")
        val two = withTimeout(5000) { m.sessions.first { it.size == 2 } }
        assertEquals(DeviceSession("a1", "ci-laptop", "relay-wss", "adb", two[0].openedAtMs), two[0])
        assertEquals("adb-pair", two[1].kind)

        p.emit("""{"event":"path_down","session_id":"a1","reason":"keepalive_timeout","transport":"relay-wss"}""")
        withTimeout(5000) { m.sessions.first { s -> s.any { it.id == "a1" && it.path == PathState.DOWN } } }
        p.emit("""{"event":"path_up","session_id":"a1","transport":"lan","outage_ms":900}""")
        val up = withTimeout(5000) { m.sessions.first { s -> s.any { it.id == "a1" && it.path == PathState.UP } } }
        assertEquals("lan", up.first { it.id == "a1" }.transport)

        assertFalse(m.endSession("nope"), "unknown sessions are not sent")
        assertTrue(m.endSession("a1"))
        val cmd = JSONObject(agent.commands.poll(5, TimeUnit.SECONDS)!!)
        assertEquals("end_session", cmd.getString("cmd"))
        assertEquals("a1", cmd.getString("session_id"))
        p.emit("""{"event":"session_close","session_id":"a1","reason":"ended_on_device"}""")
        val one = withTimeout(5000) { m.sessions.first { it.size == 1 } }
        assertEquals("b2", one[0].id)

        val audit = m.recentAuditEvents.value
        val types = audit.map { it.type }
        assertTrue(types.containsAll(listOf("session_open", "session_end_requested", "session_close")), "$types")
        assertEquals("ended_on_device", audit.last { it.type == "session_close" }.fields["reason"])
        assertEquals("ci-laptop", audit.first { it.type == "session_open" }.fields["peer_label"])

        // The agent dies: its sessions are gone with it.
        p.exit(1)
        withTimeout(5000) { m.sessions.first { it.isEmpty() } }
        m.stop()
        assertEquals(0, HashChainedAuditLog.verify(m.auditFile))
    }

    @Test
    fun lockScreenNeverShowsThePairingCode() {
        val code = "4821-093357"
        val online = ConnectionState.Online("dev-1", pairingCode = code)
        val n = SetuNotifications.content(online)
        assertTrue(code in n.text, "the unlocked notification shows the code")
        assertTrue(n.containsSecret)
        assertFalse(code in n.publicText)
        assertFalse(Regex("""\d{4}-\d{6}""").containsMatchIn(n.publicText))
        val s = listOf(DeviceSession("a1", "ci-laptop", "relay-wss"))
        val busy = SetuNotifications.content(online, s)
        assertFalse(code in busy.publicText)
        assertTrue("ci-laptop" in busy.publicText)
        val down = SetuNotifications.content(online, s.map { it.copy(path = PathState.DOWN) })
        assertTrue("reconnecting" in down.publicText)
        val corp = SetuNotifications.content(ConnectionState.Online("dev-1"))
        assertFalse(corp.containsSecret)
        assertEquals("Online", corp.publicText)
        for (st in listOf(ConnectionState.Idle, ConnectionState.Starting, ConnectionState.Blocked("x"),
            ConnectionState.PolicyMissing("policy_json"), ConnectionState.Reconnecting(1, "boom", 10))) {
            assertFalse(SetuNotifications.content(st).containsSecret)
        }
    }
}
