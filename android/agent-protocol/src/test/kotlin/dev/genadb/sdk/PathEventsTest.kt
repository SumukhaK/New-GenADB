package dev.genadb.sdk

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

class PathEventsTest {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val dir = Files.createTempDirectory("path").toFile()

    @AfterTest
    fun done() = scope.cancel()

    @Test
    fun parsesAllThreeTransitions() {
        val down = AgentEvent.parse("""{"event":"path_down","session_id":"ab12","reason":"keepalive_timeout","transport":"relay-wss"}""")
        assertEquals(AgentEvent.Path(PathStatus("ab12", PathState.DOWN, "relay-wss", "keepalive_timeout")), down)
        val up = AgentEvent.parse("""{"event":"path_up","session_id":"ab12","transport":"lan","outage_ms":4200}""")
        assertEquals(AgentEvent.Path(PathStatus("ab12", PathState.UP, transport = "lan", outageMs = 4200)), up)
        val lost = AgentEvent.parse("""{"event":"path_lost","session_id":"ab12","reason":"rejoin_window_expired","outage_ms":90000}""")
        assertEquals(AgentEvent.Path(PathStatus("ab12", PathState.LOST, reason = "rejoin_window_expired", outageMs = 90000)), lost)
    }

    @Test
    fun onlineStateCarriesTheLatestTransitionAndAuditRecordsIt() = runBlocking {
        val fake = FakeAgent()
        val m = ManagerCore(
            launcher = fake, policyProvider = { ManagedPolicy() }, network = { emptyList() }, stateDir = dir,
            scope = scope, backoff = Backoff(50, 100),
        )
        m.start(SetuConfig("ws://relay:7000/", audit = AuditMode.ON))
        val p = fake.awaitLaunch()
        p.emit("""{"event":"online","device_id":"dev-1"}""")
        val online = withTimeout(5000) { m.connectionState.first { it is ConnectionState.Online } }
        assertIs<ConnectionState.Online>(online)
        assertNull(online.path)

        p.emit("""{"event":"path_down","session_id":"s1","reason":"keepalive_timeout","transport":"relay-tcp"}""")
        val down = withTimeout(5000) { m.connectionState.first { (it as? ConnectionState.Online)?.path?.state == PathState.DOWN } }
        assertEquals("keepalive_timeout", (down as ConnectionState.Online).path?.reason)
        p.emit("""{"event":"path_up","session_id":"s1","transport":"relay-wss","outage_ms":3100}""")
        val up = withTimeout(5000) { m.connectionState.first { (it as? ConnectionState.Online)?.path?.state == PathState.UP } }
        assertEquals("relay-wss", (up as ConnectionState.Online).path?.transport)
        p.emit("""{"event":"path_lost","session_id":"s2","reason":"rejoin_window_expired"}""")
        withTimeout(5000) { m.connectionState.first { (it as? ConnectionState.Online)?.path?.state == PathState.LOST } }

        val audit = m.recentAuditEvents.value.filter { it.type.startsWith("path_") }
        assertEquals(listOf("path_down", "path_up", "path_lost"), audit.map { it.type })
        assertEquals(mapOf("session_id" to "s1", "transport" to "relay-wss", "outage_ms" to "3100"), audit[1].fields)
        m.stop()
        assertEquals(0, HashChainedAuditLog.verify(m.auditFile))
    }
}
