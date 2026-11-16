package dev.genadb.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AgentProtocolTest {
    @Test
    fun soloArgs() {
        val args = DeviceAgentConfig(relay = "wss://relay.example/", stateDir = "/data/x", lanListen = "0.0.0.0:47100").toArgs()
        assertEquals(listOf("device", "--relay", "wss://relay.example/", "--adbd", "auto", "--state", "/data/x",
            "--mode", "solo", "--lan-listen", "0.0.0.0:47100"), args)
    }

    @Test
    fun corporateRequiresEnrollmentAndBlocksDebugging() {
        assertFailsWith<IllegalArgumentException> {
            DeviceAgentConfig(relay = "r:1", stateDir = "s", mode = Mode.CORPORATE).toArgs()
        }
        val args = DeviceAgentConfig(relay = "r:1", stateDir = "s", mode = Mode.CORPORATE, enrollToken = "jwt",
            policyFile = "p.json", debuggingAllowed = false, lanListen = "0.0.0.0:1").toArgs()
        assertTrue("--debug-policy" in args && "disallowed" in args)
        assertTrue("--lan-listen" !in args, "no direct LAN path in corporate mode")
    }

    @Test
    fun foldsEvents() {
        val lines = listOf(
            """{"event":"online","device_id":"dev-1"}""",
            """{"event":"pairing_code","code":"1234-567890","device_id":"dev-1"}""",
            """{"event":"adbd_endpoint","addr":"192.168.1.7:37099"}""",
            "not json",
        )
        val s = lines.mapNotNull(AgentEvent::parse).fold(AgentState()) { st, e -> st.reduce(e) }
        assertEquals(AgentState(online = true, deviceId = "dev-1", pairingCode = "1234-567890",
            adbdEndpoint = "192.168.1.7:37099"), s)
    }
}
