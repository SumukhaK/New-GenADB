package dev.genadb.sdk

import org.json.JSONObject
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PolicyScopeTest {
    private val org = """{"relay_id":"r1","issuer":"https://idp","idp_ed25519_public_key":"AAAA","max_session_seconds":900,
        "grants":[{"user":"alice","devices":["dev-A","dev-B"]},{"user":"bob","devices":["dev-B"]},{"user":"carol","devices":["dev-A"]}]}"""

    private fun jwt(sub: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val h = enc.encodeToString("""{"alg":"EdDSA"}""".toByteArray())
        val p = enc.encodeToString("""{"sub":"$sub","typ":"device"}""".toByteArray())
        return "$h.$p.c2ln"
    }

    @Test
    fun scopesGrantsToOneDevice() {
        val s = JSONObject(scopePolicyJson(org, "dev-A")!!)
        val g = s.getJSONArray("grants")
        assertEquals(2, g.length())
        assertEquals(setOf("alice", "carol"), (0 until g.length()).map { g.getJSONObject(it).getString("user") }.toSet())
        assertFalse(s.toString().contains("dev-B") || s.toString().contains("bob"))
        assertEquals("r1", s.getString("relay_id"))
        assertEquals(900, s.getInt("max_session_seconds"))
        assertNull(scopePolicyJson("{nope", "dev-A"))
    }

    @Test
    fun effectiveConfigWritesOnlyThisPhonesGrants() {
        val e = effective(SetuConfig("wss://corp/"), ManagedPolicy(enrollmentToken = jwt("dev-B"), policyJson = org))
        val p = JSONObject(e.policyJson!!)
        val g = p.getJSONArray("grants")
        assertEquals(setOf("alice", "bob"), (0 until g.length()).map { g.getJSONObject(it).getString("user") }.toSet())
        assertFalse(e.policyJson!!.contains("carol") || e.policyJson!!.contains("dev-A"))
        assertEquals("dev-B", tokenSubject(jwt("dev-B")))
        assertNull(tokenSubject("not-a-token"))
        // An unreadable token leaves the policy as pushed (the agent rejects the token anyway).
        val raw = effective(SetuConfig("wss://corp/"), ManagedPolicy(enrollmentToken = "ENROLL", policyJson = org))
        assertTrue(raw.policyJson!!.contains("bob"))
    }
}
