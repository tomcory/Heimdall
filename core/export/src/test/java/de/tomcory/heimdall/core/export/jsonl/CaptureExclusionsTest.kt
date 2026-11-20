package de.tomcory.heimdall.core.export.jsonl

import de.tomcory.heimdall.core.database.entity.ConnectionFacts
import de.tomcory.heimdall.core.database.entity.Protocol
import de.tomcory.heimdall.core.database.entity.SecurityProtocol
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class CaptureExclusionsTest {

    private fun facts(
        protocol: Protocol = Protocol.TCP,
        security: SecurityProtocol? = SecurityProtocol.TLS,
        port: Int = 443,
        bytesOut: Long = 100,
        blocked: Boolean = false,
        blockReason: String? = null,
        passthrough: String? = null,
        hasRequest: Boolean = true
    ) = ConnectionFacts(protocol, security, port, bytesOut, blocked, blockReason, passthrough, hasRequest)

    @Test
    fun `a decrypted connection with requests is observed`() {
        assertNull(CaptureExclusions.classOf(facts(), mitm = true))
        assertNull(CaptureExclusions.classOf(facts(security = SecurityProtocol.PLAIN, port = 80), mitm = true))
    }

    @Test
    fun `each class`() {
        assertEquals("blocked:quic_policy", CaptureExclusions.classOf(facts(protocol = Protocol.UDP, blocked = true, blockReason = "quic_policy"), true))
        assertEquals("blocked:host_rule", CaptureExclusions.classOf(facts(blocked = true, blockReason = "host_rule"), true))
        assertEquals("dns", CaptureExclusions.classOf(facts(protocol = Protocol.UDP, security = SecurityProtocol.PLAIN, port = 53, hasRequest = false), true))
        assertEquals("dns", CaptureExclusions.classOf(facts(port = 853, hasRequest = false), true))
        assertEquals("quic", CaptureExclusions.classOf(facts(protocol = Protocol.UDP, security = SecurityProtocol.QUIC, hasRequest = false), true))
        assertEquals(
            "passthrough:CLIENT_CLOSED_DURING_HANDSHAKE",
            CaptureExclusions.classOf(facts(passthrough = "CLIENT_CLOSED_DURING_HANDSHAKE", hasRequest = false), true)
        )
        assertEquals(
            "rejected:CLIENT_HANDSHAKE_ERROR",
            CaptureExclusions.classOf(facts(passthrough = "REJECTED:CLIENT_HANDSHAKE_ERROR", hasRequest = false), true)
        )
        assertEquals("tls_without_mitm", CaptureExclusions.classOf(facts(hasRequest = false), mitm = false))
        assertEquals("udp", CaptureExclusions.classOf(facts(protocol = Protocol.UDP, security = SecurityProtocol.PLAIN, port = 3478, hasRequest = false), true))
        assertEquals("no_request", CaptureExclusions.classOf(facts(security = SecurityProtocol.PLAIN, port = 1883, hasRequest = false), true))
    }

    @Test
    fun `a connection that sent nothing is in no class`() {
        assertNull(CaptureExclusions.classOf(facts(bytesOut = 0, hasRequest = false), true))
        assertNull(CaptureExclusions.classOf(facts(security = null, bytesOut = 0, hasRequest = false), true))
    }

    @Test
    fun `without the session's settings, undecrypted TLS without a reason counts as no request`() {
        assertEquals("no_request", CaptureExclusions.classOf(facts(hasRequest = false), mitm = null))
    }

    @Test
    fun `counts per class in a stable order`() {
        val counts = CaptureExclusions.classify(
            listOf(
                facts(),
                facts(protocol = Protocol.UDP, security = SecurityProtocol.PLAIN, port = 53),
                facts(protocol = Protocol.UDP, security = SecurityProtocol.PLAIN, port = 53),
                facts(passthrough = "CLIENT_HANDSHAKE_ERROR", hasRequest = false)
            ),
            mitm = true
        )
        assertEquals(mapOf("dns" to 2, "passthrough:CLIENT_HANDSHAKE_ERROR" to 1), counts)
        assertEquals(listOf("dns", "passthrough:CLIENT_HANDSHAKE_ERROR"), counts.keys.toList())
    }

    @Test
    fun `settings as the manifest carries them`() {
        val json = CaptureSettings(
            mitm = true,
            includedApps = null,
            excludedApps = setOf("b.app", "a.app"),
            hostMode = "ALL",
            hosts = emptyList(),
            learnPassthrough = true,
            trustAllUpstreamCertificates = false,
            quicPolicy = "BLOCK",
            blockedHosts = listOf("ads.example"),
            maxHttpBodyBytes = 1048576,
            privateDnsStrict = false,
            apps = listOf("com.example.app")
        ).toJson()
        assertEquals(true, json["mitm"]!!.jsonPrimitive.boolean)
        assertEquals(true, json["alpn_http1_only"]!!.jsonPrimitive.boolean)
        assertEquals("block", json["quic_policy"]!!.jsonPrimitive.content)
        assertEquals("dot_to_vpn_dns_refused", json["private_dns"]!!.jsonPrimitive.content)
        val scope = json["mitm_scope"]!!.jsonObject
        assertEquals("null", scope["included_apps"].toString())
        assertEquals(listOf("a.app", "b.app"), scope["excluded_apps"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals("all", scope["host_mode"]!!.jsonPrimitive.content)
    }
}
