package de.tomcory.heimdall.core.vpn.mitm

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.net.ssl.SSLContext

/** Tests for docs/records/vpn-mitm-audit.md PKT-57. */
class AlpnTest {

    @Test
    fun `clients without ALPN or with HTTP 1_1 among their protocols can be intercepted`() {
        assertTrue(Alpn.interceptable(emptyList()))
        assertTrue(Alpn.interceptable(listOf("h2", "http/1.1")))
        assertTrue(Alpn.interceptable(listOf("http/1.1")))
    }

    @Test
    fun `clients that offer ALPN without HTTP 1_1 cannot`() {
        assertFalse(Alpn.interceptable(listOf("h2")))
        assertFalse(Alpn.interceptable(listOf("grpc-exp", "h2")))
        assertFalse(Alpn.interceptable(listOf("acme-tls/1")))
    }

    @Test
    fun `the API is found on the JVM the tests run on`() {
        assertTrue(Alpn.supported)
    }

    @Test
    fun `offer sets the protocols and keeps the engine's other parameters`() {
        val engine = SSLContext.getDefault().createSSLEngine("example.com", 443)
        engine.useClientMode = true
        val protocolsBefore = engine.sslParameters.protocols.toList()

        Alpn.offer(engine, listOf("http/1.1"))

        assertEquals(listOf("http/1.1"), engine.sslParameters.applicationProtocols.toList())
        assertEquals(protocolsBefore, engine.sslParameters.protocols.toList())
    }

    @Test
    fun `an empty list leaves the engine without ALPN`() {
        val engine = SSLContext.getDefault().createSSLEngine()
        Alpn.offer(engine, emptyList())
        assertTrue(engine.sslParameters.applicationProtocols.isEmpty())
        assertNull("nothing negotiated before a handshake", Alpn.selected(engine))
    }
}
