package de.tomcory.heimdall.core.vpn.connection.appLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.PlaintextConnection
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.TlsConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TcpConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.UdpConnection
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertTrue
import org.junit.Test

/** Tests for docs/records/vpn-mitm-audit.md PKT-58: which connections are read as DNS, and how. */
class AppLayerSelectionTest {

    private val componentManager: ComponentManager = mockk(relaxed = true)
    private val firstPayload = byteArrayOf(0, 29, 0x12, 0x34, 1, 0, 0, 1)

    private inline fun <reified T : TransportLayerConnection> transport(port: Int): T {
        val transport = mockk<T>(relaxed = true)
        every { transport.remotePort } returns port
        return transport
    }

    private fun appLayerFor(encryptionLayer: EncryptionLayerConnection) =
        AppLayerConnection.getInstance(firstPayload, 0, encryptionLayer, componentManager)

    private fun plaintext(transport: TransportLayerConnection): PlaintextConnection {
        val layer = mockk<PlaintextConnection>(relaxed = true)
        every { layer.transportLayer } returns transport
        return layer
    }

    private fun tls(transport: TransportLayerConnection, decrypted: Boolean): TlsConnection {
        val layer = mockk<TlsConnection>(relaxed = true)
        every { layer.transportLayer } returns transport
        every { layer.doMitm } returns decrypted
        return layer
    }

    @Test
    fun `UDP to port 53 is read one message per datagram`() {
        assertTrue(appLayerFor(plaintext(transport<UdpConnection>(53))) is DnsConnection)
    }

    @Test
    fun `TCP to port 53 is read as length-prefixed messages`() {
        assertTrue(appLayerFor(plaintext(transport<TcpConnection>(53))) is DnsStreamConnection)
    }

    @Test
    fun `decrypted DNS over TLS is read as length-prefixed messages`() {
        assertTrue(appLayerFor(tls(transport<TcpConnection>(853), decrypted = true)) is DnsStreamConnection)
    }

    @Test
    fun `passed-through DNS over TLS is ciphertext and not read as DNS`() {
        assertTrue(appLayerFor(tls(transport<TcpConnection>(853), decrypted = false)) is RawConnection)
    }

    @Test
    fun `other ports are not DNS`() {
        assertTrue(appLayerFor(plaintext(transport<TcpConnection>(5353))) is RawConnection)
    }
}
