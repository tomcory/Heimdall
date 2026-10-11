package de.tomcory.heimdall.core.vpn.connection.encryptionLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.metadata.TlsPassthroughCache
import de.tomcory.heimdall.core.vpn.mitm.MitmScope
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import org.junit.Before
import org.junit.Test

/**
 * Tests for docs/records/vpn-mitm-audit.md PKT-53: bytes the transport layer counts as in process in the
 * TLS layer are released exactly once, also when the TLS layer has already closed itself and
 * never processes them. Otherwise the transport layer waits forever before closing its channel.
 */
class TlsProcessingAccountingTest {

    private lateinit var transportLayer: TransportLayerConnection
    private lateinit var tlsConnection: TlsConnection

    // an application data record; with MitM off it is passed straight on
    private val record = byteArrayOf(0x17, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03)

    @Before
    fun setup() {
        val componentManager: ComponentManager = mockk(relaxed = true)
        every { componentManager.doMitm } returns false
        every { componentManager.tlsPassthroughCache } returns TlsPassthroughCache()
        every { componentManager.mitmScope } returns MitmScope.ALL

        transportLayer = mockk(relaxed = true)
        every { transportLayer.remoteHost } returns null
        every { transportLayer.remotePort } returns 443
        every { transportLayer.appId } returns null

        tlsConnection = TlsConnection(0, transportLayer, componentManager, Dispatchers.Unconfined)
    }

    /** What closeConnection() does to the scope: the TLS layer has closed itself. */
    private fun cancelConnectionScope() {
        val field = TlsConnection::class.java.getDeclaredField("connectionScope")
        field.isAccessible = true
        (field.get(tlsConnection) as CoroutineScope).cancel()
    }

    @Test
    fun `processed payloads are released exactly once`() {
        tlsConnection.unwrapOutbound(record)
        tlsConnection.unwrapInbound(record)

        verify(exactly = 1) { transportLayer.outboundProcessingDeferred(record.size) }
        verify(exactly = 1) { transportLayer.outboundProcessingFinished(record.size) }
        verify(exactly = 1) { transportLayer.inboundProcessingDeferred(record.size) }
        verify(exactly = 1) { transportLayer.inboundProcessingFinished(record.size) }
    }

    @Test
    fun `payloads handed over after the TLS layer closed itself are released too`() {
        cancelConnectionScope()

        tlsConnection.unwrapOutbound(record)
        tlsConnection.unwrapInbound(record)

        verify(exactly = 1) { transportLayer.outboundProcessingFinished(record.size) }
        verify(exactly = 1) { transportLayer.inboundProcessingFinished(record.size) }
        // and they are not processed
        verify(exactly = 0) { transportLayer.wrapOutbound(any()) }
        verify(exactly = 0) { transportLayer.wrapInbound(any()) }
    }
}
