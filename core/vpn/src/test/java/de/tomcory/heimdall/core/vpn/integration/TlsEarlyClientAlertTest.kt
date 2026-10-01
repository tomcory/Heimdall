package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection.TransportLayerState
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.FakeClientTlsDriver
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import de.tomcory.heimdall.core.vpn.integration.support.SelectorPump
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.TcpPacket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Tests for docs/vpn-mitm-audit.md PKT-31 (V-43): an alert the client sends before the
 * client-facing SSLEngine exists used to be handed to that non-existent engine. The resulting
 * null was treated as an engine failure and the client's TCP connection was reset.
 *
 * The upstream here accepts TCP connections but never speaks TLS, which keeps the MitM in its
 * server-facing handshake, the phase in which no client-facing engine exists.
 */
class TlsEarlyClientAlertTest {

    private lateinit var silentServer: ServerSocket
    private lateinit var acceptThread: Thread
    private lateinit var componentManager: ComponentManager
    private lateinit var pump: SelectorPump
    private lateinit var deviceWriter: RecordingDeviceWriter
    private lateinit var synPacket: IpV4Packet
    private lateinit var connection: TransportLayerConnection

    private val acceptedSockets = CopyOnWriteArrayList<Socket>()

    private val hostname = "example.com"
    private val appId = 1000 // ComponentManagerFixtures' default
    private val localAddr = InetAddress.getByName("10.0.0.60") as Inet4Address
    private val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
    private var deviceSeq = 1

    private val closeNotify = byteArrayOf(0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00)
    private val fatalHandshakeFailure = byteArrayOf(0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28)

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        silentServer = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        acceptThread = Thread {
            try {
                while (true) {
                    acceptedSockets.add(silentServer.accept())
                }
            } catch (e: Exception) {
                // closed during teardown
            }
        }
        acceptThread.start()

        componentManager = ComponentManagerFixtures.buildTestComponentManager(keyStoreDir = createTempDir())
        pump = SelectorPump(componentManager.selector)
        pump.start()
        deviceWriter = RecordingDeviceWriter()

        // device-side TCP handshake
        synPacket = PacketFixtures.buildTcpSynPacket(localAddr, LOCAL_PORT, remoteAddr, silentServer.localPort)
        connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)!!
        connection.unwrapOutbound(synPacket.payload)
        awaitUntil("expected a SYN-ACK") { deviceWriter.sentMessages.isNotEmpty() }
        sendFromDevice()
        assertEquals(TransportLayerState.CONNECTED, connection.state)
    }

    @After
    fun teardown() {
        pump.stop()
        acceptedSockets.forEach { it.close() }
        silentServer.close()
        acceptThread.join(2000)
        ConnectionCache.closeAllAndClear()
    }

    private fun sendFromDevice(payload: ByteArray = ByteArray(0), finFlag: Boolean = false) {
        val packet = PacketFixtures.buildTcpDataPacket(
            localAddr, LOCAL_PORT, remoteAddr, silentServer.localPort,
            seq = deviceSeq, ack = 1, payload = payload, pshFlag = payload.isNotEmpty(), finFlag = finFlag
        )
        deviceSeq += payload.size
        connection.unwrapOutbound(packet.payload)
    }

    private fun awaitUntil(message: String, timeoutMs: Long = 5000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline && !condition()) {
            Thread.sleep(20)
        }
        assertTrue(message, condition())
    }

    private fun segmentsSince(index: Int): List<TcpPacket> {
        return deviceWriter.sentMessages.drop(index).map { (it.obj as IpPacket).payload as TcpPacket }
    }

    private fun clientHello(): ByteArray = FakeClientTlsDriver(hostname, silentServer.localPort).wrap()!!

    /**
     * Asserts that the connection was neither reset nor torn down nor learned as a passthrough
     * pair, then completes the close the way a client does after its alert: with a FIN.
     */
    private fun assertClosedCleanlyOnFin(messagesBeforeAlert: Int) {
        // give the connection-confined coroutine time to process the records, and a wrong
        // implementation time to reset the connection
        Thread.sleep(500)

        assertFalse(
            "the alert must not make us reset the client's TCP connection",
            segmentsSince(messagesBeforeAlert).any { it.header.rst }
        )
        assertEquals(
            "the transport layer must stay open until the client closes it",
            TransportLayerState.CONNECTED,
            connection.state
        )
        assertSame(connection, ConnectionCache.findConnection(synPacket))
        assertFalse(
            "an alert sent before our certificate was presented says nothing about whether the app accepts it",
            componentManager.tlsPassthroughCache.get(appId, hostname)
        )

        // the client follows its alert with a FIN. The connection is MitM'd, so it cannot be
        // half-closed (PKT-30) and is closed fully: our FIN-ACK goes out at once.
        val messagesBeforeFin = deviceWriter.sentMessages.size
        sendFromDevice(finFlag = true)

        assertEquals(TransportLayerState.CLOSING, connection.state)
        val closing = segmentsSince(messagesBeforeFin)
        assertEquals(1, closing.size)
        assertTrue("the client's FIN must be answered with our FIN-ACK", closing.single().header.fin && closing.single().header.ack)
        assertFalse(closing.single().header.rst)

        // still nothing learned once the client-closed notification has had time to arrive
        Thread.sleep(300)
        assertFalse(componentManager.tlsPassthroughCache.get(appId, hostname))
    }

    @Test
    fun `a close_notify right behind the ClientHello closes the TLS session without resetting the client`() {
        val messagesBefore = deviceWriter.sentMessages.size

        // both records in one TCP segment, as OpenSSL sends them when it gives up at once
        sendFromDevice(clientHello() + closeNotify)

        assertClosedCleanlyOnFin(messagesBefore)
    }

    @Test
    fun `a fatal alert during the server-facing handshake closes the TLS session without resetting the client`() {
        val messagesBefore = deviceWriter.sentMessages.size
        sendFromDevice(clientHello())

        // the MitM has started its own handshake with the upstream, which never answers
        awaitUntil("expected the MitM to connect upstream") { acceptedSockets.isNotEmpty() }
        Thread.sleep(300)

        sendFromDevice(fatalHandshakeFailure)

        assertClosedCleanlyOnFin(messagesBefore)
    }

    @Test
    fun `records the client sends after its early alert are ignored`() {
        val messagesBefore = deviceWriter.sentMessages.size
        sendFromDevice(clientHello() + closeNotify)
        Thread.sleep(300)

        // a client that keeps talking after close_notify is misbehaving; it must not revive the
        // session or crash the connection
        sendFromDevice(clientHello())
        Thread.sleep(300)

        assertFalse(segmentsSince(messagesBefore).any { it.header.rst })
        assertEquals(TransportLayerState.CONNECTED, connection.state)
    }

    companion object {
        private const val LOCAL_PORT = 46001
    }
}
