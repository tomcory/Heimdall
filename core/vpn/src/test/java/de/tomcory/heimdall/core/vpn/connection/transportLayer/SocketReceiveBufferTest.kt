package de.tomcory.heimdall.core.vpn.connection.transportLayer

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.channels.DatagramChannel
import java.nio.channels.SocketChannel

/**
 * Tests for docs/vpn-mitm-audit.md PKT-34 (V-53): both transports used to set their
 * outward-facing socket's receive buffer to maxPacketSize (16 KB). For UDP that made the kernel
 * drop most of any burst, for TCP it throttled downloads.
 */
class SocketReceiveBufferTest {

    private lateinit var tcpServer: ServerSocket
    private lateinit var udpServer: DatagramSocket

    private val localAddr = InetAddress.getByName("10.0.0.70") as Inet4Address
    private val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
    private val maxPacketSize = 16413

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        tcpServer = ServerSocket(0, 1, remoteAddr)
        udpServer = DatagramSocket(0, remoteAddr)
    }

    @After
    fun teardown() {
        ConnectionCache.closeAllAndClear()
        tcpServer.close()
        udpServer.close()
    }

    /** The connection's outward-facing channel, which is not part of its public interface. */
    private inline fun <reified T> channelOf(connection: TransportLayerConnection): T {
        val field = connection.javaClass.getDeclaredField("selectableChannel")
        field.isAccessible = true
        return field.get(connection) as T
    }

    @Test
    fun `TCP upstream socket keeps the platform's default receive buffer`() {
        val platformDefault = SocketChannel.open().use { it.socket().receiveBufferSize }
        val componentManager = ComponentManagerFixtures.buildTestComponentManager(keyStoreDir = createTempDir(), maxPacketSize = maxPacketSize)
        val syn = PacketFixtures.buildTcpSynPacket(localAddr, 47001, remoteAddr, tcpServer.localPort)

        val connection = TransportLayerConnection.getInstance(syn, componentManager, RecordingDeviceWriter().handler)!!
        val receiveBuffer = channelOf<SocketChannel>(connection).socket().receiveBufferSize

        assertTrue(
            "the TCP receive buffer ($receiveBuffer) must not be smaller than the platform default ($platformDefault)",
            receiveBuffer >= platformDefault
        )
    }

    @Test
    fun `UDP upstream socket gets a receive buffer that holds a burst of datagrams`() {
        val platformDefault = DatagramChannel.open().use { it.socket().receiveBufferSize }
        val componentManager = ComponentManagerFixtures.buildTestComponentManager(keyStoreDir = createTempDir(), maxPacketSize = maxPacketSize)
        val datagram = PacketFixtures.buildUdpPacket(localAddr, 47002, remoteAddr, udpServer.localPort, byteArrayOf(1, 2, 3))

        val connection = TransportLayerConnection.getInstance(datagram, componentManager, RecordingDeviceWriter().handler)!!
        val receiveBuffer = channelOf<DatagramChannel>(connection).socket().receiveBufferSize

        // the kernel may cap the request, but it must never end up below what an untouched
        // socket gets, and it must be far above the single-datagram size it used to be set to
        assertTrue(
            "the UDP receive buffer ($receiveBuffer) must not be smaller than the platform default ($platformDefault)",
            receiveBuffer >= minOf(platformDefault, UdpConnection.RECEIVE_BUFFER_SIZE)
        )
        assertTrue(
            "the UDP receive buffer ($receiveBuffer) must hold many datagrams, not one",
            receiveBuffer >= 8 * maxPacketSize
        )
    }
}
