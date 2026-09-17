package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import de.tomcory.heimdall.core.vpn.integration.support.SelectorPump
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.Inet4Address
import java.util.concurrent.atomic.AtomicReference

class ConnectionTeardownTest {

    private lateinit var serverSocket: ServerSocket
    private lateinit var acceptThread: Thread
    private lateinit var pump: SelectorPump

    private val acceptedSocket = AtomicReference<Socket?>(null)

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        serverSocket = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
    }

    @After
    fun teardown() {
        if (::pump.isInitialized) pump.stop()
        acceptedSocket.get()?.close()
        if (::serverSocket.isInitialized && !serverSocket.isClosed) serverSocket.close()
        if (::acceptThread.isInitialized) acceptThread.join(2000)
        ConnectionCache.closeAllAndClear()
    }

    @Test
    fun `closing a connection mid-flight releases the socket and removes it from the cache`() {
        acceptThread = Thread {
            try {
                acceptedSocket.set(serverSocket.accept())
            } catch (e: Exception) {
                // closed during teardown
            }
        }
        acceptThread.start()

        val componentManager = ComponentManagerFixtures.buildTestComponentManager(keyStoreDir = createTempDir())
        pump = SelectorPump(componentManager.selector)
        pump.start()

        val deviceWriter = RecordingDeviceWriter()
        val localAddr = InetAddress.getByName("10.0.0.7") as Inet4Address
        val localPort = 41000
        val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
        val remotePort = serverSocket.localPort

        val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, localPort, remoteAddr, remotePort)
        val connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)
        connection?.unwrapOutbound(synPacket.payload)

        // wait for the SYN-ACK to be written back to the "device"
        val handshakeDeadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < handshakeDeadline && deviceWriter.sentMessages.isEmpty()) {
            Thread.sleep(20)
        }
        assertTrue("expected a SYN-ACK to be sent back to the device", deviceWriter.sentMessages.isNotEmpty())

        // complete the local handshake with an empty ACK so the connection reaches CONNECTED
        val ackPacket = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = localPort, remoteAddr = remoteAddr, remotePort = remotePort,
            seq = 1, ack = 1, payload = ByteArray(0), pshFlag = false
        )
        connection?.unwrapOutbound(ackPacket.payload)

        // close mid-flight, with no FIN exchanged
        connection?.closeHard()

        assertEquals(
            TransportLayerConnection.TransportLayerState.CLOSED,
            connection?.state
        )

        // the real peer socket should observe the close (read returns EOF) - proves the SocketChannel was actually released
        val socketDeadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < socketDeadline && acceptedSocket.get() == null) {
            Thread.sleep(20)
        }
        val peerSocket = acceptedSocket.get()
        assertTrue("server never accepted the connection", peerSocket != null)
        peerSocket!!.soTimeout = 5000
        val eof = peerSocket.getInputStream().read()
        assertEquals("peer should observe end-of-stream once the client-side channel is closed", -1, eof)

        // the connection must no longer be reachable via the cache: a fresh SYN for the same flow yields a new instance
        val secondSynPacket = PacketFixtures.buildTcpSynPacket(localAddr, localPort, remoteAddr, remotePort, seq = 100)
        val secondConnection = TransportLayerConnection.getInstance(secondSynPacket, componentManager, deviceWriter.handler)
        assertNotSame(connection, secondConnection)

        secondConnection?.closeHard()
    }
}
