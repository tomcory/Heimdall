package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import de.tomcory.heimdall.core.vpn.integration.support.SelectorPump
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.TcpPacket
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

    @Test
    fun `graceful FIN close writes only a FIN-ACK, not an RST`() {
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
        val localPort = 41001
        val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
        val remotePort = serverSocket.localPort

        val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, localPort, remoteAddr, remotePort)
        val connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)
        connection?.unwrapOutbound(synPacket.payload)

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
        assertEquals(TransportLayerConnection.TransportLayerState.CONNECTED, connection?.state)

        val messagesBeforeFin = deviceWriter.sentMessages.size

        // the device app closes its end gracefully with a FIN+ACK, not an abort
        val finPacket = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = localPort, remoteAddr = remoteAddr, remotePort = remotePort,
            seq = 1, ack = 1, payload = ByteArray(0), pshFlag = false, finFlag = true
        )
        connection?.unwrapOutbound(finPacket.payload)

        assertEquals(
            "expected exactly one new segment (the FIN-ACK) to be written back to the device",
            messagesBeforeFin + 1,
            deviceWriter.sentMessages.size
        )

        val newSegments = deviceWriter.sentMessages.drop(messagesBeforeFin).map { msg ->
            (msg.obj as IpPacket).payload as TcpPacket
        }
        assertFalse(
            "a graceful close must not also send an RST to the device",
            newSegments.any { it.header.rst }
        )
        assertTrue(
            "expected the new segment to be a FIN (the closing handshake's FIN-ACK)",
            newSegments.any { it.header.fin }
        )

        // the outward-facing channel is closed, but the closing handshake with the device isn't
        // done yet - the connection must stay CLOSING (and in the cache) until the device ACKs
        assertEquals(TransportLayerConnection.TransportLayerState.CLOSING, connection?.state)
        assertTrue(
            "connection should remain reachable via the cache until the device's final ACK arrives",
            ConnectionCache.findConnection(synPacket) === connection
        )

        // the device sends the final ACK, completing the closing handshake
        val finalAckPacket = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = localPort, remoteAddr = remoteAddr, remotePort = remotePort,
            seq = 2, ack = 2, payload = ByteArray(0), pshFlag = false
        )
        connection?.unwrapOutbound(finalAckPacket.payload)

        assertEquals(TransportLayerConnection.TransportLayerState.CLOSED, connection?.state)
        assertTrue(
            "connection must be removed from the cache once the closing handshake completes",
            ConnectionCache.findConnection(synPacket) == null
        )

        // a fresh SYN for the same flow must yield a brand-new connection, not the dead one
        val secondSynPacket = PacketFixtures.buildTcpSynPacket(localAddr, localPort, remoteAddr, remotePort, seq = 100)
        val secondConnection = TransportLayerConnection.getInstance(secondSynPacket, componentManager, deviceWriter.handler)
        assertNotSame(connection, secondConnection)

        secondConnection?.closeHard()
    }

    @Test
    fun `a retransmitted FIN while awaiting the closing ACK resends the FIN-ACK without re-closing or re-incrementing`() {
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
        val localPort = 41003
        val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
        val remotePort = serverSocket.localPort

        val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, localPort, remoteAddr, remotePort)
        val connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)
        connection?.unwrapOutbound(synPacket.payload)

        val handshakeDeadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < handshakeDeadline && deviceWriter.sentMessages.isEmpty()) {
            Thread.sleep(20)
        }

        val ackPacket = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = localPort, remoteAddr = remoteAddr, remotePort = remotePort,
            seq = 1, ack = 1, payload = ByteArray(0), pshFlag = false
        )
        connection?.unwrapOutbound(ackPacket.payload)

        val finPacket = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = localPort, remoteAddr = remoteAddr, remotePort = remotePort,
            seq = 1, ack = 1, payload = ByteArray(0), pshFlag = false, finFlag = true
        )
        connection?.unwrapOutbound(finPacket.payload)
        assertEquals(TransportLayerConnection.TransportLayerState.CLOSING, connection?.state)

        val firstFinAck = (deviceWriter.sentMessages.last().obj as IpPacket).payload as TcpPacket
        val messagesAfterFirstFin = deviceWriter.sentMessages.size

        // the device's TCP stack didn't see our FIN-ACK in time and retransmits its own FIN
        connection?.unwrapOutbound(finPacket.payload)

        assertEquals(
            "the retransmitted FIN should only cause a single resent FIN-ACK, not a fresh close",
            messagesAfterFirstFin + 1,
            deviceWriter.sentMessages.size
        )
        val resentFinAck = (deviceWriter.sentMessages.last().obj as IpPacket).payload as TcpPacket
        assertEquals(
            "the resent FIN-ACK must carry the same sequence number as the original - it must not double-increment",
            firstFinAck.header.sequenceNumberAsLong,
            resentFinAck.header.sequenceNumberAsLong
        )
        assertEquals(
            "the resent FIN-ACK must carry the same ack number as the original - it must not double-increment",
            firstFinAck.header.acknowledgmentNumberAsLong,
            resentFinAck.header.acknowledgmentNumberAsLong
        )
        assertEquals(TransportLayerConnection.TransportLayerState.CLOSING, connection?.state)
    }

    @Test
    fun `client-initiated RST tears down the connection without echoing an RST back`() {
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
        val localPort = 41002
        val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
        val remotePort = serverSocket.localPort

        val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, localPort, remoteAddr, remotePort)
        val connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)
        connection?.unwrapOutbound(synPacket.payload)

        val handshakeDeadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < handshakeDeadline && deviceWriter.sentMessages.isEmpty()) {
            Thread.sleep(20)
        }
        assertTrue("expected a SYN-ACK to be sent back to the device", deviceWriter.sentMessages.isNotEmpty())

        val ackPacket = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = localPort, remoteAddr = remoteAddr, remotePort = remotePort,
            seq = 1, ack = 1, payload = ByteArray(0), pshFlag = false
        )
        connection?.unwrapOutbound(ackPacket.payload)
        assertEquals(TransportLayerConnection.TransportLayerState.CONNECTED, connection?.state)

        val messagesBeforeRst = deviceWriter.sentMessages.size

        // the device app aborts the connection with an RST
        val rstPacket = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = localPort, remoteAddr = remoteAddr, remotePort = remotePort,
            seq = 1, ack = 1, payload = ByteArray(0), pshFlag = false, ackFlag = false, rstFlag = true
        )
        connection?.unwrapOutbound(rstPacket.payload)

        assertEquals(
            "the client already knows the connection is gone; nothing should be echoed back to it",
            messagesBeforeRst,
            deviceWriter.sentMessages.size
        )
        assertEquals(TransportLayerConnection.TransportLayerState.CLOSED, connection?.state)

        // the real peer socket should observe the close - proves the SocketChannel was actually released
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
