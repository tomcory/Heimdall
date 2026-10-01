package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import java.util.concurrent.atomic.AtomicInteger
import org.pcap4j.packet.Packet
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.components.DeviceWriteThread
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TcpConnection
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
import java.nio.channels.SocketChannel
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
    fun `graceful FIN close is ACKed, then completed with a FIN-ACK once the remote closes, never an RST`() {
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

        // docs/vpn-mitm-audit.md PKT-30: the FIN only ends the device's sending side. It is
        // ACKed, and the connection stays open for whatever the remote host still sends.
        assertEquals(
            "expected exactly one new segment (the ACK for the FIN) to be written back to the device",
            messagesBeforeFin + 1,
            deviceWriter.sentMessages.size
        )
        val finAck = (deviceWriter.sentMessages.last().obj as IpPacket).payload as TcpPacket
        assertTrue("the device's FIN must be acknowledged", finAck.header.ack)
        assertFalse("our own FIN must wait until the remote host closes", finAck.header.fin)
        assertEquals(TransportLayerConnection.TransportLayerState.HALF_CLOSED, connection?.state)

        // the remote host sees the end of the request stream and closes its side
        closeAcceptedSocket()
        awaitState(connection, TransportLayerConnection.TransportLayerState.CLOSING)

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

        // an ACK that doesn't cover our FIN (e.g. one for earlier data that was still in flight)
        // must not be mistaken for the end of the handshake (docs/vpn-mitm-audit.md PKT-35)
        val ourFin = newSegments.last { it.header.fin }
        val staleAckPacket = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = localPort, remoteAddr = remoteAddr, remotePort = remotePort,
            seq = 2, ack = ourFin.header.sequenceNumber, payload = ByteArray(0), pshFlag = false
        )
        connection?.unwrapOutbound(staleAckPacket.payload)
        assertEquals(TransportLayerConnection.TransportLayerState.CLOSING, connection?.state)

        // the device acknowledges our FIN, completing the closing handshake
        val finalAckPacket = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = localPort, remoteAddr = remoteAddr, remotePort = remotePort,
            seq = 2, ack = ourFin.header.sequenceNumber + 1, payload = ByteArray(0), pshFlag = false
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
        assertEquals(TransportLayerConnection.TransportLayerState.HALF_CLOSED, connection?.state)

        // the remote host closes too, which makes us send our FIN-ACK and wait for the final ACK
        closeAcceptedSocket()
        awaitState(connection, TransportLayerConnection.TransportLayerState.CLOSING)

        val firstFinAck = (deviceWriter.sentMessages.last().obj as IpPacket).payload as TcpPacket
        assertTrue(firstFinAck.header.fin)
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

    @Test
    fun `remote-initiated close releases the socket channel, not just the selection key`() {
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
        val localPort = 41004
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

        val acceptDeadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < acceptDeadline && acceptedSocket.get() == null) {
            Thread.sleep(20)
        }
        val peerSocket = acceptedSocket.get()
        assertTrue("server never accepted the connection", peerSocket != null)

        // selectableChannel is `protected` on TcpConnection, so it's read via reflection here
        val channelField = TcpConnection::class.java.getDeclaredField("selectableChannel")
        channelField.isAccessible = true
        fun isChannelOpen() = (channelField.get(connection) as SocketChannel).isOpen

        assertTrue("expected the channel to be open right after the handshake", isChannelOpen())

        // the remote server closes its side first (no FIN from the device involved at all) - the
        // selector should observe EOF on the local channel and the connection should release it,
        // not just deregister the SelectionKey
        peerSocket!!.close()

        val closedDeadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < closedDeadline && isChannelOpen()) {
            Thread.sleep(20)
        }
        assertFalse(
            "expected the local SocketChannel to be closed (fd released) after the remote side closed, not just deregistered from the selector",
            isChannelOpen()
        )

        // the connection should have started its own local closing handshake with the device
        assertEquals(TransportLayerConnection.TransportLayerState.CLOSING, connection?.state)
    }

    @Test
    fun `ACK for an unknown flow is answered with a stray RST using WRITE_STRAY`() {
        // docs/vpn-mitm-audit.md PKT-21 (V-33): this path used to post the RST with an undeclared magic code 6
        val componentManager = ComponentManagerFixtures.buildTestComponentManager(keyStoreDir = createTempDir())
        val deviceWriter = RecordingDeviceWriter()
        val localAddr = InetAddress.getByName("10.0.0.7") as Inet4Address
        val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address

        // a bare ACK with no preceding SYN - no connection exists for this flow
        val ackPacket = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = 41500, remoteAddr = remoteAddr, remotePort = 443,
            seq = 1, ack = 1, payload = ByteArray(0), pshFlag = false
        )
        val connection = TransportLayerConnection.getInstance(ackPacket, componentManager, deviceWriter.handler)

        assertEquals("no connection should be created for an unknown flow", null, connection)
        assertEquals(1, deviceWriter.sentMessages.size)
        val message = deviceWriter.sentMessages[0]
        assertEquals(DeviceWriteThread.WRITE_STRAY, message.what)
        val tcp = (message.obj as IpPacket).payload as TcpPacket
        assertTrue("stray reply should be an RST", tcp.header.rst)
    }

    // ---- docs/vpn-mitm-audit.md PKT-22: client-closed notification to the encryption layer ----

    /** Waits for the fake server to accept the connection, then closes it from the remote side. */
    private fun closeAcceptedSocket() {
        val deadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < deadline && acceptedSocket.get() == null) {
            Thread.sleep(20)
        }
        acceptedSocket.get()!!.close()
    }

    private fun awaitState(connection: TransportLayerConnection?, expected: TransportLayerConnection.TransportLayerState) {
        val deadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < deadline && connection?.state != expected) {
            Thread.sleep(20)
        }
        assertEquals(expected, connection?.state)
    }

    /** Encryption layer stand-in that only counts [onClientClosed] calls. */
    private class RecordingEncryptionLayer(
        transportLayer: TransportLayerConnection,
        componentManager: ComponentManager
    ) : EncryptionLayerConnection(0, transportLayer, componentManager) {
        override val protocol = "TEST"
        val clientClosedCalls = AtomicInteger(0)
        override fun onClientClosed() { clientClosedCalls.incrementAndGet() }
        override fun unwrapOutbound(payload: ByteArray) {}
        override fun unwrapOutbound(packet: Packet) {}
        override fun unwrapInbound(payload: ByteArray) {}
        override fun wrapOutbound(payload: ByteArray) {}
        override fun wrapInbound(payload: ByteArray) {}
    }

    private class EstablishedFlow(
        val connection: TransportLayerConnection,
        val deviceWriter: RecordingDeviceWriter,
        val recorder: RecordingEncryptionLayer,
        val localAddr: Inet4Address,
        val localPort: Int,
        val remoteAddr: Inet4Address,
        val remotePort: Int
    ) {
        fun sendFromDevice(finFlag: Boolean = false, rstFlag: Boolean = false, seq: Int = 1, ack: Int = 1) {
            val packet = PacketFixtures.buildTcpDataPacket(
                localAddr = localAddr, localPort = localPort, remoteAddr = remoteAddr, remotePort = remotePort,
                seq = seq, ack = ack, payload = ByteArray(0), pshFlag = false,
                ackFlag = !rstFlag, finFlag = finFlag, rstFlag = rstFlag
            )
            connection.unwrapOutbound(packet.payload)
        }
    }

    /**
     * Opens a CONNECTED TCP flow to [serverSocket] and installs a [RecordingEncryptionLayer] in
     * place of the lazily-created real one (reflection, since the field is private to the transport layer).
     */
    private fun establishFlowWithRecorder(localPort: Int): EstablishedFlow {
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
        val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
        val remotePort = serverSocket.localPort

        val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, localPort, remoteAddr, remotePort)
        val connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)!!
        connection.unwrapOutbound(synPacket.payload)

        val handshakeDeadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < handshakeDeadline && deviceWriter.sentMessages.isEmpty()) {
            Thread.sleep(20)
        }
        assertTrue("expected a SYN-ACK to be sent back to the device", deviceWriter.sentMessages.isNotEmpty())

        val flow = EstablishedFlow(
            connection, deviceWriter, RecordingEncryptionLayer(connection, componentManager),
            localAddr, localPort, remoteAddr, remotePort
        )
        flow.sendFromDevice() // bare ACK completes the local handshake
        assertEquals(TransportLayerConnection.TransportLayerState.CONNECTED, connection.state)

        val field = TransportLayerConnection::class.java.getDeclaredField("encryptionLayer")
        field.isAccessible = true
        field.set(connection, flow.recorder)
        return flow
    }

    @Test
    fun `device FIN notifies the encryption layer exactly once`() {
        val flow = establishFlowWithRecorder(localPort = 41600)

        flow.sendFromDevice(finFlag = true)
        // a retransmitted FIN while CLOSING must not notify again
        flow.sendFromDevice(finFlag = true)

        assertEquals(1, flow.recorder.clientClosedCalls.get())
    }

    @Test
    fun `device RST notifies the encryption layer exactly once`() {
        val flow = establishFlowWithRecorder(localPort = 41601)

        flow.sendFromDevice(rstFlag = true)

        assertEquals(1, flow.recorder.clientClosedCalls.get())
    }

    @Test
    fun `remote close does not notify the encryption layer`() {
        val flow = establishFlowWithRecorder(localPort = 41602)

        // wait for the server to accept, then close it from the remote side
        val acceptDeadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < acceptDeadline && acceptedSocket.get() == null) {
            Thread.sleep(20)
        }
        val messagesBeforeClose = flow.deviceWriter.sentMessages.size
        acceptedSocket.get()!!.close()

        // the remote EOF makes the transport send its own FIN to the device and move to CLOSING
        val finDeadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < finDeadline &&
            flow.connection.state != TransportLayerConnection.TransportLayerState.CLOSING) {
            Thread.sleep(20)
        }
        assertEquals(TransportLayerConnection.TransportLayerState.CLOSING, flow.connection.state)
        assertTrue(flow.deviceWriter.sentMessages.size > messagesBeforeClose)

        // the device answering that close (FIN-ACK), or resetting after it, is not the client giving up
        flow.sendFromDevice(finFlag = true)
        flow.sendFromDevice(rstFlag = true)

        assertEquals(0, flow.recorder.clientClosedCalls.get())
    }

    // -----------------------------------------------------------------------
    // docs/vpn-mitm-audit.md PKT-35 (V-47): the remote-initiated close
    // -----------------------------------------------------------------------

    /** Closes the fake server's side and returns the segment our transport sends to the device in response. */
    private fun remoteCloses(flow: EstablishedFlow): TcpPacket {
        val before = flow.deviceWriter.sentMessages.size
        closeAcceptedSocket()
        awaitState(flow.connection, TransportLayerConnection.TransportLayerState.CLOSING)
        val deadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < deadline && flow.deviceWriter.sentMessages.size == before) {
            Thread.sleep(20)
        }
        assertEquals("a remote close must produce exactly one segment", before + 1, flow.deviceWriter.sentMessages.size)
        return (flow.deviceWriter.sentMessages.last().obj as IpPacket).payload as TcpPacket
    }

    private fun lastSegment(flow: EstablishedFlow) = (flow.deviceWriter.sentMessages.last().obj as IpPacket).payload as TcpPacket

    private fun isCached(flow: EstablishedFlow): Boolean {
        val syn = PacketFixtures.buildTcpSynPacket(flow.localAddr, flow.localPort, flow.remoteAddr, flow.remotePort)
        return ConnectionCache.findConnection(syn) === flow.connection
    }

    @Test
    fun `remote close is announced with a FIN that carries the ACK flag`() {
        val flow = establishFlowWithRecorder(localPort = 41700)

        val fin = remoteCloses(flow)

        // a segment of an established connection without ACK is discarded by the device, which
        // then never learns that the remote host is done
        assertTrue("expected a FIN", fin.header.fin)
        assertTrue("the FIN must carry the ACK flag", fin.header.ack)
        assertFalse(fin.header.rst)
    }

    @Test
    fun `after a remote close the handshake completes with the device's ACK and FIN`() {
        val flow = establishFlowWithRecorder(localPort = 41701)
        val fin = remoteCloses(flow)
        val coversOurFin = fin.header.sequenceNumber + 1

        // the device acknowledges our FIN but keeps its own side open for now
        flow.sendFromDevice(seq = 1, ack = coversOurFin)
        assertEquals(TransportLayerConnection.TransportLayerState.CLOSING, flow.connection.state)
        assertTrue("the connection must stay cached until the device has closed too", isCached(flow))

        // the app closes its socket: the device sends its FIN
        val messagesBeforeFin = flow.deviceWriter.sentMessages.size
        flow.sendFromDevice(finFlag = true, seq = 1, ack = coversOurFin)

        assertEquals("the device's FIN must be acknowledged with one segment", messagesBeforeFin + 1, flow.deviceWriter.sentMessages.size)
        val ack = lastSegment(flow)
        assertTrue(ack.header.ack)
        assertFalse("our FIN must not be sent a second time", ack.header.fin)
        assertFalse(ack.header.rst)
        assertEquals("the ACK must cover the device's FIN", 2, ack.header.acknowledgmentNumber)
        assertEquals(TransportLayerConnection.TransportLayerState.CLOSED, flow.connection.state)
        assertFalse(isCached(flow))
    }

    @Test
    fun `an ACK for earlier data does not complete the close`() {
        val flow = establishFlowWithRecorder(localPort = 41702)
        val fin = remoteCloses(flow)

        // acknowledges everything before our FIN, but not the FIN itself
        flow.sendFromDevice(seq = 1, ack = fin.header.sequenceNumber)
        flow.sendFromDevice(finFlag = true, seq = 1, ack = fin.header.sequenceNumber)

        // the device's FIN is acknowledged, but ours is still outstanding
        assertEquals(2, lastSegment(flow).header.acknowledgmentNumber)
        assertEquals(TransportLayerConnection.TransportLayerState.CLOSING, flow.connection.state)
        assertTrue(isCached(flow))

        flow.sendFromDevice(seq = 2, ack = fin.header.sequenceNumber + 1)

        assertEquals(TransportLayerConnection.TransportLayerState.CLOSED, flow.connection.state)
        assertFalse(isCached(flow))
    }

    @Test
    fun `a closing connection the device never finishes is dropped by the sweep without a reset`() {
        val flow = establishFlowWithRecorder(localPort = 41703)
        remoteCloses(flow)
        val messagesBefore = flow.deviceWriter.sentMessages.size

        TcpConnection.sweepStaleConnections(now = System.currentTimeMillis() + 1_000)
        assertTrue("a connection that only just started closing must be kept", isCached(flow))

        TcpConnection.sweepStaleConnections(now = System.currentTimeMillis() + TcpConnection.DEFAULT_CLOSING_TIMEOUT_MS + 1_000)

        assertFalse(isCached(flow))
        assertEquals("the device's side is not reset: the app may simply not have closed yet", messagesBefore, flow.deviceWriter.sentMessages.size)
    }
}
