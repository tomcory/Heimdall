package de.tomcory.heimdall.core.vpn.connection.transportLayer

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.TcpPacket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicReference

/**
 * Regression test for docs/vpn-mitm-audit.md PKT-01 (V-14): `TcpConnection.wrapInbound()`'s
 * split-payload loop used to advance the server-facing sequence number by the size of the
 * *entire* original payload on every iteration, instead of the size of the segment actually
 * written - inflating `ourSeqNum` by `(segmentCount - 1) * payload.size` for any inbound payload
 * larger than `maxPacketSize` (routine for MitM'd HTTPS response bodies).
 */
class TcpConnectionSequenceNumberTest {

    private lateinit var serverSocket: ServerSocket
    private lateinit var acceptThread: Thread
    private val acceptedSocket = AtomicReference<Socket?>(null)

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        serverSocket = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        acceptThread = Thread {
            try {
                acceptedSocket.set(serverSocket.accept())
            } catch (e: Exception) {
                // closed during teardown
            }
        }
        acceptThread.start()
    }

    @After
    fun teardown() {
        acceptedSocket.get()?.close()
        if (::serverSocket.isInitialized && !serverSocket.isClosed) serverSocket.close()
        if (::acceptThread.isInitialized) acceptThread.join(2000)
        ConnectionCache.closeAllAndClear()
    }

    @Test
    fun `wrapInbound advances the sequence number by each segment's actual size, not the whole payload`() {
        val maxPacketSize = 100
        val componentManager = ComponentManagerFixtures.buildTestComponentManager(
            keyStoreDir = createTempDir(),
            maxPacketSize = maxPacketSize
        )

        val deviceWriter = RecordingDeviceWriter()
        val localAddr = InetAddress.getByName("10.0.0.7") as Inet4Address
        val localPort = 41000
        val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
        val remotePort = serverSocket.localPort

        val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, localPort, remoteAddr, remotePort)
        val connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)
        assertTrue("expected a TcpConnection to be created", connection != null)

        // a payload well over maxPacketSize, forcing wrapInbound's split-payload loop (4 segments: 100+100+100+37)
        val payload = ByteArray(maxPacketSize * 3 + 37) { (it % 251).toByte() }
        connection!!.wrapInbound(payload)

        assertTrue(
            "expected multiple segments to be written back to the device",
            deviceWriter.sentMessages.size > 1
        )

        val tcpPackets = deviceWriter.sentMessages.map { msg ->
            (msg.obj as IpPacket).payload as TcpPacket
        }
        val sequenceNumbers = tcpPackets.map { it.header.sequenceNumberAsLong }
        val segmentSizes = tcpPackets.map { it.payload?.length() ?: 0 }

        assertEquals(
            "segment sizes should sum to the total payload size",
            payload.size,
            segmentSizes.sum()
        )

        // each subsequent segment's sequence number must advance by exactly the size of the
        // *previous* segment actually written, not by the whole original payload
        for (i in 1 until sequenceNumbers.size) {
            val expected = (sequenceNumbers[i - 1] + segmentSizes[i - 1]) and 0xFFFFFFFFL
            assertEquals(
                "sequence number after segment $i should advance by the previous segment's actual size",
                expected,
                sequenceNumbers[i]
            )
        }
    }
}
