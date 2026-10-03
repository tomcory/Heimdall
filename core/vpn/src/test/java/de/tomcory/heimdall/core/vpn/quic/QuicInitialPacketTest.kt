package de.tomcory.heimdall.core.vpn.quic

import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.ClientHelloParser
import de.tomcory.heimdall.core.vpn.integration.support.QuicInitialFixtures
import de.tomcory.heimdall.core.vpn.integration.support.QuicRfcVectors
import de.tomcory.heimdall.core.vpn.integration.support.QuicRfcVectors.bytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

/**
 * docs/vpn-mitm-audit.md PKT-49: removing the protection from QUIC Initial packets, checked
 * against the sample packets of RFC 9001 Appendix A and RFC 9369 Appendix A, and the test
 * fixture that builds such packets checked against the same samples.
 */
class QuicInitialPacketTest {

    private val dcid = bytes(QuicRfcVectors.DCID)

    private class Vectors(val version: Int, val clientCryptoFrame: String, val clientProtected: String, val serverPayload: String, val serverProtected: String)

    private val v1 = QuicRfcVectors.V1.let { Vectors(QuicInitialKeys.VERSION_1, it.CLIENT_CRYPTO_FRAME, it.CLIENT_PROTECTED, it.SERVER_PAYLOAD, it.SERVER_PROTECTED) }
    private val v2 = QuicRfcVectors.V2.let { Vectors(QuicInitialKeys.VERSION_2, it.CLIENT_CRYPTO_FRAME, it.CLIENT_PROTECTED, it.SERVER_PAYLOAD, it.SERVER_PROTECTED) }

    /** The client Initial's payload as the RFCs describe it: the CRYPTO frame, then PADDING. */
    private fun clientPayload(vectors: Vectors) = bytes(vectors.clientCryptoFrame).copyOf(QuicRfcVectors.CLIENT_PAYLOAD_LENGTH)

    private fun decrypted(result: QuicInitialPacket.Result): QuicInitialPacket.Result.Decrypted {
        assertTrue("expected a decrypted Initial, got ${result.javaClass.simpleName}", result is QuicInitialPacket.Result.Decrypted)
        return result as QuicInitialPacket.Result.Decrypted
    }

    private fun checkClientInitial(vectors: Vectors) {
        val datagram = bytes(vectors.clientProtected)
        assertEquals(1200, datagram.size)

        val packet = decrypted(QuicInitialPacket.decrypt(datagram))
        assertEquals(vectors.version, packet.version)
        assertArrayEquals(dcid, packet.destinationConnectionId)
        assertEquals(0, packet.sourceConnectionId.size)
        assertEquals(0, packet.token.size)
        assertEquals(QuicRfcVectors.CLIENT_PACKET_NUMBER, packet.packetNumber)
        assertEquals(1200, packet.consumed)
        assertArrayEquals(clientPayload(vectors), packet.payload)

        // the CRYPTO frame (type 0x06, offset 0, a 2-byte length) holds the ClientHello
        val clientHello = ClientHelloParser.parse(packet.payload, 4)!!
        assertEquals("example.com", clientHello.sni)
        assertEquals(listOf("alpn"), clientHello.alpn)
    }

    private fun checkServerInitial(vectors: Vectors) {
        val datagram = bytes(vectors.serverProtected)
        val serverKeys = QuicInitialKeys.forServer(vectors.version, dcid)!!

        val packet = decrypted(QuicInitialPacket.decrypt(datagram, keys = serverKeys))
        assertEquals(0, packet.destinationConnectionId.size)
        assertArrayEquals(bytes(QuicRfcVectors.SERVER_SCID), packet.sourceConnectionId)
        assertEquals(QuicRfcVectors.SERVER_PACKET_NUMBER, packet.packetNumber)
        assertEquals(datagram.size, packet.consumed)
        assertArrayEquals(bytes(vectors.serverPayload), packet.payload)
    }

    @Test
    fun `the client Initial of RFC 9001 decrypts to the listed payload`() = checkClientInitial(v1)

    @Test
    fun `the client Initial of RFC 9369 decrypts to the listed payload`() = checkClientInitial(v2)

    @Test
    fun `the server Initials of both RFCs decrypt with the server keys`() {
        // a 2-byte packet number, an empty Destination and a non-empty Source Connection ID
        checkServerInitial(v1)
        checkServerInitial(v2)
    }

    @Test
    fun `the fixture reproduces the sample packets of both RFCs byte for byte`() {
        for (vectors in listOf(v1, v2)) {
            val client = QuicInitialFixtures.protectInitial(
                version = vectors.version,
                destinationConnectionId = dcid,
                packetNumber = QuicRfcVectors.CLIENT_PACKET_NUMBER,
                packetNumberLength = 4,
                payload = clientPayload(vectors)
            )
            assertArrayEquals("client Initial, version ${vectors.version}", bytes(vectors.clientProtected), client)

            val server = QuicInitialFixtures.protectInitial(
                version = vectors.version,
                destinationConnectionId = ByteArray(0),
                sourceConnectionId = bytes(QuicRfcVectors.SERVER_SCID),
                packetNumber = QuicRfcVectors.SERVER_PACKET_NUMBER,
                packetNumberLength = 2,
                payload = bytes(vectors.serverPayload),
                keys = QuicInitialKeys.forServer(vectors.version, dcid)!!
            )
            assertArrayEquals("server Initial, version ${vectors.version}", bytes(vectors.serverProtected), server)
        }
    }

    @Test
    fun `a changed ciphertext byte fails authentication`() {
        val datagram = bytes(v1.clientProtected)
        datagram[600] = (datagram[600].toInt() xor 0x01).toByte()

        val result = QuicInitialPacket.decrypt(datagram)
        assertTrue(result is QuicInitialPacket.Result.AuthenticationFailed)
        result as QuicInitialPacket.Result.AuthenticationFailed
        assertArrayEquals("the caller learns which connection ID the packet names", dcid, result.destinationConnectionId)
        assertEquals(1200, result.consumed)
    }

    @Test
    fun `keys for another connection ID fail authentication`() {
        val otherKeys = QuicInitialKeys.forClient(QuicInitialKeys.VERSION_1, bytes("0011223344556677"))!!
        assertTrue(QuicInitialPacket.decrypt(bytes(v1.clientProtected), keys = otherKeys) is QuicInitialPacket.Result.AuthenticationFailed)
    }

    @Test
    fun `a truncated packet is malformed`() {
        val datagram = bytes(v1.clientProtected)
        // cut inside the header, and after the header but before the end the length field states
        for (size in listOf(1, 6, 10, 18, 30, 600)) {
            val result = QuicInitialPacket.decrypt(datagram.copyOf(size))
            assertTrue("$size bytes: ${result.javaClass.simpleName}", result is QuicInitialPacket.Result.Malformed)
        }
    }

    @Test
    fun `other packet types are skipped and unknown versions are reported`() {
        val keys = QuicInitialKeys.forClient(QuicInitialKeys.VERSION_1, dcid)!!
        val initial = bytes(v1.clientProtected)

        // an Initial followed by a Handshake packet (type 2) and a short header packet
        val handshake = QuicInitialFixtures.protectInitial(
            version = QuicInitialKeys.VERSION_1, destinationConnectionId = dcid, packetNumber = 0,
            payload = ByteArray(40), keys = keys, packetType = 0b10
        )
        val shortHeader = byteArrayOf(0x41) + ByteArray(30)
        val datagram = initial + handshake + shortHeader

        val first = decrypted(QuicInitialPacket.decrypt(datagram, 0))
        val second = QuicInitialPacket.decrypt(datagram, first.consumed)
        assertTrue(second is QuicInitialPacket.Result.NotInitial)
        assertEquals(handshake.size, (second as QuicInitialPacket.Result.NotInitial).consumed)
        val third = QuicInitialPacket.decrypt(datagram, first.consumed + second.consumed)
        assertEquals(shortHeader.size, (third as QuicInitialPacket.Result.NotInitial).consumed)

        // Retry (type 3 in version 1) has no length field and takes the rest
        val retry = byteArrayOf(0xF0.toByte(), 0, 0, 0, 1, 8) + dcid + byteArrayOf(0) + ByteArray(40)
        assertEquals(retry.size, (QuicInitialPacket.decrypt(retry) as QuicInitialPacket.Result.NotInitial).consumed)

        // Version Negotiation (version 0) takes the rest
        val versionNegotiation = byteArrayOf(0xC0.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
        assertEquals(versionNegotiation.size, (QuicInitialPacket.decrypt(versionNegotiation) as QuicInitialPacket.Result.NotInitial).consumed)

        // a version without known keys
        val unknown = initial.copyOf()
        unknown[1] = 0x0a; unknown[2] = 0x0a; unknown[3] = 0x0a; unknown[4] = 0x0a
        assertTrue(QuicInitialPacket.decrypt(unknown) is QuicInitialPacket.Result.UnknownVersion)
    }

    @Test
    fun `arbitrary input never throws`() {
        val random = Random(42)
        val base = bytes(v1.clientProtected)
        repeat(2000) { round ->
            val data = if (round % 2 == 0) {
                ByteArray(random.nextInt(1300)).also { random.nextBytes(it) }
            } else {
                // a real packet with a few bytes of its header and length fields changed
                base.copyOf().also { for (i in 0 until 3) it[random.nextInt(25)] = random.nextInt(256).toByte() }
            }
            QuicInitialPacket.decrypt(data, if (data.isEmpty()) 0 else random.nextInt(data.size))
        }
    }

    @Test
    fun `fixture flights decrypt to CRYPTO frames that rebuild the ClientHello`() {
        val clientHello = QuicInitialFixtures.clientHello("www.example.org", listOf("h3"), extraLength = 1500)
        for ((datagrams, shuffle) in listOf(1 to false, 2 to false, 2 to true, 3 to true)) {
            if (datagrams == 1 && clientHello.size > 1100) continue
            val flight = QuicInitialFixtures.clientInitialDatagrams(clientHello, datagrams = datagrams, shuffle = shuffle)
            assertTrue(flight.all { it.size == QuicInitialFixtures.MIN_DATAGRAM_SIZE })

            val keys = QuicInitialKeys.forClient(QuicInitialKeys.VERSION_1, QuicInitialFixtures.RandomBytes.of(8, 1))!!
            val stream = ByteArray(clientHello.size)
            var received = 0
            for (datagram in flight) {
                val payload = decrypted(QuicInitialPacket.decrypt(datagram, keys = keys)).payload
                var position = 0
                while (position < payload.size) {
                    when (payload[position].toInt()) {
                        0x00, 0x01 -> position++ // PADDING, PING
                        0x06 -> {
                            position++
                            val offset = QuicVarInt.decode(payload, position).toInt()
                            position += QuicVarInt.length(payload[position])
                            val length = QuicVarInt.decode(payload, position).toInt()
                            position += QuicVarInt.length(payload[position])
                            System.arraycopy(payload, position, stream, offset, length)
                            received += length
                            position += length
                        }
                        else -> throw AssertionError("unexpected frame type ${payload[position]}")
                    }
                }
            }
            assertEquals("$datagrams datagrams, shuffled: $shuffle", clientHello.size, received)
            assertArrayEquals(clientHello, stream)
            val parsed = ClientHelloParser.parse(stream)!!
            assertEquals("www.example.org", parsed.sni)
            assertEquals(listOf("h3"), parsed.alpn)
        }

        // a ClientHello that fits into one datagram
        val small = QuicInitialFixtures.clientHello("small.example", listOf("h3", "h3-29"))
        val one = QuicInitialFixtures.clientInitialDatagrams(small, version = QuicInitialKeys.VERSION_2).single()
        val packet = decrypted(QuicInitialPacket.decrypt(one))
        assertEquals(QuicInitialKeys.VERSION_2, packet.version)
        assertEquals(listOf("h3", "h3-29"), ClientHelloParser.parse(packet.payload, 4)!!.alpn)
    }
}
