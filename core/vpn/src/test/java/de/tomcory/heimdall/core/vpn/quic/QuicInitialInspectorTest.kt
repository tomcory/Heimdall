package de.tomcory.heimdall.core.vpn.quic

import de.tomcory.heimdall.core.vpn.integration.support.QuicInitialFixtures
import de.tomcory.heimdall.core.vpn.integration.support.QuicRfcVectors
import de.tomcory.heimdall.core.vpn.integration.support.QuicRfcVectors.bytes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

/** docs/vpn-mitm-audit.md PKT-50: reading the ClientHello of a QUIC flow from its Initial packets. */
class QuicInitialInspectorTest {

    private fun complete(result: QuicInitialInspector.Result): QuicInitialInspector.Result.Complete {
        assertTrue("expected a ClientHello, got ${(result as? QuicInitialInspector.Result.GaveUp)?.reason ?: result.javaClass.simpleName}",
            result is QuicInitialInspector.Result.Complete)
        return result as QuicInitialInspector.Result.Complete
    }

    private fun gaveUp(result: QuicInitialInspector.Result) {
        assertTrue("expected the inspector to give up, got ${result.javaClass.simpleName}", result is QuicInitialInspector.Result.GaveUp)
    }

    @Test
    fun `the RFC 9001 sample Initial yields its ClientHello`() {
        val result = complete(QuicInitialInspector().offer(bytes(QuicRfcVectors.V1.CLIENT_PROTECTED)))
        assertEquals("example.com", result.clientHello.sni)
        assertEquals(listOf("alpn"), result.clientHello.alpn)
        assertEquals(QuicInitialKeys.VERSION_1, result.quicVersion)
    }

    @Test
    fun `a ClientHello in one datagram, version 1 and version 2`() {
        val clientHello = QuicInitialFixtures.clientHello("one.example", listOf("h3"))
        for (version in listOf(QuicInitialKeys.VERSION_1, QuicInitialKeys.VERSION_2)) {
            val datagram = QuicInitialFixtures.clientInitialDatagrams(clientHello, version = version).single()
            val result = complete(QuicInitialInspector().offer(datagram))
            assertEquals("one.example", result.clientHello.sni)
            assertEquals(listOf("h3"), result.clientHello.alpn)
            assertEquals(version, result.quicVersion)
        }
    }

    @Test
    fun `a ClientHello over two datagrams, in order and shuffled`() {
        // as with hybrid key shares: well over one datagram
        val clientHello = QuicInitialFixtures.clientHello("two.example", listOf("h3", "h3-29"), extraLength = 1300)
        for (shuffle in listOf(false, true)) {
            val inspector = QuicInitialInspector()
            val flight = QuicInitialFixtures.clientInitialDatagrams(clientHello, datagrams = 2, shuffle = shuffle)
            assertSame(QuicInitialInspector.Result.Pending, inspector.offer(flight[0]))
            val result = complete(inspector.offer(flight[1]))
            assertEquals("two.example", result.clientHello.sni)
            assertEquals(listOf("h3", "h3-29"), result.clientHello.alpn)
        }
    }

    @Test
    fun `the second half of a ClientHello may come first`() {
        val clientHello = QuicInitialFixtures.clientHello("reversed.example", listOf("h3"), extraLength = 1300)
        val flight = QuicInitialFixtures.clientInitialDatagrams(clientHello, datagrams = 2, shuffle = true)
        val inspector = QuicInitialInspector()
        assertSame(QuicInitialInspector.Result.Pending, inspector.offer(flight[1]))
        assertEquals("reversed.example", complete(inspector.offer(flight[0])).clientHello.sni)
    }

    @Test
    fun `later Initials naming another connection ID keep the first keys`() {
        val clientHello = QuicInitialFixtures.clientHello("cid.example", listOf("h3"), extraLength = 1300)
        val first = QuicInitialFixtures.RandomBytes.of(8, 11)
        val serverChosen = QuicInitialFixtures.RandomBytes.of(8, 12)
        val keys = QuicInitialKeys.forClient(QuicInitialKeys.VERSION_1, first)!!
        val flight = QuicInitialFixtures.clientInitialDatagrams(clientHello, destinationConnectionId = first, datagrams = 2)
        // the second datagram names the server's connection ID but is protected with the first keys
        val half = clientHello.size / 2 + 1
        val frames = QuicInitialFixtures.cryptoFrame(half.toLong(), clientHello.copyOfRange(half, clientHello.size))
        val second = QuicInitialFixtures.protectInitial(
            version = QuicInitialKeys.VERSION_1, destinationConnectionId = serverChosen, packetNumber = 1,
            payload = frames + ByteArray(1100 - frames.size), keys = keys
        )
        val inspector = QuicInitialInspector()
        assertSame(QuicInitialInspector.Result.Pending, inspector.offer(flight[0]))
        assertEquals("cid.example", complete(inspector.offer(second)).clientHello.sni)
    }

    @Test
    fun `after a Retry the keys of the new connection ID are adopted`() {
        val clientHello = QuicInitialFixtures.clientHello("retry.example", listOf("h3"))
        val inspector = QuicInitialInspector()
        // the first Initial is cut short, so the ClientHello stays incomplete
        val firstHalf = QuicInitialFixtures.cryptoFrame(0, clientHello.copyOf(20))
        val first = QuicInitialFixtures.protectInitial(
            version = QuicInitialKeys.VERSION_1, destinationConnectionId = QuicInitialFixtures.RandomBytes.of(8, 21),
            packetNumber = 0, payload = firstHalf + ByteArray(1100)
        )
        assertSame(QuicInitialInspector.Result.Pending, inspector.offer(first))
        // after the Retry the client starts over, protected with keys from the server's connection ID
        val again = QuicInitialFixtures.clientInitialDatagrams(clientHello, destinationConnectionId = QuicInitialFixtures.RandomBytes.of(8, 22)).single()
        assertEquals("retry.example", complete(inspector.offer(again)).clientHello.sni)
    }

    @Test
    fun `ACK frames between CRYPTO frames are skipped`() {
        val clientHello = QuicInitialFixtures.clientHello("ack.example", listOf("h3"))
        val ack = bytes("02" + "05" + "00" + "01" + "00" + "01" + "00")   // largest 5, delay 0, 1 more range
        val ackEcn = bytes("03" + "02" + "00" + "00" + "00" + "01" + "02" + "03")
        val payload = ack + QuicInitialFixtures.cryptoFrame(0, clientHello) + ackEcn + ByteArray(800)
        val datagram = QuicInitialFixtures.protectInitial(
            version = QuicInitialKeys.VERSION_1, destinationConnectionId = QuicInitialFixtures.RandomBytes.of(8, 31),
            packetNumber = 3, payload = payload
        )
        assertEquals("ack.example", complete(QuicInitialInspector().offer(datagram)).clientHello.sni)
    }

    @Test
    fun `an unknown version, random bytes and a damaged Initial give up without throwing`() {
        val unknown = bytes(QuicRfcVectors.V1.CLIENT_PROTECTED).also { it[1] = 0x0a; it[2] = 0x0a; it[3] = 0x0a; it[4] = 0x0a }
        gaveUp(QuicInitialInspector().offer(unknown))

        val damaged = bytes(QuicRfcVectors.V1.CLIENT_PROTECTED).also { it[700] = (it[700].toInt() xor 0x40).toByte() }
        gaveUp(QuicInitialInspector().offer(damaged))

        val random = Random(5)
        repeat(500) {
            val inspector = QuicInitialInspector()
            repeat(3) { inspector.offer(ByteArray(random.nextInt(1500)).also { random.nextBytes(it) }) }
            assertTrue(inspector.result != QuicInitialInspector.Result.Pending)
        }
    }

    @Test
    fun `the inspector gives up after the datagram limit and stays terminal`() {
        val clientHello = QuicInitialFixtures.clientHello("limit.example", listOf("h3"), extraLength = 4000)
        val flight = QuicInitialFixtures.clientInitialDatagrams(clientHello, datagrams = 6)
        val inspector = QuicInitialInspector(maxDatagrams = 4)
        flight.take(3).forEach { assertSame(QuicInitialInspector.Result.Pending, inspector.offer(it)) }
        gaveUp(inspector.offer(flight[3]))
        // further datagrams change nothing
        val terminal = inspector.result
        assertSame(terminal, inspector.offer(flight[4]))
    }

    @Test
    fun `a handshake stream larger than the buffer gives up`() {
        val clientHello = QuicInitialFixtures.clientHello("big.example", listOf("h3"), extraLength = 3000)
        val flight = QuicInitialFixtures.clientInitialDatagrams(clientHello, datagrams = 4)
        val inspector = QuicInitialInspector(maxCryptoBytes = 2000)
        val results = flight.map { inspector.offer(it) }
        gaveUp(results.last())
    }
}
