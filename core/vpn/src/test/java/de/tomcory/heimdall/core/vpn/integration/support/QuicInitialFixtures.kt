package de.tomcory.heimdall.core.vpn.integration.support

import de.tomcory.heimdall.core.vpn.quic.QuicInitialKeys
import de.tomcory.heimdall.core.vpn.quic.QuicInitialPacket
import de.tomcory.heimdall.core.vpn.quic.QuicVarInt
import java.io.ByteArrayOutputStream
import java.util.Random
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Builds protected QUIC Initial packets, the way a client would send them, for tests of the code
 * that takes them apart (docs/vpn-mitm-audit.md PKT-49). Validated by reproducing the sample
 * packets of RFC 9001 and RFC 9369 byte for byte (`QuicInitialPacketTest`).
 */
object QuicInitialFixtures {

    /** The size QUIC clients pad datagrams that carry an Initial to (RFC 9000 section 14.1). */
    const val MIN_DATAGRAM_SIZE = 1200

    private const val FRAME_PADDING: Byte = 0x00
    private const val FRAME_PING: Byte = 0x01
    private const val FRAME_CRYPTO: Byte = 0x06

    /**
     * Builds one Initial packet around [payload] and protects it.
     *
     * @param keys The keys to protect it with; derived from [destinationConnectionId] by default.
     * @param lengthFieldSize How many bytes the length field takes (RFC senders use 2).
     * @param packetType The long header packet type; another type than Initial (0-RTT,
     * Handshake) gives a packet for tests of skipping, protected with the same keys.
     */
    fun protectInitial(
        version: Int,
        destinationConnectionId: ByteArray,
        sourceConnectionId: ByteArray = ByteArray(0),
        token: ByteArray = ByteArray(0),
        packetNumber: Long,
        packetNumberLength: Int = 4,
        payload: ByteArray,
        keys: QuicInitialKeys = QuicInitialKeys.forClient(version, destinationConnectionId)!!,
        lengthFieldSize: Int = 2,
        packetType: Int = if (version == QuicInitialKeys.VERSION_2) 0b01 else 0b00
    ): ByteArray {
        val header = ByteArrayOutputStream()
        header.write(0xC0 or (packetType shl 4) or (packetNumberLength - 1))
        header.write(byteArrayOf((version ushr 24).toByte(), (version ushr 16).toByte(), (version ushr 8).toByte(), version.toByte()))
        header.write(destinationConnectionId.size)
        header.write(destinationConnectionId)
        header.write(sourceConnectionId.size)
        header.write(sourceConnectionId)
        val initialType = if (version == QuicInitialKeys.VERSION_2) 0b01 else 0b00
        if (packetType == initialType) {
            // only Initial packets have a token field
            header.write(QuicVarInt.encode(token.size.toLong()))
            header.write(token)
        }
        header.write(QuicVarInt.encode((packetNumberLength + payload.size + 16).toLong(), lengthFieldSize))
        val packetNumberOffset = header.size()
        for (i in packetNumberLength - 1 downTo 0) {
            header.write((packetNumber ushr (8 * i)).toInt() and 0xFF)
        }
        val unprotectedHeader = header.toByteArray()

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keys.key, "AES"), GCMParameterSpec(128, QuicInitialPacket.nonce(keys.iv, packetNumber)))
        cipher.updateAAD(unprotectedHeader)
        val sealed = cipher.doFinal(payload)

        val packet = unprotectedHeader + sealed
        val mask = QuicInitialPacket.headerProtectionMask(keys.hp, packet, packetNumberOffset + 4)
        packet[0] = (packet[0].toInt() xor (mask[0].toInt() and 0x0F)).toByte()
        for (i in 0 until packetNumberLength) {
            packet[packetNumberOffset + i] = (packet[packetNumberOffset + i].toInt() xor mask[1 + i].toInt()).toByte()
        }
        return packet
    }

    /** A CRYPTO frame carrying [data] at [offset] in the handshake stream. */
    fun cryptoFrame(offset: Long, data: ByteArray): ByteArray {
        return byteArrayOf(FRAME_CRYPTO) + QuicVarInt.encode(offset) + QuicVarInt.encode(data.size.toLong()) + data
    }

    /**
     * A client's first flight: [clientHello] (a bare handshake message) in CRYPTO frames, spread
     * over [datagrams] Initial packets, each padded to a datagram of [MIN_DATAGRAM_SIZE] bytes.
     *
     * @param shuffle Whether to split each datagram's share into several CRYPTO frames, send them
     * out of order and put PING frames between them, as Chrome does.
     */
    fun clientInitialDatagrams(
        clientHello: ByteArray,
        version: Int = QuicInitialKeys.VERSION_1,
        destinationConnectionId: ByteArray = RandomBytes.of(8, 1),
        sourceConnectionId: ByteArray = RandomBytes.of(8, 2),
        datagrams: Int = 1,
        shuffle: Boolean = false,
        seed: Long = 7
    ): List<ByteArray> {
        val random = Random(seed)
        val share = (clientHello.size + datagrams - 1) / datagrams
        return (0 until datagrams).map { index ->
            val from = index * share
            val to = minOf(clientHello.size, from + share)
            val frames = mutableListOf<ByteArray>()
            if (shuffle && to - from >= 3) {
                val cut1 = from + (to - from) / 3
                val cut2 = from + 2 * (to - from) / 3
                listOf(from to cut1, cut1 to cut2, cut2 to to).forEach { (a, b) ->
                    frames.add(cryptoFrame(a.toLong(), clientHello.copyOfRange(a, b)))
                }
                frames.shuffle(random)
                for (i in frames.size - 1 downTo 1) {
                    frames.add(i, byteArrayOf(FRAME_PING))
                }
            } else {
                frames.add(cryptoFrame(from.toLong(), clientHello.copyOfRange(from, to)))
            }
            val content = frames.fold(ByteArray(0)) { acc, frame -> acc + frame }
            // header without the payload: first byte, version, two connection IDs, token
            // length, 2-byte length field, 4-byte packet number; then the tag
            val overhead = 1 + 4 + 1 + destinationConnectionId.size + 1 + sourceConnectionId.size + 1 + 2 + 4 + 16
            val paddingLength = MIN_DATAGRAM_SIZE - overhead - content.size
            require(paddingLength >= 0) { "${content.size} bytes of frames do not fit into one datagram; use more datagrams" }
            protectInitial(
                version = version,
                destinationConnectionId = destinationConnectionId,
                sourceConnectionId = sourceConnectionId,
                packetNumber = index.toLong(),
                payload = content + ByteArray(paddingLength) { FRAME_PADDING }
            )
        }
    }

    /**
     * A ClientHello handshake message with a server name, an ALPN list and TLS 1.3 in
     * supported_versions, made [extraLength] bytes longer by a padding extension, as hybrid key
     * shares make real ones.
     */
    fun clientHello(sni: String?, alpn: List<String>, extraLength: Int = 0): ByteArray {
        val extensions = ByteArrayOutputStream()
        fun extension(type: Int, body: ByteArray) {
            extensions.write(u16(type))
            extensions.write(u16(body.size))
            extensions.write(body)
        }
        if (sni != null) {
            val name = sni.toByteArray(Charsets.US_ASCII)
            extension(0, u16(name.size + 3) + byteArrayOf(0) + u16(name.size) + name)
        }
        if (alpn.isNotEmpty()) {
            val list = alpn.fold(ByteArray(0)) { acc, protocol -> acc + byteArrayOf(protocol.length.toByte()) + protocol.toByteArray(Charsets.US_ASCII) }
            extension(16, u16(list.size) + list)
        }
        extension(43, byteArrayOf(2, 0x03, 0x04))
        if (extraLength > 0) {
            extension(21, ByteArray(extraLength))
        }

        val body = ByteArrayOutputStream()
        body.write(byteArrayOf(0x03, 0x03))         // legacy_version
        body.write(RandomBytes.of(32, 3))           // random
        body.write(0)                               // legacy_session_id
        body.write(u16(2) + byteArrayOf(0x13, 0x01)) // cipher_suites: TLS_AES_128_GCM_SHA256
        body.write(byteArrayOf(1, 0))               // legacy_compression_methods
        val extensionBytes = extensions.toByteArray()
        body.write(u16(extensionBytes.size))
        body.write(extensionBytes)
        val bodyBytes = body.toByteArray()
        return byteArrayOf(1, (bodyBytes.size ushr 16).toByte(), (bodyBytes.size ushr 8).toByte(), bodyBytes.size.toByte()) + bodyBytes
    }

    private fun u16(value: Int) = byteArrayOf((value ushr 8).toByte(), value.toByte())

    /** Deterministic pseudo-random bytes, so that fixtures are the same in every run. */
    object RandomBytes {
        fun of(size: Int, seed: Long): ByteArray = ByteArray(size).also { Random(seed).nextBytes(it) }
    }
}
