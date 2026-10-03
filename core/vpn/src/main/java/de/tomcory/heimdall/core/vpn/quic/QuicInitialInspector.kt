package de.tomcory.heimdall.core.vpn.quic

import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.ClientHelloInfo
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.ClientHelloParser
import java.util.BitSet

/**
 * Reads the ClientHello of one QUIC flow out of the client's Initial packets, without taking
 * part in the connection (docs/vpn-mitm-audit.md PKT-50). One instance per flow, fed with the
 * client's datagrams in the order they were sent, until it reaches a terminal [Result].
 *
 * What real clients do, and what this therefore has to handle:
 * - The ClientHello can be larger than one datagram (hybrid key shares), so CRYPTO frames are
 *   collected across datagrams by their offset in the handshake stream.
 * - Frames come in any order, with PING and PADDING between them (Chrome does this on purpose).
 * - Initials after the first may name another Destination Connection ID once the server has
 *   answered, but stay protected with the keys derived from the first one.
 * - After a Retry, the client derives new keys from the connection ID the server chose.
 *
 * Not thread-safe; a flow's datagrams all come from one thread.
 *
 * @param maxDatagrams How many datagrams to look at before giving up.
 * @param maxCryptoBytes How much of the handshake stream to hold before giving up.
 */
class QuicInitialInspector(
    private val maxDatagrams: Int = DEFAULT_MAX_DATAGRAMS,
    private val maxCryptoBytes: Int = DEFAULT_MAX_CRYPTO_BYTES
) {

    sealed class Result {
        /** More datagrams are needed. */
        object Pending : Result()

        /** The ClientHello is complete. */
        class Complete(val clientHello: ClientHelloInfo, val quicVersion: Int) : Result()

        /** The ClientHello cannot be read from this flow; the reason is for the log. */
        class GaveUp(val reason: String) : Result()
    }

    /** The outcome so far; once it is no longer [Result.Pending], it does not change. */
    var result: Result = Result.Pending
        private set

    private var datagrams = 0
    private var keys: QuicInitialKeys? = null
    private var firstConnectionId: ByteArray? = null
    private var version = 0

    // the handshake stream as far as it has arrived, and which of its bytes have
    private var stream: ByteArray? = null
    private val received = BitSet()

    /**
     * Takes in the next datagram the client sent. Never throws for any input.
     *
     * @return the outcome after this datagram, also available as [result].
     */
    fun offer(datagram: ByteArray): Result {
        if (result != Result.Pending) {
            return result
        }
        datagrams++
        result = inspect(datagram)
        if (result == Result.Pending && datagrams >= maxDatagrams) {
            result = Result.GaveUp("ClientHello incomplete after $datagrams datagrams")
        }
        return result
    }

    private fun inspect(datagram: ByteArray): Result {
        var offset = 0
        var decryptedAny = false
        while (offset < datagram.size) {
            var packet = QuicInitialPacket.decrypt(datagram, offset, keys)
            if (packet is QuicInitialPacket.Result.AuthenticationFailed && keys != null
                && !packet.destinationConnectionId.contentEquals(firstConnectionId)) {
                // after a Retry the client protects its Initials with keys derived from the
                // connection ID the server chose; try those once
                val retried = QuicInitialPacket.decrypt(datagram, offset)
                if (retried is QuicInitialPacket.Result.Decrypted) {
                    keys = QuicInitialKeys.forClient(retried.version, retried.destinationConnectionId)
                    firstConnectionId = retried.destinationConnectionId
                    packet = retried
                }
            }

            when (packet) {
                is QuicInitialPacket.Result.Decrypted -> {
                    if (keys == null) {
                        keys = QuicInitialKeys.forClient(packet.version, packet.destinationConnectionId)
                        firstConnectionId = packet.destinationConnectionId
                        version = packet.version
                    }
                    decryptedAny = true
                    readFrames(packet.payload)?.let { return it }
                    offset += packet.consumed
                }
                is QuicInitialPacket.Result.NotInitial -> offset += packet.consumed
                is QuicInitialPacket.Result.AuthenticationFailed -> offset += packet.consumed
                QuicInitialPacket.Result.UnknownVersion -> {
                    if (keys == null) {
                        return Result.GaveUp("unknown QUIC version")
                    }
                    // the layout of what follows is unknown, so the rest of the datagram is lost
                    break
                }
                QuicInitialPacket.Result.Malformed -> break
            }
        }
        if (keys == null && !decryptedAny) {
            return Result.GaveUp("the first datagram holds no Initial that can be decrypted")
        }
        return completeClientHello() ?: Result.Pending
    }

    /**
     * Collects the CRYPTO frames of one decrypted Initial packet.
     *
     * @return a terminal result if the packet ends the inspection, otherwise null.
     */
    private fun readFrames(payload: ByteArray): Result? {
        var position = 0
        while (position < payload.size) {
            when (val type = payload[position].toInt() and 0xFF) {
                FRAME_PADDING, FRAME_PING -> position++
                FRAME_ACK, FRAME_ACK_ECN -> {
                    // largest acknowledged, ACK delay, ACK range count, first ACK range, then
                    // two values per further range, and three ECN counts for type 0x03
                    val afterHeader = skipVarInts(payload, position + 1, 2) ?: return malformed()
                    val rangeCount = QuicVarInt.decode(payload, afterHeader)
                    if (rangeCount < 0 || rangeCount > payload.size) return malformed()
                    val remaining = 1 + 2 * rangeCount.toInt() + if (type == FRAME_ACK_ECN) 3 else 0
                    position = skipVarInts(payload, afterHeader + QuicVarInt.length(payload[afterHeader]), remaining)
                        ?: return malformed()
                }
                FRAME_CRYPTO -> {
                    position++
                    val offset = QuicVarInt.decode(payload, position)
                    if (offset < 0) return malformed()
                    position += QuicVarInt.length(payload[position])
                    val length = QuicVarInt.decode(payload, position)
                    if (length < 0) return malformed()
                    position += QuicVarInt.length(payload[position])
                    if (length > payload.size - position) return malformed()
                    if (offset + length > maxCryptoBytes) {
                        return Result.GaveUp("the handshake stream exceeds $maxCryptoBytes bytes")
                    }
                    val buffer = stream ?: ByteArray(maxCryptoBytes).also { stream = it }
                    System.arraycopy(payload, position, buffer, offset.toInt(), length.toInt())
                    received.set(offset.toInt(), (offset + length).toInt())
                    position += length.toInt()
                }
                FRAME_CONNECTION_CLOSE -> return Result.GaveUp("the client closed the connection")
                else -> return Result.GaveUp("unexpected frame type $type in an Initial packet")
            }
        }
        return null
    }

    /** The ClientHello, if the handshake stream holds all of it from its first byte. */
    private fun completeClientHello(): Result? {
        val buffer = stream ?: return null
        val contiguous = received.nextClearBit(0)
        if (contiguous < HANDSHAKE_HEADER_SIZE) {
            return null
        }
        if (buffer[0].toInt() != HANDSHAKE_TYPE_CLIENT_HELLO) {
            return Result.GaveUp("the handshake stream does not start with a ClientHello")
        }
        val messageLength = HANDSHAKE_HEADER_SIZE + (((buffer[1].toInt() and 0xFF) shl 16) or
                ((buffer[2].toInt() and 0xFF) shl 8) or (buffer[3].toInt() and 0xFF))
        if (messageLength > maxCryptoBytes) {
            return Result.GaveUp("the ClientHello is larger than $maxCryptoBytes bytes")
        }
        if (contiguous < messageLength) {
            return null
        }
        val clientHello = ClientHelloParser.parse(buffer.copyOf(messageLength))
        return if (clientHello == null || clientHello.truncated) {
            Result.GaveUp("the ClientHello is malformed")
        } else {
            Result.Complete(clientHello, version)
        }
    }

    private fun malformed() = Result.GaveUp("malformed frame in an Initial packet")

    /** The position after [count] variable-length integers from [start], or null if the data ends first. */
    private fun skipVarInts(data: ByteArray, start: Int, count: Int): Int? {
        var position = start
        repeat(count) {
            if (QuicVarInt.decode(data, position) < 0) return null
            position += QuicVarInt.length(data[position])
        }
        return position
    }

    companion object {
        const val DEFAULT_MAX_DATAGRAMS = 4
        const val DEFAULT_MAX_CRYPTO_BYTES = 16 * 1024

        // the frame types an Initial packet may carry (RFC 9000 section 12.4)
        private const val FRAME_PADDING = 0x00
        private const val FRAME_PING = 0x01
        private const val FRAME_ACK = 0x02
        private const val FRAME_ACK_ECN = 0x03
        private const val FRAME_CRYPTO = 0x06
        private const val FRAME_CONNECTION_CLOSE = 0x1c

        private const val HANDSHAKE_TYPE_CLIENT_HELLO = 1
        private const val HANDSHAKE_HEADER_SIZE = 4
    }
}
