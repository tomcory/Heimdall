package de.tomcory.heimdall.core.vpn.quic

import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Removes the protection from QUIC Initial packets (RFC 9000 section 17.2.2, RFC 9001
 * sections 5.3 and 5.4; RFC 9369 for version 2), so that the ClientHello they carry can be read
 * (docs/vpn-mitm-audit.md PKT-49).
 *
 * A datagram may hold several QUIC packets back to back (coalesced, RFC 9000 section 12.2).
 * [decrypt] handles the packet at one offset and reports how many bytes it took, so a caller can
 * walk through the datagram.
 *
 * Nothing here throws: whatever the input, the outcome is a [Result].
 */
object QuicInitialPacket {

    /** The largest connection ID that QUIC versions 1 and 2 allow (RFC 9000 section 17.2). */
    private const val MAX_CONNECTION_ID_LENGTH = 20

    /** The number of ciphertext bytes sampled for header protection. */
    private const val SAMPLE_LENGTH = 16

    /** The length of the AES-GCM authentication tag. */
    private const val TAG_LENGTH = 16

    sealed class Result {
        /**
         * An Initial packet whose protection was removed.
         *
         * @property payload The frames the packet carries.
         * @property consumed How many bytes of the datagram, from the offset given, the packet took.
         */
        class Decrypted(
            val version: Int,
            val destinationConnectionId: ByteArray,
            val sourceConnectionId: ByteArray,
            val token: ByteArray,
            val packetNumber: Long,
            val payload: ByteArray,
            val consumed: Int
        ) : Result()

        /**
         * A packet of a known version that is not an Initial (0-RTT, Handshake, Retry, a short
         * header packet, or Version Negotiation), to be skipped.
         *
         * @property consumed How many bytes to skip to reach the next packet; for packet types
         * without a length field, the rest of the datagram.
         */
        class NotInitial(val consumed: Int) : Result()

        /** A long header packet of a version whose Initial keys are not known. Its layout is unknown too, so nothing after it can be read. */
        object UnknownVersion : Result()

        /**
         * An Initial whose authentication tag did not match: the keys were wrong (for example
         * derived from another connection ID) or the packet was altered.
         *
         * @property destinationConnectionId The packet's Destination Connection ID, so that a
         * caller can try keys derived from it.
         */
        class AuthenticationFailed(val destinationConnectionId: ByteArray, val consumed: Int) : Result()

        /** Not a well-formed packet. */
        object Malformed : Result()
    }

    /**
     * Removes the protection from the packet at [offset] in [datagram].
     *
     * @param keys The keys to use. If null, they are derived from the packet's own Destination
     * Connection ID, which is right for the first Initial of a connection.
     */
    fun decrypt(datagram: ByteArray, offset: Int = 0, keys: QuicInitialKeys? = null): Result {
        return try {
            decryptOrThrow(datagram, offset, keys)
        } catch (e: Exception) {
            Result.Malformed
        }
    }

    private fun decryptOrThrow(datagram: ByteArray, offset: Int, keys: QuicInitialKeys?): Result {
        if (offset < 0 || offset >= datagram.size) {
            return Result.Malformed
        }
        val rest = datagram.size - offset
        val firstByte = datagram[offset].toInt() and 0xFF
        if (firstByte and 0x80 == 0) {
            // a short header packet has no length field and is always last in a datagram
            return Result.NotInitial(rest)
        }
        if (rest < 7) {
            return Result.Malformed
        }

        var position = offset + 1
        val version = readInt(datagram, position)
        position += 4
        if (version == 0) {
            // Version Negotiation, which takes the rest of the datagram
            return Result.NotInitial(rest)
        }
        if (!QuicInitialKeys.isSupported(version)) {
            return Result.UnknownVersion
        }

        val destinationConnectionId = readConnectionId(datagram, position) ?: return Result.Malformed
        position += 1 + destinationConnectionId.size
        val sourceConnectionId = readConnectionId(datagram, position) ?: return Result.Malformed
        position += 1 + sourceConnectionId.size

        // QUIC version 2 renumbered the long header packet types (RFC 9369 section 3.2)
        val packetType = (firstByte and 0x30) ushr 4
        val (initialType, retryType) = if (version == QuicInitialKeys.VERSION_2) 0b01 to 0b00 else 0b00 to 0b11
        if (packetType == retryType) {
            // a Retry packet has no length field
            return Result.NotInitial(rest)
        }

        var token = ByteArray(0)
        if (packetType == initialType) {
            val tokenLength = QuicVarInt.decode(datagram, position)
            if (tokenLength < 0) {
                return Result.Malformed
            }
            position += QuicVarInt.length(datagram[position])
            if (tokenLength > datagram.size - position) {
                return Result.Malformed
            }
            token = datagram.copyOfRange(position, position + tokenLength.toInt())
            position += tokenLength.toInt()
        }

        val length = QuicVarInt.decode(datagram, position)
        if (length < 0) {
            return Result.Malformed
        }
        position += QuicVarInt.length(datagram[position])
        val packetNumberOffset = position
        if (length > datagram.size - packetNumberOffset) {
            return Result.Malformed
        }
        val end = packetNumberOffset + length.toInt()
        val consumed = end - offset

        if (packetType != initialType) {
            // 0-RTT or Handshake: skip it
            return Result.NotInitial(consumed)
        }

        // header protection: the sample starts 4 bytes after the start of the packet number,
        // as if the packet number were 4 bytes long (RFC 9001 section 5.4.2)
        val sampleOffset = packetNumberOffset + 4
        if (sampleOffset + SAMPLE_LENGTH > end) {
            return Result.Malformed
        }
        val packetKeys = keys ?: QuicInitialKeys.forClient(version, destinationConnectionId) ?: return Result.UnknownVersion
        val mask = headerProtectionMask(packetKeys.hp, datagram, sampleOffset)

        val unprotectedFirstByte = firstByte xor (mask[0].toInt() and 0x0F)
        val packetNumberLength = (unprotectedFirstByte and 0x03) + 1
        if (packetNumberOffset + packetNumberLength + TAG_LENGTH > end) {
            return Result.Malformed
        }

        // the header as it was before protection is the AEAD's associated data
        val header = datagram.copyOfRange(offset, packetNumberOffset + packetNumberLength)
        header[0] = unprotectedFirstByte.toByte()
        var packetNumber = 0L
        for (i in 0 until packetNumberLength) {
            val headerIndex = packetNumberOffset - offset + i
            val unmasked = (header[headerIndex].toInt() xor mask[1 + i].toInt()) and 0xFF
            header[headerIndex] = unmasked.toByte()
            packetNumber = (packetNumber shl 8) or unmasked.toLong()
        }
        // The first Initial packets of a connection have the lowest packet numbers, so the
        // truncated value is the full one (RFC 9000 appendix A.3 with no packet received yet).

        val payload = try {
            aeadOpen(packetKeys, packetNumber, header, datagram, packetNumberOffset + packetNumberLength, end)
        } catch (e: AEADBadTagException) {
            return Result.AuthenticationFailed(destinationConnectionId, consumed)
        }

        return Result.Decrypted(
            version = version,
            destinationConnectionId = destinationConnectionId,
            sourceConnectionId = sourceConnectionId,
            token = token,
            packetNumber = packetNumber,
            payload = payload,
            consumed = consumed
        )
    }

    /** The 5-byte header protection mask: AES-ECB of the sample (RFC 9001 section 5.4.3). */
    internal fun headerProtectionMask(hp: ByteArray, data: ByteArray, sampleOffset: Int): ByteArray {
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(hp, "AES"))
        return cipher.doFinal(data, sampleOffset, SAMPLE_LENGTH).copyOf(5)
    }

    /** The AEAD nonce: the IV with the packet number XORed into its last bytes (RFC 9001 section 5.3). */
    internal fun nonce(iv: ByteArray, packetNumber: Long): ByteArray {
        val nonce = iv.copyOf()
        for (i in 0 until 8) {
            val index = nonce.size - 1 - i
            nonce[index] = (nonce[index].toInt() xor ((packetNumber ushr (8 * i)).toInt() and 0xFF)).toByte()
        }
        return nonce
    }

    private fun aeadOpen(keys: QuicInitialKeys, packetNumber: Long, header: ByteArray, data: ByteArray, from: Int, to: Int): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keys.key, "AES"), GCMParameterSpec(TAG_LENGTH * 8, nonce(keys.iv, packetNumber)))
        cipher.updateAAD(header)
        return cipher.doFinal(data, from, to - from)
    }

    private fun readInt(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 24) or
                ((data[offset + 1].toInt() and 0xFF) shl 16) or
                ((data[offset + 2].toInt() and 0xFF) shl 8) or
                (data[offset + 3].toInt() and 0xFF)
    }

    /** Reads a length-prefixed connection ID, or returns null if it is too long or cut off. */
    private fun readConnectionId(data: ByteArray, offset: Int): ByteArray? {
        if (offset >= data.size) {
            return null
        }
        val length = data[offset].toInt() and 0xFF
        if (length > MAX_CONNECTION_ID_LENGTH || offset + 1 + length > data.size) {
            return null
        }
        return data.copyOfRange(offset + 1, offset + 1 + length)
    }
}
