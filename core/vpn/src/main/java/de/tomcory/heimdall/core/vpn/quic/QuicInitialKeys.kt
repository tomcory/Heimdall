package de.tomcory.heimdall.core.vpn.quic

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The keys that protect QUIC Initial packets (RFC 9001 section 5.2; RFC 9369 section 3.3 for
 * QUIC version 2). They are derived from public values only, the version's salt and the
 * Destination Connection ID of the client's first Initial packet, so anyone on the path can
 * compute them. That is what lets Heimdall read the ClientHello of a QUIC flow without
 * intercepting it (docs/vpn-mitm-audit.md PKT-49).
 *
 * @property key The AEAD key (AES-128-GCM).
 * @property iv The AEAD nonce base.
 * @property hp The header protection key (AES-128-ECB).
 */
class QuicInitialKeys(val key: ByteArray, val iv: ByteArray, val hp: ByteArray) {

    companion object {
        /** QUIC version 1 (RFC 9000). */
        const val VERSION_1 = 0x00000001

        /** QUIC version 2 (RFC 9369). */
        const val VERSION_2 = 0x6b3343cf

        private val SALT_V1 = hex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
        private val SALT_V2 = hex("0dede3def700a6db819381be6e269dcbf9bd2ed9")

        /** Whether keys can be derived for [version]. */
        fun isSupported(version: Int): Boolean = version == VERSION_1 || version == VERSION_2

        /**
         * The keys that protect the client's Initial packets.
         *
         * @param destinationConnectionId The Destination Connection ID of the client's first
         * Initial packet. Later Initials of the same connection keep these keys even after the
         * client has switched to the server's connection ID.
         * @return null for a version this class does not know.
         */
        fun forClient(version: Int, destinationConnectionId: ByteArray): QuicInitialKeys? {
            return derive(version, destinationConnectionId, "client in")
        }

        /** The keys that protect the server's Initial packets; see [forClient]. */
        fun forServer(version: Int, destinationConnectionId: ByteArray): QuicInitialKeys? {
            return derive(version, destinationConnectionId, "server in")
        }

        private fun derive(version: Int, destinationConnectionId: ByteArray, direction: String): QuicInitialKeys? {
            val salt = when (version) {
                VERSION_1 -> SALT_V1
                VERSION_2 -> SALT_V2
                else -> return null
            }
            val labelPrefix = if (version == VERSION_2) "quicv2" else "quic"
            val secret = expandLabel(initialSecret(salt, destinationConnectionId), direction, 32)
            return QuicInitialKeys(
                key = expandLabel(secret, "$labelPrefix key", 16),
                iv = expandLabel(secret, "$labelPrefix iv", 12),
                hp = expandLabel(secret, "$labelPrefix hp", 16)
            )
        }

        /** `initial_secret = HKDF-Extract(salt, client_dst_connection_id)`. */
        internal fun initialSecret(salt: ByteArray, destinationConnectionId: ByteArray): ByteArray {
            return hmac(salt, destinationConnectionId)
        }

        internal fun initialSecret(version: Int, destinationConnectionId: ByteArray): ByteArray? {
            return when (version) {
                VERSION_1 -> initialSecret(SALT_V1, destinationConnectionId)
                VERSION_2 -> initialSecret(SALT_V2, destinationConnectionId)
                else -> null
            }
        }

        /**
         * `HKDF-Expand-Label(secret, label, "", length)` of TLS 1.3 (RFC 8446 section 7.1), with
         * SHA-256 and an empty context, as QUIC uses it.
         */
        internal fun expandLabel(secret: ByteArray, label: String, length: Int): ByteArray {
            val fullLabel = "tls13 $label".toByteArray(Charsets.US_ASCII)
            // HkdfLabel: uint16 length, opaque label<7..255>, opaque context<0..255>
            val info = ByteArray(2 + 1 + fullLabel.size + 1)
            info[0] = (length ushr 8).toByte()
            info[1] = length.toByte()
            info[2] = fullLabel.size.toByte()
            System.arraycopy(fullLabel, 0, info, 3, fullLabel.size)
            info[info.size - 1] = 0
            return expand(secret, info, length)
        }

        /** HKDF-Expand (RFC 5869 section 2.3) with SHA-256. */
        private fun expand(pseudoRandomKey: ByteArray, info: ByteArray, length: Int): ByteArray {
            val output = ByteArray(length)
            var previous = ByteArray(0)
            var written = 0
            var counter = 1
            while (written < length) {
                previous = hmac(pseudoRandomKey, previous + info + byteArrayOf(counter.toByte()))
                val take = minOf(previous.size, length - written)
                System.arraycopy(previous, 0, output, written, take)
                written += take
                counter++
            }
            return output
        }

        private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            return mac.doFinal(data)
        }

        private fun hex(value: String): ByteArray {
            return ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        }
    }
}
