package de.tomcory.heimdall.core.vpn.connection.encryptionLayer

/**
 * What a TLS ClientHello reveals about the connection the client is trying to open.
 *
 * @property sni The server name the client asked for (`server_name` extension), if it sent one.
 * @property alpn The application protocols the client offered (`application_layer_protocol_negotiation`
 * extension), in the client's order of preference. Empty if it sent none.
 * @property echOffered Whether the client sent an `encrypted_client_hello` extension. Clients
 * also send it as GREASE, so this alone does not mean that [sni] is only a public name.
 * @property supportedVersions The TLS versions the client offered (`supported_versions`
 * extension), e.g. 0x0304 for TLS 1.3. Empty if it sent none, as TLS 1.2-only clients do.
 * @property truncated Whether the message ended before its extensions did. The other properties
 * then only reflect the extensions that were complete.
 */
data class ClientHelloInfo(
    val sni: String?,
    val alpn: List<String>,
    val echOffered: Boolean,
    val supportedVersions: List<Int>,
    val truncated: Boolean
)

/**
 * Parses TLS ClientHello handshake messages (RFC 8446 section 4.1.2). Works on the bare
 * handshake message, without a record header, because that is what both carriers have in common:
 * TLS over TCP wraps the message in a record, QUIC carries it in CRYPTO frames
 * (docs/vpn-mitm-audit.md PKT-29).
 */
object ClientHelloParser {

    private const val HANDSHAKE_TYPE_CLIENT_HELLO = 1
    private const val HANDSHAKE_HEADER_SIZE = 4
    private const val CLIENT_VERSION_SIZE = 2
    private const val RANDOM_SIZE = 32

    private const val EXTENSION_SERVER_NAME = 0
    private const val EXTENSION_ALPN = 16
    private const val EXTENSION_SUPPORTED_VERSIONS = 43
    private const val EXTENSION_ENCRYPTED_CLIENT_HELLO = 0xfe0d

    private const val SERVER_NAME_TYPE_HOST_NAME = 0

    /**
     * Parses the ClientHello handshake message that starts at [offset] in [data]. Never throws.
     *
     * The message may be cut short: a declared length that exceeds the available bytes is
     * tolerated, and whatever is complete is parsed (see [ClientHelloInfo.truncated]).
     *
     * @return the parsed message, or null if [data] does not hold a ClientHello at [offset] or
     * the message is malformed before its extensions begin.
     */
    fun parse(data: ByteArray, offset: Int = 0): ClientHelloInfo? {
        if (offset < 0 || data.size - offset < HANDSHAKE_HEADER_SIZE) {
            return null
        }
        if (u8(data, offset) != HANDSHAKE_TYPE_CLIENT_HELLO) {
            return null
        }
        val declaredLength = (u8(data, offset + 1) shl 16) or u16(data, offset + 2)
        val bodyStart = offset + HANDSHAKE_HEADER_SIZE
        val end = minOf(bodyStart + declaredLength, data.size)
        var truncated = bodyStart + declaredLength > data.size

        // legacy_version, random
        var pos = bodyStart + CLIENT_VERSION_SIZE + RANDOM_SIZE

        // legacy_session_id
        if (pos + 1 > end) return null
        pos += 1 + u8(data, pos)

        // cipher_suites
        if (pos + 2 > end) return null
        pos += 2 + u16(data, pos)

        // legacy_compression_methods
        if (pos + 1 > end) return null
        pos += 1 + u8(data, pos)

        // a ClientHello may end here: extensions are optional before TLS 1.3
        if (pos == end) {
            return ClientHelloInfo(null, emptyList(), false, emptyList(), truncated)
        }
        if (pos + 2 > end) return null

        val declaredExtensionsEnd = pos + 2 + u16(data, pos)
        pos += 2
        val extensionsEnd = minOf(declaredExtensionsEnd, end)
        if (declaredExtensionsEnd > end) {
            truncated = true
        }

        var sni: String? = null
        var alpn: List<String> = emptyList()
        var echOffered = false
        var supportedVersions: List<Int> = emptyList()

        while (pos < extensionsEnd) {
            if (pos + 4 > extensionsEnd) {
                truncated = true
                break
            }
            val type = u16(data, pos)
            val length = u16(data, pos + 2)
            val bodyPos = pos + 4
            if (bodyPos + length > extensionsEnd) {
                truncated = true
                break
            }
            when (type) {
                EXTENSION_SERVER_NAME -> sni = parseServerName(data, bodyPos, bodyPos + length) ?: sni
                EXTENSION_ALPN -> alpn = parseAlpn(data, bodyPos, bodyPos + length)
                EXTENSION_SUPPORTED_VERSIONS -> supportedVersions = parseSupportedVersions(data, bodyPos, bodyPos + length)
                EXTENSION_ENCRYPTED_CLIENT_HELLO -> echOffered = true
            }
            pos = bodyPos + length
        }

        return ClientHelloInfo(sni, alpn, echOffered, supportedVersions, truncated)
    }

    /** `ServerNameList`: a 2-byte list length, then entries of name type (1), length (2), name. */
    private fun parseServerName(data: ByteArray, start: Int, end: Int): String? {
        if (start + 2 > end) return null
        val listEnd = minOf(start + 2 + u16(data, start), end)
        var pos = start + 2
        while (pos + 3 <= listEnd) {
            val nameType = u8(data, pos)
            val nameLength = u16(data, pos + 1)
            val nameStart = pos + 3
            if (nameStart + nameLength > listEnd) return null
            if (nameType == SERVER_NAME_TYPE_HOST_NAME && nameLength > 0) {
                return String(data, nameStart, nameLength, Charsets.US_ASCII)
            }
            pos = nameStart + nameLength
        }
        return null
    }

    /** `ProtocolNameList`: a 2-byte list length, then entries of length (1), name. */
    private fun parseAlpn(data: ByteArray, start: Int, end: Int): List<String> {
        if (start + 2 > end) return emptyList()
        val listEnd = minOf(start + 2 + u16(data, start), end)
        val protocols = mutableListOf<String>()
        var pos = start + 2
        while (pos + 1 <= listEnd) {
            val nameLength = u8(data, pos)
            val nameStart = pos + 1
            if (nameLength == 0 || nameStart + nameLength > listEnd) break
            protocols.add(String(data, nameStart, nameLength, Charsets.US_ASCII))
            pos = nameStart + nameLength
        }
        return protocols
    }

    /** In a ClientHello: a 1-byte list length, then 2-byte versions. */
    private fun parseSupportedVersions(data: ByteArray, start: Int, end: Int): List<Int> {
        if (start + 1 > end) return emptyList()
        val listEnd = minOf(start + 1 + u8(data, start), end)
        val versions = mutableListOf<Int>()
        var pos = start + 1
        while (pos + 2 <= listEnd) {
            versions.add(u16(data, pos))
            pos += 2
        }
        return versions
    }

    private fun u8(data: ByteArray, index: Int) = data[index].toInt() and 0xFF

    private fun u16(data: ByteArray, index: Int) = (u8(data, index) shl 8) or u8(data, index + 1)
}
