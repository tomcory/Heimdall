package de.tomcory.heimdall.core.vpn.connection.inetLayer

import java.net.Inet4Address

/**
 * Builds the ICMP "destination unreachable, port unreachable" error (RFC 792) that tells an app
 * its UDP datagram will not be answered (docs/vpn-mitm-audit.md PKT-52). The kernel matches the
 * error to the app's socket by the datagram it quotes, and a connected UDP socket then fails
 * with "connection refused" at once, instead of the app waiting for its own timeout.
 *
 * Built byte by byte rather than with pcap4j: the message quotes a truncated IP packet, which
 * pcap4j's builders do not represent, and the layout is small and fixed.
 */
object IcmpUnreachableBuilder {

    private const val IPV4_HEADER_LENGTH = 20
    private const val UDP_HEADER_LENGTH = 8
    private const val ICMP_HEADER_LENGTH = 8
    private const val PROTOCOL_ICMP = 1
    private const val PROTOCOL_UDP = 17
    private const val ICMP_TYPE_DESTINATION_UNREACHABLE = 3
    private const val ICMP_CODE_PORT_UNREACHABLE = 3
    private const val TTL = 64

    /**
     * The IPv4 packet carrying the error, from the remote host to the device.
     *
     * @param local The app's address and port, the sender of the datagram.
     * @param remote The address and port the datagram was sent to.
     * @param udpPayload The datagram's payload; the quoted UDP header is the one that was sent
     * with it, length and checksum included.
     */
    fun portUnreachable(local: Inet4Address, localPort: Int, remote: Inet4Address, remotePort: Int, udpPayload: ByteArray): ByteArray {
        // the invoking datagram, as the app sent it: its IP header and the first 8 bytes of its
        // payload, which is the UDP header (RFC 792)
        val udpLength = UDP_HEADER_LENGTH + udpPayload.size
        val invokingHeader = ipv4Header(IPV4_HEADER_LENGTH + udpLength, PROTOCOL_UDP, local, remote, dontFragment = true)
        val udpHeader = ByteArray(UDP_HEADER_LENGTH)
        putShort(udpHeader, 0, localPort)
        putShort(udpHeader, 2, remotePort)
        putShort(udpHeader, 4, udpLength)
        putShort(udpHeader, 6, udpChecksum(local, remote, udpHeader, udpPayload))

        val icmp = ByteArray(ICMP_HEADER_LENGTH + IPV4_HEADER_LENGTH + UDP_HEADER_LENGTH)
        icmp[0] = ICMP_TYPE_DESTINATION_UNREACHABLE.toByte()
        icmp[1] = ICMP_CODE_PORT_UNREACHABLE.toByte()
        // bytes 4 to 7 are unused for this code
        System.arraycopy(invokingHeader, 0, icmp, ICMP_HEADER_LENGTH, IPV4_HEADER_LENGTH)
        System.arraycopy(udpHeader, 0, icmp, ICMP_HEADER_LENGTH + IPV4_HEADER_LENGTH, UDP_HEADER_LENGTH)
        putShort(icmp, 2, checksum(icmp, 0, icmp.size))

        return ipv4Header(IPV4_HEADER_LENGTH + icmp.size, PROTOCOL_ICMP, remote, local, dontFragment = false) + icmp
    }

    private fun ipv4Header(totalLength: Int, protocol: Int, source: Inet4Address, destination: Inet4Address, dontFragment: Boolean): ByteArray {
        val header = ByteArray(IPV4_HEADER_LENGTH)
        header[0] = 0x45 // version 4, header length 5 words
        putShort(header, 2, totalLength)
        if (dontFragment) {
            header[6] = 0x40
        }
        header[8] = TTL.toByte()
        header[9] = protocol.toByte()
        System.arraycopy(source.address, 0, header, 12, 4)
        System.arraycopy(destination.address, 0, header, 16, 4)
        putShort(header, 10, checksum(header, 0, header.size))
        return header
    }

    private fun udpChecksum(source: Inet4Address, destination: Inet4Address, udpHeader: ByteArray, payload: ByteArray): Int {
        val udpLength = udpHeader.size + payload.size
        // pseudo header, UDP header (checksum field zero), payload, padded to an even length
        val data = ByteArray(12 + udpLength + (udpLength and 1))
        System.arraycopy(source.address, 0, data, 0, 4)
        System.arraycopy(destination.address, 0, data, 4, 4)
        data[9] = PROTOCOL_UDP.toByte()
        putShort(data, 10, udpLength)
        System.arraycopy(udpHeader, 0, data, 12, udpHeader.size)
        System.arraycopy(payload, 0, data, 12 + udpHeader.size, payload.size)
        val sum = checksum(data, 0, data.size)
        // a computed zero is sent as all ones; zero means "no checksum" in UDP
        return if (sum == 0) 0xFFFF else sum
    }

    /** The Internet checksum (RFC 1071) of [length] bytes from [offset]. */
    internal fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        while (i + 1 < offset + length) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < offset + length) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while (sum ushr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }

    private fun putShort(data: ByteArray, offset: Int, value: Int) {
        data[offset] = (value ushr 8).toByte()
        data[offset + 1] = value.toByte()
    }
}
