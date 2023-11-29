package de.tomcory.heimdall.core.vpn.connection.inetLayer

import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.IpV4Packet.IpV4Tos
import org.pcap4j.packet.Packet
import org.pcap4j.packet.factory.PacketFactories
import org.pcap4j.packet.namednumber.IpVersion
import org.pcap4j.packet.namednumber.NotApplicable
import timber.log.Timber
import java.net.Inet4Address

/**
 * Represents a connection based on IP version 4.
 *
 * @param initialPacket [IpPacket] from which the necessary metadata is extracted to create the instance (ideally the very first packet of a new socket).
 */
class IpV4PacketBuilder(
    initialPacket: IpV4Packet
) : IpPacketBuilder(
    localAddress = initialPacket.header.srcAddr,
    remoteAddress = initialPacket.header.dstAddr,
    transportProtocol = initialPacket.header.protocol
) {

    /**
     * IPv4 type of service used by this connection.
     */
    val tos: IpV4Tos? = initialPacket.header.tos
    /**
     * IPv4 identification header value used by [buildPacket] to construct packets for this connection.
     */
    var identification: Short = 0

    override fun buildPacket(payloadBuilder: Packet.Builder?): IpPacket {
        val safeTos = tos ?: PacketFactories.getFactory(IpV4Tos::class.java, NotApplicable::class.java).newInstance(byteArrayOf(0), 0, 1)
        if(tos == null) {
            Timber.e("%s", safeTos)
        }

        return IpV4Packet.Builder()
            .version(IpVersion.IPV4)
            .ihl(5.toByte())
            .tos(safeTos)
            .identification(identification++)
            .reservedFlag(false)
            .dontFragmentFlag(false)
            .moreFragmentFlag(false)
            .fragmentOffset(0.toShort())
            .ttl(64.toByte())
            .protocol(transportProtocol)
            .srcAddr(remoteAddress as Inet4Address)
            .dstAddr(localAddress as Inet4Address)
            .options(ArrayList())
            .padding(ByteArray(0))
            .payloadBuilder(payloadBuilder)
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true)
            .build()
    }

    companion object {
        internal fun buildStray(strayPacket: IpV4Packet, payloadBuilder: Packet.Builder?): IpV4Packet {
            return IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .ihl(5.toByte())
                .tos(strayPacket.header.tos)
                .identification((strayPacket.header.identification + 1).toShort())
                .reservedFlag(false)
                .dontFragmentFlag(false)
                .moreFragmentFlag(false)
                .fragmentOffset(0.toShort())
                .ttl(64.toByte())
                .protocol(strayPacket.header.protocol)
                .srcAddr(strayPacket.header.dstAddr)
                .dstAddr(strayPacket.header.srcAddr)
                .options(ArrayList())
                .padding(ByteArray(0))
                .payloadBuilder(payloadBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .build()
        }
    }
}