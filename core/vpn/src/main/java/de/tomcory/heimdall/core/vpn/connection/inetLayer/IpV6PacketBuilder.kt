package de.tomcory.heimdall.core.vpn.connection.inetLayer

import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.IpV6Packet
import org.pcap4j.packet.IpV6Packet.IpV6FlowLabel
import org.pcap4j.packet.IpV6Packet.IpV6TrafficClass
import org.pcap4j.packet.Packet
import org.pcap4j.packet.namednumber.IpVersion
import java.net.Inet6Address

/**
 * Represents a connection based on IP version 6.
 *
 * @param initialPacket [IpPacket] from which the necessary metadata is extracted to create the instance (ideally the very first packet of a new socket).
 */
class IpV6PacketBuilder(
    initialPacket: IpV6Packet
) : IpPacketBuilder(
    localAddress = initialPacket.header.srcAddr,
    remoteAddress = initialPacket.header.dstAddr,
    transportProtocol = initialPacket.header.protocol
) {

    /**
     * IPv6 traffic class used by this connection.
     */
    val trafficClass: IpV6TrafficClass = initialPacket.header.trafficClass

    /**
     * IPv6 flow label used by this connection.
     */
    val flowLabel: IpV6FlowLabel = initialPacket.header.flowLabel

    override fun buildPacket(payloadBuilder: Packet.Builder?): IpPacket {
        return IpV6Packet.Builder()
            .version(IpVersion.IPV6)
            .trafficClass(trafficClass)
            .flowLabel(flowLabel)
            .nextHeader(transportProtocol)
            .hopLimit(64.toByte())
            .srcAddr(remoteAddress as Inet6Address)
            .dstAddr(localAddress as Inet6Address)
            .payloadBuilder(payloadBuilder)
            .correctLengthAtBuild(true)
            .build()
    }

    companion object {
        internal fun buildStray(strayPacket: IpV6Packet, payloadBuilder: Packet.Builder?): IpV6Packet {
            return IpV6Packet.Builder()
                .version(IpVersion.IPV6)
                .trafficClass(strayPacket.header.trafficClass)
                .flowLabel(strayPacket.header.flowLabel)
                .nextHeader(strayPacket.header.nextHeader)
                .hopLimit(64.toByte())
                .srcAddr(strayPacket.header.dstAddr)
                .dstAddr(strayPacket.header.srcAddr)
                .payloadBuilder(payloadBuilder)
                .correctLengthAtBuild(true)
                .build()
        }
    }
}