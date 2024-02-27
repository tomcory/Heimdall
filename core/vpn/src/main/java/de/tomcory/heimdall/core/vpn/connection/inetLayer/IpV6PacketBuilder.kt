package de.tomcory.heimdall.core.vpn.connection.inetLayer

import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.IpV6Packet
import org.pcap4j.packet.IpV6Packet.IpV6FlowLabel
import org.pcap4j.packet.IpV6Packet.IpV6TrafficClass
import org.pcap4j.packet.Packet
import org.pcap4j.packet.namednumber.IpVersion
import java.net.Inet6Address

/**
 * Represents a connection based on IPv6. This class is used to build new IPv6 packets and to store the necessary metadata for the connection
 *
 * @param initialPacket [IpV6Packet] from which the necessary metadata is extracted to create the instance (ideally the very first packet of a new socket).
 */
class IpV6PacketBuilder(
    initialPacket: IpV6Packet
) : IpPacketBuilder(
    localAddress = initialPacket.header.srcAddr,
    remoteAddress = initialPacket.header.dstAddr,
    ipVersion = 6,
    transportProtocol = initialPacket.header.protocol
) {

    /**
     * IPv6 traffic class used by this connection.
     */
    private val trafficClass: IpV6TrafficClass = initialPacket.header.trafficClass

    /**
     * IPv6 flow label used by this connection.
     */
    private val flowLabel: IpV6FlowLabel = initialPacket.header.flowLabel

    /**
     * Builds a new [IpV6Packet] with the specified payload.
     *
     * @param payloadBuilder The [Packet.Builder] used to build the payload of the packet.
     * @return The newly created [IpV6Packet].
     */
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

        /**
         * Builds a new [IpV6Packet] with the specified payload. This method is used to create a response to a stray packet, i.e. a packet that does not belong to any known connection.
         *
         * @param strayPacket The [IpV6Packet] from which the necessary metadata is extracted to create the instance.
         * @param payloadBuilder The [Packet.Builder] used to build the payload of the packet.
         * @return The newly created [IpV6Packet].
         */
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