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
 * Represents a connection based on IPv4. This class is used to build new IPv4 packets and to store the necessary metadata for the connection
 *
 * @param initialPacket [IpV4Packet] from which the necessary metadata is extracted to create the instance (ideally the very first packet of a new socket).
 */
class IpV4PacketBuilder(
    initialPacket: IpV4Packet
) : IpPacketBuilder(
    localAddress = initialPacket.header.srcAddr,
    remoteAddress = initialPacket.header.dstAddr,
    ipVersion = 4,
    transportProtocol = initialPacket.header.protocol
) {

    /**
     * IPv4 type of service used by this connection.
     */
    private val tos: IpV4Tos? = initialPacket.header.tos
    /**
     * IPv4 identification header value used by [buildPacket] to construct packets for this connection.
     */
    private var identification: Short = 0

    /**
     * Builds a new [IpV4Packet] with the specified payload.
     *
     * @param payloadBuilder The [Packet.Builder] used to build the payload of the packet.
     * @return The newly created [IpV4Packet].
     */
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

        /**
         * Builds a new [IpV4Packet] with the specified payload. This method is used to create a response to a stray packet, i.e. a packet that does not belong to any known connection.
         *
         * @param strayPacket The [IpV4Packet] from which the necessary metadata is extracted to create the instance.
         * @param payloadBuilder The [Packet.Builder] used to build the payload of the packet.
         * @return The newly created [IpV4Packet].
         */
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