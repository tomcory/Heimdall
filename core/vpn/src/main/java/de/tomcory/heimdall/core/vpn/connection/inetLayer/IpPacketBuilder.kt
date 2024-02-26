package de.tomcory.heimdall.core.vpn.connection.inetLayer

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.IpV6Packet
import org.pcap4j.packet.Packet
import org.pcap4j.packet.namednumber.IpNumber
import java.net.InetAddress

/**
 * Base class for all internet-layer connection holders.
 *
 * @property localAddress Intercepted client's IP address.
 * @property remoteAddress Remote host's IP address.
 * @property transportProtocol Transport protocol used by this connection.
 */
abstract class IpPacketBuilder protected constructor(
    val localAddress: InetAddress,
    val remoteAddress: InetAddress,
    val ipVersion: Int,
    val transportProtocol: IpNumber) {

    /**
     * Constructs an [IpPacket] around the supplied transport-layer payload [Packet.Builder].
     * If no payload builder is supplied, an empty packet is constructed.
     */
    abstract fun buildPacket(payloadBuilder: Packet.Builder?) : IpPacket

    companion object {
        /**
         * Attempts to retrieve a matching [IpPacketBuilder] from the [ConnectionCache].
         * If no matching connection is found, a new [IpPacketBuilder] instance based on the IP version of the supplied packet is created.
         * The created instance is written to the [ConnectionCache] before being returned.
         *
         * @param initialPacket [IpPacket] from which the necessary metadata is extracted to create the instance (ideally the very first packet of a new socket).
         */
        fun getInstance(initialPacket: IpPacket) : IpPacketBuilder {
            val inetLayerConnection = when(initialPacket) {
                is IpV4Packet -> IpV4PacketBuilder(initialPacket)
                is IpV6Packet -> IpV6PacketBuilder(initialPacket)
                else -> throw IllegalArgumentException("Invalid IP version")
            }
            return inetLayerConnection
        }

        /**
         * Builds a response packet for a stray [IpPacket] based on the supplied packet's data and the supplied transport-layer [Packet.Builder].
         */
        fun buildStray(strayPacket: IpPacket, payloadBuilder: Packet.Builder?): IpPacket? {
            val strayResponse =  when(strayPacket) {
                is IpV4Packet -> IpV4PacketBuilder.buildStray(strayPacket, payloadBuilder)
                is IpV6Packet -> IpV6PacketBuilder.buildStray(strayPacket, payloadBuilder)
                else -> null
            }

            return strayResponse
        }
    }
}