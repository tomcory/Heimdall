package de.tomcory.heimdall.core.vpn.cache

import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.TransportPacket
import timber.log.Timber
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Structural key for [ConnectionCache], used directly as a map key instead of being packed into
 * a single [Int] - the old `remoteAddress.hashCode() xor (protocol shl 16) xor (localPort shl 8)
 * xor remotePort` packing had overlapping bit ranges for localPort/remotePort (e.g.
 * (localPort=1, remotePort=0) and (localPort=0, remotePort=256) both packed to the same value),
 * silently overwriting a live connection's cache entry.
 */
private data class ConnectionKey(
    val remoteAddress: InetAddress,
    val protocol: Int,
    val localPort: Int,
    val remotePort: Int
)

class ConnectionCache {
    private val connections = ConcurrentHashMap<ConnectionKey, TransportLayerConnection>()

    companion object {
        private val cache = ConnectionCache()

        fun findConnection(ipPacket: IpPacket): TransportLayerConnection? {
            return cache.connections[getKey(
                ipPacket
            )]
        }

        fun addConnection(connection: TransportLayerConnection) {
            val key = getKey(
                connection
            )
            val oldConnection = cache.connections.put(key, connection)
            if (oldConnection != null) {
                Timber.e("Flow overwritten: $oldConnection $connection")
            }
        }

        fun removeConnection(connection: TransportLayerConnection) {
            cache.connections.remove(
                getKey(
                    connection
                )
            )
        }

        /** Snapshot of every currently-cached connection, regardless of protocol. */
        fun allConnections(): List<TransportLayerConnection> {
            return cache.connections.values.toList()
        }

        fun closeAllAndClear() {
            for (connection in cache.connections.values) {
                connection.closeSoft()
            }
            cache.connections.clear()
        }

        private fun getKey(ipPacket: IpPacket): ConnectionKey {
            val remoteAddress = ipPacket.header.dstAddr
            val transportPacket = ipPacket.payload as TransportPacket
            val localPort = transportPacket.header.srcPort.valueAsInt()
            val remotePort = transportPacket.header.dstPort.valueAsInt()
            val protocol = ipPacket.header.protocol.value()
            return ConnectionKey(remoteAddress, protocol.toInt(), localPort, remotePort)
        }

        private fun getKey(connection: TransportLayerConnection): ConnectionKey {
            val remoteAddress = connection.ipPacketBuilder.remoteAddress
            val localPort = connection.localPort
            val remotePort = connection.remotePort
            val protocol = connection.ipPacketBuilder.transportProtocol.value()
            return ConnectionKey(remoteAddress, protocol.toInt(), localPort, remotePort)
        }
    }
}