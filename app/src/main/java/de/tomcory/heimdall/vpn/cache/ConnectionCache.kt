package de.tomcory.heimdall.vpn.cache

import de.tomcory.heimdall.vpn.connection.transportLayer.TransportLayerConnection
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.TransportPacket
import timber.log.Timber
import java.net.InetAddress

class ConnectionCache {
    private val connections = HashMap<Int, TransportLayerConnection>()

    companion object {
        private val cache = ConnectionCache()

        fun findConnection(ipPacket: IpPacket): TransportLayerConnection? {
            return cache.connections[getKey(ipPacket)]
        }

        fun findConnection(key: Int): TransportLayerConnection? {
            return cache.connections[key]
        }

        fun addConnection(connection: TransportLayerConnection) {
            val key = getKey(connection)
            val oldConnection = cache.connections.put(key, connection)
            if (oldConnection != null) {
                Timber.e("Flow overwritten: $oldConnection $connection")
            }
        }

        fun removeConnection(connection: TransportLayerConnection) {
            cache.connections.remove(getKey(connection))
        }

        fun closeAllAndClear() {
            for (connection in cache.connections.values) {
                connection.closeSoft()
            }
            cache.connections.clear()
        }

        private fun getKey(ipPacket: IpPacket): Int {
            val remoteAddress = ipPacket.header.dstAddr
            val transportPacket = ipPacket.payload as TransportPacket
            val localPort = transportPacket.header.srcPort.valueAsInt()
            val remotePort = transportPacket.header.dstPort.valueAsInt()
            val protocol = ipPacket.header.protocol.value()
            return getKey(remoteAddress, protocol.toInt(), localPort, remotePort)
        }

        private fun getKey(connection: TransportLayerConnection): Int {
            val remoteAddress = connection.ipPacketBuilder.remoteAddress
            val localPort = connection.localPort.valueAsInt()
            val remotePort = connection.remotePort.valueAsInt()
            val protocol = connection.ipPacketBuilder.transportProtocol.value()
            return getKey(remoteAddress, protocol.toInt(), localPort, remotePort)
        }

        private fun getKey(remoteAddress: InetAddress, protocol: Int, localPort: Int, remotePort: Int): Int {
            return remoteAddress.hashCode() xor (protocol shl 16) xor (localPort shl 8) xor remotePort
        }
    }
}