package de.tomcory.heimdall.scanner.traffic.cache

import de.tomcory.heimdall.scanner.traffic.connection.transportLayer.TransportLayerConnection
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.TransportPacket
import timber.log.Timber
import java.net.InetAddress

class ConnectionCache {
    private val connections = HashMap<Int, TransportLayerConnection>()

    companion object {
        private val cache = de.tomcory.heimdall.scanner.traffic.cache.ConnectionCache()

        fun findConnection(ipPacket: IpPacket): TransportLayerConnection? {
            return de.tomcory.heimdall.scanner.traffic.cache.ConnectionCache.Companion.cache.connections[de.tomcory.heimdall.scanner.traffic.cache.ConnectionCache.Companion.getKey(
                ipPacket
            )]
        }

        fun findConnection(key: Int): TransportLayerConnection? {
            return de.tomcory.heimdall.scanner.traffic.cache.ConnectionCache.Companion.cache.connections[key]
        }

        fun addConnection(connection: TransportLayerConnection) {
            val key = de.tomcory.heimdall.scanner.traffic.cache.ConnectionCache.Companion.getKey(
                connection
            )
            val oldConnection = de.tomcory.heimdall.scanner.traffic.cache.ConnectionCache.Companion.cache.connections.put(key, connection)
            if (oldConnection != null) {
                Timber.e("Flow overwritten: $oldConnection $connection")
            }
        }

        fun removeConnection(connection: TransportLayerConnection) {
            de.tomcory.heimdall.scanner.traffic.cache.ConnectionCache.Companion.cache.connections.remove(
                de.tomcory.heimdall.scanner.traffic.cache.ConnectionCache.Companion.getKey(
                    connection
                )
            )
        }

        fun closeAllAndClear() {
            for (connection in de.tomcory.heimdall.scanner.traffic.cache.ConnectionCache.Companion.cache.connections.values) {
                connection.closeSoft()
            }
            de.tomcory.heimdall.scanner.traffic.cache.ConnectionCache.Companion.cache.connections.clear()
        }

        private fun getKey(ipPacket: IpPacket): Int {
            val remoteAddress = ipPacket.header.dstAddr
            val transportPacket = ipPacket.payload as TransportPacket
            val localPort = transportPacket.header.srcPort.valueAsInt()
            val remotePort = transportPacket.header.dstPort.valueAsInt()
            val protocol = ipPacket.header.protocol.value()
            return de.tomcory.heimdall.scanner.traffic.cache.ConnectionCache.Companion.getKey(
                remoteAddress,
                protocol.toInt(),
                localPort,
                remotePort
            )
        }

        private fun getKey(connection: TransportLayerConnection): Int {
            val remoteAddress = connection.ipPacketBuilder.remoteAddress
            val localPort = connection.localPort.valueAsInt()
            val remotePort = connection.remotePort.valueAsInt()
            val protocol = connection.ipPacketBuilder.transportProtocol.value()
            return de.tomcory.heimdall.scanner.traffic.cache.ConnectionCache.Companion.getKey(
                remoteAddress,
                protocol.toInt(),
                localPort,
                remotePort
            )
        }

        private fun getKey(remoteAddress: InetAddress, protocol: Int, localPort: Int, remotePort: Int): Int {
            return remoteAddress.hashCode() xor (protocol shl 16) xor (localPort shl 8) xor remotePort
        }
    }
}