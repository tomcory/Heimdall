package de.tomcory.heimdall.scanner.traffic.connection.transportLayer

import android.net.TrafficStats
import android.net.VpnService
import android.os.Handler
import de.tomcory.heimdall.scanner.traffic.cache.ConnectionCache
import de.tomcory.heimdall.scanner.traffic.components.ComponentManager
import de.tomcory.heimdall.scanner.traffic.components.DeviceWriteThread
import de.tomcory.heimdall.scanner.traffic.connection.inetLayer.IpPacketBuilder
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.TcpPacket
import org.pcap4j.packet.UnknownPacket
import org.pcap4j.packet.namednumber.TcpPort
import timber.log.Timber
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.BufferOverflowException
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.*

/**
 * Represents a transport-layer connection using TCP.
 *
 * @param localAddress The local client's [InetAddress].
 * @param remoteAddress The remote host's [InetAddress].
 * @param initialPacket [IpPacket] from which the necessary metadata is extracted to create the instance (ideally the very first packet of a new socket).
 */
class TcpConnection internal constructor(
    manager: ComponentManager,
    deviceWriter: Handler,
    initialPacket: TcpPacket,
    ipPacketBuilder: IpPacketBuilder
) : TransportLayerConnection(
    deviceWriter,
    manager.mitmManager,
    localPort = initialPacket.header.srcPort,
    remotePort = initialPacket.header.dstPort,
    ipPacketBuilder
) {

    init {
        Timber.d("%s Creating TCP connection", id)
    }

    private val MAX_PAYLOAD_SIZE = Short.MAX_VALUE.toInt()

    override val appId = manager.appFinder.getAppId(ipPacketBuilder.localAddress, ipPacketBuilder.remoteAddress, this)
    override val appPackage = manager.appFinder.getAppPackage(appId)

    private val window = initialPacket.header.window
    private val theirInitSeqNum = initialPacket.header.sequenceNumberAsLong
    private val ourInitSeqNum = (Math.random() * 0xFFFFFFF).toLong()
    private var theirSeqNum = theirInitSeqNum + 1 // SYN packets increase the client's sequence number by 1
    private var ourSeqNum = ourInitSeqNum

    override val selectableChannel: SocketChannel = openChannel(ipPacketBuilder.remoteAddress, manager.vpnService)
    override val selectionKey = connectChannel(manager.selector)

    private fun openChannel(remoteAddress: InetAddress, vpnService: VpnService?): SocketChannel {
        state = TransportLayerState.CONNECTING
        TrafficStats.setThreadStatsTag(42)
        val selectableChannel = SocketChannel.open()
        vpnService?.protect(selectableChannel.socket())
        selectableChannel.configureBlocking(false)
        selectableChannel.socket().keepAlive = true
        selectableChannel.socket().tcpNoDelay = true
        selectableChannel.socket().soTimeout = 0
        selectableChannel.socket().receiveBufferSize = 65535
        selectableChannel.connect(InetSocketAddress(remoteAddress, remotePort.valueAsInt()))
        //Timber.d("%s Connecting SocketChannel to %s:%s", id, remoteAddress, remotePort.valueAsInt())
        return selectableChannel
    }

    private fun connectChannel(selector: Selector): SelectionKey? {
        // register OP_READ interest for the channel
        synchronized(ComponentManager.selectorMonitor) {
            selector.wakeup()
            val selectionKey = try {
                selectableChannel.register(selector, SelectionKey.OP_CONNECT)
            } catch (e: Exception) {
                //Timber.e(e, "%s Error registering SelectableChannel", id)
                null
            }
            selectionKey?.attach(this)
            return selectionKey
        }
    }

    private fun writeToDevice(packet: IpPacket) {
        deviceWriter.sendMessage(deviceWriter.obtainMessage(DeviceWriteThread.WRITE_TCP, packet))
    }

    override fun unwrapOutbound(outgoingPacket: IpPacket) {
        val tcpHeader = outgoingPacket.payload.header as TcpPacket.TcpHeader
        if (tcpHeader.ack) {
            if (outgoingPacket.payload.payload != null && outgoingPacket.payload.payload.length() > 0) {
                //Timber.d("%s Unwrapping TCP out (%s bytes)", id, outgoingPacket.payload.length())
                handleAckData(outgoingPacket) // data was sent and needs to be forwarded
            } else if (!tcpHeader.syn && !tcpHeader.fin) {
                handleAckEmpty()
            }
            if (tcpHeader.syn) {
                handleSynAck() // this should not happen, since we never initiate a handshake
            } else if (tcpHeader.fin) {
                handleFinAck() // this is either the first or second packet of the closing handshake
            }
        } else if (tcpHeader.fin) {
            handleFin() // closing handshake was initiated
        }
    }

    override fun unwrapInbound() {
        if(selectionKey == null) {
            Timber.e("%s SelectionKey is null", id)
            state = TransportLayerState.ABORTED
            return
        }

        if (!selectionKey.isValid) {
            Timber.e("Invalid Selection key")
            abortAndRst()
            return
        }
        if (selectionKey.isConnectable) {
            //Timber.d("%s Unwrapping TCP in connectable", id)
            unwrapInboundConnectable()
        } else if (selectionKey.isReadable) {
            //Timber.d("%s Unwrapping TCP in readable", id)
            unwrapInboundReadable()
        }
    }

    override fun wrapOutbound(payload: ByteArray) {
        //Timber.d("%s Wrapping TCP out (%s bytes)", id, payload.size)
        if (payload.isNotEmpty()) {
            if(payload.size <= outBuffer.limit()) {
                outBuffer.clear()
                outBuffer.put(payload)
                outBuffer.flip()

                while (outBuffer.hasRemaining()) {
                    try {
                        selectableChannel.write(outBuffer)
                    } catch (e: IOException) {
                        Timber.e("SocketChannel registered: %s", selectableChannel.isRegistered)
                        Timber.e("SocketChannel connected: %s", selectableChannel.isConnected)
                        Timber.e(e, "Error writing to SocketChannel, closing connection")
                        closeHard()
                        break
                    } catch (e: BufferOverflowException) {
                        Timber.e(e, "Error writing to SocketChannel, closing connection")
                        closeHard()
                        break
                    }
                }
            } else {

                //TODO: this is a dirty hack to prevent buffer overflows for stupidly large reassembled payloads
                val largeBuffer = ByteBuffer.wrap(payload)

                while (largeBuffer.hasRemaining()) {
                    try {
                        selectableChannel.write(largeBuffer)
                    } catch (e: IOException) {
                        Timber.e("SocketChannel registered: %s", selectableChannel.isRegistered)
                        Timber.e("SocketChannel connected: %s", selectableChannel.isConnected)
                        Timber.e("SocketChannel open: %s", selectableChannel.isOpen)
                        Timber.e(e, "Error writing to SocketChannel, closing connection")
                        abortAndRst()
                        break
                    } catch (e: BufferOverflowException) {
                        Timber.e(e, "Error writing to SocketChannel, closing connection")
                        abortAndRst()
                        break
                    }
                }
            }
        }
    }

    override fun wrapInbound(payload: ByteArray) {
        //Timber.d("%s Wrapping TCP in (%s bytes)", id, payload.size)
        // if the application layer returned anything, write it to the device's VPN interface
        if (payload.isNotEmpty()) {
            if(payload.size <= Short.MAX_VALUE.toInt()) {
                // if the payload fits into a single TCP segment, wrap and write it directly
                val ackDataPacket = ipPacketBuilder.buildPacket(buildDataAck(payload))
                increaseOurSeqNum(payload.size)
                writeToDevice(ackDataPacket)
            } else {
                // if the payload exceeds the max. TCP payload size, split it into multiple segments
                //TODO: there has to be a better way...
                //Timber.d("%s Splitting large payload (%s bytes)", id, payload.size)
                val largeBuffer = ByteBuffer.wrap(payload)
                while(largeBuffer.hasRemaining()) {
                    val temp = ByteArray(maxOf(largeBuffer.limit() - largeBuffer.position(), MAX_PAYLOAD_SIZE))
                    largeBuffer.get(temp)
                    Timber.d("%s Writing split payload (%s bytes, %s remaining)", id, temp.size, largeBuffer.limit() - largeBuffer.position())
                    val ackDataPacket = ipPacketBuilder.buildPacket(buildDataAck(temp))
                    increaseOurSeqNum(payload.size)
                    writeToDevice(ackDataPacket)
                }
            }
        }
    }

    private fun handleAckData(outgoingPacket: IpPacket) {
        val tcpPacket = outgoingPacket.payload as TcpPacket
        if (state != TransportLayerState.CONNECTED) {
            // the connection is not ready to forward data, abort
            Timber.e("%s Got ACK (data, invalid state %s)", id, state)
            abortAndRst()
        } else {
            //Timber.i("%s Got ACK data (%s bytes)", id, outgoingPacket.payload.length())
            increaseTheirSeqNum(tcpPacket.payload.rawData.size)

            // acknowledge packet to the client by sending an empty ACK
            writeToDevice(ipPacketBuilder.buildPacket(buildEmptyAck()))

            // pass the payload to the encryption and application layers for processing and store the result
            //TODO: below is just a placeholder for passOutboundToEncryptionLayer(tcpPacket.payload.rawData)
            wrapOutbound(tcpPacket.payload.rawData)
        }
    }

    private fun handleAckEmpty() {
        when (state) {
            TransportLayerState.CONNECTING -> {
                //Timber.i("%s Got ACK (connecting -> connected)", id)
                // establishing handshake complete, set status to CONNECTED
                state = TransportLayerState.CONNECTED
            }
            TransportLayerState.CONNECTED -> {
                //Timber.i("%s Got ACK", id)
                // ignore empty ACK packets, there is no packet loss that would make acknowledgements useful
            }
            TransportLayerState.CLOSING -> {
                //Timber.i("%s Got ACK (closing -> closed)", id)
                // closing handshake complete, set status to CLOSED
                state = TransportLayerState.CLOSED
                ConnectionCache.removeConnection(this)
            }
            else -> {
                // there is no good reason for an acknowledgement in any other flow state, abort
                Timber.e("%s Got ACK (empty, invalid state %s)", id, state)
                abortAndRst()
            }
        }
    }

    private fun handleSynAck() {
        // SYN ACK packets should not be sent by the client, abort
        Timber.e("%s Got SYN ACK (invalid)", id)
        abortAndRst()
    }

    private fun handleFinAck() {
        if (state == TransportLayerState.CLOSING) {
            //Timber.i("%s Got FIN ACK", id)
            // connection is closing, so this must be an actual FIN ACK - acknowledge it and close the connection for good
            increaseTheirSeqNum(1)
            val ackResponse = ipPacketBuilder.buildPacket(buildEmptyAck())
            writeToDevice(ackResponse)
        } else {
            // we're not expecting a FIN ACK, so we treat it like a normal FIN packet and start closing the connection
            handleFin()
        }
    }

    private fun handleFin() {
        //Timber.i("%s Got FIN", id)
        if (state == TransportLayerState.CLOSED) {
            // the connection is already closed, abort
            abortAndRst()
        } else {
            // close asynchronously
            closeSoft()
            increaseTheirSeqNum(1)
            val finAckResponse = ipPacketBuilder.buildPacket(buildFinAck())
            increaseOurSeqNum(1)
            writeToDevice(finAckResponse)
        }
    }

    /**
     * Handles the OP_READ event on a connection's [SocketChannel], which means that inbound data is available on the channel.
     */
    private fun unwrapInboundReadable() {

        // OP_READ event triggered
        var bytesRead: Int
        do {
            try {
                // read and forward the incoming data chunk by chunk (i.e. loop as long as data is read)
                inBuffer.clear()
                bytesRead = selectableChannel.read(inBuffer)
                if (bytesRead > 0) {
                    inBuffer.flip()
                    val rawData = Arrays.copyOf(inBuffer.array(), bytesRead)

                    // pass the payload to the application layer for processing and store the result
                    //TODO: below is just a placeholder for passInboundToEncryptionLayer(rawData)
                    wrapInbound(rawData)
                }
            }  catch (e: IOException) {
                bytesRead = -1
            }
        } while (bytesRead > 0) //TODO: improve

        // SocketChannel is closed
        if (bytesRead == -1) {
            selectionKey?.cancel()
            if (state == TransportLayerState.CLOSING) {
                // client and server agree that the connection is close
                state = TransportLayerState.CLOSED
                ConnectionCache.removeConnection(this)
            } else {
                // connection closed by server, move to CLOSING state and send a FIN to initiate the local closing handshake
                state = TransportLayerState.CLOSING
                val finPacket = ipPacketBuilder.buildPacket(buildFin())
                increaseOurSeqNum(1)
                writeToDevice(finPacket)
            }
        }
    }

    /**
     * Handles the OP_CONNECT event on a connection's [SocketChannel], which means that the channel is connected and ready for outbound data.
     */
    private fun unwrapInboundConnectable() {
        // complete the SocketChannel's connection process
        try {
            selectableChannel.finishConnect()
        } catch (e: IOException) {
            Timber.e(e, "%s Error connecting SocketChannel to %s:%s", id, ipPacketBuilder.remoteAddress, remotePort)
            abortAndRst()
            return
        }

        val socketChannel = selectionKey?.channel() as SocketChannel

        // make sure the SocketChannel is actually connected
        if (socketChannel.isConnected) {
            // prepare SocketChannel for incoming data and complete local handshake
            selectionKey.interestOps(SelectionKey.OP_READ)
            // advance the client-facing TCP handshake by sending a SYN ACK packet
            val synAckPacket = ipPacketBuilder.buildPacket(buildSynAck())
            increaseOurSeqNum(1)
            //Timber.d("%s SocketChannel connected", id)
            writeToDevice(synAckPacket)
        } else {
            Timber.e("%s Error connecting SocketChannel to %s:%s", id, ipPacketBuilder.remoteAddress, remotePort)
            abortAndRst()
        }
    }

    private fun abortAndRst() {
        //Timber.i("%s Abort and reset", id)
        selectionKey?.cancel()
        val rstResponse = ipPacketBuilder.buildPacket(buildRst())
        state = TransportLayerState.ABORTED
        closeHard()
        writeToDevice(rstResponse)
    }

    /**
     * Increases the client-side sequence number by the supplied amount.
     */
    private fun increaseTheirSeqNum(increase: Int) {
        theirSeqNum += increase.toLong()
    }

    /**
     * Increases the server-side sequence number by the supplied amount.
     */
    private fun increaseOurSeqNum(increase: Int) {
        ourSeqNum += increase.toLong()
    }

    override fun buildPayload(rawPayload: ByteArray): TcpPacket.Builder {
        return buildDataAck(rawPayload)
    }

    /**
     * Constructs a [TcpPacket.Builder] with the supplied TCP flags to be used by [IpPacketBuilder.buildPacket].
     */
    private fun buildTcpPayload(urg: Boolean, ack: Boolean, psh: Boolean, rst: Boolean, syn: Boolean, fin: Boolean, rawPayload: ByteArray): TcpPacket.Builder {
        val builder = TcpPacket.Builder()
            .srcAddr(ipPacketBuilder.remoteAddress)
            .dstAddr(ipPacketBuilder.localAddress)
            .srcPort(remotePort as TcpPort)
            .dstPort(localPort as TcpPort)
            .sequenceNumber(ourSeqNum.toInt())
            .acknowledgmentNumber(theirSeqNum.toInt())
            .dataOffset(5.toByte())
            .reserved(0.toByte())
            .urg(urg)
            .ack(ack)
            .psh(psh)
            .rst(rst)
            .syn(syn)
            .fin(fin)
            .window(window)
            .urgentPointer(0.toShort())
            .padding(ByteArray(0))
            .options(ArrayList())
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true)
            .paddingAtBuild(true)
        if (rawPayload.isNotEmpty()) {
            builder.payloadBuilder(UnknownPacket.newPacket(rawPayload, 0, rawPayload.size).builder)
        }
        return builder
    }

    /**
     * Convenience method that calls [buildTcpPayload] with the required flags to construct a SYN-ACK packet.
     */
    private fun buildSynAck(): TcpPacket.Builder {
        return buildTcpPayload(urg = false, ack = true, psh = false, rst = false, syn = true, fin = false, rawPayload = ByteArray(0))
    }

    /**
     * Convenience method that calls [buildTcpPayload] with the required flags to construct an ACK packet without an application-layer payload.
     */
    private fun buildEmptyAck(): TcpPacket.Builder {
        return buildTcpPayload(urg = false, ack = true, psh = false, rst = false, syn = false, fin = false, rawPayload = ByteArray(0))
    }

    /**
     * Convenience method that calls [buildTcpPayload] with the required flags to construct an around the supplied application-layer payload.
     */
    private fun buildDataAck(rawPayload: ByteArray): TcpPacket.Builder {
        return buildTcpPayload(urg = false, ack = true, psh = true, rst = false, syn = false, fin = false, rawPayload)
    }

    /**
     * Convenience method that calls [buildTcpPayload] with the required flags to construct an RST packet.
     */
    private fun buildRst(): TcpPacket.Builder {
        return buildTcpPayload(urg = false, ack = false, psh = false, rst = true, syn = false, fin = false, rawPayload = ByteArray(0))
    }

    /**
     * Convenience method that calls [buildTcpPayload] with the required flags to construct a FIN packet.
     */
    private fun buildFin(): TcpPacket.Builder {
        return buildTcpPayload(urg = false, ack = false, psh = false, rst = false, syn = false, fin = true, rawPayload = ByteArray(0))
    }

    /**
     * Convenience method that calls [buildTcpPayload] with the required flags to construct a FIN-ACK packet.
     */
    private fun buildFinAck(): TcpPacket.Builder {
        return buildTcpPayload(urg = false, ack = true, psh = false, rst = false, syn = false, fin = true, rawPayload = ByteArray(0))
    }

    companion object {
        fun buildStrayRst(strayPacket: IpPacket): TcpPacket.Builder? {
            if(strayPacket.payload is TcpPacket) {
                val tcpPacket = strayPacket.payload as TcpPacket
                return TcpPacket.Builder()
                    .srcAddr(strayPacket.header.dstAddr)
                    .dstAddr(strayPacket.header.srcAddr)
                    .srcPort(tcpPacket.header.dstPort)
                    .dstPort(tcpPacket.header.srcPort)
                    .sequenceNumber(tcpPacket.header.acknowledgmentNumber)
                    .acknowledgmentNumber(tcpPacket.header.sequenceNumber)
                    .dataOffset(5.toByte())
                    .reserved(0.toByte())
                    .urg(false)
                    .ack(false)
                    .psh(false)
                    .rst(true)
                    .syn(false)
                    .fin(false)
                    .window(tcpPacket.header.window)
                    .urgentPointer(0.toShort())
                    .padding(ByteArray(0))
                    .options(ArrayList())
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true)
                    .paddingAtBuild(true)
            } else {
                return null
            }
        }

    }
}