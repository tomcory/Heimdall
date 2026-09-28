package de.tomcory.heimdall.core.vpn.connection.transportLayer

import android.os.Handler
import android.system.OsConstants
import de.tomcory.heimdall.core.database.entity.Protocol
import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.components.DeviceWriteThread
import de.tomcory.heimdall.core.vpn.connection.inetLayer.IpPacketBuilder
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.Packet
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
import java.util.Arrays
import java.util.concurrent.atomic.AtomicLong

/**
 * Represents a transport-layer connection using TCP.
 *
 * @param componentManager
 * @param deviceWriter
 * @param initialPacket TCP segment from which the necessary metadata is extracted to create the instance (ideally the very first segment of a new socket).
 * @param ipPacketBuilder
 */
class TcpConnection internal constructor(
    componentManager: ComponentManager,
    deviceWriter: Handler,
    initialPacket: TcpPacket,
    ipPacketBuilder: IpPacketBuilder,
    remoteHost: String?
) : TransportLayerConnection(
    deviceWriter = deviceWriter,
    componentManager = componentManager,
    localPort = initialPacket.header.srcPort.valueAsInt(),
    remotePort = initialPacket.header.dstPort.valueAsInt(),
    remoteHost = remoteHost,
    ipPacketBuilder = ipPacketBuilder
) {

    private val window = initialPacket.header.window
    private val theirInitSeqNum = initialPacket.header.sequenceNumberAsLong
    private val ourInitSeqNum = (Math.random() * 0xFFFFFFF).toLong()

    // ourSeqNum is advanced both by the InboundTrafficHandler-driven data path (wrapInbound) and
    // by the OutboundTrafficHandler-driven close path (handleFin, on a device-initiated close) -
    // a genuine cross-thread read-modify-write, so a plain Long isn't safe here. theirSeqNum only
    // has one writer thread in practice, but is read from both, so it gets the same treatment for
    // consistency and to avoid relying on that asymmetry staying true.
    private val theirSeqNum = AtomicLong(theirInitSeqNum + 1) // SYN packets increase the client's sequence number by 1
    private val ourSeqNum = AtomicLong(ourInitSeqNum)

    /** The FIN-ACK segment sent to start our side of the closing handshake, cached so a retransmitted FIN from the device can be answered with the exact same segment instead of one built from an already-advanced sequence number. */
    private var pendingFinAck: IpPacket? = null

    override val protocol = Protocol.TCP
    override val appId: Int?
    override val appPackage: String?
    override val id: Long
    override val selectableChannel: SocketChannel
    override val selectionKey: SelectionKey?

    init {
        // these values must be initialised in this order because they each depend on the previous one
        appId = componentManager.appFinder.getAppId(ipPacketBuilder.localAddress, ipPacketBuilder.remoteAddress, localPort, remotePort, OsConstants.IPPROTO_TCP)
        appPackage = componentManager.appFinder.getAppPackage(appId)
        id = createDatabaseEntity()

        if(id > 0) {
            Timber.d("tcp$id Creating TCP Connection to ${ipPacketBuilder.remoteAddress.hostAddress}:${remotePort} ($remoteHost)")
        }

        selectableChannel = try {
            openChannel(ipPacketBuilder.remoteAddress)
        } catch (e: Exception) {
            Timber.e("tcp$id Error while creating TCP connection: ${e.message}")
            state = TransportLayerState.ABORTED
            deleteDatabaseEntity()
            SocketChannel.open()
        }
        selectionKey = if(state != TransportLayerState.ABORTED) {
            try {
                connectChannel(componentManager.selector)
            } catch (e: Exception) {
                Timber.e("tcp$id Error while creating TCP connection: ${e.message}")
                state = TransportLayerState.ABORTED
                deleteDatabaseEntity()
                try {
                    selectableChannel.close()
                } catch (closeException: Exception) {
                    Timber.e("tcp$id Error while closing leaked SocketChannel: ${closeException.message}")
                }
                null
            }
        } else {
            null
        }
    }

    /**
     * Opens a [SocketChannel] and throws all exceptions that occur during the process.
     *
     * @param remoteAddress The remote address to connect to.
     *
     * @return the opened and protected [SocketChannel]
     */
    private fun openChannel(remoteAddress: InetAddress): SocketChannel {
        state = TransportLayerState.CONNECTING
        val selectableChannel = SocketChannel.open()
        componentManager.protectSocket(selectableChannel.socket())
        selectableChannel.configureBlocking(false)
        selectableChannel.socket().keepAlive = true
        selectableChannel.socket().tcpNoDelay = true
        selectableChannel.socket().soTimeout = 0
        selectableChannel.socket().receiveBufferSize = componentManager.maxPacketSize
        selectableChannel.connect(InetSocketAddress(remoteAddress, remotePort))
        return selectableChannel
    }

    private fun connectChannel(selector: Selector): SelectionKey? {
        // register OP_READ interest for the channel
        synchronized(ComponentManager.selectorMonitor) {
            selector.wakeup()
            val selectionKey = try {
                selectableChannel.register(selector, SelectionKey.OP_CONNECT)
            } catch (e: Exception) {
                null
            }
            selectionKey?.attach(this)
            return selectionKey
        }
    }

    private fun writeToDevice(packet: IpPacket) {
        deviceWriter.sendMessage(deviceWriter.obtainMessage(DeviceWriteThread.WRITE_TCP, packet))
    }

    override fun unwrapOutbound(outgoingPacket: Packet) {
        if(state == TransportLayerState.ABORTED) {
            return
        }
        val tcpHeader = outgoingPacket.header as TcpPacket.TcpHeader
        if (tcpHeader.rst) {
            // RST takes precedence over any other flags that may also be set (e.g. RST+ACK)
            handleRst() // the client aborted the connection
        } else if (tcpHeader.ack) {
            if (outgoingPacket.payload != null && outgoingPacket.payload.length() > 0) {
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
        if(state == TransportLayerState.ABORTED) {
            return
        }
        if(selectionKey == null) {
            Timber.e("tcp$id SelectionKey is null")
            state = TransportLayerState.ABORTED
            return
        }

        if (!selectionKey.isValid) {
            Timber.e("tcp$id Invalid Selection key")
            closeHard()
            return
        }
        if (selectionKey.isConnectable) {
            unwrapInboundConnectable()
        } else if (selectionKey.isReadable) {
            unwrapInboundReadable()
        }
    }

    override fun wrapOutbound(payload: ByteArray) {
        if (payload.isNotEmpty()) {
            if(payload.size <= outBuffer.limit()) {
                outBuffer.clear()
                outBuffer.put(payload)
                outBuffer.flip()

                var bytesWritten = 0
                while (outBuffer.hasRemaining()) {
                    try {
                        bytesWritten += selectableChannel.write(outBuffer)
                    } catch (e: Exception) {
                        Timber.e("tcp$id Error writing to SocketChannel (${e.javaClass}, closing connection")
                        closeHard()
                        break
                    }
                }
                recordBytesOut(bytesWritten)
            } else {

                //TODO: this is a dirty hack to prevent buffer overflows for stupidly large reassembled payloads
                val largeBuffer = ByteBuffer.wrap(payload)

                var bytesWritten = 0
                while (largeBuffer.hasRemaining()) {
                    try {
                        bytesWritten += selectableChannel.write(largeBuffer)
                    } catch (e: IOException) {
                        Timber.e("tcp$id SocketChannel registered: ${selectableChannel.isRegistered}, connected: ${selectableChannel.isConnected}, open: ${selectableChannel.isOpen}")
                        Timber.e(e, "tcp$id Error writing to SocketChannel, closing connection")
                        closeHard()
                        break
                    } catch (e: BufferOverflowException) {
                        Timber.e(e, "tcp$id Error writing to SocketChannel, closing connection")
                        closeHard()
                        break
                    }
                }
                recordBytesOut(bytesWritten)
            }
        }
    }

    override fun wrapInbound(payload: ByteArray) {
        // if the application layer returned anything, write it to the device's VPN interface
        if (payload.isNotEmpty()) {
            if(payload.size <= componentManager.maxPacketSize) {
                // if the payload fits into a single TCP segment, wrap and write it directly
                val ackDataPacket = ipPacketBuilder.buildPacket(buildDataAck(payload))
                increaseOurSeqNum(payload.size)
                writeToDevice(ackDataPacket)
            } else {
                // if the payload exceeds the max. TCP payload size, split it into multiple segments
                //TODO: there has to be a better way...
                Timber.d("tcp$id Splitting large payload (${payload.size} bytes), because maxPacketSize is ${componentManager.maxPacketSize}")
                val largeBuffer = ByteBuffer.wrap(payload)
                while(largeBuffer.hasRemaining()) {
                    val temp = ByteArray(minOf(largeBuffer.limit() - largeBuffer.position(), componentManager.maxPacketSize))
                    largeBuffer.get(temp)
                    Timber.d("tcp$id Writing split payload (${temp.size} bytes, ${largeBuffer.limit() - largeBuffer.position()} remaining)")
                    val ackDataPacket = ipPacketBuilder.buildPacket(buildDataAck(temp))
                    increaseOurSeqNum(temp.size)
                    writeToDevice(ackDataPacket)
                }
            }
        }
    }

    private fun handleAckData(outgoingPacket: Packet) {
        if (state != TransportLayerState.CONNECTED) {
            // the connection is not ready to forward data, abort
            Timber.w("tcp$id Got ACK (data, invalid state $state)")
            closeHard()
        } else {
            increaseTheirSeqNum(outgoingPacket.payload.length())

            // acknowledge packet to the client by sending an empty ACK
            writeToDevice(ipPacketBuilder.buildPacket(buildEmptyAck()))

            // pass the payload to the encryption and application layers for processing and store the result
            outgoingPacket.payload?.let {
                passOutboundToEncryptionLayer(it)
            }
        }
    }

    private fun handleAckEmpty() {
        when (state) {
            TransportLayerState.CONNECTING -> {
                // establishing handshake complete, set status to CONNECTED
                state = TransportLayerState.CONNECTED
            }
            TransportLayerState.CONNECTED, TransportLayerState.CLOSED -> {
                // ignore empty ACK packets, there is no packet loss that would make acknowledgements useful
            }
            TransportLayerState.CLOSING -> {
                // closing handshake complete, set status to CLOSED and remove the connection from the cache
                closeChannel()
                state = TransportLayerState.CLOSED
                ConnectionCache.removeConnection(this)
            }
            else -> {
                // there is no good reason for an acknowledgement in any other flow state, abort
                Timber.w("tcp$id Got ACK (empty, invalid state $state)")
                closeHard()
            }
        }
    }

    private fun handleSynAck() {
        // SYN ACK packets should not be sent by the client, abort
        Timber.w("tcp$id Got SYN ACK (invalid)")
        closeHard()
    }

    /**
     * Handles a client-initiated RST by tearing down the connection immediately. No RST is echoed
     * back to the device: the client already knows the connection is gone, since it's the one that
     * sent the RST.
     */
    private fun handleRst() {
        Timber.d("tcp$id Got RST from client, closing connection")
        closeHard(abortClientSession = false)
    }

    private fun handleFinAck() {
        if (state == TransportLayerState.CLOSING) {
            // we already sent our FIN-ACK and are awaiting the device's final (plain) ACK; a
            // FIN(+ACK) arriving in this state is a retransmission of the device's original
            // closing FIN, not a new event - resend our cached FIN-ACK rather than advancing
            // sequence numbers again for something we've already accounted for.
            pendingFinAck?.let { writeToDevice(it) }
        } else {
            // we're not expecting a FIN ACK, so we treat it like a normal FIN packet and start closing the connection
            handleFin()
        }
    }

    private fun handleFin() {
        when (state) {
            TransportLayerState.CLOSED, TransportLayerState.ABORTED -> {
                // the connection is already closed, abort
                closeHard()
            }
            TransportLayerState.CLOSING -> {
                // a duplicate/retransmitted FIN while we're already waiting for the device's final
                // ACK to our own FIN-ACK (e.g. the original FIN-ACK was lost) - the outward-facing
                // channel is already closed and the sequence numbers already advanced, so resend
                // the exact same FIN-ACK segment rather than building a fresh (higher-sequenced) one.
                pendingFinAck?.let { writeToDevice(it) }
            }
            else -> {
                // close the outward-facing (remote-server) channel now, but leave the connection's
                // state at CLOSING and in the cache until the device acknowledges our FIN-ACK below
                // - this is a graceful, client-initiated close, not an abort, so don't also send a
                // client-facing RST; the FIN-ACK written below is the correct signal. The device's
                // final ACK is what finalizes the state to CLOSED and removes the connection from
                // the cache, via handleAckEmpty()'s CLOSING branch.
                closeSoft(abortClientSession = false, finalizeState = false)
                increaseTheirSeqNum(1)
                val finAckResponse = ipPacketBuilder.buildPacket(buildFinAck())
                increaseOurSeqNum(1)
                pendingFinAck = finAckResponse
                writeToDevice(finAckResponse)
            }
        }
    }

    /**
     * Handles the OP_READ event on a connection's [SocketChannel], which means that inbound data is available on the channel.
     */
    private fun unwrapInboundReadable() {
        // OP_READ event triggered
        var bytesRead: Int
        var totalBytesRead = 0
        do {
            try {
                // read and forward the incoming data chunk by chunk (i.e. loop as long as data is read)
                inBuffer.clear()
                bytesRead = selectableChannel.read(inBuffer)
                if (bytesRead > 0) {
                    totalBytesRead += bytesRead
                    inBuffer.flip()
                    val rawData = Arrays.copyOf(inBuffer.array(), bytesRead)

                    // pass the payload to the encryption layer for processing and store the result
                    passInboundToEncryptionLayer(rawData)
                }
            }  catch (e: IOException) {
                bytesRead = -1
            }
        } while (bytesRead > 0) // ignore the lint warning, bytesRead can definitely be greater than 0

        recordBytesIn(totalBytesRead)

        // SocketChannel is closed
        if (bytesRead == -1) {
            selectionKey?.cancel()
            // the remote side is done; release the socket/fd now regardless of which branch
            // below we take, instead of only deregistering the SelectionKey and leaking it
            closeChannel()
            if (state == TransportLayerState.CLOSING) {
                // client and server agree that the connection is close
                state = TransportLayerState.CLOSED
                ConnectionCache.removeConnection(this)
            } else {
                // connection closed by server, move to CLOSING state and send a FIN to initiate the local closing handshake
                Timber.d("tcp$id SocketChannel closed, state transition $state -> CLOSING")
                state = TransportLayerState.CLOSING
                val finPacket = ipPacketBuilder.buildPacket(buildFin())
                increaseOurSeqNum(1)
                writeToDevice(finPacket)
            }
        }
    }

    /**
     * Closes the outward-facing [SocketChannel], releasing its underlying fd. Safe to call
     * more than once ([java.nio.channels.Channel.close] is a no-op if already closed) - several
     * of the paths that call this may already have closed the channel via [closeSoft]/[closeHard].
     */
    private fun closeChannel() {
        try {
            selectableChannel.close()
        } catch (e: IOException) {
            Timber.e(e, "tcp$id Error closing SocketChannel")
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
            Timber.e(e, "tcp$id Error connecting SocketChannel to ${ipPacketBuilder.remoteAddress.hostAddress}:$remotePort")
            closeHard()
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
            Timber.e("tcp$id Error connecting SocketChannel to ${ipPacketBuilder.remoteAddress.hostAddress}:$remotePort")
            closeHard()
        }
    }

    /**
     * Closes the client-side connection by sending a RST packet and setting the connection's state to ABORTED.
     */
    override fun closeClientSession() {
        state = TransportLayerState.ABORTED
        val rstResponse = ipPacketBuilder.buildPacket(buildRst())
        writeToDevice(rstResponse)
    }

    /**
     * Increases the client-side sequence number by the supplied amount.
     */
    private fun increaseTheirSeqNum(increase: Int) {
        theirSeqNum.addAndGet(increase.toLong())
    }

    /**
     * Increases the server-side sequence number by the supplied amount.
     */
    private fun increaseOurSeqNum(increase: Int) {
        ourSeqNum.addAndGet(increase.toLong())
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
            .srcPort(TcpPort(remotePort.toShort(), ""))
            .dstPort(TcpPort(localPort.toShort(), ""))
            .sequenceNumber(ourSeqNum.get().toInt())
            .acknowledgmentNumber(theirSeqNum.get().toInt())
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