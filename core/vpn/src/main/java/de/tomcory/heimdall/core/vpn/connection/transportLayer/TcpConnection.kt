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

    /**
     * Guards the transitions around closing. The client's FIN is handled on the
     * OutboundTrafficHandler thread and the remote side's EOF on the InboundTrafficHandler
     * thread, and each one's outcome depends on whether the other has already happened.
     */
    private val closeLock = Any()

    /**
     * Wall-clock time of the last sign of life while [TransportLayerState.HALF_CLOSED]: entering
     * the state, or inbound data arriving in it. Used by [sweepStaleConnections].
     */
    @Volatile
    private var halfClosedActivityAt: Long = 0

    // The closing handshake is complete once both of these are true: the device has sent its
    // FIN (and we have acknowledged it), and the device has acknowledged ours. Which of the two
    // happens first depends on who closes. Both are only touched under closeLock.

    /** Whether the device's FIN has been received and counted in [theirSeqNum]. */
    private var deviceFinReceived = false

    /** Whether the device has acknowledged our FIN. */
    private var ourFinAcknowledged = false

    /** The acknowledgement number that covers our FIN, as it appears in a TCP header. Only meaningful once our FIN was sent. */
    private var ourFinAckNumber = 0

    /** Wall-clock time at which our FIN was sent, used by [sweepStaleConnections]. */
    @Volatile
    private var closingSince: Long = 0

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
        // The receive buffer is deliberately left at the platform default. It bounds the window
        // the remote host may send into, and shrinking it (it used to be set to maxPacketSize)
        // halved download throughput (docs/vpn-mitm-audit.md PKT-34).
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
                handleAckEmpty(tcpHeader.acknowledgmentNumber)
            }
            if (tcpHeader.syn) {
                handleSynAck() // this should not happen, since we never initiate a handshake
            } else if (tcpHeader.fin) {
                handleFin(tcpHeader.acknowledgmentNumber) // this is either the first or second packet of the closing handshake
            }
        } else if (tcpHeader.fin) {
            handleFin(null) // closing handshake was initiated
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

    /**
     * @param ackNumber The acknowledgement number of the device's segment.
     */
    private fun handleAckEmpty(ackNumber: Int) {
        when (state) {
            TransportLayerState.CONNECTING -> {
                // establishing handshake complete, set status to CONNECTED
                state = TransportLayerState.CONNECTED
            }
            TransportLayerState.CONNECTED, TransportLayerState.HALF_CLOSED, TransportLayerState.CLOSED -> {
                // ignore empty ACK packets, there is no packet loss that would make acknowledgements useful
            }
            TransportLayerState.CLOSING -> synchronized(closeLock) {
                // Only the ACK that covers our FIN moves the closing handshake forward. Others
                // acknowledge data sent before the FIN and say nothing about the close
                // (docs/vpn-mitm-audit.md PKT-35).
                if (state == TransportLayerState.CLOSING && ackNumber == ourFinAckNumber) {
                    ourFinAcknowledged = true
                    finishCloseIfComplete()
                }
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
        // only a live connection counts as the client giving up - an RST after the remote side
        // already started closing (CLOSING) or after teardown isn't the client's decision
        if (state == TransportLayerState.CONNECTING || state == TransportLayerState.CONNECTED) {
            notifyClientClosed()
        }
        closeHard(abortClientSession = false)
    }

    /**
     * Handles a FIN from the device.
     *
     * @param ackNumber The acknowledgement number of the segment, or null if it has no ACK flag.
     */
    private fun handleFin(ackNumber: Int?) {
        synchronized(closeLock) {
            handleFinLocked(ackNumber)
        }
    }

    /**
     * Sets the connection to CLOSED and removes it from the cache once the closing handshake is
     * complete in both directions. Must be called under [closeLock].
     */
    private fun finishCloseIfComplete() {
        if (deviceFinReceived && ourFinAcknowledged) {
            closeChannel()
            state = TransportLayerState.CLOSED
            ConnectionCache.removeConnection(this)
        }
    }

    private fun handleFinLocked(ackNumber: Int?) {
        when (state) {
            TransportLayerState.CLOSED, TransportLayerState.ABORTED -> {
                // the connection is already closed, abort
                closeHard()
            }
            TransportLayerState.HALF_CLOSED -> {
                // a retransmitted FIN: our ACK for it was lost. The sequence numbers already
                // account for the FIN, so an empty ACK built now acknowledges it again.
                writeToDevice(ipPacketBuilder.buildPacket(buildEmptyAck()))
            }
            TransportLayerState.CONNECTED -> {
                // A FIN only means the client has finished sending. It may still be waiting for
                // the remote host's reply (docs/vpn-mitm-audit.md PKT-30), so if the layers above
                // can carry it, pass the half-close on instead of closing the connection.
                notifyClientClosed()
                if (encryptionLayerSupportsHalfClose() && shutdownOutwardOutput()) {
                    increaseTheirSeqNum(1)
                    deviceFinReceived = true
                    halfClosedActivityAt = System.currentTimeMillis()
                    state = TransportLayerState.HALF_CLOSED
                    writeToDevice(ipPacketBuilder.buildPacket(buildEmptyAck()))
                } else {
                    closeFully()
                }
            }
            TransportLayerState.CLOSING -> {
                if (deviceFinReceived) {
                    // a duplicate/retransmitted FIN while we're already waiting for the device's final
                    // ACK to our own FIN-ACK (e.g. the original FIN-ACK was lost) - the outward-facing
                    // channel is already closed and the sequence numbers already advanced, so resend
                    // the exact same FIN-ACK segment rather than building a fresh (higher-sequenced) one.
                    pendingFinAck?.let { writeToDevice(it) }
                } else {
                    // The remote host closed first, we sent our FIN, and this is the device's
                    // own FIN: count it and acknowledge it. It usually acknowledges our FIN in
                    // the same segment, which completes the handshake.
                    deviceFinReceived = true
                    increaseTheirSeqNum(1)
                    // the cached FIN-ACK predates the device's FIN, so it must not be resent
                    pendingFinAck = null
                    writeToDevice(ipPacketBuilder.buildPacket(buildEmptyAck()))
                    if (ackNumber == ourFinAckNumber) {
                        ourFinAcknowledged = true
                    }
                    finishCloseIfComplete()
                }
            }
            else -> {
                // the outward-facing channel isn't connected yet, so there is nothing to keep
                // open for a reply
                notifyClientClosed()
                closeFully()
            }
        }
    }

    /**
     * Answers the client's FIN by closing the whole connection at once. The outward-facing
     * channel is closed now, but the connection stays [TransportLayerState.CLOSING] and in the
     * cache until the device acknowledges our FIN-ACK - this is a graceful, client-initiated
     * close, not an abort, so no client-facing RST is sent. The device's final ACK finalizes the
     * state to CLOSED and removes the connection from the cache (handleAckEmpty).
     */
    private fun closeFully() {
        closeSoft(abortClientSession = false, finalizeState = false)
        increaseTheirSeqNum(1)
        deviceFinReceived = true
        sendFinAck()
    }

    /**
     * Sends our FIN-ACK to the device and caches it for retransmission. The caller is
     * responsible for the connection being in (or moving to) [TransportLayerState.CLOSING].
     */
    private fun sendFinAck() {
        val finAckResponse = ipPacketBuilder.buildPacket(buildFinAck())
        increaseOurSeqNum(1)
        // our FIN occupies one sequence number, so the ACK that covers it carries the next one
        ourFinAckNumber = ourSeqNum.get().toInt()
        closingSince = System.currentTimeMillis()
        pendingFinAck = finAckResponse
        writeToDevice(finAckResponse)
    }

    /**
     * Shuts down the sending side of the outward-facing channel, which sends a FIN to the remote
     * host while leaving the channel readable.
     *
     * @return false if the channel could not be half-closed, e.g. because it is already closed.
     */
    private fun shutdownOutwardOutput(): Boolean {
        return try {
            selectableChannel.shutdownOutput()
            true
        } catch (e: IOException) {
            Timber.w("tcp$id Could not shut down the SocketChannel's output (${e.javaClass.simpleName}), closing the connection instead")
            false
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

                    if (state == TransportLayerState.HALF_CLOSED) {
                        halfClosedActivityAt = System.currentTimeMillis()
                    }

                    // pass the payload to the encryption layer for processing and store the result
                    passInboundToEncryptionLayer(rawData)
                }
            }  catch (e: IOException) {
                bytesRead = -1
            }
        } while (bytesRead > 0) // ignore the lint warning, bytesRead can definitely be greater than 0

        recordBytesIn(totalBytesRead)

        // SocketChannel is closed
        if (bytesRead == -1) synchronized(closeLock) {
            selectionKey?.cancel()
            // the remote side is done; release the socket/fd now regardless of which branch
            // below we take, instead of only deregistering the SelectionKey and leaking it
            closeChannel()
            if (state == TransportLayerState.CLOSING) {
                // client and server agree that the connection is close
                state = TransportLayerState.CLOSED
                ConnectionCache.removeConnection(this)
            } else if (state == TransportLayerState.HALF_CLOSED) {
                // the client finished sending earlier and now the remote host has too: complete
                // the close with our FIN-ACK. The device's final ACK finalizes the state to
                // CLOSED and removes the connection from the cache (handleAckEmpty).
                Timber.d("tcp$id SocketChannel closed, state transition $state -> CLOSING")
                state = TransportLayerState.CLOSING
                sendFinAck()
            } else {
                // The remote host closed first: move to CLOSING and start the closing handshake
                // with a FIN-ACK. It has to carry the ACK flag like every segment of an
                // established connection, or the device discards it and never learns that the
                // remote host is done (docs/vpn-mitm-audit.md PKT-35). The device's ACK for it
                // and the device's own FIN complete the handshake.
                Timber.d("tcp$id SocketChannel closed, state transition $state -> CLOSING")
                state = TransportLayerState.CLOSING
                sendFinAck()
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
     * Convenience method that calls [buildTcpPayload] with the required flags to construct a FIN-ACK packet.
     */
    private fun buildFinAck(): TcpPacket.Builder {
        return buildTcpPayload(urg = false, ack = true, psh = false, rst = false, syn = false, fin = true, rawPayload = ByteArray(0))
    }

    companion object {
        /**
         * How long a connection may stay [TransportLayerState.HALF_CLOSED] without any inbound
         * data before [sweepStaleConnections] aborts it.
         */
        const val DEFAULT_HALF_CLOSED_TIMEOUT_MS = 2 * 60 * 1000L

        /**
         * How long a connection may stay [TransportLayerState.CLOSING] before
         * [sweepStaleConnections] drops it. An app is free to keep its side of a connection open
         * long after the remote host has closed, e.g. in a connection pool.
         */
        const val DEFAULT_CLOSING_TIMEOUT_MS = 2 * 60 * 1000L

        /**
         * Removes cached [TcpConnection]s that are waiting for something that may never come:
         *
         * - [TransportLayerState.HALF_CLOSED] without inbound data for longer than
         *   [halfClosedTimeoutMs]. Such a connection normally ends when the remote host closes
         *   its side. One whose remote host neither sends nor closes would otherwise keep its
         *   SocketChannel until the VPN stops. It is aborted, which resets the device's side.
         * - [TransportLayerState.CLOSING] for longer than [closingTimeoutMs]: our FIN is out, but
         *   the device hasn't finished its part of the closing handshake. The outward-facing
         *   channel is already closed, so only the cache entry is dropped, without a reset.
         *
         * @param now Injectable for testing; defaults to the real current time.
         */
        fun sweepStaleConnections(
            halfClosedTimeoutMs: Long = DEFAULT_HALF_CLOSED_TIMEOUT_MS,
            closingTimeoutMs: Long = DEFAULT_CLOSING_TIMEOUT_MS,
            now: Long = System.currentTimeMillis()
        ) {
            val connections = ConnectionCache.allConnections().filterIsInstance<TcpConnection>()

            connections
                .filter { it.state == TransportLayerState.HALF_CLOSED && now - it.halfClosedActivityAt > halfClosedTimeoutMs }
                .forEach { connection ->
                    try {
                        Timber.d("tcp${connection.id} aborting half-closed TCP connection to ${connection.remoteHost ?: connection.ipPacketBuilder.remoteAddress.hostAddress}:${connection.remotePort} (no inbound data for over ${halfClosedTimeoutMs}ms)")
                        connection.closeHard()
                    } catch (e: Throwable) {
                        Timber.e(e, "Error closing half-closed TCP connection during sweep")
                    }
                }

            connections
                .filter { it.state == TransportLayerState.CLOSING && it.closingSince > 0 && now - it.closingSince > closingTimeoutMs }
                .forEach { connection ->
                    try {
                        Timber.d("tcp${connection.id} dropping TCP connection to ${connection.remoteHost ?: connection.ipPacketBuilder.remoteAddress.hostAddress}:${connection.remotePort} whose closing handshake the device never finished")
                        connection.closeHard(abortClientSession = false)
                    } catch (e: Throwable) {
                        Timber.e(e, "Error dropping closing TCP connection during sweep")
                    }
                }
        }

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