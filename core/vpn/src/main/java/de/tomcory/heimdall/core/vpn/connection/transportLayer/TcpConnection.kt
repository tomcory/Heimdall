package de.tomcory.heimdall.core.vpn.connection.transportLayer

import android.os.Handler
import android.system.OsConstants
import de.tomcory.heimdall.core.database.entity.Protocol
import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.components.DeviceWriteThread
import de.tomcory.heimdall.core.vpn.connection.inetLayer.IpPacketBuilder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
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
import java.nio.channels.CancelledKeyException
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.ArrayDeque
import java.util.Arrays
import java.util.concurrent.atomic.AtomicBoolean
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

    /** The FIN-ACK segment sent to start our side of the closing handshake, cached so a retransmitted FIN from the device can be answered with the exact same segment instead of one built from an already-advanced sequence number. Written under [sendLock]. */
    @Volatile
    private var pendingFinAck: IpPacket? = null

    // Sending to the device (docs/vpn-mitm-audit.md PKT-42). Data for the device is queued and
    // sent only as far as the device's receive window allows. Everything a segment's sequence
    // number depends on happens under sendLock, so that segments are built and handed to the
    // device writer in sequence order whichever thread sends them: the selector thread
    // (plaintext and passed-through data), a TLS connection's own dispatcher (decrypted data)
    // or the thread that handles the device's packets (when an ACK opens the window).
    //
    // Nothing is ever retransmitted. A TUN interface does not lose packets, so what was sent
    // inside the window has arrived.
    private val sendLock = Any()

    /** Data for the device that the window has not let through yet, in order. Guarded by [sendLock]. */
    private val sendQueue = ArrayDeque<ByteBuffer>()

    /** Bytes in [sendQueue]. Written under [sendLock]. */
    @Volatile
    private var queuedBytes = 0L

    /**
     * The highest acknowledgement number received from the device, as it appears in a TCP
     * header. Our SYN occupies one sequence number, so this is where it starts. Guarded by
     * [sendLock].
     */
    private var acknowledgedByDevice = (ourInitSeqNum + 1).toInt()

    /**
     * The receive window the device advertised last, in bytes. Our SYN-ACK carries no options,
     * so window scaling is not in effect in either direction and the header field is the window.
     * Guarded by [sendLock].
     */
    private var deviceWindow = initialPacket.header.windowAsInt

    /** Whether our FIN is to be sent once [sendQueue] is empty. Guarded by [sendLock]. */
    private var finRequested = false

    /** Whether our FIN has been sent. Written under [sendLock]. */
    @Volatile
    private var finSent = false

    /** Whether reading from the outward-facing channel is suspended because of the backlog. Guarded by [sendLock]. */
    private var readPaused = false

    /** Wall-clock time at which data was last sent to the device, or queued while nothing was waiting. */
    @Volatile
    private var lastSendProgressAt = 0L

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

    /** The acknowledgement number that covers our FIN, as it appears in a TCP header. Only meaningful once [finSent]. Written under [sendLock]. */
    @Volatile
    private var ourFinAckNumber = 0

    /** Whether the remote host's close has been passed on to the device (see [deliverRemoteClose]). */
    private val remoteCloseDelivered = AtomicBoolean(false)

    /** Whether our SYN-ACK has been sent to the device, i.e. the outward-facing channel is connected. */
    @Volatile
    private var synAckSent = false

    /**
     * Wall-clock time of the last progress towards closing: our FIN being requested, data that
     * has to go out before it being sent, or the FIN itself. Used by [sweepStaleConnections].
     */
    @Volatile
    private var closingSince: Long = 0

    override val protocol = Protocol.TCP
    // Filled in by setUp(), which runs off the thread that handles the device's packets. Until
    // then the connection is CONNECTING and the device has only sent its SYN, so nothing reads
    // them for anything but log output.
    @Volatile
    override var appId: Int? = null
        private set
    @Volatile
    override var appPackage: String? = null
        private set
    @Volatile
    override var id: Long = 0
        private set
    @Volatile
    override var selectionKey: SelectionKey? = null
        private set

    override val selectableChannel: SocketChannel = try {
        SocketChannel.open()
    } catch (e: Exception) {
        Timber.e("Error while creating TCP connection: ${e.message}")
        state = TransportLayerState.ABORTED
        // a placeholder that is never connected, so that the property is always usable
        SocketChannel.open()
    }

    /**
     * Does everything a new connection needs that can block: finding the app that owns the
     * connection (a binder call), protecting the socket from the VPN (another one), connecting
     * it (which involves netd) and registering it with the selector. On the thread that handles
     * the device's packets this held up every other connection's packets, and with them their
     * ACKs, for as long as new connections kept coming (docs/vpn-mitm-audit.md PKT-41).
     *
     * The device has only sent its SYN at this point and waits for our SYN-ACK, which is sent
     * once the outward-facing channel is connected ([unwrapInboundConnectable]).
     */
    private fun setUp() {
        try {
            // these values must be initialised in this order because they each depend on the previous one
            appId = componentManager.appFinder.getAppId(ipPacketBuilder.localAddress, ipPacketBuilder.remoteAddress, localPort, remotePort, OsConstants.IPPROTO_TCP)
            appPackage = componentManager.appFinder.getAppPackage(appId)

            if (state != TransportLayerState.CONNECTING) {
                // closed in the meantime (the device reset the connection, or the VPN stopped)
                return
            }
            id = createDatabaseEntity()

            if(id > 0) {
                Timber.d("tcp$id Creating TCP Connection to ${ipPacketBuilder.remoteAddress.hostAddress}:${remotePort} ($remoteHost)")
            }

            connectChannel(ipPacketBuilder.remoteAddress)
            selectionKey = registerChannel(componentManager.selector)

            // The connection may have been closed while the channel was being registered.
            // Closing a channel cancels its keys; doing it again here covers a close that came
            // just before the registration. (CONNECTED is possible by now and is fine: the
            // selector thread may already have completed the handshake.)
            when (state) {
                TransportLayerState.CLOSING, TransportLayerState.CLOSED, TransportLayerState.ABORTED -> closeChannel()
                else -> {}
            }
        } catch (e: Exception) {
            if (state == TransportLayerState.CONNECTING) {
                Timber.e("tcp$id Error while creating TCP connection: ${e.message}")
                state = TransportLayerState.ABORTED
                deleteDatabaseEntity()
            }
            closeChannel()
        }
    }

    /**
     * Protects and connects the [SocketChannel] and throws all exceptions that occur during the process.
     *
     * @param remoteAddress The remote address to connect to.
     */
    private fun connectChannel(remoteAddress: InetAddress) {
        componentManager.protectSocket(selectableChannel.socket())
        selectableChannel.configureBlocking(false)
        selectableChannel.socket().keepAlive = true
        selectableChannel.socket().tcpNoDelay = true
        selectableChannel.socket().soTimeout = 0
        // The receive buffer is deliberately left at the platform default. It bounds the window
        // the remote host may send into, and shrinking it (it used to be set to maxPacketSize)
        // halved download throughput (docs/vpn-mitm-audit.md PKT-34).
        selectableChannel.connect(InetSocketAddress(remoteAddress, remotePort))
    }

    private fun registerChannel(selector: Selector): SelectionKey {
        // register OP_CONNECT interest for the channel
        synchronized(ComponentManager.selectorMonitor) {
            selector.wakeup()
            return selectableChannel.register(selector, SelectionKey.OP_CONNECT, this)
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
        } else if (tcpHeader.syn) {
            if (tcpHeader.ack) {
                handleSynAck() // this should not happen, since we never initiate a handshake
            }
        } else {
            if (tcpHeader.ack) {
                handleAckField(tcpHeader)
            }
            val payloadLength = outgoingPacket.payload?.length() ?: 0
            if (payloadLength == 0 && !tcpHeader.fin) {
                if (tcpHeader.ack) {
                    handleAckEmpty(tcpHeader.sequenceNumber, tcpHeader.acknowledgmentNumber)
                }
                return
            }
            if (tcpHeader.ack && state == TransportLayerState.CONNECTING && synAckSent) {
                // The ACK that completes the handshake was lost or overtaken by this segment,
                // which acknowledges our SYN-ACK just as well.
                state = TransportLayerState.CONNECTED
            }
            if (acceptInOrder(outgoingPacket, tcpHeader, payloadLength) && tcpHeader.fin) {
                // this is either the first or second packet of the closing handshake
                handleFin(if (tcpHeader.ack) tcpHeader.acknowledgmentNumber else null)
            }
        }
    }

    /**
     * Checks a segment that occupies sequence space (data, a FIN, or both) against the next
     * sequence number expected from the device, and forwards only data that is new
     * (docs/vpn-mitm-audit.md PKT-39). The device retransmits whenever an ACK of ours is late,
     * so duplicates are routine. Forwarding one repeats bytes in the stream, which a TLS peer
     * rejects as a bad record.
     *
     * - A segment that starts at the expected sequence number is forwarded.
     * - One that lies entirely below it was already received: it is acknowledged again.
     * - One that starts below and reaches beyond it is forwarded from the expected byte on.
     * - One that starts above it follows a gap: it is dropped and the expected sequence number is
     *   acknowledged again, which makes the device retransmit from there. Nothing is buffered
     *   for reordering.
     *
     * @return whether the segment's FIN, if it has one, should be handled: it is either next in
     * the stream or a retransmission of the FIN that was already counted.
     */
    private fun acceptInOrder(outgoingPacket: Packet, tcpHeader: TcpPacket.TcpHeader, payloadLength: Int): Boolean {
        // How far the segment starts below the expected sequence number. Sequence numbers wrap
        // around at 32 bits, and so does this subtraction, so the sign of the result is right on
        // either side of the wrap.
        val alreadyReceived = theirSeqNum.get().toInt() - tcpHeader.sequenceNumber
        // the same for the position just past the segment's data, which is where its FIN sits
        val endAlreadyReceived = alreadyReceived - payloadLength

        if (alreadyReceived < 0) {
            Timber.d("tcp$id Dropping out-of-order segment (${-alreadyReceived} bytes ahead, $payloadLength bytes)")
            sendEmptyAck()
            return false
        }

        if (payloadLength > 0) {
            if (endAlreadyReceived >= 0) {
                // nothing new in it; whether to acknowledge it again is decided below
                Timber.d("tcp$id Ignoring retransmitted segment ($payloadLength bytes)")
            } else if (!handleAckData(outgoingPacket.payload, alreadyReceived)) {
                return false
            }
        }

        if (tcpHeader.fin) {
            val retransmittedFin = synchronized(closeLock) { deviceFinReceived } && endAlreadyReceived == 1
            if (endAlreadyReceived <= 0 || retransmittedFin) {
                return true
            }
        }

        if (endAlreadyReceived >= 0) {
            sendEmptyAck()
        }
        return false
    }

    override fun unwrapInbound() {
        if(state == TransportLayerState.ABORTED) {
            return
        }
        // The selector can report the channel before setUp() has stored the key it got from
        // the registration, so ask the channel for it.
        val selectionKey = this.selectionKey ?: selectableChannel.keyFor(componentManager.selector)
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
            unwrapInboundConnectable(selectionKey)
        } else if (selectionKey.isReadable) {
            unwrapInboundReadable(selectionKey)
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
        if (payload.isEmpty()) {
            return
        }
        synchronized(sendLock) {
            if (sendQueue.isEmpty()) {
                lastSendProgressAt = System.currentTimeMillis()
            }
            sendQueue.addLast(ByteBuffer.wrap(payload))
            queuedBytes += payload.size
            flushSendQueue()
        }
    }

    /**
     * Sends queued data to the device as far as its receive window allows, then our FIN if one
     * is due, and lets the outward-facing channel be read again once the backlog is small
     * enough. Must be called under [sendLock].
     */
    private fun flushSendQueue() {
        if (state == TransportLayerState.CLOSED || state == TransportLayerState.ABORTED) {
            // the device's side of the connection is gone, there is nobody to send to
            sendQueue.clear()
            queuedBytes = 0
            return
        }

        var sent = false
        while (true) {
            val head = sendQueue.peekFirst() ?: break
            // sequence numbers wrap around at 32 bits, and so does this subtraction
            val unacknowledged = ourSeqNum.get().toInt() - acknowledgedByDevice
            val available = deviceWindow - unacknowledged
            if (available <= 0) {
                break
            }
            val length = minOf(head.remaining(), available, componentManager.maxPacketSize)
            val segment = if (head.position() == 0 && length == head.capacity()) {
                head.position(length)
                head.array()
            } else {
                ByteArray(length).also { head.get(it) }
            }
            if (!head.hasRemaining()) {
                sendQueue.removeFirst()
            }
            queuedBytes -= length

            val packet = ipPacketBuilder.buildPacket(buildDataAck(segment))
            increaseOurSeqNum(length)
            writeToDevice(packet)
            sent = true
        }

        if (sent) {
            val now = System.currentTimeMillis()
            lastSendProgressAt = now
            if (finRequested) {
                closingSince = now
            }
            if (state == TransportLayerState.HALF_CLOSED) {
                halfClosedActivityAt = now
            }
        }

        if (sendQueue.isEmpty() && finRequested && !finSent) {
            sendFinAck()
        }

        resumeReadingIfBacklogAllows()
    }

    /**
     * Takes note of what a segment from the device acknowledges and of the receive window it
     * advertises, and sends whatever that lets through.
     */
    private fun handleAckField(tcpHeader: TcpPacket.TcpHeader) {
        synchronized(sendLock) {
            val ackNumber = tcpHeader.acknowledgmentNumber
            // Wrap-safe comparisons: the segment must not acknowledge less than an earlier one
            // did (then its window is out of date as well), nor anything we have not sent.
            val isCurrent = ackNumber - acknowledgedByDevice >= 0
            val isPlausible = ourSeqNum.get().toInt() - ackNumber >= 0
            if (isCurrent && isPlausible) {
                acknowledgedByDevice = ackNumber
                deviceWindow = tcpHeader.windowAsInt
                flushSendQueue()
            }
        }
    }

    /** Data read from the remote host that has not reached the device yet, wherever it is waiting. */
    private fun inboundBacklog(): Long = queuedBytes + inboundBytesInProcess

    /**
     * Stops reading from the outward-facing channel if too much of what was read is still
     * waiting to be sent to the device. The remote host's data then stays in the socket buffer,
     * and TCP's own flow control slows the remote host down.
     *
     * @return whether reading is suspended.
     */
    private fun pauseReadingIfBacklogged(selectionKey: SelectionKey): Boolean {
        synchronized(sendLock) {
            if (inboundBacklog() < SEND_BACKLOG_HIGH) {
                return false
            }
            readPaused = true
            try {
                selectionKey.interestOps(0)
            } catch (e: CancelledKeyException) {
                // the channel was closed in the meantime
            }
            return true
        }
    }

    /** Must be called under [sendLock]. */
    private fun resumeReadingIfBacklogAllows() {
        if (!readPaused || inboundBacklog() > SEND_BACKLOG_LOW) {
            return
        }
        readPaused = false
        val selectionKey = selectableChannel.keyFor(componentManager.selector) ?: return
        try {
            // Unlike registering a channel, changing a key's interest set does not wait for a
            // select() in progress, so this needs no selectorMonitor. The wake-up makes the
            // selector notice the change.
            selectionKey.interestOps(SelectionKey.OP_READ)
            componentManager.selector.wakeup()
        } catch (e: CancelledKeyException) {
            // the channel was closed in the meantime
        }
    }

    override fun onInboundBacklogChanged() {
        synchronized(sendLock) {
            resumeReadingIfBacklogAllows()
        }
    }

    /**
     * Sends an empty ACK to the device. Under [sendLock] like everything else that is sent, so
     * that its sequence number is not one that data sent at the same moment has already passed.
     */
    private fun sendEmptyAck() {
        synchronized(sendLock) {
            writeToDevice(ipPacketBuilder.buildPacket(buildEmptyAck()))
        }
    }

    /**
     * Asks the device for its current receive window if data has been waiting for it for a
     * while. The device announces on its own when its window opens, and the TUN interface does
     * not lose that announcement, so this is only a safeguard against waiting forever. The
     * probe is an empty segment one below the next sequence number, which a TCP stack answers
     * with an ACK.
     */
    private fun probeDeviceWindow(now: Long, stalledForMs: Long) {
        synchronized(sendLock) {
            if (sendQueue.isEmpty() || now - lastSendProgressAt < stalledForMs) {
                return
            }
            if (state == TransportLayerState.CLOSED || state == TransportLayerState.ABORTED) {
                return
            }
            val probe = buildEmptyAck().sequenceNumber(ourSeqNum.get().toInt() - 1)
            writeToDevice(ipPacketBuilder.buildPacket(probe))
        }
    }

    /**
     * Forwards the new data of a segment from the device.
     *
     * @param payload The segment's payload.
     * @param alreadyReceived How many bytes at the start of the payload were received before.
     * @return false if the connection was aborted because it is in no state to forward data.
     */
    private fun handleAckData(payload: Packet, alreadyReceived: Int): Boolean {
        if (state != TransportLayerState.CONNECTED) {
            // the connection is not ready to forward data, abort
            Timber.w("tcp$id Got ACK (data, invalid state $state)")
            closeHard()
            return false
        }

        increaseTheirSeqNum(payload.length() - alreadyReceived)

        // acknowledge packet to the client by sending an empty ACK
        sendEmptyAck()

        // pass the payload to the encryption and application layers for processing and store the result
        if (alreadyReceived == 0) {
            passOutboundToEncryptionLayer(payload)
        } else {
            Timber.d("tcp$id Skipping $alreadyReceived retransmitted bytes at the start of a segment (${payload.length()} bytes)")
            val rawData = payload.rawData
            passOutboundToEncryptionLayer(UnknownPacket.newPacket(rawData, alreadyReceived, rawData.size - alreadyReceived))
        }
        return true
    }

    /**
     * @param sequenceNumber The sequence number of the device's segment.
     * @param ackNumber The acknowledgement number of the device's segment.
     */
    private fun handleAckEmpty(sequenceNumber: Int, ackNumber: Int) {
        when (state) {
            TransportLayerState.CONNECTING -> {
                // establishing handshake complete, set status to CONNECTED
                state = TransportLayerState.CONNECTED
            }
            TransportLayerState.CONNECTED, TransportLayerState.HALF_CLOSED -> {
                // An empty segment one below the expected sequence number is a keep-alive probe,
                // which the device expects to be answered. Other empty ACKs are ignored, there
                // is no packet loss that would make acknowledgements useful.
                if (theirSeqNum.get().toInt() - sequenceNumber == 1) {
                    sendEmptyAck()
                }
            }
            TransportLayerState.CLOSED -> {
                // nothing left to acknowledge
            }
            TransportLayerState.CLOSING -> synchronized(closeLock) {
                // Only the ACK that covers our FIN moves the closing handshake forward. Others
                // acknowledge data sent before the FIN and say nothing about the close
                // (docs/vpn-mitm-audit.md PKT-35).
                if (state == TransportLayerState.CLOSING && finSent && ackNumber == ourFinAckNumber) {
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
                sendEmptyAck()
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
                    sendEmptyAck()
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
                    // If our FIN has not gone out yet, because data that precedes it is still
                    // waiting for the device's window, acknowledge the device's FIN again.
                    pendingFinAck?.let { writeToDevice(it) } ?: sendEmptyAck()
                } else {
                    // The remote host closed first, we sent our FIN, and this is the device's
                    // own FIN: count it and acknowledge it. It usually acknowledges our FIN in
                    // the same segment, which completes the handshake.
                    deviceFinReceived = true
                    increaseTheirSeqNum(1)
                    // the cached FIN-ACK predates the device's FIN, so it must not be resent
                    pendingFinAck = null
                    sendEmptyAck()
                    if (finSent && ackNumber == ourFinAckNumber) {
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
        if (!requestFin()) {
            // our FIN-ACK would have acknowledged the device's FIN; it has to wait, so do that now
            sendEmptyAck()
        }
    }

    /**
     * Has our FIN sent to the device as soon as everything queued for it has been sent, which
     * is at once if nothing is queued. The caller is responsible for the connection being in
     * (or moving to) [TransportLayerState.CLOSING].
     *
     * @return whether the FIN was sent at once.
     */
    private fun requestFin(): Boolean {
        synchronized(sendLock) {
            finRequested = true
            closingSince = System.currentTimeMillis()
            flushSendQueue()
            return finSent
        }
    }

    /**
     * Sends our FIN-ACK to the device and caches it for retransmission. Must be called under
     * [sendLock], with nothing left in [sendQueue].
     */
    private fun sendFinAck() {
        val finAckResponse = ipPacketBuilder.buildPacket(buildFinAck())
        increaseOurSeqNum(1)
        // our FIN occupies one sequence number, so the ACK that covers it carries the next one
        ourFinAckNumber = ourSeqNum.get().toInt()
        closingSince = System.currentTimeMillis()
        pendingFinAck = finAckResponse
        finSent = true
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
    private fun unwrapInboundReadable(selectionKey: SelectionKey) {
        // OP_READ event triggered
        var bytesRead = 0
        var totalBytesRead = 0
        do {
            // Read no further ahead of the device than the backlog limit. This is what keeps a
            // device that reads slowly from being sent data it has no room for
            // (docs/vpn-mitm-audit.md PKT-42).
            if (pauseReadingIfBacklogged(selectionKey)) {
                break
            }
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
        if (bytesRead == -1) {
            synchronized(closeLock) {
                selectableChannel.keyFor(componentManager.selector)?.cancel()
                // the remote side is done; release the socket/fd now, instead of only
                // deregistering the SelectionKey and leaking it
                closeChannel()
            }
            // The device must not hear about the close before it has received everything the
            // remote host sent. The layers above may still be working on that data, so they
            // decide when the close is delivered (docs/vpn-mitm-audit.md PKT-36).
            notifyRemoteClosed(::deliverRemoteClose)
        }
    }

    /**
     * Passes the remote host's close on to the device. Called once the encryption layer has
     * handed on all inbound data it received before the close; possibly on another thread than
     * the one that noticed the close, and possibly more than once.
     */
    private fun deliverRemoteClose() {
        if (!remoteCloseDelivered.compareAndSet(false, true)) {
            return
        }
        synchronized(closeLock) {
            when (state) {
                TransportLayerState.CONNECTING, TransportLayerState.CONNECTED, TransportLayerState.HALF_CLOSED -> {
                    // Start (or, if the client had already finished sending, complete) the
                    // closing handshake with a FIN-ACK, which goes out once the device has been
                    // sent everything that is still queued for it. It has to carry the ACK flag like every
                    // segment of an established connection, or the device discards it and never
                    // learns that the remote host is done (docs/vpn-mitm-audit.md PKT-35). The
                    // device's ACK for it and the device's own FIN complete the handshake
                    // (handleAckEmpty, handleFin).
                    Timber.d("tcp$id SocketChannel closed, state transition $state -> CLOSING")
                    state = TransportLayerState.CLOSING
                    requestFin()
                }
                else -> {
                    // CLOSING: the device closed in the meantime and our FIN is already out.
                    // CLOSED, ABORTED: the connection was torn down in the meantime.
                    // Either way there is nothing left to tell the device.
                }
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
    private fun unwrapInboundConnectable(selectionKey: SelectionKey) {
        // complete the SocketChannel's connection process
        try {
            selectableChannel.finishConnect()
        } catch (e: IOException) {
            Timber.e(e, "tcp$id Error connecting SocketChannel to ${ipPacketBuilder.remoteAddress.hostAddress}:$remotePort")
            closeHard()
            return
        }

        // make sure the SocketChannel is actually connected
        if (selectableChannel.isConnected) {
            // prepare SocketChannel for incoming data and complete local handshake
            selectionKey.interestOps(SelectionKey.OP_READ)
            // advance the client-facing TCP handshake by sending a SYN ACK packet
            synchronized(sendLock) {
                val synAckPacket = ipPacketBuilder.buildPacket(buildSynAck())
                increaseOurSeqNum(1)
                //Timber.d("%s SocketChannel connected", id)
                synAckSent = true
                writeToDevice(synAckPacket)
            }
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

    init {
        // Last in the class body, so that every property above is initialised before setUp()
        // can touch the connection from another thread.
        if (state != TransportLayerState.ABORTED) {
            setupScope.launch { setUp() }
        }
    }

    companion object {
        /**
         * Runs [setUp] for new connections. A burst of new connections is a burst of binder
         * calls, which a handful of threads serve as fast as many would.
         */
        @OptIn(ExperimentalCoroutinesApi::class)
        private val setupScope = CoroutineScope(Dispatchers.IO.limitedParallelism(8) + SupervisorJob())

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
         * How much data read from the remote host may wait to be sent to the device before
         * reading is suspended. Twice the largest window the device can advertise, so that
         * there is always enough at hand to fill the window when it opens.
         */
        const val SEND_BACKLOG_HIGH = 2 * 65535L

        /** The backlog at or below which reading from the remote host resumes. */
        const val SEND_BACKLOG_LOW = 32 * 1024L

        /** How long data may wait for the device's window before [sweepStaleConnections] asks for it. */
        const val DEFAULT_WINDOW_PROBE_AFTER_MS = 10 * 1000L

        /**
         * Removes cached [TcpConnection]s that are waiting for something that may never come:
         *
         * - [TransportLayerState.HALF_CLOSED] without inbound data for longer than
         *   [halfClosedTimeoutMs]. Such a connection normally ends when the remote host closes
         *   its side. One whose remote host neither sends nor closes would otherwise keep its
         *   SocketChannel until the VPN stops. It is aborted, which resets the device's side.
         * - [TransportLayerState.CLOSING] without progress for longer than [closingTimeoutMs]:
         *   our FIN is out, or waiting behind data the device does not take, but the device
         *   hasn't finished its part of the closing handshake. The outward-facing channel is
         *   already closed, so only the cache entry is dropped, without a reset.
         *
         * It also probes the receive window of devices that have left data waiting for longer
         * than [windowProbeAfterMs] ([probeDeviceWindow]).
         *
         * @param now Injectable for testing; defaults to the real current time.
         */
        fun sweepStaleConnections(
            halfClosedTimeoutMs: Long = DEFAULT_HALF_CLOSED_TIMEOUT_MS,
            closingTimeoutMs: Long = DEFAULT_CLOSING_TIMEOUT_MS,
            windowProbeAfterMs: Long = DEFAULT_WINDOW_PROBE_AFTER_MS,
            now: Long = System.currentTimeMillis()
        ) {
            val connections = ConnectionCache.allConnections().filterIsInstance<TcpConnection>()

            connections.forEach { connection ->
                try {
                    connection.probeDeviceWindow(now, windowProbeAfterMs)
                } catch (e: Throwable) {
                    Timber.e(e, "Error probing a TCP connection's receive window during sweep")
                }
            }

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