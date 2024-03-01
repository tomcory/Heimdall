package de.tomcory.heimdall.core.vpn.connection.encryptionLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.util.ByteUtils
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.pcap4j.packet.Packet
import timber.log.Timber
import java.nio.ByteBuffer
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLException

class TlsConnection(
    id: Int,
    transportLayer: TransportLayerConnection,
    componentManager: ComponentManager
) : EncryptionLayerConnection(
    id,
    transportLayer,
    componentManager
) {

    init {
        if(id > 0) {
            Timber.d("tls$id Creating TLS connection to ${transportLayer.ipPacketBuilder.remoteAddress.hostAddress}:${transportLayer.remotePort} (${transportLayer.remoteHost})")
        }
    }

    override val protocol = "TLS"

    private var state: ConnectionState = ConnectionState.NEW
    private var hostname: String = transportLayer.remoteHost ?: transportLayer.ipPacketBuilder.remoteAddress.hostAddress ?: ""

    private lateinit var originalClientHello: ByteArray
    private var sni: String? = null

    private val outboundCache = mutableListOf<ByteArray>()
    private var remainingOutboundBytes = 0

    private val inboundCache = mutableListOf<ByteArray>()
    private var remainingInboundBytes = 0

    private var outboundSnippet: ByteArray? = null
    private var inboundSnippet: ByteArray? = null

    private var serverSSLEngine: SSLEngine? = null
    private var clientSSLEngine: SSLEngine? = null

    private var serverAppBuffer: ByteBuffer = ByteBuffer.allocate(0)
    private var serverNetBuffer: ByteBuffer = ByteBuffer.allocate(0)
    private var clientAppBuffer: ByteBuffer = ByteBuffer.allocate(0)
    private var clientNetBuffer: ByteBuffer = ByteBuffer.allocate(0)

    private var serverSessionOpen = false
    private var clientSessionOpen = false

    private var outboundCount = 0
    private var inboundCount = 0

    private val log = true

    ////////////////////////////////////////////////////////////////////////
    ///// Inherited methods ///////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    override fun unwrapOutbound(payload: ByteArray) {
        if(log) Timber.d("tls$id unwrapOutbound of ${payload.size} bytes in state $state")
        prepareRecords(payload, true)
    }

    override fun unwrapOutbound(packet: Packet) {
        unwrapOutbound(packet.rawData)
    }

    override fun unwrapInbound(payload: ByteArray) {
        if(log) Timber.d("tls$id unwrapInbound of ${payload.size} bytes in state $state")
        prepareRecords(payload, false)
    }

    override fun wrapOutbound(payload: ByteArray) {
        if(doMitm) {
            handlePayload(payload, true)
        } else {
            transportLayer.wrapOutbound(payload)
        }
    }

    override fun wrapInbound(payload: ByteArray) {
        if(doMitm) {
            handlePayload(payload, false)
        } else {
            transportLayer.wrapInbound(payload)
        }
    }

    ////////////////////////////////////////////////////////////////////////
    ///// Traffic handler methods /////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    /**
     * Handles an application layer payload by wrapping it into TLS records and passing it to the transport layer.
     * If the connection is not ready to handle application data, the connection is closed.
     *
     * @param payload The application layer payload to be wrapped and passed to the transport layer.
     * @param isOutbound Whether the payload is outbound (true) or inbound (false).
     */
    private fun handlePayload(payload: ByteArray, isOutbound: Boolean) {
        val direction = if(isOutbound) "outbound" else "inbound"
        if(log) Timber.d("tls$id handlePayload of ${payload.size} bytes in state $state")

        if(state == ConnectionState.CLIENT_ESTABLISHED) {
            val (wrappedRecord, _) = handleWrap(payload, isOutbound)
            wrappedRecord?.let {
                if(it.isNotEmpty()) {
                    if(log) Timber.d("tls$id handlePayload ($direction) wrapped ${it.size} bytes, passing to transport layer")

                    if(isOutbound) {
                        transportLayer.wrapOutbound(it)
                    } else {
                        transportLayer.wrapInbound(it)
                    }
                }
            }
        } else {
            Timber.e("tls$id handlePayload ($direction) invalid state $state")
            closeConnection()
        }
    }

    /**
     * Handles an outbound TLS record based on the connection's state, using it to advance the client-facing TLS handshake or to pass the record to the application layer.
     * If the connection is not ready to handle the record (i.e. if the record is invalid or premature), the connection is closed.
     *
     * @param record The TLS record to be handled.
     * @param recordType The [RecordType] of the record (e.g. HANDSHAKE_CLIENT_HELLO, APPLICATION_DATA).
     */
    private fun handleOutboundRecord(record: ByteArray, recordType: RecordType) {
        if(log) Timber.d("tls$id handleOutboundRecord $recordType in state $state")

        // grab the remote hostname from the CLIENT HELLO message
        if (recordType == RecordType.HANDSHAKE_CLIENT_HELLO) {
            sni = findSni(record)
            sni?.let { hostname = it }

            // update the doMitm flag if the connection is marked for passthroughs
            doMitm = doMitm && !(transportLayer.appId?.let { componentManager.tlsPassthroughCache.get(it, hostname) } ?: false)
        }

        // if we don't want to MITM, we can hand the unprocessed record straight to the application layer
        if (!doMitm) {
            passOutboundToAppLayer(record)
            return
        }

        // if the record is an ALERT, handle it and return
        if(recordType == RecordType.ALERT) {
            if(log) Timber.w("tls$id outbound alert in state $state ${ByteUtils.bytesToHex(record)}")
            handleUnwrap(record, true)
            return
        }

        when (state) {
            // new connections require a CLIENT HELLO and initiate the server-facing TLS session based on it
            ConnectionState.NEW -> {
                if (recordType == RecordType.HANDSHAKE_CLIENT_HELLO) {
                    initiateServerHandshake(record)
                } else {
                    Timber.e("tls$id Invalid outbound record ($recordType in state $state)")
                    Timber.e("tls$id ${ByteUtils.bytesToHex(record)}")
                    closeConnection()
                }
            }

            // server-facing handshake ongoing, any messages from the client are unexpected
            ConnectionState.SERVER_HANDSHAKE, ConnectionState.SERVER_ESTABLISHED -> {
                Timber.e("tls$id handleOutboundRecord Invalid outbound record ($recordType in state $state)")
                Timber.e("tls$id ${ByteUtils.bytesToHex(record)}")
                closeConnection()
            }

            // client-facing handshake ongoing, use the record to advance it
            ConnectionState.CLIENT_HANDSHAKE -> {
                continueHandshake(record, recordType, true, SSLEngineResult.HandshakeStatus.NEED_UNWRAP)
            }

            // unwrap the record to extract its app-layer payload and pass it to the appLayerConnection
            ConnectionState.CLIENT_ESTABLISHED -> {
                if(recordType == RecordType.CHANGE_CIPHER_SPEC) {
                    if(log) Timber.w("tls$id handleOutboundRecord ignoring $recordType in state $state")
                    return
                }

                val (unwrappedPayload, _) = handleUnwrap(record, true)
                unwrappedPayload?.let {
                    if(it.isNotEmpty()) {
                        if(log) Timber.d("tls$id handleOutboundRecord unwrapped ${it.size} bytes, passing to app layer")
                        passOutboundToAppLayer(it)
                    }
                }
            }

            // the connection is closed, call closeConnection to clean up
            ConnectionState.CLOSED -> {
                closeConnection()
            }
        }
    }

    /**
     * Handles an inbound TLS record based on the connection's state, using it to advance the server-facing TLS handshake or to pass the record to the application layer.
     * If the connection is not ready to handle the record (i.e. if the record is invalid or premature), the connection is closed.
     *
     * @param record The TLS record to be handled.
     * @param recordType The [RecordType] of the record (e.g. HANDSHAKE_CLIENT_HELLO, APPLICATION_DATA).
     */
    private fun handleInboundRecord(record: ByteArray, recordType: RecordType) {
        if(log) Timber.d("tls$id handleInboundRecord $recordType in state $state")

        // if we don't want to MITM, we can hand the unprocessed record straight to the application layer
        if(!doMitm) {
            passInboundToAppLayer(record)
            return
        }

        // if the record is an ALERT, handle it and return
        if(recordType == RecordType.ALERT) {
            if(log) Timber.w("tls$id inbound alert in state $state ${ByteUtils.bytesToHex(record)}")
            handleUnwrap(record, false)
            return
        }

        when(state) {
            // new connections should never have incoming records, something has to be very wrong
            ConnectionState.NEW -> {
                Timber.e("tls$id handleInboundRecord Invalid inbound record ($recordType in state $state)")
                closeConnection()
            }

            // server-facing handshake ongoing, use the record to advance it
            ConnectionState.SERVER_HANDSHAKE -> {
                continueHandshake(record, recordType, false, SSLEngineResult.HandshakeStatus.NEED_UNWRAP)
            }

            // client-facing handshake ongoing, not ready to MitM yet
            ConnectionState.SERVER_ESTABLISHED, ConnectionState.CLIENT_HANDSHAKE -> {
                if(log) Timber.w("tls$id (premature) inbound $recordType (${record.size} bytes) in state $state")

                if(recordType == RecordType.CHANGE_CIPHER_SPEC) {
                    if(log) Timber.w("tls$id handleInboundRecord ignoring $recordType in state $state")
                    return
                }

                val (unwrappedPayload, _) = handleUnwrap(record, false)
                unwrappedPayload?.let {
                    if(log) Timber.w("tls$id handleInboundRecord unwrapped ${it.size} bytes, dropping because handshake is not finished")
                }
            }

            // both TLS sessions established, ready to MitM - unwrap the data and pass it to the app layer
            ConnectionState.CLIENT_ESTABLISHED -> {
                if(recordType == RecordType.CHANGE_CIPHER_SPEC) {
                    if(log) Timber.w("tls$id handleInboundRecord ignoring $recordType spec in state $state")
                    return
                }

                val (unwrappedPayload, _) = handleUnwrap(record, false)
                unwrappedPayload?.let {
                    if(it.isNotEmpty()) {
                        if(log) Timber.d("tls$id handleInboundRecord unwrapped ${it.size} bytes, passing to app layer")
                        passInboundToAppLayer(it)
                    }
                }
            }

            // the connection is closed, call closeConnection to clean up
            ConnectionState.CLOSED -> {
                closeConnection()
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////
    ///// opening TLS handshake methods ///////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    /**
     * Initiates the server-facing TLS handshake by setting up the server-facing SSLEngine and initiating the handshake.
     * The original client hello message is persisted for use in the client-facing handshake.
     *
     * @param record The TLS record containing the client hello message that opened the connection.
     */
    private fun initiateServerHandshake(record: ByteArray) {
        if(log) Timber.d("tls$id initiateServerHandshake Hostname: $hostname")

        // store the client hello for the client-facing handshake
        originalClientHello = record

        // set up the server-facing SSLEngine and initiate the handshake
        CoroutineScope(Dispatchers.IO).launch {
            setupServerSSLEngine()
            continueHandshake(handshakeStatus = SSLEngineResult.HandshakeStatus.NEED_WRAP, isClientFacing = false)
        }
    }

    /**
     * Initiates the client-facing TLS handshake by setting up the client-facing SSLEngine and initiating the handshake.
     * The original client hello message is used as the opening message of the handshake.
     */
    private fun initiateClientHandshake() {
        if(log) Timber.d("tls$id initiateClientHandshake Hostname: $hostname")

        // set up the client-facing SSLEngine and initiate the handshake
        CoroutineScope(Dispatchers.IO).launch {
            setupClientSSLEngine()
            continueHandshake(originalClientHello, RecordType.HANDSHAKE_CLIENT_HELLO, true, SSLEngineResult.HandshakeStatus.NEED_UNWRAP)
        }
    }

    /**
     * Continues a TLS handshake based on the current handshake status and result of the previous handshake operation.
     *
     * @param record The TLS record to be processed, or null if the handshake operation does not require a record (e.g. NEED_WRAP).
     * @param recordType The [RecordType] of the record to be processed, or null if the handshake operation does not require a record (e.g. NEED_WRAP).
     * @param isClientFacing Whether the handshake is for the client-facing session (true) or the server-facing session (false).
     * @param handshakeStatus The current [SSLEngineResult.HandshakeStatus] of the handshake (resulting from the previous handshake operation).
     */
    private fun continueHandshake(record: ByteArray? = null, recordType: RecordType? = null, isClientFacing: Boolean, handshakeStatus: SSLEngineResult.HandshakeStatus) {
        val direction = if(isClientFacing) "client" else "server"

        if(log) Timber.d("tls$id continueHandshake ($direction) recordType: $recordType, handshakeStatus: $handshakeStatus")

        when(handshakeStatus) {
            // if the clientSSLEngine needs to send data to continue the handshake, wrap the handshake messages and forward them to the remote host
            SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                val (wrappedRecord, res) = handleWrap(isOutbound = !isClientFacing)
                if(wrappedRecord != null && res != null) {
                    if(isClientFacing) {
                        transportLayer.wrapInbound(wrappedRecord)
                    } else {
                        transportLayer.wrapOutbound(wrappedRecord)
                    }
                    if(res.handshakeStatus != SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                        continueHandshake(handshakeStatus = res.handshakeStatus, isClientFacing = isClientFacing)
                    }
                }
            }

            // if the SSLEngine needs more data to continue the handshake, unwrap the record and continue the handshake based on the resulting handshakeStatus
            SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                record?.let {
                    val (unwrappedPayload, res) = handleUnwrap(it, isClientFacing)
                    if(unwrappedPayload != null && res != null) {
                        continueHandshake(handshakeStatus = res.handshakeStatus, isClientFacing = isClientFacing)
                    }
                }
            }

            // the SSLEngine is not currently handshaking, something went wrong, close the connection
            SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING -> {
                Timber.e("tls$id continueHandshake ($direction) failure, handshakeStatus is NOT_HANDSHAKING")
                closeConnection()
            }

            // TLS session established, advance connection state accordingly
            SSLEngineResult.HandshakeStatus.FINISHED -> {
                if(isClientFacing) {
                    switchState(ConnectionState.CLIENT_ESTABLISHED)
                } else {
                    switchState(ConnectionState.SERVER_ESTABLISHED)
                    initiateClientHandshake()
                }
            }

            // the SSLEngine needs to perform a task to continue the handshake, handle it and continue the handshake based on the resulting handshakeStatus
            SSLEngineResult.HandshakeStatus.NEED_TASK -> {
                val task = if(isClientFacing) clientSSLEngine?.delegatedTask else serverSSLEngine?.delegatedTask
                if(task != null) {
                    CoroutineScope(Dispatchers.IO).launch {
                        if(log) Timber.d("tls$id continueHandshake ($direction) delegated task: $task")
                        task.run()
                        continueHandshake(handshakeStatus = if(isClientFacing) clientSSLEngine?.handshakeStatus ?: handshakeStatus else serverSSLEngine?.handshakeStatus ?: handshakeStatus, isClientFacing = isClientFacing)
                    }
                } else {
                    Timber.e("tls$id continueHandshake ($direction) failure, handshakeStatus is NEED_TASK but task is NULL")
                    closeConnection()
                }
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////
    ///// closing TLS handshake methods ///////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    /**
     * Closes the connection by initiating the close handshake for both the client-facing and server-facing TLS sessions and closing the transport layer.
     */
    private fun closeConnection() {
        if(log) Timber.d("tls$id closeConnection in state $state")

        switchState(ConnectionState.CLOSED)

        // close the server-facing TLS session if it's still open
        if(serverSessionOpen) {
            closeSession(isClientFacing = false)
        } else {
            if(log) Timber.d("tls$id closeConnection server session already closed or not initialized")
        }

        // close the client-facing TLS session if it's still open
        if(clientSessionOpen) {
            closeSession(isClientFacing = true)
        } else {
            if(log) Timber.d("tls$id closeConnection client session already closed or not initialized")
        }

        // close the transport layer
        transportLayer.closeHard()
    }

    /**
     * Closes the client-facing or server-facing TLS session by telling the SSLEngine to close the session, wrapping the resulting close message and passing it to the transport layer.
     *
     * @param isClientFacing Whether the session to be closed is the client-facing session (true) or the server-facing session (false).
     */
    private fun closeSession(isClientFacing: Boolean) {
        val direction = if(isClientFacing) "client" else "server"
        if(log) Timber.d("tls$id closeSession ($direction) in state $state")

        // tell the SSLEngine to close the session
        if(isClientFacing) {
            clientSessionOpen = false
            clientSSLEngine?.closeOutbound()
        } else {
            serverSessionOpen = false
            serverSSLEngine?.closeOutbound()
        }

        // wrap the resulting close message and forward it to the remote host
        val (wrappedRecord, _) = handleWrap(isOutbound = false, closing = true)
        wrappedRecord?.let {
            if(isClientFacing) {
                transportLayer.wrapInbound(wrappedRecord)
            } else {
                transportLayer.wrapOutbound(wrappedRecord)
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////
    ///// SSLEngine setup methods /////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    /**
     * Creates a new SSLEngine in client mode to handle the TLS session facing the remote host and initiates the TLS handshake for it.
     * The application and network buffers used by the serverSSLEngine are allocated and the handshake is initiated.
     */
    private fun setupServerSSLEngine() {
        if(log) Timber.d("tls$id setupServerSSLEngine")

        // create a new SSLEngine to handle the TLS session facing the remote host
        serverSSLEngine = componentManager.mitmManager.createServerSSLEngine(sni, transportLayer.remotePort)

        // allocate the application and network buffers used by the serverSSLEngine
        serverAppBuffer = ByteBuffer.allocate(serverSSLEngine?.session?.applicationBufferSize ?: 0)
        serverNetBuffer = ByteBuffer.allocate(serverSSLEngine?.session?.packetBufferSize ?: 0)

        // initiate the TLS handshake for the serverSSLEngine
        switchState(ConnectionState.SERVER_HANDSHAKE)
        serverSSLEngine?.beginHandshake()

        serverSessionOpen = true
    }

    /**
     * Creates a new SSLEngine in server mode to handle the TLS session facing the local client and initiates the TLS handshake for it.
     * The application and network buffers used by the clientSSLEngine are allocated and the handshake is initiated.
     * The created SSLEngine clones the serverSSLEngine's remote server credentials to fool the client into establishing a session with us.
     */
    private fun setupClientSSLEngine() {
        if(log) Timber.d("tls$id setupClientSSLEngine")

        // create a new SSLEngine to handle the TLS session facing the local client
        clientSSLEngine = serverSSLEngine?.session?.let { componentManager.mitmManager.createClientSSLEngineFor(it) }

        // allocate the application and network buffers used by the clientSSLEngine
        clientAppBuffer = ByteBuffer.allocate(clientSSLEngine?.session?.applicationBufferSize ?: 0)
        clientNetBuffer = ByteBuffer.allocate(clientSSLEngine?.session?.packetBufferSize ?: 0)

        // initiate the TLS handshake for the clientSSLEngine
        switchState(ConnectionState.CLIENT_HANDSHAKE)
        clientSSLEngine?.beginHandshake()

        clientSessionOpen = true
    }

    ////////////////////////////////////////////////////////////////////////
    ///// SSLEngine wrap() and unwrap() handler methods ///////////////////
    //////////////////////////////////////////////////////////////////////

    /**
     * Calls ServerSSLEngine.wrap() to wrap application data into a TLS record or generate a handshake message. If the wrap operation is part of the handshake, the SSLEngine's handshake status is advanced accordingly.
     *
     * @param payload The application data to be wrapped, or null if the wrap operation is part of the handshake.
     * @param isOutbound Whether the wrap operation is for outbound data wrapped by the serverSSLEngine (true) or inbound data wrapped by the clientSSLEngine (false).
     * @param resizeFactor The factor by which to resize the buffers if they are too small to fit the payload (default: 2).
     *
     * @return The wrapped TLS record, or null if the wrap operation failed. If the operation failed, [closeConnection] is called before returning.
     */
    private fun handleWrap(payload: ByteArray? = null, isOutbound: Boolean, resizeFactor: Int = 2, closing: Boolean = false): Pair<ByteArray?, SSLEngineResult?> {
        val direction = if(isOutbound) "outbound" else "inbound"

        var appBuffer = if(isOutbound) serverAppBuffer else clientAppBuffer
        var netBuffer = if(isOutbound) serverNetBuffer else clientNetBuffer
        val sslEngine = if(isOutbound) serverSSLEngine else clientSSLEngine

        if(log) Timber.d("tls$id handleWrap ($direction) wrapping ${payload?.size ?: 0} bytes, SSLEngine handshakeStatus: ${sslEngine?.handshakeStatus}")

        // prepare the appBuffer by switching it to write mode
        appBuffer.clear()

        // if necessary, preemptively increase the capacity of the buffers to fit the payload
        payload?.let {
            if(appBuffer.capacity() < (it.size)) {
                if(log) Timber.w("tls$id handleWrap ($direction) Resizing buffers: appBuffer ${appBuffer.capacity()} -> ${it.size}, netBuffer ${netBuffer.capacity()} -> ${it.size * resizeFactor}")
                if(isOutbound) {
                    serverAppBuffer = ByteBuffer.allocate(it.size)
                    serverNetBuffer = ByteBuffer.allocate(it.size * resizeFactor)
                    appBuffer = serverAppBuffer
                    netBuffer = serverNetBuffer
                } else {
                    clientAppBuffer = ByteBuffer.allocate(it.size)
                    clientNetBuffer = ByteBuffer.allocate(it.size * resizeFactor)
                    appBuffer = clientAppBuffer
                    netBuffer = clientNetBuffer
                }
            }

            // write the payload to the appBuffer
            appBuffer.put(it)
        }

        // prepare the buffers for the wrap operation by switching them to read and write mode, respectively
        appBuffer.flip()
        netBuffer.clear()

        // use the SSLEngine to wrap the payload, producing an encrypted record in the netBuffer
        val res = try {
            sslEngine?.wrap(appBuffer, netBuffer)
        } catch (sslException: SSLException) {
            Timber.e("tls$id handleWrap ($direction) SSLException in state $state\n${sslException.message}")
            null
        }

        if(log) Timber.d("tls$id handleWrap ($direction) wrap result: $res")

        when(res?.status) {
            // if the wrap() operation was successful, return the encrypted record
            SSLEngineResult.Status.OK -> {
                return if(netBuffer.position() > 0) {
                    netBuffer.flip()
                    val out = ByteArray(netBuffer.limit())
                    netBuffer.get(out)
                    Pair(out, res)
                } else {
                    Pair(ByteArray(0), res)
                }
            }

            // if the wrap() operation requires more input data, increase the capacity of the appBuffer and retry
            SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                Timber.w("tls$id handleWrap ($isOutbound) buffer underflow, increasing appBuffer capacity and retrying")
                if(isOutbound) {
                    serverAppBuffer = ByteBuffer.allocate(serverAppBuffer.capacity() + (payload?.size ?: serverAppBuffer.capacity()))
                } else {
                    clientAppBuffer = ByteBuffer.allocate(clientAppBuffer.capacity() + (payload?.size ?: clientAppBuffer.capacity()))
                }
                return handleWrap(payload, isOutbound, resizeFactor)
            }

            // if the wrap() operation generates more data than the netBuffer can hold, increase the capacity of the netBuffer and retry
            SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                Timber.w("tls$id handleWrap ($isOutbound) buffer overflow, increasing netBuffer capacity and retrying")
                if(isOutbound) {
                    serverNetBuffer = ByteBuffer.allocate(serverNetBuffer.capacity() * resizeFactor)
                } else {
                    clientNetBuffer = ByteBuffer.allocate(clientNetBuffer.capacity() * resizeFactor)
                }
                return handleWrap(payload, isOutbound, resizeFactor)
            }

            // if the wrap() operation results in a closed session, close the connection
            SSLEngineResult.Status.CLOSED -> {
                return if(closing) {
                    if(netBuffer.position() > 0) {
                        netBuffer.flip()
                        val out = ByteArray(netBuffer.limit())
                        netBuffer.get(out)
                        Pair(out, res)
                    } else {
                        Pair(ByteArray(0), res)
                    }
                } else {
                    Timber.d("tls$id handleWrap ($isOutbound) resulted in closed session, closing connection")
                    closeConnection()
                    Pair(null, res)
                }
            }

            // if either the result or the status is null, something went wrong, close the connection
            null -> {
                Timber.e("tls$id handleWrap ($isOutbound) unexpected res.status: NULL")
                closeConnection()
                return Pair(null, res)
            }
        }
    }

    /**
     * Calls ServerSSLEngine.unwrap() to unwrap a TLS record into its application data payload. If the record is a handshake message, the SSLEngine's handshake status is advanced accordingly.
     *
     * @param record The TLS record to be unwrapped.
     * @param isOutbound Whether the unwrap operation is for outbound data unwrapped by the clientSSLEngine (true) or inbound data unwrapped by the serverSSLEngine (false).
     * @param resizeFactor The factor by which to resize the buffers if they are too small to fit the record (default: 2).
     *
     * @return The unwrapped application data payload (might be empty), or null if the unwrap operation failed. If the operation failed, [closeConnection] is called before returning.
     */
    private fun handleUnwrap(record: ByteArray, isOutbound: Boolean, resizeFactor: Int = 2): Pair<ByteArray?, SSLEngineResult?> {
        val direction = if(isOutbound) "outbound" else "inbound"

        var appBuffer = if(isOutbound) clientAppBuffer else serverAppBuffer
        var netBuffer = if(isOutbound) clientNetBuffer else serverNetBuffer
        val sslEngine = if(isOutbound) clientSSLEngine else serverSSLEngine

        if(log) Timber.d("tls$id handleUnwrap ($direction) Unwrapping ${record.size} bytes in state $state, handshakeStatus: ${sslEngine?.handshakeStatus}")

        // prepare the clientNetBuffer by switching it to write mode
        netBuffer.clear()

        // if necessary, preemptively increase the capacity of the buffers to fit the record
        if(netBuffer.capacity() < record.size) {
            if(log) Timber.w("tls$id handleClientUnwrap ($direction) Resizing buffers: netBuffer ${netBuffer.capacity()} -> ${record.size}, appBuffer ${appBuffer.capacity()} -> ${record.size * resizeFactor}")
            if(isOutbound) {
                clientNetBuffer = ByteBuffer.allocate(record.size)
                clientAppBuffer = ByteBuffer.allocate(record.size * resizeFactor)
                netBuffer = clientNetBuffer
                appBuffer = clientAppBuffer
            } else {
                serverNetBuffer = ByteBuffer.allocate(record.size)
                serverAppBuffer = ByteBuffer.allocate(record.size * resizeFactor)
                netBuffer = serverNetBuffer
                appBuffer = serverAppBuffer
            }
        }

        // write the record to the clientNetBuffer
        netBuffer.put(record)

        // prepare the buffers for the unwrap operation by switching them to read and write mode, respectively
        netBuffer.flip()
        appBuffer.clear()

        // use the clientSSLEngine to unwrap the record, producing an unencrypted payload in the clientAppBuffer
        val res = try {
            sslEngine?.unwrap(netBuffer, appBuffer)
        } catch (sslException: SSLException) {
            Timber.e("tls$id handleUnwrap ($direction) SSLException in state $state\n${sslException.message}")
            Timber.e("tls$id ${record.size} bytes: ${ByteUtils.bytesToHex(record)}")
            null
        }

        if(log) Timber.d("tls$id handleClientUnwrap clientSSLEngine unwrap result: $res")

        when(res?.status) {
            // if the unwrap() operation was successful, return the unencrypted payload
            SSLEngineResult.Status.OK -> {
                return if(appBuffer.position() > 0) {
                    appBuffer.flip()
                    val out = ByteArray(appBuffer.limit())
                    appBuffer.get(out)
                    Pair(out, res)
                } else {
                    Pair(ByteArray(0), res)
                }
            }

            // if the unwrap() operation requires more input data, increase the capacity of the netBuffer and retry
            SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                Timber.w("tls$id handleUnwrap ($direction) buffer underflow, increasing netBuffer capacity and retrying")
                if(isOutbound) {
                    clientNetBuffer = ByteBuffer.allocate(clientNetBuffer.capacity() + record.size)
                } else {
                    serverNetBuffer = ByteBuffer.allocate(serverNetBuffer.capacity() + record.size)
                }
                return handleUnwrap(record, isOutbound, resizeFactor)
            }

            // if the unwrap() operation generates more data than the appBuffer can hold, increase the capacity of the appBuffer and retry
            SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                Timber.w("tls$id handleUnwrap ($direction) buffer overflow, increasing appBuffer capacity and retrying")
                if(isOutbound) {
                    clientAppBuffer = ByteBuffer.allocate(clientAppBuffer.capacity() + record.size)
                } else {
                    serverAppBuffer = ByteBuffer.allocate(serverAppBuffer.capacity() + record.size)
                }
                return handleUnwrap(record, isOutbound, resizeFactor)
            }

            // if the unwrap() operation results in a closed session, close the connection
            SSLEngineResult.Status.CLOSED -> {
                Timber.d("tls$id handleUnwrap ($direction) resulted in closed session, closing connection")
                closeConnection()
                return Pair(null, res)
            }

            // if either the result or the status is null, something went wrong, close the connection
            null -> {
                Timber.e("tls$id handleUnwrap ($direction) unexpected res.status: NULL")
                closeConnection()
                return Pair(null, res)
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////
    ///// TLS record handler, parser, and assembly methods ////////////////
    //////////////////////////////////////////////////////////////////////

    /**
     * Processes a TLS record by parsing its type and passing it to the appropriate handler (inbound or outbound).
     *
     * @param record The TLS record to be processed.
     * @param isOutbound Whether the record is outbound (true) or inbound (false).
     *
     * @see [parseRecordType]
     * @see [handleOutboundRecord]
     * @see [handleInboundRecord]
     */
    private fun processRecord(record: ByteArray, isOutbound: Boolean) {
        if(record.isNotEmpty()) {

            val recordType = parseRecordType(record)

            if(isOutbound) {
                handleOutboundRecord(record, recordType)
            } else {
                handleInboundRecord(record, recordType)
            }
        }
    }

    /**
     * Attaches previously encountered snippets of TLS records by appending them to the beginning of the current transport-layer payload.
     *
     * @param rawPayload The raw transport-layer payload to be processed.
     * @param isOutbound Whether the payload is outbound (true) or inbound (false).
     *
     * @return The raw transport-layer payload with any attached snippets of TLS records appended to the beginning.
     */
    private fun checkForSnippets(rawPayload: ByteArray, isOutbound: Boolean): ByteArray {
        return if(isOutbound && outboundSnippet != null) {
            val combined = outboundSnippet!! + rawPayload
            outboundSnippet = null
            combined
        } else if(!isOutbound && inboundSnippet != null) {
            val combined = inboundSnippet!! + rawPayload
            inboundSnippet = null
            combined
        } else {
            rawPayload
        }
    }

    /**
     * Extracts TLS records from raw transport-layer payloads. Fragmented records (i.e. records that span multiple transport-layer payloads) are cached and reassembled before being processed.
     * If multiple records are contained in a single payload, they are split off and processed separately.
     *
     * @param rawPayload The raw transport-layer payload to be processed.
     * @param isOutbound Whether the payload is outbound (true) or inbound (false).
     */
    private fun prepareRecords(rawPayload: ByteArray, isOutbound: Boolean) {
        val direction = if(isOutbound) "outbound" else "inbound"

        val payload = checkForSnippets(rawPayload, isOutbound)
        val recordType = payload[0].toInt()
        var remainingBytes = if(isOutbound) remainingOutboundBytes else remainingInboundBytes
        val cache = if(isOutbound) outboundCache else inboundCache

        if(remainingBytes > 0) {
            // the payload is added to the overflow
            if(log) Timber.d("tls$id prepareRecords ($direction) Adding payload (${payload.size} bytes) to cache because $remainingBytes bytes are still missing")

            var attachedPayloadStart = 0
            // check whether there are additional records appended to the current payload and split them off (we'll handle them separately below)
            val currentPayload = if(remainingBytes < payload.size) {
                attachedPayloadStart = remainingBytes
                payload.slice(0 until attachedPayloadStart).toByteArray()
            } else {
                payload
            }

            // add the payload to the cache
            cache.add(currentPayload)
            remainingBytes -= currentPayload.size

            if(isOutbound)
                remainingOutboundBytes = remainingBytes
            else
                remainingInboundBytes = remainingBytes

            // if there are still overflow bytes remaining, do nothing and await the next payload
            if(remainingBytes > 0) {
                return
            }

            // otherwise combine the cached parts into one record and clear the cache
            if(log) Timber.d("tls$id prepareRecords ($direction) Assembling cached payload")
            val combinedRecord = cache.reduce { acc, x -> acc + x }
            cache.clear()

            // process the reassembled record
            processRecord(combinedRecord, isOutbound)

            // if there are additional payloads attached, process them as well
            if(payload.size > currentPayload.size) {
                if(log) Timber.d("tls$id prepareRecords ($direction) Handling attached payloads")
                val attachedPayload = payload.slice(attachedPayloadStart until payload.size).toByteArray()
                prepareRecords(attachedPayload, isOutbound)
            }

        } else {
            if(log) Timber.w("tls$id prepareRecords ($direction) Handling fresh payload of ${payload.size} bytes in state $state")

            // count the number of records we're processing after the handshake
            if(state == ConnectionState.CLIENT_ESTABLISHED) {
                if(isOutbound) {
                    if(outboundCount++ > 0) {
                        if(log) Timber.w("tls$id prepareRecords(outbound) this is the ${outboundCount}nd fresh record of the session")
                        if(log) Timber.w("tls$id cache size: ${outboundCache.size}, remaining bytes: $remainingOutboundBytes, snippet: ${outboundSnippet?.size ?: 0} bytes, clientAppBuffer: ${clientAppBuffer.position()} bytes, clientNetBuffer: ${clientNetBuffer.position()} bytes")
                    }
                } else {
                    if(inboundCount++ > 0) {
                        if(log) Timber.w("tls$id prepareRecords(inbound) this is the ${inboundCount}nd fresh record of the session")
                        if(log) Timber.w("tls$id cache size: ${inboundCache.size}, remaining bytes: $remainingInboundBytes, snippet: ${inboundSnippet?.size ?: 0} bytes, serverAppBuffer: ${serverAppBuffer.position()} bytes, serverNetBuffer: ${serverNetBuffer.position()} bytes")
                    }
                }
            }

            // make sure that we have a valid TLS record...
            if(recordType !in 0x14..0x17) {
                Timber.e("tls$id prepareRecords ($direction) Invalid TLS record type: ${ByteUtils.bytesToHex(recordType.toByte())}")
                Timber.e("tls$id ${ByteUtils.bytesToHex(payload)}")
                return
            }

            // ... which must at least comprise a TLS header with 5 bytes
            if(payload.size < 5) {
                if(log) Timber.d("tls$id Got a tiny snippet of a TLS record (${payload.size} bytes), stashing it and awaiting the rest")
                if(isOutbound) {
                    outboundSnippet = payload
                } else {
                    inboundSnippet = payload
                }
                return
            }

            // the first byte of the record is the record type, the next two bytes are the TLS version, and the next two bytes are the stated record length
            val statedLength = payload[3].toUByte().toInt() shl 8 or payload[4].toUByte().toInt()
            // the actual record length is the payload length minus the 5-byte header
            val actualLength = payload.size - 5

            // if the stated record length is larger than the payload length, we go into overflow mode and cache the payload
            if(statedLength > actualLength) {
                if(log) Timber.d("tls$id prepareRecords ($direction) Payload is shorter than stated record length ($actualLength < $statedLength), caching it for later")
                cache.add(payload)
                remainingBytes = statedLength - actualLength

                if(isOutbound) {
                    remainingOutboundBytes = remainingBytes
                } else {
                    remainingInboundBytes = remainingBytes
                }

            } else if(statedLength < actualLength) {
                if(log) Timber.d("tls$id prepareRecords ($direction) Payload is longer than stated record length ($actualLength > $statedLength), splitting it")
                // if the stated record length is smaller than the payload length, we split the payload into the current record and the attached payload...
                val currentRecord = payload.slice(0 until statedLength + 5).toByteArray()
                val attachedPayload = payload.slice(statedLength + 5 until payload.size).toByteArray()

                // ...process the extracted record...
                processRecord(currentRecord, isOutbound)

                // ...and when that is done, handle the remaining attached payload
                prepareRecords(attachedPayload, isOutbound)

            } else {
                // if the stated record length matches the payload length, we can just handle the record as-is
                if(log) Timber.d("tls$id prepareRecords ($direction) Payload matches stated record length ($actualLength = $statedLength), processing it")
                processRecord(payload, isOutbound)
            }
        }
    }

    /**
     * Extracts the record type from a TLS record. The record type is the first byte of the record and determines the type of the record (e.g. handshake message, application data).
     *
     * @param payload The TLS record to extract the record type from.
     *
     * @return The [RecordType] of the record.
     */
    private fun parseRecordType(payload: ByteArray): RecordType {
        return when (payload[0].toInt()) {
            0x14 -> RecordType.CHANGE_CIPHER_SPEC
            0x15 -> RecordType.ALERT
            0x16 -> {
                if(payload.size <= 5) {
                    RecordType.HANDSHAKE_INVALID
                } else {
                    when (payload[5].toInt()) {
                        0x01 -> RecordType.HANDSHAKE_CLIENT_HELLO
                        0x02 -> RecordType.HANDSHAKE_SERVER_HELLO
                        0x0B -> RecordType.HANDSHAKE_SERVER_CERT
                        0x0c -> RecordType.HANDSHAKE_SERVER_KEY
                        0x0e -> RecordType.HANDSHAKE_SERVER_DONE
                        0x10 -> RecordType.HANDSHAKE_CLIENT_KEY
                        else -> RecordType.HANDSHAKE_INDETERMINATE
                    }
                }
            }
            0x17 -> RecordType.APP_DATA
            else -> if(payload.size < 5) {
                Timber.e("tls$id Invalid TLS record (too short)")
                RecordType.INVALID
            } else {
                RecordType.INDETERMINATE
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////
    ///// Utility methods /////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    /**
     * Extracts the Server Name Indication (SNI) from a TLS Client Hello message.
     * The SNI is used to determine the hostname of the remote server that the client is trying to connect to.
     *
     * @param clientHello The TLS Client Hello message to extract the SNI from.
     *
     * @return The SNI, or null if the SNI could not be extracted.
     */
    private fun findSni(clientHello: ByteArray): String? {
        val msg = clientHello.map { x -> x.toUByte().toInt() }.toIntArray()
        var i = 43

        val sessionLength = msg[i++]
        i += sessionLength

        val cipherLength = msg[i++] shl 8 or msg[i++]
        i += cipherLength

        val compressionLength = msg[i++]
        i += compressionLength

        val totalExtensionsLength = msg[i++] shl 8 or msg[i++]

        var j = 0
        while(j < totalExtensionsLength) {
            val extensionValue = msg[i + j++] shl 8 or msg[i + j++]
            val extensionLength = msg[i + j++] shl 8 or msg[i + j++]
            if(extensionValue == 0) {
                val entryLength = msg[i + j] shl 8 or msg[i + j + 1]
                return String(msg.copyOfRange(i + j + 5, i + j + 2 + entryLength).map { x -> x.toChar() }.toCharArray())
            }
            j += extensionLength
        }

        return null
    }

    private fun switchState(newState: ConnectionState) {
        state = newState
    }

    ////////////////////////////////////////////////////////////////////////
    ///// Internal enums //////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    /**
     * Enum to represent the state of a TLS MitM connection.
     */
    private enum class ConnectionState {
        /**
         * Fresh connection, where neither SSLEngine is initialised.
         */
        NEW,

        /**
         * Server-facing SSLEngine initialised and TLS handshake in progress.
         */
        SERVER_HANDSHAKE,

        /**
         * Server-facing TLS handshake complete and session established.
         */
        SERVER_ESTABLISHED,

        /**
         * Client-facing SSLEngine initialised and TLS handshake in progress.
         */
        CLIENT_HANDSHAKE,

        /**
         * Client-facing TLS handshake complete, connection is ready for application data.
         */
        CLIENT_ESTABLISHED,

        /**
         * Connection is closed, either because of a close notification sent by a peer or due to an internal error.
         */
        CLOSED
    }

    /**
     * Enum to represent the type of a TLS record.
     */
    private enum class RecordType {
        HANDSHAKE_CLIENT_HELLO,
        HANDSHAKE_SERVER_HELLO,
        HANDSHAKE_SERVER_CERT,
        HANDSHAKE_SERVER_KEY,
        HANDSHAKE_CLIENT_KEY,
        HANDSHAKE_SERVER_DONE,
        HANDSHAKE_INDETERMINATE,
        HANDSHAKE_INVALID,
        CHANGE_CIPHER_SPEC,
        ALERT,
        APP_DATA,
        INDETERMINATE,
        INVALID
    }
}