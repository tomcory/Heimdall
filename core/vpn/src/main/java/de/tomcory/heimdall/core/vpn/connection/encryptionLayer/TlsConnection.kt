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

    private val outboundCache = mutableListOf<ByteArray>()
    private var remainingOutboundBytes = 0

    private val inboundCache = mutableListOf<ByteArray>()
    private var remainingInboundBytes = 0

    private var outboundSnippet: ByteArray? = null

    private var inboundSnippet: ByteArray? = null

    private var serverSSLEngine: SSLEngine? = null

    private var clientSSLEngine: SSLEngine? = null

    private var serverSessionClosed = false
    private var clientSessionClosed = false

    private lateinit var originalClientHello: ByteArray

    private var sni: String? = null

    private lateinit var serverAppBuffer: ByteBuffer

    private lateinit var serverNetBuffer: ByteBuffer

    private lateinit var clientAppBuffer: ByteBuffer

    private lateinit var clientNetBuffer: ByteBuffer

    private var outboundCount = 0
    private var inboundCount = 0

    private val log = false

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
            handleOutboundPayload(payload)
        } else {
            transportLayer.wrapOutbound(payload)
        }
    }

    override fun wrapInbound(payload: ByteArray) {
        if(doMitm) {
            handleInboundPayload(payload)
        } else {
            transportLayer.wrapInbound(payload)
        }
    }

    ////////////////////////////////////////////////////////////////////////
    ///// Traffic handler methods /////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    private fun handleOutboundPayload(payload: ByteArray) {
        if(log) Timber.d("tls$id handleOutboundPayload of ${payload.size} bytes in state $state")

        if(state == ConnectionState.CLIENT_ESTABLISHED) {
            val res = handleServerWrap(payload)

            if(res == null) {
                Timber.e("tls$id handleOutboundPayload wrap failure, result is null")
                closeConnection()
                return
            }

            when(res.status) {
                SSLEngineResult.Status.OK -> {
                    if(serverNetBuffer.position() > 0) {
                        serverNetBuffer.flip()
                        val output = ByteArray(serverNetBuffer.limit())
                        serverNetBuffer.get(output)
                        transportLayer.wrapOutbound(output)
                    }
                }
                SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                    TODO("tls$id handleOutboundPayload handle buffer underflow")
                }
                SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                    TODO("tls$id handleOutboundPayload handle buffer overflow")
                }
                SSLEngineResult.Status.CLOSED -> {
                    closeConnection()
                }
                null -> {
                    Timber.e("tls$id handleOutboundPayload unwrap unexpected res.status: NULL")
                    closeConnection()
                }
            }
        } else {
            Timber.e("tls$id handleOutboundPayload invalid state $state")
            closeConnection()
        }
    }

    private fun handleInboundPayload(payload: ByteArray) {
        if(log) Timber.d("tls$id handleInboundPayload of ${payload.size} bytes in state $state")

        if(state == ConnectionState.CLIENT_ESTABLISHED) {
            val res = handleClientWrap(payload)

            if(res == null) {
                Timber.e("tls$id handleInboundPayload wrap failure, result is null")
                closeConnection()
                return
            }

            when(res.status) {
                SSLEngineResult.Status.OK -> {
                    if(clientNetBuffer.position() > 0) {
                        clientNetBuffer.flip()
                        val out = ByteArray(clientNetBuffer.limit())
                        clientNetBuffer.get(out)
                        transportLayer.wrapInbound(out)
                    }
                }

                SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                    TODO("tls$id handleInboundPayload handle buffer underflow")
                }
                SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                    TODO("tls$id handleInboundPayload handle buffer overflow")
                }
                SSLEngineResult.Status.CLOSED -> {
                    closeConnection()
                }
                null -> {
                    Timber.e("tls$id handleInboundPayload unwrap unexpected res.status: NULL")
                    closeConnection()
                }
            }
        } else {
            Timber.e("tls$id handleInboundPayload invalid state $state")
            closeConnection()
        }
    }

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

        if(recordType == RecordType.ALERT) {
            if(log) Timber.w("tls$id outbound alert in state $state ${ByteUtils.bytesToHex(record)}")
            //TODO: handle alerts
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
                continueClientHandshake(record, recordType, SSLEngineResult.HandshakeStatus.NEED_UNWRAP)
            }

            // unwrap the record to extract its app-layer payload and pass it to the appLayerConnection
            ConnectionState.CLIENT_ESTABLISHED -> {
                if(recordType == RecordType.CHANGE_CIPHER_SPEC) {
                    if(log) Timber.w("tls$id handleOutboundRecord ignoring $recordType in state $state")
                    return
                }

                val res = handleClientUnwrap(record)

                if(res == null) {
                    Timber.e("tls$id handleOutboundRecord unwrap failure, result is null")
                    closeConnection()
                    return
                }

                when(res.status) {
                    SSLEngineResult.Status.OK -> {
                        if(clientAppBuffer.position() > 0) {
                            clientAppBuffer.flip()
                            val out = ByteArray(clientAppBuffer.limit())
                            clientAppBuffer.get(out)
                            if(log) Timber.d("tls$id handleOutboundRecord unwrapped ${out.size} bytes, passing to app layer")
                            passOutboundToAppLayer(out)
                        } else {
                            if(log) Timber.w("tls$id handleOutboundRecord unwrapped 0 bytes, dropping because there is nothing to pass to the app layer")
                        }
                    }

                    SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                        Timber.e("tls$id handleOutboundRecord unwrap result is BUFFER_UNDERFLOW: record size ${record.size}, clientNetBuffer size ${clientNetBuffer.capacity()}")
                        TODO("tls$id handle buffer underflow")
                    }

                    SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                        Timber.e("tls$id handleOutboundRecord unwrap result is BUFFER_OVERFLOW: record size ${record.size}, clientAppBuffer size ${clientAppBuffer.capacity()}")
                        TODO("tls$id handle buffer overflow")
                    }

                    SSLEngineResult.Status.CLOSED -> {
                        closeConnection()
                    }

                    null -> {
                        Timber.e("tls$id handleOutboundRecord unwrap unexpected res.status: NULL")
                        closeConnection()
                    }
                }
            }

            ConnectionState.CLOSED -> {
                closeConnection()
            }
        }
    }

    private fun handleInboundRecord(record: ByteArray, recordType: RecordType) {
        if(log) Timber.d("tls$id handleInboundRecord $recordType in state $state")

        // if we don't want to MITM, we can hand the unprocessed record straight to the application layer
        if(!doMitm) {
            passInboundToAppLayer(record)
            return
        }

        if(recordType == RecordType.ALERT) {
            if(log) Timber.w("tls$id inbound alert in state $state ${ByteUtils.bytesToHex(record)}")
            //TODO: handle alerts
        }

        when(state) {
            // new connections should never have incoming records, something has to be very wrong
            ConnectionState.NEW -> {
                Timber.e("tls$id handleInboundRecord Invalid inbound record ($recordType in state $state)")
                closeConnection()
            }

            // server-facing handshake ongoing, use the record to advance it
            ConnectionState.SERVER_HANDSHAKE -> {
                continueServerHandshake(record, recordType, SSLEngineResult.HandshakeStatus.NEED_UNWRAP)
            }

            // client-facing handshake ongoing, not ready to MitM yet
            ConnectionState.SERVER_ESTABLISHED, ConnectionState.CLIENT_HANDSHAKE -> {
                if(log) Timber.w("tls$id (premature) inbound $recordType (${record.size} bytes) in state $state")

                if(recordType == RecordType.CHANGE_CIPHER_SPEC) {
                    if(log) Timber.w("tls$id handleInboundRecord ignoring $recordType in state $state")
                    return
                }

                val res = handleServerUnwrap(record)

                if(res == null) {
                    Timber.e("tls$id handleInboundRecord unwrap failure, result is null")
                    closeConnection()
                    return
                }

                when(res.status) {
                    SSLEngineResult.Status.OK -> {
                        if(serverAppBuffer.position() > 0) {
                            serverAppBuffer.flip()
                            val out = ByteArray(serverAppBuffer.limit())
                            serverAppBuffer.get(out)
                            if(log) Timber.w("tls$id handleInboundRecord unwrapped ${out.size} bytes, dropping because handshake is not finished")
                        } else {
                            if(log) Timber.w("tls$id handleInboundRecord unwrapped 0 bytes, dropping because handshake is not finished")
                        }
                    }
                    SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                        Timber.e("tls$id handleInboundRecord unwrap result is BUFFER_UNDERFLOW: record size ${record.size}, serverNetBuffer size ${serverNetBuffer.capacity()}")
                        TODO("tls$id handle buffer underflow")
                    }
                    SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                        Timber.e("tls$id handleInboundRecord unwrap result is BUFFER_OVERFLOW: record size ${record.size}, serverAppBuffer size ${serverAppBuffer.capacity()}")
                        TODO("tls$id handle buffer overflow")
                    }
                    SSLEngineResult.Status.CLOSED -> {
                        closeConnection()
                    }
                    null -> {
                        Timber.e("tls$id handleInboundRecord failure, result is null")
                        closeConnection()
                    }
                }
            }

            // both TLS sessions established, ready to MitM - unwrap the data and pass it to the app layer
            ConnectionState.CLIENT_ESTABLISHED -> {
                if(recordType == RecordType.CHANGE_CIPHER_SPEC) {
                    if(log) Timber.w("tls$id handleInboundRecord ignoring $recordType spec in state $state")
                    return
                }

                val res = handleServerUnwrap(record)

                if(res == null) {
                    Timber.e("tls$id handleInboundRecord unwrap failure, result is null")
                    closeConnection()
                    return
                }

                when(res.status) {
                    SSLEngineResult.Status.OK -> {
                        if(serverAppBuffer.position() > 0) {
                            serverAppBuffer.flip()
                            val out = ByteArray(serverAppBuffer.limit())
                            serverAppBuffer.get(out)
                            if(log) Timber.d("tls$id handleInboundRecord unwrapped ${out.size} bytes, passing to app layer")
                            passInboundToAppLayer(out)
                        } else {
                            if(log) Timber.w("tls$id handleInboundRecord unwrapped 0 bytes, dropping because there is nothing to pass to the app layer")
                        }
                    }
                    SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                        Timber.e("tls$id handleInboundRecord unwrap result is BUFFER_UNDERFLOW: record size ${record.size}, serverNetBuffer size ${serverNetBuffer.capacity()}")
                        TODO("tls$id handle buffer underflow")
                    }
                    SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                        Timber.e("tls$id handleInboundRecord unwrap result is BUFFER_OVERFLOW: record size ${record.size}, serverAppBuffer size ${serverAppBuffer.capacity()}")
                        TODO("tls$id handle buffer overflow")
                    }
                    SSLEngineResult.Status.CLOSED -> {
                        closeConnection()
                    }
                    null -> {
                        Timber.e("tls$id handleInboundRecord unwrap unexpected res.status: NULL")
                        closeConnection()
                    }
                }
            }

            ConnectionState.CLOSED -> {
                closeConnection()
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////
    ///// TLS handshake methods ///////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    private fun closeConnection() {
        if(log) Timber.d("tls$id closeConnection in state $state")

        switchState(ConnectionState.CLOSED)

        if(!serverSessionClosed && this::serverNetBuffer.isInitialized) {
            closeServerSession()
        } else {
            if(log) Timber.d("tls$id closeConnection server session already closed or not initialized")
        }

        if(!clientSessionClosed && this::clientNetBuffer.isInitialized) {
            closeClientSession()
        } else {
            if(log) Timber.d("tls$id closeConnection client session already closed or not initialized")
        }

        transportLayer.closeHard()
    }

    private fun closeClientSession() {
        if(log) Timber.d("tls$id closeClientSession in state $state")

        clientSessionClosed = true
        clientSSLEngine?.closeOutbound()
        val res = handleClientWrap()
        if(res?.status == SSLEngineResult.Status.CLOSED) {
            if(clientNetBuffer.position() > 0) {
                clientNetBuffer.flip()
                val out = ByteArray(clientNetBuffer.limit())
                clientNetBuffer.get(out)
                if(log) Timber.d("tls$id closeClientSession wrap result is $res, produced ${out.size} bytes")
                transportLayer.wrapInbound(out)
            } else {
                if(log) Timber.d("tls$id closeClientSession wrap result is $res, produced 0 bytes")
            }
        } else {
            Timber.e("tls$id closeClientSession wrap result is $res, unexpected status")
        }
    }

    private fun closeServerSession() {
        if(log) Timber.d("tls$id closeServerSession in state $state")

        serverSessionClosed = true
        serverSSLEngine?.closeOutbound()
        val res = handleServerWrap()
        if(res?.status == SSLEngineResult.Status.CLOSED) {
            if(serverNetBuffer.position() > 0) {
                serverNetBuffer.flip()
                val out = ByteArray(serverNetBuffer.limit())
                serverNetBuffer.get(out)
                if(log) Timber.d("tls$id closeServerSession wrap result is $res, produced ${out.size} bytes")
                transportLayer.wrapOutbound(out)
            } else {
                if(log) Timber.d("tls$id closeServerSession wrap result is $res, produced 0 bytes")
            }
        } else {
            Timber.e("tls$id closeServerSession wrap result is $res, unexpected status")
        }
    }

    private fun initiateServerHandshake(record: ByteArray) {
        if(log) Timber.d("tls$id initiateServerHandshake Hostname: $hostname")

        // store the client hello for the client-facing handshake
        originalClientHello = record

        // set up the server-facing SSLEngine and initiate the handshake
        CoroutineScope(Dispatchers.IO).launch {
            setupServerSSLEngine()
            continueServerHandshake(handshakeStatus = SSLEngineResult.HandshakeStatus.NEED_WRAP)
        }
    }

    private fun initiateClientHandshake() {
        if(log) Timber.d("tls$id initiateClientHandshake Hostname: $hostname")

        // set up the client-facing SSLEngine and initiate the handshake
        CoroutineScope(Dispatchers.IO).launch {
            setupClientSSLEngine()
            continueClientHandshake(originalClientHello, RecordType.HANDSHAKE_CLIENT_HELLO, SSLEngineResult.HandshakeStatus.NEED_UNWRAP)
        }
    }

    private fun continueServerHandshake(record: ByteArray? = null, recordType: RecordType? = null, handshakeStatus: SSLEngineResult.HandshakeStatus) {
        if(log) Timber.d("tls$id continueServerHandshake recordType: $recordType, handshakeStatus: $handshakeStatus")

        when(handshakeStatus) {
            SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                val res = handleServerWrap()

                if(res == null) {
                    Timber.e("tls$id continueServerHandshake NEED_WRAP failure, result is null")
                    closeConnection()
                    return
                }

                when(res.status) {
                    // if the wrap() operation was successful, forward the generated handshake messages to the remote host
                    SSLEngineResult.Status.OK, SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                        if(serverNetBuffer.position() > 0) {
                            serverNetBuffer.flip()
                            val output = ByteArray(serverNetBuffer.limit())
                            serverNetBuffer.get(output)
                            transportLayer.wrapOutbound(output)
                        }

                        if(res.handshakeStatus != SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                            continueServerHandshake(handshakeStatus = res.handshakeStatus)
                        }
                    }

                    SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                        Timber.e("tls$id continueServerHandshake NEED_WRAP unexpected res.status: BUFFER_UNDERFLOW")
                        closeConnection()
                    }
                    SSLEngineResult.Status.CLOSED -> {
                        closeConnection()
                    }
                    null -> {
                        Timber.e("tls$id continueServerHandshake NEED_UNWRAP unexpected res.status: NULL")
                        closeConnection()
                    }
                }
            }

            SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                record?.let {
                    val res = handleServerUnwrap(it)

                    if(res == null) {
                        Timber.e("tls$id continueServerHandshake NEED_UNWRAP failure, result is null")
                        closeConnection()
                        return
                    }

                    when(res.status) {
                        // if the unwrap() operation was successful, continue the handshake based on the resulting handshakeStatus
                        SSLEngineResult.Status.OK -> {
                            continueServerHandshake(handshakeStatus = res.handshakeStatus)
                        }

                        SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                            Timber.e("tls$id continueServerHandshake NEED_UNWRAP unexpected res.status: BUFFER_UNDERFLOW")
                            closeConnection()
                        }
                        SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                            serverAppBuffer = ByteBuffer.allocate(serverAppBuffer.capacity() + it.size)
                            continueClientHandshake(record = record, recordType = recordType, handshakeStatus = res.handshakeStatus)
                        }
                        SSLEngineResult.Status.CLOSED -> {
                            closeConnection()
                        }
                        null -> {
                            Timber.e("tls$id continueServerHandshake NEED_UNWRAP unexpected res.status: NULL")
                            closeConnection()
                        }
                    }
                }
            }

            SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING -> {
                Timber.e("tls$id continueServerHandshake failure, handshakeStatus is NOT_HANDSHAKING")
                closeConnection()
            }

            SSLEngineResult.HandshakeStatus.FINISHED -> {
                switchState(ConnectionState.SERVER_ESTABLISHED)
                serverSSLEngine?.session?.cipherSuite?.let {
                    if(log) Timber.w("tls$id Server handshake finished, cipher suite: $it")
                }
                // server-facing TLS session established, start the client-facing handshake
                initiateClientHandshake()
            }

            SSLEngineResult.HandshakeStatus.NEED_TASK -> {
                TODO("tls$id continueServerHandshake NEED_TASK handling")
            }
        }
    }

    private fun continueClientHandshake(record: ByteArray? = null, recordType: RecordType? = null, handshakeStatus: SSLEngineResult.HandshakeStatus) {
        if(log) Timber.d("tls$id continueClientHandshake recordType: $recordType, handshakeStatus: $handshakeStatus")

        when(handshakeStatus) {
            SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                val res = handleClientWrap()

                if(res == null) {
                    Timber.e("tls$id continueClientHandshake NEED_WRAP failure, result is null")
                    closeConnection()
                    return
                }

                when(res.status) {
                    // if the wrap() operation was successful, forward the generated handshake messages to the remote host
                    SSLEngineResult.Status.OK, SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                        if(clientNetBuffer.position() > 0) {
                            clientNetBuffer.flip()
                            val out = ByteArray(clientNetBuffer.limit())
                            clientNetBuffer.get(out)
                            transportLayer.wrapInbound(out)
                        }

                        if(res.handshakeStatus != SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                            continueClientHandshake(handshakeStatus = res.handshakeStatus)
                        }
                    }

                    SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                        Timber.e("tls$id continueClientHandshake NEED_WRAP unexpected res.status: BUFFER_UNDERFLOW")
                        closeConnection()
                    }
                    SSLEngineResult.Status.CLOSED -> {
                        closeConnection()
                    }
                    null -> {
                        Timber.e("tls$id continueClientHandshake NEED_WRAP unexpected res.status: NULL")
                        closeConnection()
                    }
                }
            }

            SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                record?.let {
                    val res = handleClientUnwrap(it)

                    if(res == null) {
                        Timber.e("tls$id continueClientHandshake NEED_UNWRAP failure, result is null")
                        closeConnection()
                        return
                    }

                    when(res.status) {
                        // if the unwrap() operation was successful, continue the handshake based on the resulting handshakeStatus
                        SSLEngineResult.Status.OK -> {
                            continueClientHandshake(handshakeStatus = res.handshakeStatus)
                        }

                        SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                            Timber.e("tls$id continueClientHandshake NEED_UNWRAP unexpected res.status: BUFFER_UNDERFLOW")
                            closeConnection()
                        }
                        SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                            clientAppBuffer = ByteBuffer.allocate(clientAppBuffer.capacity() + it.size)
                            continueClientHandshake(record = record, recordType = recordType, handshakeStatus = res.handshakeStatus)
                        }
                        SSLEngineResult.Status.CLOSED -> {
                            closeConnection()
                        }
                        null -> {
                            Timber.e("tls$id continueClientHandshake NEED_UNWRAP unexpected res.status: NULL")
                            closeConnection()
                        }
                    }
                }
            }

            SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING -> {
                Timber.e("tls$id continueServerHandshake failure, handshakeStatus is NOT_HANDSHAKING")
                closeConnection()
            }

            SSLEngineResult.HandshakeStatus.FINISHED -> {
                clientSSLEngine?.session?.cipherSuite?.let {
                    if(log) Timber.w("tls$id Client handshake finished, cipher suite: $it")
                }
                switchState(ConnectionState.CLIENT_ESTABLISHED)
            }

            SSLEngineResult.HandshakeStatus.NEED_TASK -> {
                TODO("tls$id continueClientHandshake NEED_TASK handling")
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////
    ///// SSLEngine setup methods /////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

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
    }

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
    }

    ////////////////////////////////////////////////////////////////////////
    ///// SSLEngine wrap() and unwrap() handler methods ///////////////////
    //////////////////////////////////////////////////////////////////////

    private fun handleClientUnwrap(record: ByteArray): SSLEngineResult? {
        if(log) Timber.d("tls$id handleClientUnwrap Unwrapping ${record.size} bytes in state $state, clientSSLEngine handshakeStatus: ${clientSSLEngine?.handshakeStatus}")

        // prepare the clientNetBuffer by switching it to write mode
        clientNetBuffer.clear()

        // if necessary, increase the capacity of the clientNetBuffer to fit the record
        if(clientNetBuffer.capacity() < record.size) {
            if(log) Timber.w("tls$id handleClientUnwrap Resizing clientNetBuffer: ${clientNetBuffer.capacity()} -> ${record.size}")
            clientNetBuffer = ByteBuffer.allocate(record.size)
        }

        // write the record to the clientNetBuffer
        clientNetBuffer.put(record)

        // prepare the buffers for the unwrap operation by switching them to read and write mode, respectively
        clientNetBuffer.flip()
        clientAppBuffer.clear()

        // if necessary, increase the capacity of the clientAppBuffer to fit the decrypted payload, which is guaranteed to be smaller than the encrypted record
        if(clientAppBuffer.capacity() < record.size) {
            if(log) Timber.w("tls$id handleClientUnwrap Resizing serverNetBuffer: ${clientAppBuffer.capacity()} -> ${record.size}")
            clientAppBuffer = ByteBuffer.allocate(record.size)
        }

        // use the clientSSLEngine to unwrap the record, producing an unencrypted payload in the clientAppBuffer
        val res = try {
            clientSSLEngine?.unwrap(clientNetBuffer, clientAppBuffer)
        } catch (sslException: SSLException) {
            Timber.e("tls$id handleClientUnwrap SSLException in state $state\n${sslException.message}")
            Timber.e("tls$id ${record.size} bytes: ${ByteUtils.bytesToHex(record)}")
            null
        }

        if(log) Timber.d("tls$id handleClientUnwrap clientSSLEngine unwrap result: $res")

        return res
    }

    private fun handleClientWrap(payload: ByteArray? = null): SSLEngineResult? {
        if(log) Timber.d("tls$id handleClientWrap wrapping ${payload?.size ?: 0} bytes, clientSSLEngine handshakeStatus: ${clientSSLEngine?.handshakeStatus}")

        // prepare the clientAppBuffer by switching it to write mode
        clientAppBuffer.clear()

        payload?.let {
            // if necessary, increase the capacity of the clientAppBuffer to fit the payload
            if(clientAppBuffer.capacity() < (it.size)) {
                if(log) Timber.w("tls$id handleClientWrap Resizing clientAppBuffer: ${clientAppBuffer.capacity()} -> ${it.size}")
                clientAppBuffer = ByteBuffer.allocate(it.size)
            }

            // write the payload to the clientAppBuffer
            clientAppBuffer.put(it)
        }

        // prepare the buffers for the wrap operation by switching them to read and write mode, respectively
        clientAppBuffer.flip()
        clientNetBuffer.clear()

        payload?.let {
            // if necessary, increase the capacity of the clientNetBuffer to fit the payload, adding a generous overhead to account for the increased size after encryption
            if(clientNetBuffer.capacity() < (it.size * 2)) {
                Timber.w("tls$id handleClientWrap Resizing clientNetBuffer: ${clientNetBuffer.capacity()} -> ${it.size * 2}")
                clientNetBuffer = ByteBuffer.allocate(it.size * 2)
            }
        }

        // use the clientSSLEngine to wrap the payload, producing an encrypted record in the clientNetBuffer
        val res = try {
            clientSSLEngine?.wrap(clientAppBuffer, clientNetBuffer)
        } catch (sslException: SSLException) {
            Timber.e("tls$id handleClientWrap SSLException in state $state\n${sslException.message}")
            null
        }

        if(log) Timber.d("tls$id handleClientWrap clientSSLEngine wrap result: $res")

        return res
    }

    private fun handleServerUnwrap(record: ByteArray): SSLEngineResult? {
        if(log) Timber.d("tls$id handleServerUnwrap unwrapping ${record.size} bytes, serverSSLEngine handshakeStatus: ${serverSSLEngine?.handshakeStatus}")

        // prepare the serverNetBuffer by switching it to write mode
        serverNetBuffer.clear()

        // if necessary, increase the capacity of the serverNetBuffer to fit the record
        if(serverNetBuffer.capacity() < record.size) {
            if(log) Timber.w("tls$id handleServerUnwrap Resizing serverNetBuffer: ${serverNetBuffer.capacity()} -> ${record.size}")
            serverNetBuffer = ByteBuffer.allocate(record.size)
        }

        // write the record to the serverNetBuffer
        serverNetBuffer.put(record)

        // prepare the buffers for the unwrap operation by switching them to read and write mode, respectively
        serverNetBuffer.flip()
        serverAppBuffer.clear()

        // if necessary, increase the capacity of the serverAppBuffer to fit the decrypted payload, which is guaranteed to be smaller than the encrypted record
        if(serverAppBuffer.capacity() < record.size) {
            if(log) Timber.w("tls$id handleServerUnwrap Resizing serverNetBuffer: ${serverAppBuffer.capacity()} -> ${record.size}")
            serverAppBuffer = ByteBuffer.allocate(record.size)
        }

        // use the serverSSLEngine to unwrap the record, producing an unencrypted payload in the serverAppBuffer
        val res = try {
            serverSSLEngine?.unwrap(serverNetBuffer, serverAppBuffer)
        } catch (sslException: SSLException) {
            Timber.e("tls$id handleServerUnwrap SSLException in state $state\n${sslException.message}")
            Timber.e("tls$id ${record.size} bytes: ${ByteUtils.bytesToHex(record)}")
            null
        }

        if(log) Timber.d("tls$id handleServerUnwrap serverSSLEngine unwrap result: $res")

        return res
    }

    private fun handleServerWrap(payload: ByteArray? = null): SSLEngineResult? {
        if(log) Timber.d("tls$id handleServerWrap wrapping ${payload?.size ?: 0} bytes, serverSSLEngine handshakeStatus: ${serverSSLEngine?.handshakeStatus}")

        // prepare the serverAppBuffer by switching it to write mode
        serverAppBuffer.clear()

        payload?.let {
            // if necessary, increase the capacity of the serverAppBuffer to fit the payload
            if(serverAppBuffer.capacity() < (it.size)) {
                Timber.w("tls$id handleServerWrap Resizing serverNetBuffer: ${serverNetBuffer.capacity()} -> ${it.size}")
                serverAppBuffer = ByteBuffer.allocate(it.size)
            }

            // write the payload to the serverAppBuffer
            serverAppBuffer.put(it)
        }

        // prepare the buffers for the wrap operation by switching them to read and write mode, respectively
        serverAppBuffer.flip()
        serverNetBuffer.clear()

        payload?.let {
            // if necessary, increase the capacity of the serverNetBuffer to fit the payload, adding a generous overhead to account for the increased size after encryption
            if(serverNetBuffer.capacity() < (it.size * 2)) {
                Timber.w("tls$id handleServerWrap Resizing serverNetBuffer: ${serverNetBuffer.capacity()} -> ${it.size * 2}")
                serverNetBuffer = ByteBuffer.allocate(it.size * 2)
            }
        }

        // use the serverSSLEngine to wrap the payload, producing an encrypted record in the serverNetBuffer
        val res = try {
            serverSSLEngine?.wrap(serverAppBuffer, serverNetBuffer)
        } catch (sslException: SSLException) {
            Timber.e("tls$id handleServerWrap SSLException in state $state\n${sslException.message}")
            null
        }

        if(log) Timber.d("tls$id handleServerWrap serverSSLEngine wrap result: $res")

        return res
    }

    ////////////////////////////////////////////////////////////////////////
    ///// TLS record handler, parser, and assembly methods ////////////////
    //////////////////////////////////////////////////////////////////////

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

    private fun prepareRecords(rawPayload: ByteArray, isOutbound: Boolean) {

        val payload = checkForSnippets(rawPayload, isOutbound)
        val recordType = payload[0].toInt()
        var remainingBytes = if(isOutbound) remainingOutboundBytes else remainingInboundBytes
        val cache = if(isOutbound) outboundCache else inboundCache

        if(remainingBytes > 0) {
            // the payload is added to the overflow
            if(log) Timber.d("tls$id prepareRecords(${if(isOutbound) "outbound" else "inbound"}) Adding payload (${payload.size} bytes) to cache because $remainingBytes bytes are still missing")

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
            if(log) Timber.d("tls$id prepareRecords(${if(isOutbound) "outbound" else "inbound"}) Assembling cached payload")
            val combinedRecord = cache.reduce { acc, x -> acc + x }
            cache.clear()

            // process the reassembled record
            processRecord(combinedRecord, isOutbound)

            // if there are additional payloads attached, process them as well
            if(payload.size > currentPayload.size) {
                if(log) Timber.d("tls$id prepareRecords(${if(isOutbound) "outbound" else "inbound"}) Handling attached payloads")
                val attachedPayload = payload.slice(attachedPayloadStart until payload.size).toByteArray()
                prepareRecords(attachedPayload, isOutbound)
            }

        } else {
            if(log) Timber.w("tls$id prepareRecords(${if(isOutbound) "outbound" else "inbound"}) Handling fresh payload of ${payload.size} bytes in state $state")

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
                Timber.e("tls$id prepareRecords(${if(isOutbound) "outbound" else "inbound"}) Invalid TLS record type: ${ByteUtils.bytesToHex(recordType.toByte())}")
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
                if(log) Timber.d("tls$id prepareRecords(${if(isOutbound) "outbound" else "inbound"}) Payload is shorter than stated record length ($actualLength < $statedLength), caching it for later")
                cache.add(payload)
                remainingBytes = statedLength - actualLength

                if(isOutbound) {
                    remainingOutboundBytes = remainingBytes
                } else {
                    remainingInboundBytes = remainingBytes
                }

            } else if(statedLength < actualLength) {
                if(log) Timber.d("tls$id prepareRecords(${if(isOutbound) "outbound" else "inbound"}) Payload is longer than stated record length ($actualLength > $statedLength), splitting it")
                // if the stated record length is smaller than the payload length, we split the payload into the current record and the attached payload...
                val currentRecord = payload.slice(0 until statedLength + 5).toByteArray()
                val attachedPayload = payload.slice(statedLength + 5 until payload.size).toByteArray()

                // ...process the extracted record...
                processRecord(currentRecord, isOutbound)

                // ...and when that is done, handle the remaining attached payload
                prepareRecords(attachedPayload, isOutbound)

            } else {
                // if the stated record length matches the payload length, we can just handle the record as-is
                if(log) Timber.d("tls$id prepareRecords(${if(isOutbound) "outbound" else "inbound"}) Payload matches stated record length ($actualLength = $statedLength), processing it")
                processRecord(payload, isOutbound)
            }
        }
    }

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