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
    id: Long,
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

    private lateinit var originalClientHello: ByteArray

    private var sni: String? = null

    private lateinit var serverAppBuffer: ByteBuffer

    private lateinit var serverNetBuffer: ByteBuffer

    private lateinit var clientAppBuffer: ByteBuffer

    private lateinit var clientNetBuffer: ByteBuffer

    ////////////////////////////////////////////////////////////////////////
    ///// Inherited methods ///////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    override fun unwrapOutbound(payload: ByteArray) {
        prepareRecords(payload, true)
    }

    override fun unwrapOutbound(packet: Packet) {
        prepareRecords(packet.rawData, true)
    }

    override fun unwrapInbound(payload: ByteArray) {
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
        //Timber.w("tls$id ----- handleOutboundPayload of ${payload.size} bytes in state $state -----")

        if(state == ConnectionState.CLIENT_ESTABLISHED) {
            val res = handleServerWrap(payload)

            if(res?.status == SSLEngineResult.Status.OK) {
                if(serverNetBuffer.position() > 0) {
                    serverNetBuffer.flip()
                    val output = ByteArray(serverNetBuffer.limit())
                    serverNetBuffer.get(output)
                    transportLayer.wrapOutbound(output)
                }
            } else {
                Timber.e("tls$id handleOutboundPayload invalid result status ${res?.status} in state $state")
                //TODO("tls$id error handling")
            }
        } else {
            Timber.e("tls$id handleOutboundPayload invalid state $state")
            //TODO("tls$id error handling")
        }
    }

    private fun handleInboundPayload(payload: ByteArray) {
        //Timber.w("tls$id ----- handleInboundPayload of ${payload.size} bytes in state $state -----")

        if(state == ConnectionState.CLIENT_ESTABLISHED) {
            val res = handleClientWrap(payload)

            when(res?.status) {
                SSLEngineResult.Status.OK -> {
                    if(clientNetBuffer.position() > 0) {
                        clientNetBuffer.flip()
                        val out = ByteArray(clientNetBuffer.limit())
                        clientNetBuffer.get(out)
                        transportLayer.wrapInbound(out)
                    }
                }

                SSLEngineResult.Status.BUFFER_UNDERFLOW -> TODO("tls$id")
                SSLEngineResult.Status.BUFFER_OVERFLOW -> TODO("tls$id")
                SSLEngineResult.Status.CLOSED -> {
                    if(state != ConnectionState.CLOSED) {
                        //closeServerSession()
                        //closeClientSession()
                    }
                }
                null -> TODO()
            }
        } else {
            Timber.e("tls$id handleInboundPayload invalid state $state")
            //TODO("tls$id error handling")
        }
    }

    private fun handleOutboundRecord(record: ByteArray, recordType: RecordType) {
        //Timber.w("tls$id ----- handleOutboundRecord $recordType in state $state -----")

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
            Timber.w("tls$id outbound alert in state $state ${de.tomcory.heimdall.core.util.ByteUtils.bytesToHex(record)}")
        }

        when (state) {
            // new connections require a CLIENT HELLO and initiate the server-facing TLS session based on it
            ConnectionState.NEW -> {
                if (recordType == RecordType.HANDSHAKE_CLIENT_HELLO) {
                    initiateServerHandshake(record)
                } else {
                    Timber.e("tls$id Invalid outbound record ($recordType in state $state)")
                    Timber.e("tls$id ${de.tomcory.heimdall.core.util.ByteUtils.bytesToHex(record)}")
                    //TODO("tls$id error handling")
                }
            }

            // server-facing handshake ongoing, any messages from the client are unexpected
            ConnectionState.SERVER_HANDSHAKE, ConnectionState.SERVER_ESTABLISHED -> {
                Timber.e("tls$id handleOutboundRecord Invalid outbound record ($recordType in state $state)")
                Timber.e("tls$id ${de.tomcory.heimdall.core.util.ByteUtils.bytesToHex(record)}")
                //TODO("tls$id error handling")
            }

            // client-facing handshake ongoing, use the record to advance it
            ConnectionState.CLIENT_HANDSHAKE -> {
                continueClientHandshake(record, recordType, SSLEngineResult.HandshakeStatus.NEED_UNWRAP)
            }

            // unwrap the record to extract its app-layer payload and pass it to the appLayerConnection
            ConnectionState.CLIENT_ESTABLISHED -> {
                val res = handleClientUnwrap(record)

                when(res?.status) {
                    SSLEngineResult.Status.OK -> {
                        if(clientAppBuffer.position() > 0) {
                            clientAppBuffer.flip()
                            val out = ByteArray(clientAppBuffer.limit())
                            clientAppBuffer.get(out)
                            passOutboundToAppLayer(out)
                        }
                    }

                    SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                        Timber.e("tls$id handleOutboundRecord BUFFER_UNDERFLOW: record size ${record.size}, clientNetBuffer size ${clientNetBuffer.capacity()}")
                        TODO("tls$id handle buffer underflow")
                    }

                    SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                        Timber.e("tls$id handleOutboundRecord BUFFER_OVERFLOW: record size ${record.size}, clientAppBuffer size ${clientAppBuffer.capacity()}")
                        TODO("tls$id handle buffer overflow")
                    }

                    SSLEngineResult.Status.CLOSED -> {
                        //closeServerSession()
                    }

                    null -> {
                        Timber.e("tls$id handleOutboundRecord failure, result is null")
                        //closeServerSession()
                    }
                }
            }

            ConnectionState.CLOSED -> {
                TODO("tls$id")
            }
        }
    }

    private fun handleInboundRecord(record: ByteArray, recordType: RecordType) {
        //Timber.w("tls$id ----- handleInboundRecord $recordType in state $state -----")

        // if we don't want to MITM, we can hand the unprocessed record straight to the application layer
        if(!doMitm) {
            passInboundToAppLayer(record)
            return
        }

        if(recordType == RecordType.ALERT) {
            Timber.w("tls$id inbound alert in state $state ${de.tomcory.heimdall.core.util.ByteUtils.bytesToHex(record)}")
        }

        when(state) {
            // new connections should never have incoming records, something has to be very wrong
            ConnectionState.NEW -> {
                Timber.e("tls$id handleInboundRecord Invalid inbound record ($recordType in state $state)")
            }

            // server-facing handshake ongoing, use the record to advance it
            ConnectionState.SERVER_HANDSHAKE -> {
                continueServerHandshake(record, recordType, SSLEngineResult.HandshakeStatus.NEED_UNWRAP)
            }

            // client-facing handshake ongoing, not ready to MitM yet
            ConnectionState.SERVER_ESTABLISHED, ConnectionState.CLIENT_HANDSHAKE -> {
                Timber.w("tls$id premature APP DATA in state $state")
                val res = handleServerUnwrap(record)

                when(res?.status) {
                    SSLEngineResult.Status.OK -> {
                        if(serverAppBuffer.position() > 0) {
                            serverAppBuffer.flip()
                            val out = ByteArray(serverAppBuffer.limit())
                            serverAppBuffer.get(out)
                        }
                    }
                    SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                        Timber.e("tls$id handleInboundRecord BUFFER_UNDERFLOW: record size ${record.size}, serverNetBuffer size ${serverNetBuffer.capacity()}")
                        TODO("tls$id handle buffer underflow")
                    }
                    SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                        Timber.e("tls$id handleInboundRecord BUFFER_OVERFLOW: record size ${record.size}, serverAppBuffer size ${serverAppBuffer.capacity()}")
                        TODO("tls$id handle buffer overflow")
                    }
                    SSLEngineResult.Status.CLOSED -> {}//closeClientSession()
                    null -> Timber.e("tls$id handleInboundRecord failure, result is null")
                }
            }

            // both TLS sessions established, ready to MitM - unwrap the data and pass it to the app layer
            ConnectionState.CLIENT_ESTABLISHED -> {
                val res = handleServerUnwrap(record)

                when(res?.status) {
                    SSLEngineResult.Status.OK -> {
                        if(serverAppBuffer.position() > 0) {
                            serverAppBuffer.flip()
                            val out = ByteArray(serverAppBuffer.limit())
                            serverAppBuffer.get(out)
                            passInboundToAppLayer(out)
                        }
                    }
                    SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                        Timber.e("tls$id handleInboundRecord BUFFER_UNDERFLOW: record size ${record.size}, serverNetBuffer size ${serverNetBuffer.capacity()}")
                        TODO("tls$id handle buffer underflow")
                    }
                    SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                        Timber.e("tls$id handleInboundRecord BUFFER_OVERFLOW: record size ${record.size}, serverAppBuffer size ${serverAppBuffer.capacity()}")
                        TODO("tls$id handle buffer overflow")
                    }
                    SSLEngineResult.Status.CLOSED -> {}//closeClientSession()
                    null -> Timber.e("tls$id handleInboundRecord failure, result is null")
                }
            }

            ConnectionState.CLOSED -> {
                handleServerUnwrap(record)
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////
    ///// TLS handshake methods ///////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    private fun closeClientSession() {
        //Timber.d("tls$id closeClientSession in state $state")

        switchState(ConnectionState.CLOSED)
        clientSSLEngine?.closeOutbound()
        val res = handleClientWrap()
        //TODO: handle res.status?
        if(clientNetBuffer.position() > 0) {
            clientNetBuffer.flip()
            val out = ByteArray(clientNetBuffer.limit())
            clientNetBuffer.get(out)
            transportLayer.wrapInbound(out)
        }
    }

    private fun closeServerSession() {
        //Timber.d("tls$id closeServerSession in state $state")

        switchState(ConnectionState.CLOSED)
        serverSSLEngine?.closeOutbound()
        val res = handleServerWrap()
        //TODO: handle res.status?
        if(serverNetBuffer.position() > 0) {
            serverNetBuffer.flip()
            val out = ByteArray(serverNetBuffer.limit())
            serverNetBuffer.get(out)
            transportLayer.wrapOutbound(out)
        }
    }

    private fun initiateServerHandshake(record: ByteArray) {
        //Timber.d("tls$id initiateServerHandshake Hostname: $hostname")

        // store the client hello for the client-facing handshake
        originalClientHello = record

        // set up the server-facing SSLEngine and initiate the handshake
        CoroutineScope(Dispatchers.IO).launch {
            setupServerSSLEngine()
            continueServerHandshake(handshakeStatus = SSLEngineResult.HandshakeStatus.NEED_WRAP)
        }
    }

    private fun initiateClientHandshake() {
        //Timber.d("tls$id initiateClientHandshake Hostname: $hostname")

        // set up the client-facing SSLEngine and initiate the handshake
        CoroutineScope(Dispatchers.IO).launch {
            setupClientSSLEngine()
            continueClientHandshake(originalClientHello, RecordType.HANDSHAKE_CLIENT_HELLO, SSLEngineResult.HandshakeStatus.NEED_UNWRAP)
        }
    }

    private fun continueServerHandshake(record: ByteArray? = null, recordType: RecordType? = null, handshakeStatus: SSLEngineResult.HandshakeStatus) {
        //Timber.d("tls$id continueServerHandshake recordType: $recordType, handshakeStatus: $handshakeStatus")

        when(handshakeStatus) {
            SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                val res = handleServerWrap()

                if(res == null) {
                    Timber.e("tls$id continueServerHandshake NEED_WRAP failure, result is null")
                    return
                }

                when(res.status) {
                    // if the wrap() operation was successful, forward the generated handshake messages to the remote host
                    SSLEngineResult.Status.OK -> {
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

                    SSLEngineResult.Status.BUFFER_UNDERFLOW -> TODO("tls$id")
                    SSLEngineResult.Status.BUFFER_OVERFLOW -> TODO("tls$id")
                    SSLEngineResult.Status.CLOSED -> TODO("tls$id")
                    null -> Timber.e("tls$id continueServerHandshake NEED_UNWRAP unexpected res.status: NULL")
                }
            }

            SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                record?.let {
                    val res = handleServerUnwrap(it)

                    if(res == null) {
                        Timber.e("tls$id continueServerHandshake NEED_UNWRAP failure, result is null")
                        return
                    }

                    when(res.status) {
                        // if the unwrap() operation was successful, continue the handshake based on the resulting handshakeStatus
                        SSLEngineResult.Status.OK -> {
                            continueServerHandshake(handshakeStatus = res.handshakeStatus)
                        }

                        SSLEngineResult.Status.BUFFER_UNDERFLOW -> TODO("tls$id")
                        SSLEngineResult.Status.BUFFER_OVERFLOW -> TODO("tls$id")
                        SSLEngineResult.Status.CLOSED -> TODO("tls$id")
                        null -> Timber.e("tls$id continueServerHandshake NEED_UNWRAP unexpected res.status: NULL")
                    }
                }
            }

            SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING -> {
                Timber.e("tls$id continueServerHandshake failure, handshakeStatus is NOT_HANDSHAKING")
            }

            SSLEngineResult.HandshakeStatus.FINISHED -> {
                switchState(ConnectionState.SERVER_ESTABLISHED)

                // server-facing TLS session established, start the client-facing handshake
                initiateClientHandshake()
            }

            SSLEngineResult.HandshakeStatus.NEED_TASK -> TODO("tls$id")
        }
    }

    private fun continueClientHandshake(record: ByteArray? = null, recordType: RecordType? = null, handshakeStatus: SSLEngineResult.HandshakeStatus) {
        //Timber.d("tls$id continueClientHandshake recordType: $recordType, handshakeStatus: $handshakeStatus")

        when(handshakeStatus) {
            SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                val res = handleClientWrap()

                if(res == null) {
                    Timber.e("tls$id continueClientHandshake NEED_WRAP failure, result is null")
                    return
                }

                when(res.status) {
                    // if the wrap() operation was successful, forward the generated handshake messages to the remote host
                    SSLEngineResult.Status.OK -> {
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

                    SSLEngineResult.Status.BUFFER_UNDERFLOW -> TODO("tls$id")
                    SSLEngineResult.Status.BUFFER_OVERFLOW -> TODO("tls$id")
                    SSLEngineResult.Status.CLOSED -> TODO("tls$id")
                    null -> Timber.e("tls$id continueClientHandshake NEED_UNWRAP unexpected res.status: NULL")
                }
            }

            SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                record?.let {
                    val res = handleClientUnwrap(it)

                    if(res == null) {
                        Timber.e("tls$id continueClientHandshake NEED_UNWRAP failure, result is null")
                        //TODO: error handling
                        return
                    }

                    when(res.status) {
                        // if the unwrap() operation was successful, continue the handshake based on the resulting handshakeStatus
                        SSLEngineResult.Status.OK -> {
                            continueClientHandshake(handshakeStatus = res.handshakeStatus)
                        }

                        SSLEngineResult.Status.BUFFER_UNDERFLOW -> TODO("tls$id")
                        SSLEngineResult.Status.BUFFER_OVERFLOW -> TODO("tls$id")
                        SSLEngineResult.Status.CLOSED -> TODO("tls$id")
                        null -> Timber.e("tls$id continueClientHandshake NEED_UNWRAP unexpected res.status: NULL")
                    }
                }
            }

            SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING -> {
                Timber.e("tls$id continueServerHandshake failure, handshakeStatus is NOT_HANDSHAKING")
            }

            SSLEngineResult.HandshakeStatus.FINISHED -> {
                switchState(ConnectionState.CLIENT_ESTABLISHED)
            }

            SSLEngineResult.HandshakeStatus.NEED_TASK -> TODO("tls$id")
        }
    }

    ////////////////////////////////////////////////////////////////////////
    ///// SSLEngine setup methods /////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    private fun setupServerSSLEngine() {
        //Timber.d("tls$id setupServerSSLEngine")

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
        //Timber.d("tls$id setupClientSSLEngine")

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
        //Timber.d("tls$id handleClientUnwrap unwrapping ${record.size} bytes in state $state, clientSSLEngine handshakeStatus: ${clientSSLEngine?.handshakeStatus}")

        // prepare the clientNetBuffer by switching it to write mode
        clientNetBuffer.clear()

        // if necessary, increase the capacity of the clientNetBuffer to fit the record
        if(clientNetBuffer.capacity() < record.size) {
            Timber.w("tls$id handleClientUnwrap Resizing clientNetBuffer: ${clientNetBuffer.capacity()} -> ${record.size}")
            clientNetBuffer = ByteBuffer.allocate(record.size)
        }

        // write the record to the clientNetBuffer
        clientNetBuffer.put(record)

        // prepare the buffers for the unwrap operation by switching them to read and write mode, respectively
        clientNetBuffer.flip()
        clientAppBuffer.clear()

        // use the clientSSLEngine to unwrap the record, producing an unencrypted payload in the clientAppBuffer
        val res = try {
            clientSSLEngine?.unwrap(clientNetBuffer, clientAppBuffer)
        } catch (sslException: SSLException) {
            Timber.e("tls$id handleClientUnwrap SSLException in state $state ${sslException.message}")
            transportLayer.appId?.let { componentManager.tlsPassthroughCache.put(it, hostname) }

            //closeServerSession()
            null
        }

        //Timber.d("tls$id handleClientUnwrap clientSSLEngine unwrap handshakeResult: $res")

        return res
    }

    private fun handleClientWrap(payload: ByteArray? = null): SSLEngineResult? {
        //Timber.d("tls$id handleClientWrap wrapping ${payload?.size ?: 0} bytes, clientSSLEngine handshakeStatus: ${clientSSLEngine?.handshakeStatus}")

        // prepare the clientAppBuffer by switching it to write mode
        clientAppBuffer.clear()

        payload?.let {
            // if necessary, increase the capacity of the clientAppBuffer to fit the payload
            if(clientAppBuffer.capacity() < (it.size)) {
                Timber.w("tls$id handleClientWrap Resizing clientAppBuffer: ${clientAppBuffer.capacity()} -> ${it.size}")
                clientAppBuffer = ByteBuffer.allocate(it.size)
            }

            // write the payload to the clientAppBuffer
            clientAppBuffer.put(it)
        }

        // prepare the buffers for the wrap operation by switching them to read and write mode, respectively
        clientAppBuffer.flip()
        clientNetBuffer.clear()

        // use the clientSSLEngine to wrap the payload, producing an encrypted record in the clientNetBuffer
        val res = try {
            clientSSLEngine?.wrap(clientAppBuffer, clientNetBuffer)
        } catch (sslException: SSLException) {
            Timber.e("tls$id handleClientWrap SSLException in state $state ${sslException.message}")
            transportLayer.appId?.let { componentManager.tlsPassthroughCache.put(it, hostname) }

            //closeServerSession()
            null
        }

        //Timber.d("tls$id handleClientWrap clientSSLEngine wrap handshakeResult: $res")

        return res
    }

    private fun handleServerUnwrap(record: ByteArray): SSLEngineResult? {
        //Timber.d("tls$id handleServerUnwrap unwrapping ${record.size} bytes, serverSSLEngine handshakeStatus: ${serverSSLEngine?.handshakeStatus}")

        // prepare the serverNetBuffer by switching it to write mode
        serverNetBuffer.clear()

        // if necessary, increase the capacity of the serverNetBuffer to fit the record
        if(serverNetBuffer.capacity() < record.size) {
            Timber.w("tls$id handleServerUnwrap Resizing serverNetBuffer: ${serverNetBuffer.capacity()} -> ${record.size}")
            serverNetBuffer = ByteBuffer.allocate(record.size)
        }

        // write the record to the serverNetBuffer
        serverNetBuffer.put(record)

        // prepare the buffers for the unwrap operation by switching them to read and write mode, respectively
        serverNetBuffer.flip()
        serverAppBuffer.clear()

        // use the serverSSLEngine to unwrap the record, producing an unencrypted payload in the serverAppBuffer
        val res = serverSSLEngine?.unwrap(serverNetBuffer, serverAppBuffer)

        //Timber.d("tls$id handleServerUnwrap serverSSLEngine unwrap handshakeResult: $res")

        return res
    }

    private fun handleServerWrap(payload: ByteArray? = null): SSLEngineResult? {
        //Timber.d("tls$id handleServerWrap wrapping ${payload?.size ?: 0} bytes, serverSSLEngine handshakeStatus: ${serverSSLEngine?.handshakeStatus}")

        // prepare the serverAppBuffer by switching it to write mode
        serverAppBuffer.clear()

        payload?.let {
            // if necessary, increase the capacity of the serverAppBuffer to fit the payload
            if(serverAppBuffer.capacity() < (it.size)) {
                Timber.w("tls$id handleServerUnwrap Resizing serverNetBuffer: ${serverNetBuffer.capacity()} -> ${it.size}")
                serverAppBuffer = ByteBuffer.allocate(it.size)
            }

            // write the payload to the serverAppBuffer
            serverAppBuffer.put(it)
        }

        // prepare the buffers for the wrap operation by switching them to read and write mode, respectively
        serverAppBuffer.flip()
        serverNetBuffer.clear()

        // use the serverSSLEngine to wrap the payload, producing an encrypted record in the serverNetBuffer
        val res = serverSSLEngine?.wrap(serverAppBuffer, serverNetBuffer)

        //Timber.d("tls$id handleServerWrap serverSSLEngine wrap handshakeResult: $res")

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
            val combinedRecord = cache.reduce { acc, x -> acc + x }
            cache.clear()

            // process the reassembled record
            processRecord(combinedRecord, isOutbound)

            // if there are additional payloads attached, process them as well
            if(payload.size > currentPayload.size) {
                val attachedPayload = payload.slice(attachedPayloadStart until payload.size).toByteArray()
                //Timber.d("%s Processing attached payload", id)
                prepareRecords(attachedPayload, isOutbound)
            }

        } else {
            // make sure that we have a valid TLS record...
            if(recordType !in 0x14..0x17) {
                Timber.e("tls$id Invalid TLS record type: ${de.tomcory.heimdall.core.util.ByteUtils.bytesToHex(recordType.toByte())}")
                Timber.e("tls$id ${de.tomcory.heimdall.core.util.ByteUtils.bytesToHex(payload)}")
                return
            }

            // ... which must at least comprise a TLS header with 5 bytes
            if(payload.size < 5) {
                //Timber.w("tls$id Got a tiny snippet of a TLS record (${payload.size} bytes), stashing it and awaiting the rest")
                if(isOutbound) {
                    outboundSnippet = payload
                } else {
                    inboundSnippet = payload
                }
                return
            }

            val statedLength = payload[3].toUByte().toInt() shl 8 or payload[4].toUByte().toInt()
            val actualLength = payload.size - 5

            // if the stated record length is larger than the payload length, we go into overflow mode and cache the payload
            if(statedLength > actualLength) {
                cache.add(payload)
                remainingBytes = statedLength - actualLength

                if(isOutbound) {
                    remainingOutboundBytes = remainingBytes
                } else {
                    remainingInboundBytes = remainingBytes
                }

            } else if(statedLength < actualLength) {
                val currentRecord = payload.slice(0 until statedLength + 5).toByteArray()
                val attachedPayload = payload.slice(statedLength + 5 until payload.size).toByteArray()

                // process the extracted record...
                processRecord(currentRecord, isOutbound)

                // ...and when that is done, handle the remaining attached payload
                prepareRecords(attachedPayload, isOutbound)

            } else {
                // if the stated record length matches the payload length, we can just handle the record as-is
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