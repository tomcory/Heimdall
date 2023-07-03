package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer

import de.tomcory.heimdall.scanner.traffic.components.ComponentManager
import de.tomcory.heimdall.scanner.traffic.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.util.ByteUtils
import org.pcap4j.packet.Packet
import timber.log.Timber
import java.nio.ByteBuffer
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult

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
        Timber.d("tls$id Creating TLS connection")
    }

    private var state: ConnectionState = ConnectionState.NEW
    private var hostname: String? = null

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


    ////////////////////////////////////
    //////// Inherited methods /////////
    ////////////////////////////////////

    override fun unwrapOutbound(payload: ByteArray) {
        //Timber.d("%s Unwrapping TLS out (%s bytes)", id, payload.size)

        // only reassemble and process records if it's a new connection and we need to parse the remote hostname (SNI)
        if(state == ConnectionState.NEW) {
            prepareRecords(payload, true)
        } else {
            transportLayer.wrapOutbound(payload)
        }
        //TODO: mitmManager.createClientSSLEngineFor()
        //TODO: implement MitM
    }

    override fun unwrapOutbound(packet: Packet) {
        unwrapOutbound(packet.rawData)
    }

    override fun unwrapInbound(payload: ByteArray) {
        //Timber.d("%s Unwrapping TLS in (%s bytes)", id, payload.size)

        prepareRecords(payload, false)
    }

    override fun wrapOutbound(payload: ByteArray) {
        //TODO: implement
        //Timber.d("%s Wrapping TLS out", id)
        transportLayer.wrapOutbound(payload)
    }

    override fun wrapInbound(payload: ByteArray) {
        //TODO: implement
        //Timber.d("%s Wrapping TLS in", id)
        transportLayer.wrapInbound(payload)
    }


    ////////////////////////////////////
    //////// Internal methods //////////
    ////////////////////////////////////

    private fun processRecord(record: ByteArray, isOutbound: Boolean) {
        if(record.isNotEmpty()) {

            val recordType = parseRecordType(record)

            if(isOutbound) {
                handleOutbound(record, recordType)
            } else {
                handleInbound(record, recordType)
            }
        }
    }

    private fun handleOutbound(record: ByteArray, recordType: RecordType) {
        Timber.w("tls$id ----- Outbound $recordType -----")

        if(recordType == RecordType.HANDSHAKE_CLIENT_HELLO) {
            sni = findSni(record)
            hostname = sni ?: transportLayer.ipPacketBuilder.remoteAddress.hostAddress
        }

        // if we don't want to MITM, we can hand the unprocessed record straight to the application layer
        if(!componentManager.doMitm) {
            passOutboundToAppLayer(record)
            return
        }

        if(state == ConnectionState.NEW) {
            if(recordType == RecordType.HANDSHAKE_CLIENT_HELLO) {
                handleClientHello(record)
            } else {
                Timber.e("tls$id Invalid outbound record ($recordType in state $state)")
                //TODO: error handling
            }
        } else if(state == ConnectionState.CLIENT_HANDSHAKE) {
            unwrapOutbound(record)
        } else if(state == ConnectionState.CLIENT_ESTABLISHED) {
            if(recordType == RecordType.HANDSHAKE_CLIENT_HELLO) {
                Timber.e("tls$id Invalid outbound record ($recordType in state $state)")
                //TODO: error handling
            } else {
                unwrapOutbound(record)
            }
        } else {
            Timber.e("tls$id Invalid outbound record ($recordType in state $state)")
        }
    }

    private fun handleInbound(record: ByteArray, recordType: RecordType) {
        Timber.w("tls$id ----- Inbound $recordType in state $state -----")

        // if we don't want to MITM, we can hand the unprocessed record straight to the application layer
        if(!componentManager.doMitm) {
            passInboundToAppLayer(record)
            return
        }

        if(recordType == RecordType.ALERT) {
            Timber.e(ByteUtils.bytesToHex(record))
        }

        //Timber.d(ByteUtils.bytesToHex(record))

        val res = handleServerUnwrap(record)

        when(state) {
            ConnectionState.NEW -> TODO()
            ConnectionState.SERVER_HANDSHAKE -> {
                if(res?.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                    val output = handleServerWrap(null)
                    if (output.isNotEmpty()) {
                        transportLayer.wrapOutbound(output)
                    }
                }
            }
            ConnectionState.SERVER_ESTABLISHED -> TODO()
            ConnectionState.CLIENT_HANDSHAKE -> {
                serverAppBuffer.flip()
                val out = ByteArray(serverAppBuffer.limit())
                serverAppBuffer.get(out)
                Timber.w("tls$id handleServerUnwrap post-unwrap ${ByteUtils.bytesToHex(out)}")
            }
            ConnectionState.CLIENT_ESTABLISHED -> TODO()
        }

        Timber.w("tls$id Resulting connection state $state, result status ${res?.status} and server handshake status ${serverSSLEngine?.handshakeStatus}")

        if(state == ConnectionState.SERVER_ESTABLISHED) {
            setupClientSSLEngine()
        }
    }

    private fun setupClientSSLEngine() {
        clientSSLEngine = serverSSLEngine?.session?.let { componentManager.mitmManager.createClientSSLEngineFor(it) }
        clientAppBuffer = ByteBuffer.allocate(clientSSLEngine?.session?.applicationBufferSize ?: 0)
        clientNetBuffer = ByteBuffer.allocate(clientSSLEngine?.session?.packetBufferSize ?: 0)
        state = ConnectionState.CLIENT_HANDSHAKE
        clientSSLEngine?.beginHandshake()

        Timber.e("tls$id setupClientSSLEngine clientAppBuffer: ${clientAppBuffer.capacity()}, clientNetBuffer: ${clientNetBuffer.capacity()}")

        Timber.e("tls$id setupClientSSLEngine ClientSSLEngine HandshakeStatus: ${clientSSLEngine?.handshakeStatus}")

        val res = handleClientUnwrap(originalClientHello)

        if(res?.status == SSLEngineResult.Status.OK && res.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
            val output = handleClientWrap(null)
            if(output.isNotEmpty()) {
                //Timber.d("tls$id setupClientSSLEngine Output ${ByteUtils.bytesToHex(output).replace(" ", "")}")
                largeLog(ByteUtils.bytesToHex(output).replace(" ", ""))
                transportLayer.wrapInbound(output)
            }
        }
    }

    fun largeLog(content: String) {
        if (content.length > 4000) {
            Timber.d("tls$id ${content.substring(0, 3000)}")
            largeLog("tls$id ${content.substring(3000)}")
        } else {
            Timber.d(content)
        }
    }

    private fun setupServerSSLEngine() {

    }

    private fun handleClientUnwrap(record: ByteArray):  SSLEngineResult? {
        Timber.w("tls$id handleClientUnwrap unwrapping ${record.size} bytes, clientSSLEngine handshakeStatus: ${clientSSLEngine?.handshakeStatus}")

        Timber.d("tls$id handleClientUnwrap clientAppBuffer: ${clientAppBuffer.capacity()}, clientNetBuffer: ${clientNetBuffer.capacity()}, record: ${record.size}")

        // place the outbound payload into the netBuffer of the serverSslEngine
        clientNetBuffer.clear()
        if(clientNetBuffer.capacity() < record.size) {
            Timber.w("$id handleClientUnwrap Resizing serverNetBuffer: ${clientNetBuffer.capacity()} -> ${record.size}")
            clientNetBuffer = ByteBuffer.allocate(record.size)
        }
        clientNetBuffer.put(record)
        clientNetBuffer.flip()

        // prepare the appBuffer for the unwrap operation
        clientAppBuffer.clear()

        Timber.d("tls$id handleClientUnwrap pre-unwrap - limit: ${clientNetBuffer.limit()}, capacity: ${clientNetBuffer.capacity()}, position: ${clientNetBuffer.position()}")
        val res = clientSSLEngine?.unwrap(clientNetBuffer, clientAppBuffer)
        Timber.d("tls$id handleClientUnwrap post-unwrap - limit: ${clientAppBuffer.limit()}, position: ${clientAppBuffer.position()}")

        Timber.d("tls$id handleClientUnwrap clientSSLEngine unwrap handshakeResult: $res")
        Timber.d("tls$id handleClientWrap clientSSLEngine handshakeStatus: ${clientSSLEngine?.handshakeStatus}")

        return res
    }

    private fun handleClientWrap(payload: ByteArray?): ByteArray {
        Timber.w("tls$id handleClientWrap wrapping ${payload?.size ?: 0} bytes, clientSSLEngine handshakeStatus: ${clientSSLEngine?.handshakeStatus}")

        Timber.d("tls$id handleClientWrap clientAppBuffer: ${clientAppBuffer.capacity()}, clientNetBuffer: ${clientNetBuffer.capacity()}, payload: ${payload?.size}")

        // place the outbound payload into the appBuffer of the serverSslEngine
        clientAppBuffer.clear()
        payload?.let {
            if(clientAppBuffer.capacity() < (it.size)) {
                Timber.w("$id handleClientWrap Resizing serverNetBuffer: ${clientNetBuffer.capacity()} -> ${it.size}")
                serverAppBuffer = ByteBuffer.allocate(it.size)
            }

            clientAppBuffer.put(it)
            clientAppBuffer.flip()
        }

        // prepare the netBuffer for the unwrap operation
        clientNetBuffer.clear()

        Timber.d("tls$id handleClientWrap pre-wrap - limit: ${clientAppBuffer.limit()}, capacity: ${clientAppBuffer.capacity()}, position: ${clientAppBuffer.position()}")
        val res = clientSSLEngine?.wrap(clientAppBuffer, clientNetBuffer)
        Timber.d("tls$id handleClientWrap post-wrap - limit: ${clientNetBuffer.limit()}, position: ${clientNetBuffer.position()}")

        if(res?.handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED) {
            state = ConnectionState.CLIENT_ESTABLISHED
        }

        Timber.d("tls$id handleClientWrap clientSSLEngine wrap handshakeResult: $res")
        Timber.d("tls$id handleClientWrap clientSSLEngine handshakeStatus: ${clientSSLEngine?.handshakeStatus}")

        return if(res?.status == SSLEngineResult.Status.OK && res.bytesProduced() > 0) {
            clientNetBuffer.flip()
            val out = ByteArray(res.bytesProduced())
            clientNetBuffer.get(out)
            out
        } else {
            byteArrayOf()
        }
    }

    private fun handleServerUnwrap(record: ByteArray):  SSLEngineResult? {
        Timber.w("tls$id handleServerUnwrap unwrapping ${record.size} bytes, serverSSLEngine handshakeStatus: ${serverSSLEngine?.handshakeStatus}")

        Timber.d("tls$id handleServerUnwrap serverAppBuffer: ${serverAppBuffer.capacity()}, serverNetBuffer: ${serverNetBuffer.capacity()}, record: ${record.size}")

        // place the outbound payload into the netBuffer of the serverSslEngine
        serverNetBuffer.clear()
        if(serverNetBuffer.capacity() < record.size) {
            Timber.w("$id handleServerUnwrap Resizing serverNetBuffer: ${serverNetBuffer.capacity()} -> ${record.size}")
            serverNetBuffer = ByteBuffer.allocate(record.size)
        }
        serverNetBuffer.put(record)
        serverNetBuffer.flip()

        // prepare the appBuffer for the unwrap operation
        serverAppBuffer.clear()

        Timber.d("tls$id handleServerUnwrap pre-unwrap - limit: ${serverNetBuffer.limit()}, capacity: ${serverNetBuffer.capacity()}, position: ${serverNetBuffer.position()}")

        val res = serverSSLEngine?.unwrap(serverNetBuffer, serverAppBuffer)
        Timber.d("tls$id handleServerUnwrap post-unwrap - limit: ${serverAppBuffer.limit()}, position: ${serverAppBuffer.position()}")
        Timber.d("tls$id handleServerUnwrap serverSSLEngine unwrap handshakeResult: $res")
        Timber.d("tls$id handleServerWrap serverSSLEngine handshakeStatus: ${serverSSLEngine?.handshakeStatus}")

        return res
    }

    private fun handleServerWrap(payload: ByteArray?): ByteArray {
        Timber.w("tls$id handleServerWrap wrapping ${payload?.size ?: 0} bytes, serverSSLEngine handshakeStatus: ${serverSSLEngine?.handshakeStatus}")

        Timber.d("tls$id handleServerWrap serverAppBuffer: ${serverAppBuffer.capacity()}, serverNetBuffer: ${serverNetBuffer.capacity()}, payload: ${payload?.size}")

        // place the outbound payload into the appBuffer of the serverSslEngine
        serverAppBuffer.clear()
        payload?.let {
            if(serverAppBuffer.capacity() < (it.size)) {
                Timber.w("$id handleServerUnwrap Resizing serverNetBuffer: ${serverNetBuffer.capacity()} -> ${it.size}")
                serverAppBuffer = ByteBuffer.allocate(it.size)
            }

            serverAppBuffer.put(it)
            serverAppBuffer.flip()
        }

        // prepare the netBuffer for the unwrap operation
        serverNetBuffer.clear()

        val res = serverSSLEngine?.wrap(serverAppBuffer, serverNetBuffer)

        if(res?.handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED) {
            state = ConnectionState.SERVER_ESTABLISHED
        }

        Timber.d("tls$id handleServerWrap serverSSLEngine wrap handshakeResult: $res")
        Timber.d("tls$id handleServerWrap serverSSLEngine handshakeStatus: ${serverSSLEngine?.handshakeStatus}")

        return if(res?.status == SSLEngineResult.Status.OK && res.bytesProduced() > 0) {
            serverNetBuffer.flip()
            val out = ByteArray(res.bytesProduced())
            serverNetBuffer.get(out)
            out
        } else {
            byteArrayOf()
        }
    }

    private fun handleClientHello(record: ByteArray) {

        Timber.d("tls$id handleClientHello Hostname: $hostname")

        // store the client hello for later
        originalClientHello = record

        // create a new SSLEngine to handle the TLS session facing the remote host
        serverSSLEngine = componentManager.mitmManager.createServerSSLEngine(sni, transportLayer.remotePort)
        serverAppBuffer = ByteBuffer.allocate(serverSSLEngine?.session?.applicationBufferSize ?: 0)
        serverNetBuffer = ByteBuffer.allocate(serverSSLEngine?.session?.packetBufferSize ?: 0)
        //serverSSLEngine = mitmManager?.createServerSSLEngine("www.google.de", 443)

        state = ConnectionState.SERVER_HANDSHAKE

        Timber.d("tls$id handleClientHello HandshakeStatus: ${serverSSLEngine?.handshakeStatus}")

        serverSSLEngine?.beginHandshake()

        // get the generated CLIENT HELLO from the output buffer and pass it down to the transport layer
        val output = handleServerWrap(null)
        if(output.isNotEmpty()) {
            //Timber.d("tls$id handleClientHello Output ${ByteUtils.bytesToHex(output)}")
            transportLayer.wrapOutbound(output)
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
                //Timber.w("%s Payload is larger than remaining overflow: %s > %s", id, rawPayload.size, remainingBytes)
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

            //Timber.d("%s Appended %s bytes to overflow, %s bytes remaining", id, currentPayload.size, remainingBytes)

            // if there are still overflow bytes remaining, do nothing and await the next payload
            if(remainingBytes > 0) {
                return
            }

            // otherwise combine the cached parts into one record and clear the cache
            val combinedRecord = cache.reduce { acc, x -> acc + x }
            cache.clear()
            //Timber.d("%s Got all overflow bytes, record reassembled", id)

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
                Timber.e("tls$id Invalid TLS record type: ${ByteUtils.bytesToHex(recordType.toByte())}")
                Timber.e("tls$id ${ByteUtils.bytesToHex(payload)}")
                return
            }

            // ... which must at least comprise a TLS header with 5 bytes
            if(payload.size < 5) {
                Timber.w("tls$id Got a tiny snippet of a TLS record (${payload.size} bytes), stashing it and awaiting the rest")
                if(isOutbound) {
                    outboundSnippet = payload
                } else {
                    inboundSnippet = payload
                }
                return
            }

            val statedLength = payload[3].toUByte().toInt() shl 8 or payload[4].toUByte().toInt()
            val actualLength = payload.size - 5

            //Timber.d("%s Raw: %s, Stated: %s, Actual: %s", id, rawPayload.size, statedLength, actualLength)

            // if the stated record length is larger than the payload length, we go into overflow mode and cache the payload
            if(statedLength > actualLength) {
                cache.add(payload)
                remainingBytes = statedLength - actualLength

                if(isOutbound)
                    remainingOutboundBytes = remainingBytes
                else
                    remainingInboundBytes = remainingBytes

                //Timber.d("%s Started overflow collection, %s/%s bytes remaining", id, remainingBytes, statedLength + 5)

            } else if(statedLength < actualLength) {
                //Timber.w("%s Stated record length is smaller than payload length: %s < %s", id, statedLength, actualLength)
                val currentRecord = payload.slice(0 until statedLength + 5).toByteArray()
                val attachedPayload = payload.slice(statedLength + 5 until payload.size).toByteArray()

                // process the extracted record...
                processRecord(currentRecord, isOutbound)

                // ...and when that is done, handle the remaining attached payload
                //Timber.d("%s Processing attached payload", id)
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


    ////////////////////////////////////
    //////// Internal enums ////////////
    ////////////////////////////////////

    private enum class ConnectionState {
        NEW,
        SERVER_HANDSHAKE,
        SERVER_ESTABLISHED,
        CLIENT_HANDSHAKE,
        CLIENT_ESTABLISHED
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