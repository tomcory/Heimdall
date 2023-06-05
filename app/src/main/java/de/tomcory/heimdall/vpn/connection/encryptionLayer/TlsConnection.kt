package de.tomcory.heimdall.vpn.connection.encryptionLayer

import de.tomcory.heimdall.util.ByteUtils
import de.tomcory.heimdall.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.vpn.mitm.CertificateSniffingMitmManager
import timber.log.Timber
import java.nio.ByteBuffer
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult

class TlsConnection(
    id: Int,
    transportLayer: TransportLayerConnection,
    private val mitmManager: CertificateSniffingMitmManager?,
    private val doMitm: Boolean = mitmManager != null,)
    : EncryptionLayerConnection(id, transportLayer) {

    init {
        Timber.w("%s Creating TLS connection", id)
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

    private var originalClientHello: ByteArray? = null


    ////////////////////////////////////
    //////// Inherited methods /////////
    ////////////////////////////////////

    override fun unwrapOutbound(payload: ByteArray) {
        //Timber.d("%s Unwrapping TLS out (%s bytes)", id, payload.size)

        // only reassemble and process records if we want to MITM or it's a new connection and we need to parse the remote hostname (SNI)
        if(doMitm || state == ConnectionState.NEW) {
            prepareRecords(payload, true)
        } else {
            transportLayer.wrapOutbound(payload)
        }
        //TODO: mitmManager.createClientSSLEngineFor()
    }

    override fun unwrapInbound(payload: ByteArray) {
        //Timber.d("%s Unwrapping TLS in (%s bytes)", id, payload.size)

        // only reassemble and process records if we want to MITM
        if(doMitm) {
            prepareRecords(payload, false)
        } else {
            transportLayer.wrapInbound(payload)
        }
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
        Timber.w("%s ----- Outbound %s -----", id, recordType)

        if(state == ConnectionState.NEW) {
            if(recordType == RecordType.HANDSHAKE_CLIENT_HELLO) {
                handleClientHello(record)
            } else {
                Timber.e("%s Invalid outbound record (%s in state %s)", id, recordType, state)
                //TODO: error handling
            }
        } else if(state == ConnectionState.CLIENT_HANDSHAKE) {
            //TODO: handleClientUnwrap(record)
        } else if(state == ConnectionState.CLIENT_ESTABLISHED) {
            if(recordType == RecordType.HANDSHAKE_CLIENT_HELLO) {
                Timber.e("%s Invalid outbound record (%s in state %s)", id, recordType, state)
                //TODO: error handling
            } else {
                //TODO: implement
            }
        } else {
            Timber.e("%s Invalid outbound record (%s in state %s)", id, recordType, state)
        }
    }

    private fun handleInbound(record: ByteArray, recordType: RecordType) {
        Timber.w("%s ----- Inbound %s in state %s -----", id, recordType, state)

        Timber.d(ByteUtils.bytesToHex(record))

        val res = handleServerUnwrap(record)
        if(res?.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
            val output = handleServerWrap(null)
            if (output.isNotEmpty()) {
                Timber.d("%s Output %s", id, ByteUtils.bytesToHex(output))
                transportLayer.wrapOutbound(output)
            }
        }

        Timber.w("%s Resulting state: %s", id, state)

        if(state == ConnectionState.SERVER_ESTABLISHED) {
            setupClientSSLEngine()
        }
    }

    private fun setupClientSSLEngine() {
        clientSSLEngine = serverSSLEngine?.session?.let { mitmManager?.createClientSSLEngineFor(it) }
        state = ConnectionState.CLIENT_HANDSHAKE
        clientSSLEngine?.beginHandshake()
        Timber.e("%s ClientSSLEngine HandshakeStatus: %s", id, clientSSLEngine?.handshakeStatus)

        handleClientUnwrap(byteArrayOf())
        //TODO: implement
    }

    private fun handleClientUnwrap(record: ByteArray):  SSLEngineResult? {
        Timber.d("%s Unwrapping %s bytes: %s", id, record.size, ByteUtils.bytesToHex(record))

        val input = ByteBuffer.wrap(record)
        val output = ByteBuffer.allocate(clientSSLEngine!!.session.applicationBufferSize)

        val res = clientSSLEngine?.unwrap(input, output)

        Timber.d("%s ClientSSLEngine Unwrap HandshakeResult: %s", id, res)
        Timber.d("%s ClientSSLEngine HandshakeStatus: %s", id, serverSSLEngine?.handshakeStatus)

        return res
    }

    private fun handleServerUnwrap(record: ByteArray):  SSLEngineResult? {
        Timber.d("%s Unwrapping %s bytes: %s", id, record.size, ByteUtils.bytesToHex(record))

        val input = ByteBuffer.wrap(record)
        val output = ByteBuffer.allocate(serverSSLEngine!!.session.applicationBufferSize)

        val res = serverSSLEngine?.unwrap(input, output)

        Timber.d("%s ServerSSLEngine Unwrap HandshakeResult: %s", id, res)
        Timber.d("%s ServerSSLEngine HandshakeStatus: %s", id, serverSSLEngine?.handshakeStatus)

        return res
    }

    private fun handleServerWrap(payload: ByteArray?): ByteArray {
        Timber.d("%s Wrapping, ServerSSLEngine HandshakeStatus: %s", id, serverSSLEngine?.handshakeStatus)

        val inputSize = if(payload != null) payload.size + 50 else 0

        val input = ByteBuffer.allocate(inputSize)
        val output = ByteBuffer.allocate(serverSSLEngine!!.session.packetBufferSize)

        val res = serverSSLEngine?.wrap(input, output)

        if(res?.handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED) {
            state = ConnectionState.SERVER_ESTABLISHED
        }

        Timber.d("%s ServerSSLEngine Wrap HandshakeResult: %s", id, res)
        Timber.d("%s ServerSSLEngine HandshakeStatus: %s", id, serverSSLEngine?.handshakeStatus)

        return if(res?.status == SSLEngineResult.Status.OK && res.bytesProduced() > 0) {
            output.flip()
            val out = ByteArray(res.bytesProduced())
            output.get(out)
            out
        } else {
            byteArrayOf()
        }
    }

    private fun handleClientHello(record: ByteArray) {
        // extract the SNI from the record (or use the host address if there's no SNI)
        val sni = findSni(record)
        hostname = sni ?: transportLayer.ipPacketBuilder.remoteAddress.hostAddress

        // store the client hello for later
        originalClientHello = record

        Timber.d("%s Hostname: %s", id, hostname)

        // if we don't want to MITM, we can hand the unprocessed record straight back to the transport layer
        if(!doMitm) {
            transportLayer.wrapOutbound(record)
        }

        // create a new SSLEngine to handle the TLS session facing the remote host
        serverSSLEngine = mitmManager?.createServerSSLEngine(sni, transportLayer.remotePort.valueAsInt())
        //serverSSLEngine = mitmManager?.createServerSSLEngine("www.google.de", 443)

        state = ConnectionState.SERVER_HANDSHAKE

        Timber.d("%s HandshakeStatus: %s", id, serverSSLEngine?.handshakeStatus)

        serverSSLEngine?.beginHandshake()

        // get the generated CLIENT HELLO from the output buffer and pass it down to the transport layer
        val output = handleServerWrap(null)
        if(output.isNotEmpty()) {
            Timber.d("%s Output %s", id, ByteUtils.bytesToHex(output))
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
                Timber.e("%s Invalid TLS record type: %s", id, ByteUtils.bytesToHex(recordType.toByte()))
                Timber.e("%s %s", id, ByteUtils.bytesToHex(payload))
                return
            }

            // ... which must at least comprise a TLS header with 5 bytes
            if(payload.size < 5) {
                Timber.w("%s Got a tiny snippet of a TLS record, stashing it and awaiting the rest", id)
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
                Timber.e("Invalid TLS record (too short)")
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
                return String(msg.copyOfRange(i + j + 3, i + j + entryLength).map { x -> x.toChar() }.toCharArray())
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