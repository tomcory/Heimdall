package de.tomcory.heimdall.core.vpn.connection.appLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import org.pcap4j.packet.Packet
import timber.log.Timber

class HttpConnection(
    id: Int,
    encryptionLayer: EncryptionLayerConnection,
    componentManager: ComponentManager
) : AppLayerConnection(
    id,
    encryptionLayer,
    componentManager
) {

    /**
     * Caches payloads if they don't contain the end of the headers. Once the end of the headers is found (double CRLF), the message is handled normally (chunked, overflowing, or persisted).
     */
    private var previousPayload: ByteArray = ByteArray(0)

    /**
     * Cache for chunked messages. Used for chunked messages and messages that overflow the buffer. Messages are only persisted once they are complete.
     */
    private val chunkCache = mutableListOf<ByteArray>()

    private var overflowing = false
    private var chunked = false
    private var statedContentLength = -1
    private var remainingContentLength = -1

    private val maximumMessageSize = 1024 * 1024 // 1 MB

    /**
     * Channel for passing the request ID from the HTTP request insertion coroutine to the HTTP response insertion coroutine.
     */
    private val requestIdChannel = Channel<Int>()

    init {
        if(id > 0) {
            Timber.d("http$id Creating HTTP connection to ${encryptionLayer.transportLayer.ipPacketBuilder.remoteAddress.hostAddress}:${encryptionLayer.transportLayer.remotePort} (${encryptionLayer.transportLayer.remoteHost})")
        }
    }

    override fun unwrapOutbound(payload: ByteArray) {
        handleData(payload, true)
        encryptionLayer.wrapOutbound(payload)
    }

    override fun unwrapOutbound(packet: Packet) {
        unwrapOutbound(packet.rawData)
    }

    override fun unwrapInbound(payload: ByteArray) {
        handleData(payload, false)
        encryptionLayer.wrapInbound(payload)
    }

    private fun handleData(payload: ByteArray, isOutbound: Boolean) {
        Timber.d("http$id Processing http ${if(isOutbound) "out" else "in"}: ${payload.size} bytes")
        val assembledPayload = previousPayload + payload

        // distinguish between the first/only chuck and additional chunks
        if(!chunked && !overflowing) {

            // parse the raw bytes
            val message = assembledPayload.toString(Charsets.UTF_8)

            val headerLength = message.indexOf("\r\n\r\n") + 4
            if(headerLength < 4) {
                // if the message doesn't contain the end of the headers, cache the chunk and wait for more
                Timber.w("http$id incomplete headers")
                previousPayload = assembledPayload
                return
            } else {
                if(previousPayload.isNotEmpty()) {
                    Timber.w("http$id incomplete headers resolved (header length: ${message.length})")
                }
                previousPayload = ByteArray(0)
            }

            val lowercaseHeaders = message.substring(0, headerLength).lowercase()

            // the message is "officially" chunked only if this header is present
            chunked = lowercaseHeaders.contains("transfer-encoding: chunked")
            if(chunked) {
                Timber.d("http$id chunked")
            }

            // messages can still overflow, which we can check by comparing the stated and actual content lengths
            overflowing = if(!chunked) {
                val lengthIndex = lowercaseHeaders.indexOf("content-length: ")

                statedContentLength = if(lengthIndex > 0) {
                    val endOfContentLength = lowercaseHeaders.indexOf("\r\n", lengthIndex + 16)
                    lowercaseHeaders.substring(lengthIndex + 16, endOfContentLength).toIntOrNull() ?: -1
                } else {
                    -1
                }

                // if there was no Content-Length header, we have to assume that there's no overflow since we cannot determine the intended length
                if(statedContentLength > 0) {
                    val bodyIndex = message.indexOf("\r\n\r\n") + 4
                    val actualContentLength = assembledPayload.size - bodyIndex
                    remainingContentLength = statedContentLength - actualContentLength
                    remainingContentLength > 0
                } else {
                    false
                }
            } else {
                false
            }


            // check whether the message is chunked or overflowing
            if(chunked || overflowing) {
                if(overflowing) {
                    Timber.d("http$id starting overflow with $remainingContentLength of $statedContentLength bytes remaining")
                }
                // if it is, cache this chunk and wait for more
                chunkCache.add(assembledPayload)
            } else {
                // otherwise persist the message
                persistMessage(message, isOutbound)
            }
        } else {
            // add the chunk to the cache
            chunkCache.add(assembledPayload)

            // we boldly assume that a message is overflowing XOR chunked - may the testers forgive us
            if(overflowing) {
                // check whether there's still content remaining after the current payload
                remainingContentLength -= assembledPayload.size
                if(remainingContentLength <= 0) {
                    Timber.d("http$id resolved overflow with $remainingContentLength of $statedContentLength bytes remaining")
                    // if there isn't, flatten the cache and persist the message
                    persistMessage(combineChunks().toString(Charsets.UTF_8), isOutbound)
                } else {
                    Timber.d("http$id continuing overflow with $remainingContentLength of $statedContentLength bytes remaining")
                }
            } else {
                // check whether it's the last chunk
                val lines = assembledPayload.toString(Charsets.UTF_8).split("\r\n")
                if(lines.size >= 2 && (lines[lines.size - 2].trim().toIntOrNull(16) ?: -1) == 0) {
                    Timber.d("http$id last chunk")
                    // if it is, flatten the cache, recombine the message and persist it
                    persistMessage(dechunkHttpMessage(combineChunks()), isOutbound)
                }
            }
        }
    }

    private fun persistMessage(message: String, isOutbound: Boolean) {
        // parse the three components of the message individually
        val statusLine = parseStatusLine(message, isOutbound)
        val headers = parseHeaders(message)
        val body = parseBody(message)

        // reset flags for reuse
        overflowing = false
        chunked = false
        statedContentLength = -1
        remainingContentLength = -1

        CoroutineScope(Dispatchers.IO).launch {
            if(isOutbound) {
                val requestId = componentManager.databaseConnector.persistHttpRequest(
                    connectionId = id,
                    timestamp = System.currentTimeMillis(),
                    headers = headers ?: emptyMap(),
                    content = if(body == null) "" else if(body.length > maximumMessageSize) "<too large: ${body.length} bytes>" else body,
                    contentLength = body?.length ?: 0,
                    method = statusLine?.get(0) ?: "",
                    remoteHost = encryptionLayer.transportLayer.remoteHost ?: "",
                    remotePath = statusLine?.get(1) ?: "",
                    remoteIp = encryptionLayer.transportLayer.ipPacketBuilder.remoteAddress.hostAddress ?: "",
                    remotePort = encryptionLayer.transportLayer.remotePort,
                    localIp = encryptionLayer.transportLayer.ipPacketBuilder.localAddress.hostAddress ?: "",
                    localPort = encryptionLayer.transportLayer.localPort,
                    initiatorId = encryptionLayer.transportLayer.appId ?: 0,
                    initiatorPkg = encryptionLayer.transportLayer.appPackage ?: ""
                )
                Timber.d("http$id persisting request with ID $requestId")
                requestIdChannel.send(requestId)
            } else {
                val requestId = requestIdChannel.receive()
                Timber.d("http$id persisting response to request with ID $requestId")
                componentManager.databaseConnector.persistHttpResponse(
                    connectionId = id,
                    requestId = requestId,
                    timestamp = System.currentTimeMillis(),
                    headers = headers ?: emptyMap(),
                    content = if(body == null) "" else if(body.length > maximumMessageSize) "<too large: ${body.length} bytes>" else body,
                    contentLength = body?.length ?: 0,
                    statusCode = statusLine?.get(1)?.toIntOrNull() ?: 0,
                    statusMsg = statusLine?.get(2) ?: "",
                    remoteHost = encryptionLayer.transportLayer.remoteHost ?: "",
                    remoteIp = encryptionLayer.transportLayer.ipPacketBuilder.remoteAddress.hostAddress ?: "",
                    remotePort = encryptionLayer.transportLayer.remotePort,
                    localIp = encryptionLayer.transportLayer.ipPacketBuilder.localAddress.hostAddress ?: "",
                    localPort = encryptionLayer.transportLayer.localPort,
                    initiatorId = encryptionLayer.transportLayer.appId ?: 0,
                    initiatorPkg = encryptionLayer.transportLayer.appPackage ?: ""
                )
            }
        }
    }

    private fun parseStatusLine(message: String, isOutbound: Boolean): List<String>? {
        val endOfStatusLine = message.indexOf("\r\n")

        if(endOfStatusLine < 0) {
            Timber.e("http$id Invalid status line, no newline found")
            Timber.e("http$id $message")
            return null
        }

        val statusLine = message.substring(0, endOfStatusLine)

        val parts = statusLine.split(" ", limit = 3)

        if (parts.size < 3) {
            Timber.e("http$id parseStatusLine: Invalid status line")
            return null
        }

        if(!isOutbound && parts[1].toIntOrNull() == null) {
            Timber.e("http$id parseStatusLine: Invalid status code")
            return null
        }

        return listOf(parts[0], parts[1], parts[2])
    }

    private fun parseHeaders(message: String): Map<String, String>? {
        val headersIndex = message.indexOf("\r\n") + 2
        val bodyIndex = message.indexOf("\r\n\r\n")

        if(headersIndex < 0 || bodyIndex < 0 || headersIndex >= bodyIndex) {
            Timber.e("http$id parseHeaders: Invalid HTTP message, no headers found")
            Timber.w("http$id $message")
            return emptyMap()
        }

        val headerBlock = message.substring(headersIndex, bodyIndex)

        val headerLines = headerBlock.split("\r\n")

        return try {
            headerLines.associate { line ->
                val (name, value) = line.split(": ", limit = 2)
                name to value
            }
        } catch (e: Exception) {
            Timber.e("http$id parseHeaders: Invalid headers")
            null
        }
    }

    private fun parseBody(message: String): String? {
        val bodyIndex = message.indexOf("\r\n\r\n") + 4

        if(bodyIndex < 0) {
            Timber.e("http$id parseBody: Invalid HTTP message, no chunks found")
            return null
        }

        return message.substring(bodyIndex)
    }

    private fun dechunkHttpMessage(chunkedMessage: ByteArray): String {
        val chunkedMessageStr = String(chunkedMessage, Charsets.UTF_8)

        val headersIndex = chunkedMessageStr.indexOf("\r\n") + 2
        val chunkedBodyIndex = chunkedMessageStr.indexOf("\r\n\r\n") + 4

        if(headersIndex < 0) {
            Timber.e("http$id dechunkHttpMessage Invalid HTTP message, no headers found")
            return ""
        }

        if(chunkedBodyIndex < 0) {
            Timber.e("http$id dechunkHttpMessage Invalid HTTP message, no chunks found")
            return ""
        }

        val statusAndHeaders = chunkedMessageStr.substring(0, chunkedBodyIndex)
        val chunkedBody = chunkedMessageStr.substring(chunkedBodyIndex)

        val chunks = chunkedBody.split("\r\n")
        val dechunkedBody = StringBuilder()

        var i = 0
        while (i < chunks.size) {
            // Chunks are in format: <chunk size in hex>\r\n<chunk data>\r\n
            val chunkSize = chunks[i++].toInt(16)
            if (chunkSize == 0) {
                // This is the last chunk
                break
            }

            dechunkedBody.append(chunks[i++])
        }

        return "$statusAndHeaders$dechunkedBody"
    }

    private fun combineChunks(): ByteArray {
        val totalSize = chunkCache.sumOf { it.size }
        val result = ByteArray(totalSize)
        var position = 0
        for (bytes in chunkCache) {
            bytes.copyInto(result, position)
            position += bytes.size
        }
        // at this point we're done with the cache and can clear it for reuse
        chunkCache.clear()
        return result
    }
}