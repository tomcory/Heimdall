package de.tomcory.heimdall.core.vpn.connection.appLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import org.pcap4j.packet.Packet
import timber.log.Timber
import java.util.concurrent.ConcurrentLinkedDeque

class HttpConnection(
    id: Long,
    encryptionLayer: EncryptionLayerConnection,
    componentManager: ComponentManager
) : AppLayerConnection(
    id,
    encryptionLayer,
    componentManager
) {

    /**
     * HTTP/1.1 keep-alive lets requests and responses interleave on the wire in the same
     * direction, but outbound (request) and inbound (response) bytes are otherwise entirely
     * independent streams - each direction gets its own reassembly state so that, say, a
     * response arriving mid-way through a large outbound request body can't corrupt either one.
     */
    private class ReassemblyState {
        /**
         * Caches payloads if they don't contain the end of the headers. Once the end of the headers is found (double CRLF), the message is handled normally (chunked, overflowing, or persisted).
         */
        var previousPayload: ByteArray = ByteArray(0)

        /**
         * Cache for chunked messages. Used for chunked messages and messages that overflow the buffer. Messages are only persisted once they are complete.
         */
        val chunkCache = mutableListOf<ByteArray>()

        var overflowing = false
        var chunked = false
        var statedContentLength = -1
        var remainingContentLength = -1
    }

    private val outboundState = ReassemblyState()
    private val inboundState = ReassemblyState()

    private val maximumMessageSize = 1024 * 1024 // 1 MB

    /**
     * Queue of not-yet-persisted requests' IDs, in wire order, used to correlate each inbound
     * response with the request that preceded it. Requests and responses are each processed
     * sequentially within their own direction, but persistence happens asynchronously (on
     * Dispatchers.IO), so completion order doesn't necessarily match wire order for pipelined
     * requests - pushing/popping a [CompletableDeferred] placeholder synchronously (in wire
     * order) as soon as a request/response is recognised, before the async persist even starts,
     * is what keeps the pairing correct regardless of how long any individual persist takes.
     * [ConcurrentLinkedDeque] because pushes happen on the outbound-processing thread and pops on
     * the inbound-processing thread for the same connection.
     */
    private val pendingRequestIds = ConcurrentLinkedDeque<CompletableDeferred<Long>>()

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
        val state = if (isOutbound) outboundState else inboundState
        val assembledPayload = state.previousPayload + payload

        // distinguish between the first/only chuck and additional chunks
        if(!state.chunked && !state.overflowing) {

            // parse the raw bytes
            val message = assembledPayload.toString(Charsets.UTF_8)

            val headerLength = message.indexOf("\r\n\r\n") + 4
            if(headerLength < 4) {
                // if the message doesn't contain the end of the headers, cache the chunk and wait for more
                Timber.w("http$id incomplete headers")
                state.previousPayload = assembledPayload
                return
            } else {
                if(state.previousPayload.isNotEmpty()) {
                    Timber.w("http$id incomplete headers resolved (header length: ${message.length})")
                }
                state.previousPayload = ByteArray(0)
            }

            val lowercaseHeaders = message.substring(0, headerLength).lowercase()

            // the message is "officially" chunked only if this header is present
            state.chunked = lowercaseHeaders.contains("transfer-encoding: chunked")
            if(state.chunked) {
                Timber.d("http$id chunked")
            }

            // messages can still overflow, which we can check by comparing the stated and actual content lengths
            state.overflowing = if(!state.chunked) {
                val lengthIndex = lowercaseHeaders.indexOf("content-length: ")

                state.statedContentLength = if(lengthIndex > 0) {
                    val endOfContentLength = lowercaseHeaders.indexOf("\r\n", lengthIndex + 16)
                    lowercaseHeaders.substring(lengthIndex + 16, endOfContentLength).toIntOrNull() ?: -1
                } else {
                    -1
                }

                // if there was no Content-Length header, we have to assume that there's no overflow since we cannot determine the intended length
                if(state.statedContentLength > 0) {
                    val bodyIndex = message.indexOf("\r\n\r\n") + 4
                    val actualContentLength = assembledPayload.size - bodyIndex
                    state.remainingContentLength = state.statedContentLength - actualContentLength
                    state.remainingContentLength > 0
                } else {
                    false
                }
            } else {
                false
            }


            // check whether the message is chunked or overflowing
            if(state.chunked || state.overflowing) {
                if(state.overflowing) {
                    Timber.d("http$id starting overflow with ${state.remainingContentLength} of ${state.statedContentLength} bytes remaining")
                }
                // if it is, cache this chunk and wait for more
                state.chunkCache.add(assembledPayload)
            } else {
                // otherwise persist the message
                persistMessage(message, isOutbound)
            }
        } else {
            // add the chunk to the cache
            state.chunkCache.add(assembledPayload)

            // we boldly assume that a message is overflowing XOR chunked - may the testers forgive us
            if(state.overflowing) {
                // check whether there's still content remaining after the current payload
                state.remainingContentLength -= assembledPayload.size
                if(state.remainingContentLength <= 0) {
                    Timber.d("http$id resolved overflow with ${state.remainingContentLength} of ${state.statedContentLength} bytes remaining")
                    // if there isn't, flatten the cache and persist the message
                    persistMessage(combineChunks(state).toString(Charsets.UTF_8), isOutbound)
                } else {
                    Timber.d("http$id continuing overflow with ${state.remainingContentLength} of ${state.statedContentLength} bytes remaining")
                }
            } else {
                // check whether it's the last chunk
                val lines = assembledPayload.toString(Charsets.UTF_8).split("\r\n")
                if(lines.size >= 2 && (lines[lines.size - 2].trim().toIntOrNull(16) ?: -1) == 0) {
                    Timber.d("http$id last chunk")
                    // if it is, flatten the cache, recombine the message and persist it
                    persistMessage(dechunkHttpMessage(combineChunks(state)), isOutbound)
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
        val state = if (isOutbound) outboundState else inboundState
        state.overflowing = false
        state.chunked = false
        state.statedContentLength = -1
        state.remainingContentLength = -1

        if (isOutbound) {
            // register this request's placeholder in wire order *before* launching the async
            // persist, so a response processed while the persist is still in flight still
            // correlates with the right request regardless of how long the DB write takes
            val pendingId = CompletableDeferred<Long>()
            pendingRequestIds.addLast(pendingId)

            CoroutineScope(Dispatchers.IO).launch {
                try {
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
                    pendingId.complete(requestId)
                } catch (e: Throwable) {
                    Timber.e(e, "http$id Error persisting HTTP request")
                    pendingId.completeExceptionally(e)
                }
            }
        } else {
            // pop the oldest still-pending request synchronously (in wire order) so pipelined
            // responses pair with the right request even if their persist coroutines complete
            // out of order; a response with no pending request at all is dropped immediately
            // instead of suspending forever waiting for one that will never arrive
            val pendingId = pendingRequestIds.pollFirst()
            if (pendingId == null) {
                Timber.w("http$id Received a response with no matching pending request, discarding it")
                return
            }

            CoroutineScope(Dispatchers.IO).launch {
                val requestId = try {
                    withTimeoutOrNull(REQUEST_CORRELATION_TIMEOUT_MS) { pendingId.await() }
                } catch (e: Throwable) {
                    Timber.e(e, "http$id Error awaiting matching request ID")
                    null
                }
                if (requestId == null) {
                    Timber.w("http$id No matching request ID became available in time, discarding response")
                    return@launch
                }
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
        val rawHeadersIndex = message.indexOf("\r\n")
        val bodyIndex = message.indexOf("\r\n\r\n")

        if(rawHeadersIndex < 0 || bodyIndex < 0 || rawHeadersIndex + 2 >= bodyIndex) {
            Timber.e("http$id parseHeaders: Invalid HTTP message, no headers found")
            Timber.w("http$id $message")
            return emptyMap()
        }

        val headersIndex = rawHeadersIndex + 2
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
        val rawBodyIndex = message.indexOf("\r\n\r\n")

        if(rawBodyIndex < 0) {
            Timber.e("http$id parseBody: Invalid HTTP message, no chunks found")
            return null
        }

        return message.substring(rawBodyIndex + 4)
    }

    private fun dechunkHttpMessage(chunkedMessage: ByteArray): String {
        val chunkedMessageStr = String(chunkedMessage, Charsets.UTF_8)

        val rawHeadersIndex = chunkedMessageStr.indexOf("\r\n")
        val rawChunkedBodyIndex = chunkedMessageStr.indexOf("\r\n\r\n")

        if(rawHeadersIndex < 0) {
            Timber.e("http$id dechunkHttpMessage Invalid HTTP message, no headers found")
            return ""
        }

        if(rawChunkedBodyIndex < 0) {
            Timber.e("http$id dechunkHttpMessage Invalid HTTP message, no chunks found")
            return ""
        }

        val chunkedBodyIndex = rawChunkedBodyIndex + 4
        val statusAndHeaders = chunkedMessageStr.substring(0, chunkedBodyIndex)
        val chunkedBody = chunkedMessageStr.substring(chunkedBodyIndex)

        val chunks = chunkedBody.split("\r\n")
        val dechunkedBody = StringBuilder()

        var i = 0
        while (i < chunks.size) {
            // Chunks are in format: <chunk size in hex>\r\n<chunk data>\r\n
            val chunkSize = chunks[i++].toIntOrNull(16)
            if (chunkSize == null) {
                Timber.e("http$id dechunkHttpMessage: invalid chunk size '${chunks[i - 1]}'")
                break
            }
            if (chunkSize == 0) {
                // This is the last chunk
                break
            }
            if (i >= chunks.size) {
                Timber.e("http$id dechunkHttpMessage: missing chunk data after size header")
                break
            }

            dechunkedBody.append(chunks[i++])
        }

        return "$statusAndHeaders$dechunkedBody"
    }

    private fun combineChunks(state: ReassemblyState): ByteArray {
        val totalSize = state.chunkCache.sumOf { it.size }
        val result = ByteArray(totalSize)
        var position = 0
        for (bytes in state.chunkCache) {
            bytes.copyInto(result, position)
            position += bytes.size
        }
        // at this point we're done with the cache and can clear it for reuse
        state.chunkCache.clear()
        return result
    }

    companion object {
        /**
         * Upper bound on how long a response's persist coroutine waits for its matching
         * request's persist to complete, so a request whose own persist never completes (or
         * whose completion is lost, e.g. an unanswered request when the connection is torn down)
         * can't leave a response coroutine suspended forever.
         */
        private const val REQUEST_CORRELATION_TIMEOUT_MS = 30_000L
    }
}