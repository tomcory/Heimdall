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
import java.io.ByteArrayOutputStream
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

        /** Finds the end of a chunked message's body (only used while [chunked]). */
        val chunkTracker = ChunkedBodyTracker()

        /** Number of bytes of the current chunked message held in [chunkCache]. */
        var cachedSize = 0

        /** Status line and headers of the current chunked message, kept in case its body turns out to be [tooLarge]. */
        var headerBytes: ByteArray? = null

        /** The current chunked message outgrew the size limit, so its body is no longer cached. */
        var tooLarge = false

        /** Clears everything that belongs to the message just completed, ready for the next one. */
        fun resetMessage() {
            overflowing = false
            chunked = false
            statedContentLength = -1
            remainingContentLength = -1
            chunkTracker.reset()
            cachedSize = 0
            headerBytes = null
            tooLarge = false
        }
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
            if(state.chunked) {
                // the body may already be complete within this payload, so look for its end
                // right away instead of waiting for a later payload that might never come
                val bodyStart = indexOfBytes(assembledPayload, DOUBLE_CRLF) + DOUBLE_CRLF.size
                state.headerBytes = assembledPayload.copyOf(bodyStart)
                handleChunkedBytes(assembledPayload, bodyStart, isOutbound, state)
            } else if(state.overflowing) {
                Timber.d("http$id starting overflow with ${state.remainingContentLength} of ${state.statedContentLength} bytes remaining")
                // cache this chunk and wait for more
                state.chunkCache.add(assembledPayload)
            } else {
                // otherwise persist the message
                persistMessage(message, isOutbound)
            }
        } else if(state.chunked) {
            handleChunkedBytes(assembledPayload, 0, isOutbound, state)
        } else {
            // the message is overflowing: add the chunk to the cache
            state.chunkCache.add(assembledPayload)

            // check whether there's still content remaining after the current payload
            state.remainingContentLength -= assembledPayload.size
            if(state.remainingContentLength <= 0) {
                Timber.d("http$id resolved overflow with ${state.remainingContentLength} of ${state.statedContentLength} bytes remaining")
                // if there isn't, flatten the cache and persist the message
                persistMessage(combineChunks(state).toString(Charsets.UTF_8), isOutbound)
            } else {
                Timber.d("http$id continuing overflow with ${state.remainingContentLength} of ${state.statedContentLength} bytes remaining")
            }
        }
    }

    /**
     * Handles bytes of a chunked message (docs/vpn-mitm-audit.md PKT-32). The end of the body is
     * found by following the declared chunk sizes, since that is the only reliable way: chunk
     * data may contain anything, and the terminating zero-size chunk can arrive in the same
     * payload as the headers, on its own, or split across payloads.
     *
     * @param bytes The payload, or for the message's first payload the headers plus what follows.
     * @param bodyStart Index in [bytes] at which body bytes begin.
     */
    private fun handleChunkedBytes(bytes: ByteArray, bodyStart: Int, isOutbound: Boolean, state: ReassemblyState) {
        when (val end = state.chunkTracker.feed(bytes, bodyStart)) {
            ChunkedBodyTracker.INCOMPLETE -> cacheChunkedBytes(bytes, state)

            ChunkedBodyTracker.MALFORMED -> {
                // the end of this message can't be found any more, so persist what there is
                Timber.w("http$id malformed chunked body, persisting what was received so far")
                cacheChunkedBytes(bytes, state)
                persistChunkedMessage(isOutbound, state)
            }

            else -> {
                cacheChunkedBytes(if(end == bytes.size) bytes else bytes.copyOf(end), state)
                persistChunkedMessage(isOutbound, state)
                // on a keep-alive connection the next message may start in the same payload
                if(end < bytes.size) {
                    handleData(bytes.copyOfRange(end, bytes.size), isOutbound)
                }
            }
        }
    }

    /**
     * Adds bytes of a chunked message to the cache, unless that would exceed [maximumMessageSize].
     * From then on the body is dropped and only its length is tracked.
     */
    private fun cacheChunkedBytes(bytes: ByteArray, state: ReassemblyState) {
        if(state.tooLarge) {
            return
        }
        if(state.cachedSize + bytes.size > maximumMessageSize) {
            Timber.d("http$id chunked message exceeds $maximumMessageSize bytes, no longer caching its body")
            state.tooLarge = true
            state.chunkCache.clear()
            state.cachedSize = 0
        } else {
            state.chunkCache.add(bytes)
            state.cachedSize += bytes.size
        }
    }

    private fun persistChunkedMessage(isOutbound: Boolean, state: ReassemblyState) {
        val bodyLength = state.chunkTracker.bodyLength
        Timber.d("http$id chunked message complete ($bodyLength body bytes)")
        if(state.tooLarge) {
            val headers = state.headerBytes?.toString(Charsets.UTF_8) ?: ""
            persistMessage(headers, isOutbound, oversizedBodyLength = bodyLength)
        } else {
            persistMessage(dechunkHttpMessage(combineChunks(state)), isOutbound)
        }
    }

    /**
     * @param oversizedBodyLength If not null, the message's body was too large to keep and had
     * this many bytes. [message] then only holds the status line and headers.
     */
    private fun persistMessage(message: String, isOutbound: Boolean, oversizedBodyLength: Long? = null) {
        // parse the three components of the message individually
        val statusLine = parseStatusLine(message, isOutbound)
        val headers = parseHeaders(message)
        val body = parseBody(message)

        val content = when {
            oversizedBodyLength != null -> "<too large: $oversizedBodyLength bytes>"
            body == null -> ""
            body.length > maximumMessageSize -> "<too large: ${body.length} bytes>"
            else -> body
        }
        val contentLength = oversizedBodyLength?.coerceAtMost(Int.MAX_VALUE.toLong())?.toInt() ?: body?.length ?: 0

        // reset the reassembly state for the next message
        val state = if (isOutbound) outboundState else inboundState
        state.resetMessage()

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
                        content = content,
                        contentLength = contentLength,
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
                    content = content,
                    contentLength = contentLength,
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
        // headers are plain ASCII, so locating the CRLF/double-CRLF markers byte-for-byte is safe
        val rawHeadersIndex = indexOfBytes(chunkedMessage, CRLF)
        val rawChunkedBodyIndex = indexOfBytes(chunkedMessage, DOUBLE_CRLF)

        if(rawHeadersIndex < 0) {
            Timber.e("http$id dechunkHttpMessage Invalid HTTP message, no headers found")
            return ""
        }

        if(rawChunkedBodyIndex < 0) {
            Timber.e("http$id dechunkHttpMessage Invalid HTTP message, no chunks found")
            return ""
        }

        val chunkedBodyIndex = rawChunkedBodyIndex + 4
        val statusAndHeaders = String(chunkedMessage, 0, chunkedBodyIndex, Charsets.UTF_8)

        // walk the body using each chunk's *declared* byte count, rather than splitting the
        // whole body on every CRLF - a chunk's data can legitimately contain its own CRLFs
        // (e.g. a multi-line text/JSON chunk), which would otherwise desync the parser
        val dechunkedBody = ByteArrayOutputStream()
        var offset = chunkedBodyIndex

        while (offset < chunkedMessage.size) {
            val sizeLineEnd = indexOfBytes(chunkedMessage, CRLF, offset)
            if (sizeLineEnd < 0) {
                Timber.e("http$id dechunkHttpMessage: missing CRLF after chunk size")
                break
            }

            // a chunk-size line may carry "; chunk-extension" after the size - ignore it
            val sizeLine = String(chunkedMessage, offset, sizeLineEnd - offset, Charsets.US_ASCII)
                .substringBefore(';').trim()
            val chunkSize = sizeLine.toIntOrNull(16)
            if (chunkSize == null) {
                Timber.e("http$id dechunkHttpMessage: invalid chunk size '$sizeLine'")
                break
            }
            if (chunkSize == 0) {
                // this is the last chunk
                break
            }

            val dataStart = sizeLineEnd + 2
            val dataEnd = dataStart + chunkSize
            if (dataEnd > chunkedMessage.size) {
                Timber.e("http$id dechunkHttpMessage: declared chunk size exceeds available data")
                break
            }

            dechunkedBody.write(chunkedMessage, dataStart, chunkSize)

            // each chunk's data is followed by its own trailing CRLF before the next chunk-size line
            offset = dataEnd + 2
        }

        return statusAndHeaders + dechunkedBody.toByteArray().toString(Charsets.UTF_8)
    }

    /** Index of the first occurrence of [needle] in [haystack] at or after [from], or -1. */
    private fun indexOfBytes(haystack: ByteArray, needle: ByteArray, from: Int = 0): Int {
        val limit = haystack.size - needle.size
        var i = from.coerceAtLeast(0)
        while (i <= limit) {
            var matched = true
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) {
                    matched = false
                    break
                }
            }
            if (matched) return i
            i++
        }
        return -1
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

        private val CRLF = "\r\n".toByteArray(Charsets.US_ASCII)
        private val DOUBLE_CRLF = "\r\n\r\n".toByteArray(Charsets.US_ASCII)
    }
}