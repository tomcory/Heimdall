package de.tomcory.heimdall.core.vpn.connection.appLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import org.pcap4j.packet.Packet
import timber.log.Timber
import java.io.ByteArrayOutputStream
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.atomic.AtomicInteger

/**
 * @param persistDispatcher Runs this connection's database writes (docs/vpn-mitm-audit.md PKT-60).
 * Replaceable for tests.
 */
class HttpConnection(
    id: Long,
    encryptionLayer: EncryptionLayerConnection,
    componentManager: ComponentManager,
    persistDispatcher: CoroutineDispatcher = Dispatchers.IO
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

        var overflowing = false
        var chunked = false
        var statedContentLength = -1
        var remainingContentLength = -1

        /** Finds the end of a chunked message's body, and decodes it (only used while [chunked]). */
        val chunkTracker = ChunkedBodyTracker()

        /** Status line and headers of the message whose body is still arriving ([overflowing] or [chunked]). */
        var headerBlock: String? = null

        /** The body of the message that is still arriving, as far as it is kept. */
        var body: BoundedBody? = null

        /**
         * This direction no longer carries HTTP messages that can be told apart: the connection
         * switched protocols, a response body runs until the connection closes, or the data
         * turned out not to be HTTP. Payloads are forwarded without being parsed or kept. Set
         * for both directions from the inbound thread on a protocol switch, hence [Volatile].
         */
        @Volatile
        var opaque = false

        /** Clears everything that belongs to the message just completed, ready for the next one. */
        fun resetMessage() {
            overflowing = false
            chunked = false
            statedContentLength = -1
            remainingContentLength = -1
            chunkTracker.reset()
            headerBlock = null
            body = null
        }
    }

    /**
     * A message body as far as it is kept: its first [limit] bytes, and its real length
     * (docs/vpn-mitm-audit.md PKT-59). Bytes, not text, so that binary and compressed bodies are
     * stored as they were sent; memory is bounded by [limit] however long the body is.
     */
    private class BoundedBody(private val limit: Int) {
        private val kept = ByteArrayOutputStream()

        /** The real length of the body so far. */
        var length = 0L
            private set

        fun write(bytes: ByteArray, offset: Int, count: Int) {
            length += count
            val room = limit - kept.size()
            if (room > 0) {
                kept.write(bytes, offset, minOf(room, count))
            }
        }

        fun bytes(): ByteArray = kept.toByteArray()
    }

    private val outboundState = ReassemblyState()
    private val inboundState = ReassemblyState()

    /** How much of a body is kept (docs/vpn-mitm-audit.md PKT-59). */
    private val maximumBodySize = componentManager.maxHttpBodySize.coerceIn(0, MAX_BODY_SIZE_LIMIT)

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
    private val pendingRequests = ConcurrentLinkedDeque<PendingRequest>()

    private val persistScope = CoroutineScope(persistDispatcher + SupervisorJob())

    /**
     * Lets one of this connection's database writes run at a time, in the order the messages were
     * seen: the mutex is fair, so waiting writes are let in first come, first served
     * (docs/vpn-mitm-audit.md PKT-60). Writes used to run as independent coroutines on the shared
     * IO dispatcher, so a burst started thousands of concurrent inserts, and the backlog delayed
     * request rows by more than the 30 s a response used to wait for them (V-65). A dispatcher
     * limited to one thread would not serialise them: a write that suspends inside the database
     * lets the next one start.
     *
     * A response's write waits for its request's ID while holding the mutex. That cannot
     * deadlock: the request's write was queued before it and has run by then. A write that does
     * not finish within [WRITE_SAFETY_TIMEOUT_MS] is given up, so that one stuck write cannot
     * hold up the rest of the connection's messages for good.
     */
    private val writeMutex = Mutex()

    /** Messages recognised but not yet written; see [writeMutex]. */
    private val queuedWrites = AtomicInteger(0)

    /** Queues a database write behind this connection's earlier ones, keeping [queuedWrites] up to date. */
    private fun queueWrite(write: suspend () -> Unit) {
        val queued = queuedWrites.incrementAndGet()
        if (queued == WRITE_BACKLOG_WARNING) {
            Timber.w("http$id $queued messages are waiting to be written to the database")
        }
        // UNDISPATCHED: the coroutine takes its place in the mutex's queue now, on the calling
        // thread, so that the queue order is the order in which the messages were seen
        persistScope.launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                writeMutex.withLock {
                    val finished = withTimeoutOrNull(WRITE_SAFETY_TIMEOUT_MS) { write(); true }
                    if (finished == null) {
                        Timber.e("http$id A database write did not finish within ${WRITE_SAFETY_TIMEOUT_MS / 60_000} minutes, giving it up")
                    }
                }
            } finally {
                queuedWrites.decrementAndGet()
            }
        }
    }

    /**
     * A request whose response hasn't been seen yet.
     *
     * @property method The request method, which decides whether its response can have a body.
     * @property id Completes with the request's database ID once it is persisted.
     */
    private class PendingRequest(val method: String, val id: CompletableDeferred<Long>)

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

    /**
     * Whether to log every payload. Off by default: these lines are written once per TCP
     * segment, and with Timber's debug tree each costs a stack trace to find its tag. During
     * an upload they took half of the time of the thread that handles the device's packets
     * (docs/vpn-mitm-audit.md PKT-45).
     */
    private val log = false

    private fun handleData(payload: ByteArray, isOutbound: Boolean) {
        if(log) Timber.d("http$id Processing http ${if(isOutbound) "out" else "in"}: ${payload.size} bytes")
        val state = if (isOutbound) outboundState else inboundState

        // nothing in this direction is an HTTP message any more, so there is nothing to parse or keep
        if(state.opaque) {
            if(state.previousPayload.isNotEmpty()) {
                state.previousPayload = ByteArray(0)
            }
            return
        }

        val assembledPayload = state.previousPayload + payload

        // distinguish between the first/only chuck and additional chunks
        if(!state.chunked && !state.overflowing) {

            val bodyStart = indexOfBytes(assembledPayload, DOUBLE_CRLF) + DOUBLE_CRLF.size
            if(bodyStart < DOUBLE_CRLF.size) {
                if(assembledPayload.size > MAX_HEADER_SIZE) {
                    // whatever this is, it isn't an HTTP header block; stop collecting it
                    Timber.w("http$id no end of headers within $MAX_HEADER_SIZE bytes, no longer parsing ${if(isOutbound) "outbound" else "inbound"} data")
                    state.previousPayload = ByteArray(0)
                    state.opaque = true
                    return
                }
                // if the message doesn't contain the end of the headers, cache the chunk and wait for more
                Timber.w("http$id incomplete headers")
                state.previousPayload = assembledPayload
                return
            } else {
                if(state.previousPayload.isNotEmpty()) {
                    Timber.w("http$id incomplete headers resolved (header length: $bodyStart)")
                }
                state.previousPayload = ByteArray(0)
            }

            // the status line and headers, up to and including the empty line that ends them
            val headerBlock = String(assembledPayload, 0, bodyStart, Charsets.UTF_8)
            val lowercaseHeaders = headerBlock.lowercase()

            // Some responses have no body whatever their headers say, and some end HTTP on this
            // connection altogether (docs/vpn-mitm-audit.md PKT-33). Both depend on the status
            // code and on the method of the request being answered (RFC 9112 section 6.3).
            if(!isOutbound) {
                val statusCode = parseStatusCode(headerBlock)
                val requestMethod = pendingRequests.peekFirst()?.method

                if(statusCode in 100..199 && statusCode != 101) {
                    // an interim response such as 100 Continue: the real response to the same
                    // request is still to come, so this one must not use up the pending request
                    Timber.d("http$id skipping interim response $statusCode")
                    continueAfterMessage(assembledPayload, bodyStart, isOutbound)
                    return
                }

                val switchesProtocol = statusCode == 101 || (requestMethod == "CONNECT" && statusCode in 200..299)
                if(switchesProtocol) {
                    // an upgrade (e.g. WebSocket) or a tunnel: from here on neither direction
                    // carries HTTP messages
                    Timber.d("http$id connection switches protocols ($statusCode), no longer parsing it as HTTP")
                    persistMessage(headerBlock, isOutbound)
                    outboundState.opaque = true
                    inboundState.opaque = true
                    return
                }

                if(statusCode == 204 || statusCode == 304 || requestMethod == "HEAD") {
                    persistMessage(headerBlock, isOutbound)
                    continueAfterMessage(assembledPayload, bodyStart, isOutbound)
                    return
                }
            }

            // the message is "officially" chunked only if this header is present
            state.chunked = lowercaseHeaders.contains("transfer-encoding: chunked")
            if(state.chunked) {
                Timber.d("http$id chunked")
                // the body may already be complete within this payload, so look for its end
                // right away instead of waiting for a later payload that might never come
                state.headerBlock = headerBlock
                state.body = BoundedBody(maximumBodySize)
                handleChunkedBytes(assembledPayload, bodyStart, isOutbound, state)
                return
            }

            val contentLength = parseContentLength(lowercaseHeaders)
            val availableBodyBytes = assembledPayload.size - bodyStart

            if(contentLength >= 0) {
                // Only the first maximumBodySize bytes of the body are kept, the rest is only
                // counted (docs/vpn-mitm-audit.md PKT-37, PKT-59), so memory stays bounded
                // however large the body is.
                if(availableBodyBytes >= contentLength) {
                    // the message is complete; anything behind it belongs to the next one
                    val messageEnd = bodyStart + contentLength
                    val body = BoundedBody(maximumBodySize).apply { write(assembledPayload, bodyStart, contentLength) }
                    persistMessage(headerBlock, isOutbound, body)
                    continueAfterMessage(assembledPayload, messageEnd, isOutbound)
                } else {
                    // the body overflows this payload: wait for the rest
                    state.overflowing = true
                    state.statedContentLength = contentLength
                    state.remainingContentLength = contentLength - availableBodyBytes
                    state.headerBlock = headerBlock
                    state.body = BoundedBody(maximumBodySize).apply { write(assembledPayload, bodyStart, availableBodyBytes) }
                    Timber.d("http$id starting overflow with ${state.remainingContentLength} of ${state.statedContentLength} bytes remaining")
                }
            } else if(isOutbound) {
                // a request with neither a length nor chunked encoding has no body, so anything
                // behind its headers is the next (pipelined) request
                persistMessage(headerBlock, isOutbound)
                continueAfterMessage(assembledPayload, bodyStart, isOutbound)
            } else {
                // A response with neither a length nor chunked encoding: its body runs until the
                // server closes the connection. Persist what is here and stop parsing, because
                // nothing that follows is a new message and the rest of the body isn't kept.
                Timber.d("http$id response body is delimited by connection close, persisting its start only")
                val body = BoundedBody(maximumBodySize).apply { write(assembledPayload, bodyStart, availableBodyBytes) }
                persistMessage(headerBlock, isOutbound, body, truncated = true)
                state.opaque = true
            }
        } else if(state.chunked) {
            handleChunkedBytes(assembledPayload, 0, isOutbound, state)
        } else {
            // the message is overflowing: the payload continues its body, and may also hold the
            // start of the next message
            val take = minOf(state.remainingContentLength, assembledPayload.size)
            state.body?.write(assembledPayload, 0, take)
            state.remainingContentLength -= take
            if(state.remainingContentLength == 0) {
                Timber.d("http$id resolved overflow of ${state.statedContentLength} bytes")
                val body = state.body ?: BoundedBody(0)
                persistMessage(state.headerBlock ?: "", isOutbound, body)
                continueAfterMessage(assembledPayload, take, isOutbound)
            } else {
                if(log) Timber.d("http$id continuing overflow with ${state.remainingContentLength} of ${state.statedContentLength} bytes remaining")
            }
        }
    }

    /**
     * Parses whatever follows a completed message in the same payload as the start of the next
     * message. On a keep-alive connection one read can hold the end of one message and the
     * beginning of another.
     *
     * @param messageEnd Index in [bytes] just past the completed message.
     */
    private fun continueAfterMessage(bytes: ByteArray, messageEnd: Int, isOutbound: Boolean) {
        if(messageEnd < bytes.size) {
            handleData(bytes.copyOfRange(messageEnd, bytes.size), isOutbound)
        }
    }

    /** The status code of a response's status line, or -1 if there is none. */
    private fun parseStatusCode(headerBlock: String): Int {
        return headerBlock.substringBefore("\r\n").split(" ", limit = 3).getOrNull(1)?.toIntOrNull() ?: -1
    }

    /** The value of the Content-Length header in an already lowercased header block, or -1 if there is no valid one. */
    private fun parseContentLength(lowercaseHeaders: String): Int {
        return CONTENT_LENGTH_HEADER.find(lowercaseHeaders)?.groupValues?.get(1)?.toIntOrNull() ?: -1
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
        // the tracker hands over the chunk data, so the body is decoded as it is read
        val body = state.body
        val sink: (ByteArray, Int, Int) -> Unit = { data, offset, length -> body?.write(data, offset, length) }
        when (val end = state.chunkTracker.feed(bytes, bodyStart, sink)) {
            ChunkedBodyTracker.INCOMPLETE -> {}

            ChunkedBodyTracker.MALFORMED -> {
                // the end of this message can't be found any more, so persist what there is
                Timber.w("http$id malformed chunked body, persisting what was received so far")
                persistChunkedMessage(isOutbound, state, complete = false)
            }

            else -> {
                persistChunkedMessage(isOutbound, state, complete = true)
                // on a keep-alive connection the next message may start in the same payload
                if(end < bytes.size) {
                    handleData(bytes.copyOfRange(end, bytes.size), isOutbound)
                }
            }
        }
    }

    /** @param complete Whether the body's end was found; if not, what was received is persisted as truncated. */
    private fun persistChunkedMessage(isOutbound: Boolean, state: ReassemblyState, complete: Boolean) {
        val body = state.body ?: BoundedBody(0)
        Timber.d("http$id chunked message ${if(complete) "complete" else "cut off"} (${body.length} body bytes)")
        persistMessage(state.headerBlock ?: "", isOutbound, body, truncated = !complete)
    }

    /**
     * @param headerBlock The status line and headers, up to and including the empty line that ends them.
     * @param body The body as far as it was kept; none for a message without one.
     * @param truncated Whether [body] is only the start of the body even if it is within the
     * limit (a body that ran until the connection closed, or one whose framing broke off).
     */
    private fun persistMessage(headerBlock: String, isOutbound: Boolean, body: BoundedBody? = null, truncated: Boolean = false) {
        val statusLine = parseStatusLine(headerBlock, isOutbound)
        val headers = parseHeaders(headerBlock)

        val content = body?.bytes() ?: EMPTY_BODY
        val bodyLength = body?.length ?: 0L
        val contentLength = bodyLength.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        val contentTruncated = truncated || bodyLength > content.size
        // when the message was seen, not when its row is written, which may be later
        val timestamp = System.currentTimeMillis()

        // reset the reassembly state for the next message
        val state = if (isOutbound) outboundState else inboundState
        state.resetMessage()

        if (isOutbound) {
            // Without a name from the DNS cache or an SNI, the request's own Host header names
            // the server; it also names the connection from now on (docs/vpn-mitm-audit.md PKT-58)
            if (encryptionLayer.transportLayer.remoteHost.isNullOrEmpty()) {
                hostHeaderName(headers)?.let { encryptionLayer.transportLayer.fillMissingRemoteHost(it) }
            }

            // register this request's placeholder in wire order *before* launching the async
            // persist, so a response processed while the persist is still in flight still
            // correlates with the right request regardless of how long the DB write takes
            val pendingId = CompletableDeferred<Long>()
            pendingRequests.addLast(PendingRequest(statusLine?.get(0) ?: "", pendingId))

            queueWrite {
                try {
                    val requestId = componentManager.databaseConnector.persistHttpRequest(
                        connectionId = id,
                        timestamp = timestamp,
                        headers = headers ?: emptyMap(),
                        content = content,
                        contentLength = contentLength,
                        contentTruncated = contentTruncated,
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
                } catch (e: CancellationException) {
                    // given up by the safety bound in queueWrite(), which logs it. The response
                    // must see a failure, not a cancellation of its own (PKT-63).
                    pendingId.completeExceptionally(IllegalStateException("the request's write was given up", e))
                    throw e
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
            val pendingId = pendingRequests.pollFirst()?.id
            if (pendingId == null) {
                Timber.w("http$id Received a response with no matching pending request, discarding it")
                return
            }

            queueWrite {
                // The request's write was queued before this one and has finished by now: it
                // completed the deferred with the row's ID, or failed it if the row could not be
                // written (or was given up). However long the database took, the response is not
                // dropped for being late, as it was after a 30 s wait before (PKT-60).
                val requestId = try {
                    pendingId.await()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    Timber.e(e, "http$id The request this response answers could not be written, discarding the response")
                    return@queueWrite
                }
                Timber.d("http$id persisting response to request with ID $requestId")
                try {
                    componentManager.databaseConnector.persistHttpResponse(
                        connectionId = id,
                        requestId = requestId,
                        timestamp = timestamp,
                        headers = headers ?: emptyMap(),
                        content = content,
                        contentLength = contentLength,
                        contentTruncated = contentTruncated,
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
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Timber.e(e, "http$id Error persisting HTTP response")
                }
            }
        }
    }

    private fun parseStatusLine(message: String, isOutbound: Boolean): List<String>? {
        val endOfStatusLine = message.indexOf("\r\n")

        if(endOfStatusLine < 0) {
            Timber.e("http$id Invalid status line, no newline found (${describeForLog(message)})")
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

    /**
     * The host name in a request's Host header, without a port, or null if there is no header or
     * it names an IP address (which says nothing a connection does not already know).
     */
    private fun hostHeaderName(headers: Map<String, String>?): String? {
        val value = headers?.entries?.firstOrNull { it.key.equals("Host", ignoreCase = true) }?.value?.trim()
        if (value.isNullOrEmpty() || value.startsWith("[")) {
            return null
        }
        val name = value.substringBefore(':').lowercase()
        if (name.isEmpty() || name.all { it.isDigit() || it == '.' }) {
            return null
        }
        return name
    }

    /**
     * What may be logged about a message that could not be parsed (docs/vpn-mitm-audit.md
     * PKT-63): its length and its first token (a method, or `HTTP/1.1`), cut short. Not the
     * rest: the request line's query string and the headers (`Cookie`, `Authorization`) carry
     * secrets, and logcat can be read by other apps with `READ_LOGS` and ends up in bug reports.
     */
    private fun describeForLog(message: String): String {
        val firstToken = message.substringBefore(' ').substringBefore("\r\n").take(16)
        return "${message.length} chars, starting with '$firstToken'"
    }

    private fun parseHeaders(message: String): Map<String, String>? {
        val rawHeadersIndex = message.indexOf("\r\n")
        val bodyIndex = message.indexOf("\r\n\r\n")

        if(rawHeadersIndex < 0 || bodyIndex < 0 || rawHeadersIndex + 2 >= bodyIndex) {
            Timber.e("http$id parseHeaders: Invalid HTTP message, no headers found (${describeForLog(message)})")
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

    companion object {
        /** The default of the "largest HTTP body to keep" preference (docs/vpn-mitm-audit.md PKT-59). */
        const val DEFAULT_MAX_BODY_SIZE = 256 * 1024

        /**
         * The most a body may be configured to keep. A row Room reads back must fit Android's
         * 2 MB CursorWindow, together with the headers.
         */
        const val MAX_BODY_SIZE_LIMIT = 1024 * 1024

        private val EMPTY_BODY = ByteArray(0)

        /**
         * How long one database write may take before it is given up (docs/vpn-mitm-audit.md
         * PKT-60). Only a safety net against a write that never returns. Time spent waiting
         * behind earlier writes does not count, so a long backlog delays messages but no longer
         * discards them, as the 30 s wait for a request's ID did before (V-65).
         */
        private const val WRITE_SAFETY_TIMEOUT_MS = 10 * 60_000L

        /** A connection with this many messages waiting for the database says so in the log. */
        private const val WRITE_BACKLOG_WARNING = 200

        /**
         * Upper bound on the bytes collected while looking for the end of a header block. Real
         * header blocks are a few kilobytes; a stream that exceeds this isn't HTTP.
         */
        private const val MAX_HEADER_SIZE = 64 * 1024

        /** Matches the Content-Length header line in a lowercased header block. */
        private val CONTENT_LENGTH_HEADER = Regex("\r\ncontent-length:[ \t]*(\\d+)[ \t]*\r\n")

        private val DOUBLE_CRLF = "\r\n\r\n".toByteArray(Charsets.US_ASCII)
    }
}