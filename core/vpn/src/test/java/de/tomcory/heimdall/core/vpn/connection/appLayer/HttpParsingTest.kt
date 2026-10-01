package de.tomcory.heimdall.core.vpn.connection.appLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.components.DatabaseConnector
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import de.tomcory.heimdall.core.vpn.connection.inetLayer.IpPacketBuilder
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import io.mockk.*
import kotlinx.coroutines.delay
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.net.InetAddress

/**
 * Tests for HttpConnection's HTTP parsing and persistence logic.
 *
 * HttpConnection launches persistence coroutines on Dispatchers.IO. We use
 * generous Thread.sleep() waits to let them complete before asserting.
 */
class HttpParsingTest {

    private lateinit var connector: DatabaseConnector
    private lateinit var componentManager: ComponentManager
    private lateinit var encryptionLayer: EncryptionLayerConnection
    private lateinit var httpConnection: HttpConnection

    @Before
    fun setup() {
        connector = mockk(relaxed = true)
        coEvery {
            connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        } returns 42

        componentManager = mockk(relaxed = true)
        every { componentManager.databaseConnector } returns connector

        val remoteAddr = mockk<InetAddress>(relaxed = true)
        val localAddr = mockk<InetAddress>(relaxed = true)
        every { remoteAddr.hostAddress } returns "93.184.216.34"
        every { localAddr.hostAddress } returns "10.0.0.1"

        val ipPacketBuilder = mockk<IpPacketBuilder>(relaxed = true)
        every { ipPacketBuilder.remoteAddress } returns remoteAddr
        every { ipPacketBuilder.localAddress } returns localAddr

        val transportLayer = mockk<TransportLayerConnection>(relaxed = true)
        every { transportLayer.ipPacketBuilder } returns ipPacketBuilder
        every { transportLayer.remoteHost } returns "example.com"
        every { transportLayer.remotePort } returns 80
        every { transportLayer.localPort } returns 12345
        every { transportLayer.appId } returns 1000
        every { transportLayer.appPackage } returns "com.example.test"

        encryptionLayer = mockk(relaxed = true)
        every { encryptionLayer.transportLayer } returns transportLayer

        // id=0 skips the init block Timber.d that accesses the full property chain
        httpConnection = HttpConnection(0, encryptionLayer, componentManager)
    }

    // -----------------------------------------------------------------------
    // Request parsing
    // -----------------------------------------------------------------------

    @Test
    fun `simple GET request triggers persistHttpRequest with correct method and path`() {
        httpConnection.unwrapOutbound("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
        Thread.sleep(500)

        coVerify {
            connector.persistHttpRequest(
                connectionId = 0,
                timestamp = any(),
                headers = any(),
                content = "",
                contentLength = 0,
                method = "GET",
                remoteHost = "example.com",
                remotePath = "/index.html",
                remoteIp = "93.184.216.34",
                remotePort = 80,
                localIp = "10.0.0.1",
                localPort = 12345,
                initiatorId = 1000,
                initiatorPkg = "com.example.test"
            )
        }
    }

    @Test
    fun `POST request with body captures content correctly`() {
        val body = "name=Alice&age=30"
        httpConnection.unwrapOutbound("POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: ${body.length}\r\n\r\n$body".toByteArray())
        Thread.sleep(500)

        coVerify {
            connector.persistHttpRequest(
                content = body,
                contentLength = body.length,
                method = "POST",
                remotePath = "/submit",
                connectionId = any(), timestamp = any(), headers = any(),
                remoteHost = any(), remoteIp = any(), remotePort = any(),
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    @Test
    fun `request with body exceeding 1 MB stores truncation message`() {
        val bigBody = "X".repeat(1024 * 1024 + 1)
        httpConnection.unwrapOutbound("POST /big HTTP/1.1\r\nHost: example.com\r\nContent-Length: ${bigBody.length}\r\n\r\n$bigBody".toByteArray())
        Thread.sleep(500)

        coVerify {
            connector.persistHttpRequest(
                content = match { it.startsWith("<too large:") },
                connectionId = any(), timestamp = any(), headers = any(), contentLength = any(),
                method = any(), remoteHost = any(), remotePath = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    @Test
    fun `fragmented headers are accumulated before persistence`() {
        httpConnection.unwrapOutbound("GET /partial HTTP/1.1\r\nHost: example".toByteArray())
        Thread.sleep(200)

        coVerify(exactly = 0) { connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }

        httpConnection.unwrapOutbound(".com\r\n\r\n".toByteArray())
        Thread.sleep(500)

        coVerify(exactly = 1) { connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }
    }

    @Test
    fun `chunked request body is dechunked before persistence`() {
        // First payload: headers + first chunk; sets chunked=true and caches
        httpConnection.unwrapOutbound("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n".toByteArray())
        Thread.sleep(200)

        coVerify(exactly = 0) { connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }

        // The zero-size chunk and the empty line after it end the body
        httpConnection.unwrapOutbound("0\r\n\r\n".toByteArray())
        Thread.sleep(500)

        coVerify {
            connector.persistHttpRequest(
                content = "Hello",
                method = "POST",
                connectionId = any(), timestamp = any(), headers = any(), contentLength = any(),
                remoteHost = any(), remotePath = any(), remoteIp = any(), remotePort = any(),
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    @Test
    fun `chunk data containing an embedded CRLF is dechunked without truncation`() {
        // docs/vpn-mitm-audit.md PKT-18 (V-19): dechunkHttpMessage used to split the whole
        // chunked body on every literal CRLF, desyncing as soon as a chunk's own data contained
        // one - a multi-line body (e.g. JSON) is a routine case, not an edge case
        val chunkData = "line1\r\nline2"
        val chunkSizeHex = chunkData.toByteArray(Charsets.UTF_8).size.toString(16)

        httpConnection.unwrapOutbound(
            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n$chunkSizeHex\r\n$chunkData\r\n".toByteArray()
        )
        Thread.sleep(200)
        coVerify(exactly = 0) { connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }

        httpConnection.unwrapOutbound("0\r\n\r\n".toByteArray())
        Thread.sleep(500)

        coVerify {
            connector.persistHttpRequest(
                content = chunkData,
                method = "POST",
                connectionId = any(), timestamp = any(), headers = any(), contentLength = any(),
                remoteHost = any(), remotePath = any(), remoteIp = any(), remotePort = any(),
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    // -----------------------------------------------------------------------
    // Response parsing
    // -----------------------------------------------------------------------

    @Test
    fun `200 OK response triggers persistHttpResponse with correct status`() {
        // Send a request first so requestIdChannel gets a value
        httpConnection.unwrapOutbound("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
        Thread.sleep(500) // let request coroutine reach the channel send

        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".toByteArray())
        Thread.sleep(500) // let response coroutine receive from channel and persist

        coVerify {
            connector.persistHttpResponse(
                statusCode = 200,
                statusMsg = "OK",
                content = "",
                connectionId = any(), requestId = any(), timestamp = any(), headers = any(),
                contentLength = any(), remoteHost = any(), remoteIp = any(), remotePort = any(),
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    @Test
    fun `404 response stores correct status code and message`() {
        httpConnection.unwrapOutbound("GET /missing HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
        Thread.sleep(500)

        httpConnection.unwrapInbound("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".toByteArray())
        Thread.sleep(500)

        coVerify {
            connector.persistHttpResponse(
                statusCode = 404,
                statusMsg = "Not Found",
                connectionId = any(), requestId = any(), timestamp = any(), headers = any(),
                content = any(), contentLength = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    @Test
    fun `response requestId correlates with request persistence result`() {
        coEvery {
            connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        } returns 99

        httpConnection.unwrapOutbound("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
        Thread.sleep(500)

        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".toByteArray())
        Thread.sleep(500)

        coVerify {
            connector.persistHttpResponse(
                requestId = 99,
                connectionId = any(), timestamp = any(), headers = any(), content = any(),
                contentLength = any(), statusCode = any(), statusMsg = any(), remoteHost = any(),
                remoteIp = any(), remotePort = any(), localIp = any(), localPort = any(),
                initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    @Test
    fun `response with body captures content`() {
        httpConnection.unwrapOutbound("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
        Thread.sleep(500)

        val responseBody = "Hello, World!"
        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: ${responseBody.length}\r\n\r\n$responseBody".toByteArray())
        Thread.sleep(500)

        coVerify {
            connector.persistHttpResponse(
                content = responseBody,
                statusCode = 200,
                connectionId = any(), requestId = any(), timestamp = any(), headers = any(),
                contentLength = any(), statusMsg = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    // -----------------------------------------------------------------------
    // docs/vpn-mitm-audit.md PKT-17 (V-18, V-20): per-direction reassembly state
    // and request/response correlation
    // -----------------------------------------------------------------------

    @Test
    fun `inbound response interleaved between two halves of an outbound request body does not corrupt either`() {
        // a first, complete request/response pair establishes a pending request to correlate
        // the interleaved response against (a response needs a request that was actually sent)
        httpConnection.unwrapOutbound("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
        Thread.sleep(200)

        val requestBody = "name=Alice&age=30&extra=data"
        val firstHalf = requestBody.substring(0, 10)
        val secondHalf = requestBody.substring(10)

        // headers + only the first half of a second request's body - Content-Length names the
        // *full* body, so this leaves the outbound side mid-way through its overflow reassembly
        httpConnection.unwrapOutbound(
            "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: ${requestBody.length}\r\n\r\n$firstHalf".toByteArray()
        )
        Thread.sleep(200)
        coVerify(exactly = 1) { connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }

        // the first request's response arrives while the second (POST) request is still
        // mid-body - with shared reassembly state this used to be misread as a continuation of
        // the outbound overflow instead of a brand new inbound message
        val responseBody = "OK"
        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: ${responseBody.length}\r\n\r\n$responseBody".toByteArray())
        Thread.sleep(500)

        coVerify {
            connector.persistHttpResponse(
                content = responseBody,
                statusCode = 200,
                connectionId = any(), requestId = any(), timestamp = any(), headers = any(),
                contentLength = any(), statusMsg = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }

        // complete the still-in-flight outbound request body - must still resolve to the full,
        // uncorrupted body despite the inbound response that arrived in the middle of it
        httpConnection.unwrapOutbound(secondHalf.toByteArray())
        Thread.sleep(500)

        coVerify {
            connector.persistHttpRequest(
                content = requestBody,
                contentLength = requestBody.length,
                method = "POST",
                remotePath = "/submit",
                connectionId = any(), timestamp = any(), headers = any(),
                remoteHost = any(), remoteIp = any(), remotePort = any(),
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    @Test
    fun `two pipelined requests correlate with responses in the right order`() {
        // the first request's persist deliberately finishes *after* the second's, so a
        // correlation scheme relying on persist-completion order instead of wire order would
        // pair the responses with the wrong requests
        coEvery {
            connector.persistHttpRequest(
                remotePath = "/first",
                connectionId = any(), timestamp = any(), headers = any(), content = any(), contentLength = any(),
                method = any(), remoteHost = any(), remoteIp = any(), remotePort = any(),
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        } coAnswers {
            delay(300)
            101L
        }
        coEvery {
            connector.persistHttpRequest(
                remotePath = "/second",
                connectionId = any(), timestamp = any(), headers = any(), content = any(), contentLength = any(),
                method = any(), remoteHost = any(), remoteIp = any(), remotePort = any(),
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        } returns 202L

        // two requests pipelined back-to-back, before either response arrives
        httpConnection.unwrapOutbound("GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
        httpConnection.unwrapOutbound("GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
        Thread.sleep(600)

        coVerify(exactly = 2) { connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }

        // responses arrive in the same order the requests were sent
        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".toByteArray())
        httpConnection.unwrapInbound("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n".toByteArray())
        Thread.sleep(500)

        coVerify {
            connector.persistHttpResponse(
                requestId = 101L,
                statusCode = 200,
                connectionId = any(), timestamp = any(), headers = any(), content = any(),
                contentLength = any(), statusMsg = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
        coVerify {
            connector.persistHttpResponse(
                requestId = 202L,
                statusCode = 201,
                connectionId = any(), timestamp = any(), headers = any(), content = any(),
                contentLength = any(), statusMsg = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    // -----------------------------------------------------------------------
    // docs/vpn-mitm-audit.md PKT-32 (V-44): the end of a chunked message is found by following
    // the declared chunk sizes, after every payload including the first
    // -----------------------------------------------------------------------

    private fun sendRequest(path: String = "/") {
        httpConnection.unwrapOutbound("GET $path HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
        Thread.sleep(300)
    }

    private fun verifyResponse(statusCode: Int, content: String, requestId: Long? = null) {
        coVerify(exactly = 1) {
            connector.persistHttpResponse(
                content = content,
                statusCode = statusCode,
                requestId = requestId ?: any(),
                connectionId = any(), timestamp = any(), headers = any(),
                contentLength = any(), statusMsg = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    private fun verifyNoResponse() {
        coVerify(exactly = 0) {
            connector.persistHttpResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        }
    }

    private val chunkedHeaders = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"

    @Test
    fun `chunked response that arrives whole in one payload is persisted`() {
        // the case that never completed before: there is no later payload to trigger a check
        sendRequest()

        httpConnection.unwrapInbound("${chunkedHeaders}5\r\nHello\r\n7\r\n, World\r\n0\r\n\r\n".toByteArray())
        Thread.sleep(500)

        verifyResponse(200, "Hello, World")
    }

    @Test
    fun `chunked response is persisted when the terminator arrives in its own payload`() {
        sendRequest()

        httpConnection.unwrapInbound("${chunkedHeaders}5\r\nHello\r\n".toByteArray())
        Thread.sleep(200)
        verifyNoResponse()

        httpConnection.unwrapInbound("0\r\n\r\n".toByteArray())
        Thread.sleep(500)

        verifyResponse(200, "Hello")
    }

    @Test
    fun `chunked response is persisted when the terminator is split across payloads`() {
        sendRequest()

        httpConnection.unwrapInbound("${chunkedHeaders}5\r\nHello\r\n".toByteArray())
        httpConnection.unwrapInbound("0\r\n".toByteArray())
        Thread.sleep(200)
        // the zero-size chunk alone does not end the body: the empty line after it does
        verifyNoResponse()

        httpConnection.unwrapInbound("\r\n".toByteArray())
        Thread.sleep(500)

        verifyResponse(200, "Hello")
    }

    @Test
    fun `chunk boundaries may fall anywhere within payloads`() {
        sendRequest()
        val wire = "${chunkedHeaders}5\r\nHello\r\n7\r\n, World\r\n0\r\n\r\n"

        // deliver the headers, then the body one byte at a time
        httpConnection.unwrapInbound(chunkedHeaders.toByteArray())
        wire.substring(chunkedHeaders.length).forEach { httpConnection.unwrapInbound(byteArrayOf(it.code.toByte())) }
        Thread.sleep(500)

        verifyResponse(200, "Hello, World")
    }

    @Test
    fun `chunk data that looks like a terminator does not end the body early`() {
        sendRequest()
        val data = "0\r\n\r\n"

        httpConnection.unwrapInbound("${chunkedHeaders}${data.length.toString(16)}\r\n$data\r\n".toByteArray())
        Thread.sleep(200)
        verifyNoResponse()

        httpConnection.unwrapInbound("0\r\n\r\n".toByteArray())
        Thread.sleep(500)

        verifyResponse(200, data)
    }

    @Test
    fun `chunked response with a trailer section is persisted once the trailers end`() {
        sendRequest()

        httpConnection.unwrapInbound("${chunkedHeaders}5\r\nHello\r\n0\r\nX-Checksum: abc\r\n".toByteArray())
        Thread.sleep(200)
        verifyNoResponse()

        httpConnection.unwrapInbound("\r\n".toByteArray())
        Thread.sleep(500)

        verifyResponse(200, "Hello")
    }

    @Test
    fun `chunk extensions after the size are ignored`() {
        sendRequest()

        httpConnection.unwrapInbound("${chunkedHeaders}5;name=value\r\nHello\r\n0\r\n\r\n".toByteArray())
        Thread.sleep(500)

        verifyResponse(200, "Hello")
    }

    @Test
    fun `two chunked responses on one connection are each persisted and paired with their request`() {
        coEvery {
            connector.persistHttpRequest(
                remotePath = "/first",
                connectionId = any(), timestamp = any(), headers = any(), content = any(), contentLength = any(),
                method = any(), remoteHost = any(), remoteIp = any(), remotePort = any(),
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        } returns 101L
        coEvery {
            connector.persistHttpRequest(
                remotePath = "/second",
                connectionId = any(), timestamp = any(), headers = any(), content = any(), contentLength = any(),
                method = any(), remoteHost = any(), remoteIp = any(), remotePort = any(),
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        } returns 202L

        sendRequest("/first")
        httpConnection.unwrapInbound("${chunkedHeaders}3\r\none\r\n0\r\n\r\n".toByteArray())
        sendRequest("/second")
        httpConnection.unwrapInbound("${chunkedHeaders}3\r\ntwo\r\n0\r\n\r\n".toByteArray())
        Thread.sleep(500)

        // before the fix the first response left the parser in chunked mode for good, so the
        // second one was swallowed as well
        verifyResponse(200, "one", requestId = 101L)
        verifyResponse(200, "two", requestId = 202L)
    }

    @Test
    fun `a message that follows a chunked one in the same payload is parsed too`() {
        sendRequest("/first")
        sendRequest("/second")

        httpConnection.unwrapInbound(
            "${chunkedHeaders}3\r\none\r\n0\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\ngone".toByteArray()
        )
        Thread.sleep(500)

        verifyResponse(200, "one")
        verifyResponse(404, "gone")
    }

    @Test
    fun `chunked body over the size limit is persisted with a marker instead of its content`() {
        sendRequest()
        val chunk = ByteArray(64 * 1024) { 'a'.code.toByte() }
        val chunkCount = 20 // 1.25 MB, above the 1 MB limit

        httpConnection.unwrapInbound(chunkedHeaders.toByteArray())
        repeat(chunkCount) {
            httpConnection.unwrapInbound("${chunk.size.toString(16)}\r\n".toByteArray() + chunk + "\r\n".toByteArray())
        }
        Thread.sleep(200)
        verifyNoResponse()

        httpConnection.unwrapInbound("0\r\n\r\n".toByteArray())
        Thread.sleep(500)

        val total = chunk.size * chunkCount
        coVerify(exactly = 1) {
            connector.persistHttpResponse(
                content = "<too large: $total bytes>",
                contentLength = total,
                statusCode = 200,
                connectionId = any(), requestId = any(), timestamp = any(), headers = any(),
                statusMsg = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    @Test
    fun `a response after an oversized chunked one is still parsed`() {
        sendRequest("/big")
        sendRequest("/small")
        val chunk = ByteArray(64 * 1024) { 'a'.code.toByte() }

        httpConnection.unwrapInbound(chunkedHeaders.toByteArray())
        repeat(20) {
            httpConnection.unwrapInbound("${chunk.size.toString(16)}\r\n".toByteArray() + chunk + "\r\n".toByteArray())
        }
        httpConnection.unwrapInbound("0\r\n\r\n".toByteArray())
        httpConnection.unwrapInbound("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".toByteArray())
        Thread.sleep(500)

        verifyResponse(204, "")
    }

    @Test
    fun `a malformed chunk size persists what was received instead of waiting forever`() {
        sendRequest()

        httpConnection.unwrapInbound("${chunkedHeaders}5\r\nHello\r\nnot-hex\r\n".toByteArray())
        Thread.sleep(500)

        verifyResponse(200, "Hello")
    }

    // -----------------------------------------------------------------------
    // docs/vpn-mitm-audit.md PKT-33 (V-45): responses that have no body whatever their
    // headers say, bodies that run until the connection closes, and connections that stop
    // being HTTP
    // -----------------------------------------------------------------------

    private fun sendRequest(method: String, path: String) {
        httpConnection.unwrapOutbound("$method $path HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
        Thread.sleep(300)
    }

    /** Number of bytes the parser is holding on to for one direction, read through reflection. */
    private fun bufferedBytes(isOutbound: Boolean): Int {
        val stateField = HttpConnection::class.java.getDeclaredField(if (isOutbound) "outboundState" else "inboundState")
        stateField.isAccessible = true
        val state = stateField.get(httpConnection)
        val previousPayload = state.javaClass.getDeclaredField("previousPayload").apply { isAccessible = true }.get(state) as ByteArray
        @Suppress("UNCHECKED_CAST")
        val chunkCache = state.javaClass.getDeclaredField("chunkCache").apply { isAccessible = true }.get(state) as List<ByteArray>
        return previousPayload.size + chunkCache.sumOf { it.size }
    }

    @Test
    fun `response to a HEAD request is complete without the body its Content-Length announces`() {
        sendRequest("HEAD", "/file")

        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n".toByteArray())
        Thread.sleep(500)
        verifyResponse(200, "")

        // the parser must not be left waiting for those 1000 bytes
        sendRequest("GET", "/next")
        httpConnection.unwrapInbound("HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\ngone".toByteArray())
        Thread.sleep(500)
        verifyResponse(404, "gone")
    }

    @Test
    fun `304 response is complete without the body its Content-Length announces`() {
        sendRequest("GET", "/cached")

        httpConnection.unwrapInbound("HTTP/1.1 304 Not Modified\r\nContent-Length: 500\r\n\r\n".toByteArray())
        Thread.sleep(500)
        verifyResponse(304, "")

        sendRequest("GET", "/next")
        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".toByteArray())
        Thread.sleep(500)
        verifyResponse(200, "ok")
    }

    @Test
    fun `204 response without Content-Length does not end parsing of later responses`() {
        sendRequest("GET", "/first")
        httpConnection.unwrapInbound("HTTP/1.1 204 No Content\r\n\r\n".toByteArray())
        sendRequest("GET", "/second")
        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".toByteArray())
        Thread.sleep(500)

        verifyResponse(204, "")
        verifyResponse(200, "ok")
    }

    @Test
    fun `100 Continue is skipped and the final response is paired with the request`() {
        httpConnection.unwrapOutbound("POST /upload HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n".toByteArray())
        httpConnection.unwrapInbound("HTTP/1.1 100 Continue\r\n\r\n".toByteArray())
        httpConnection.unwrapOutbound("data".toByteArray())
        Thread.sleep(300)

        httpConnection.unwrapInbound("HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok".toByteArray())
        Thread.sleep(500)

        // the interim response is not a response to record, and it must not use up the request
        verifyResponse(201, "ok", requestId = 42L)
        coVerify(exactly = 1) {
            connector.persistHttpResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        }
    }

    @Test
    fun `an interim response and the final one in the same payload are told apart`() {
        sendRequest("GET", "/")

        httpConnection.unwrapInbound("HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".toByteArray())
        Thread.sleep(500)

        verifyResponse(200, "ok")
    }

    @Test
    fun `two pipelined requests in one payload are both persisted`() {
        httpConnection.unwrapOutbound(
            "HEAD /first HTTP/1.1\r\nHost: example.com\r\n\r\nGET /second HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
        )
        Thread.sleep(500)

        for ((method, path) in listOf("HEAD" to "/first", "GET" to "/second")) {
            coVerify(exactly = 1) {
                connector.persistHttpRequest(
                    method = method,
                    remotePath = path,
                    content = "",
                    connectionId = any(), timestamp = any(), headers = any(), contentLength = any(),
                    remoteHost = any(), remoteIp = any(), remotePort = any(),
                    localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
                )
            }
        }

        // the HEAD response has no body, so the GET response right behind it is found
        httpConnection.unwrapInbound(
            "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".toByteArray()
        )
        Thread.sleep(500)

        verifyResponse(200, "")
        verifyResponse(200, "ok")
    }

    @Test
    fun `two responses with Content-Length in one payload are both persisted`() {
        sendRequest("GET", "/first")
        sendRequest("GET", "/second")

        httpConnection.unwrapInbound(
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\noneHTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\ngone".toByteArray()
        )
        Thread.sleep(500)

        verifyResponse(200, "one")
        verifyResponse(404, "gone")
    }

    @Test
    fun `a body that ends mid-payload is separated from the response that follows it`() {
        sendRequest("GET", "/first")
        sendRequest("GET", "/second")

        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc".toByteArray())
        httpConnection.unwrapInbound("defHTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\ngone".toByteArray())
        Thread.sleep(500)

        verifyResponse(200, "abcdef")
        verifyResponse(404, "gone")
    }

    @Test
    fun `a body delimited by connection close is persisted once and not buffered afterwards`() {
        sendRequest("GET", "/stream")

        httpConnection.unwrapInbound("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\npart 0".toByteArray())
        repeat(10) { httpConnection.unwrapInbound("part ${it + 1} of a long body\n".repeat(50).toByteArray()) }
        Thread.sleep(500)

        coVerify(exactly = 1) {
            connector.persistHttpResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        }
        verifyResponse(200, "part 0")
        assertEquals("nothing of the rest of the body may be held on to", 0, bufferedBytes(isOutbound = false))
    }

    @Test
    fun `101 Switching Protocols ends HTTP parsing in both directions`() {
        httpConnection.unwrapOutbound("GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".toByteArray())
        Thread.sleep(300)
        httpConnection.unwrapInbound("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".toByteArray())
        Thread.sleep(300)
        verifyResponse(101, "")

        // WebSocket frames in both directions are not HTTP messages
        val frame = ByteArray(2000) { 0x55 }
        repeat(10) {
            httpConnection.unwrapOutbound(frame)
            httpConnection.unwrapInbound(frame)
        }
        Thread.sleep(300)

        assertEquals(0, bufferedBytes(isOutbound = true))
        assertEquals(0, bufferedBytes(isOutbound = false))
        coVerify(exactly = 1) { connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }
        coVerify(exactly = 1) {
            connector.persistHttpResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        }
    }

    @Test
    fun `bytes that never complete a header block stop being buffered beyond the limit`() {
        sendRequest("GET", "/")
        val garbage = ByteArray(16 * 1024) { 'x'.code.toByte() }

        repeat(10) { httpConnection.unwrapInbound(garbage) }

        assertTrue(
            "expected the parser to give up instead of buffering ${bufferedBytes(isOutbound = false)} bytes",
            bufferedBytes(isOutbound = false) <= 64 * 1024
        )
    }

    // -----------------------------------------------------------------------
    // docs/vpn-mitm-audit.md PKT-37 (V-52): bodies with a Content-Length above the size limit
    // are counted, not buffered
    // -----------------------------------------------------------------------

    private val sizeLimit = 1024 * 1024

    /** Feeds [total] body bytes in payloads of [payloadSize], calling [afterEach] after every payload. */
    private fun feedBody(total: Int, isOutbound: Boolean, payloadSize: Int = 16 * 1024, afterEach: () -> Unit = {}) {
        val payload = ByteArray(payloadSize) { 'b'.code.toByte() }
        var sent = 0
        while (sent < total) {
            val size = minOf(payloadSize, total - sent)
            val bytes = if (size == payloadSize) payload else payload.copyOf(size)
            if (isOutbound) httpConnection.unwrapOutbound(bytes) else httpConnection.unwrapInbound(bytes)
            sent += size
            afterEach()
        }
    }

    @Test
    fun `large response with Content-Length is counted instead of buffered`() {
        sendRequest("GET", "/big")
        sendRequest("GET", "/next")
        val size = 5_000_000
        var maxBuffered = 0

        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: $size\r\n\r\n".toByteArray())
        feedBody(size, isOutbound = false) { maxBuffered = maxOf(maxBuffered, bufferedBytes(isOutbound = false)) }
        Thread.sleep(500)

        assertEquals("nothing of a body that is too large to store may be held in memory", 0, maxBuffered)
        coVerify(exactly = 1) {
            connector.persistHttpResponse(
                content = "<too large: $size bytes>",
                contentLength = size,
                statusCode = 200,
                connectionId = any(), requestId = any(), timestamp = any(), headers = any(),
                statusMsg = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }

        // the parser is back in step for the next response on the connection
        httpConnection.unwrapInbound("HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\ngone".toByteArray())
        Thread.sleep(500)
        verifyResponse(404, "gone")
    }

    @Test
    fun `large request with Content-Length is counted instead of buffered`() {
        val size = 5_000_000
        var maxBuffered = 0

        httpConnection.unwrapOutbound("POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: $size\r\n\r\n".toByteArray())
        feedBody(size, isOutbound = true) { maxBuffered = maxOf(maxBuffered, bufferedBytes(isOutbound = true)) }
        Thread.sleep(500)

        assertEquals(0, maxBuffered)
        coVerify(exactly = 1) {
            connector.persistHttpRequest(
                content = "<too large: $size bytes>",
                contentLength = size,
                method = "POST",
                remotePath = "/upload",
                connectionId = any(), timestamp = any(), headers = any(),
                remoteHost = any(), remoteIp = any(), remotePort = any(),
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }

        // the next request on the connection is parsed on its own
        httpConnection.unwrapOutbound("GET /after HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
        Thread.sleep(500)
        coVerify(exactly = 1) {
            connector.persistHttpRequest(
                method = "GET",
                remotePath = "/after",
                connectionId = any(), timestamp = any(), headers = any(), content = any(), contentLength = any(),
                remoteHost = any(), remoteIp = any(), remotePort = any(),
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    @Test
    fun `a body of exactly the size limit is still stored in full`() {
        sendRequest("GET", "/")
        var maxBuffered = 0

        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: $sizeLimit\r\n\r\n".toByteArray())
        feedBody(sizeLimit, isOutbound = false) { maxBuffered = maxOf(maxBuffered, bufferedBytes(isOutbound = false)) }
        Thread.sleep(500)

        assertTrue("a storable body is buffered, but never more than the limit plus its headers", maxBuffered in 1..(sizeLimit + 1024))
        coVerify(exactly = 1) {
            connector.persistHttpResponse(
                content = match { it.length == sizeLimit && !it.startsWith("<too large") },
                contentLength = sizeLimit,
                statusCode = 200,
                connectionId = any(), requestId = any(), timestamp = any(), headers = any(),
                statusMsg = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    @Test
    fun `a body one byte over the size limit is not stored`() {
        sendRequest("GET", "/")
        val size = sizeLimit + 1

        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: $size\r\n\r\n".toByteArray())
        feedBody(size, isOutbound = false)
        Thread.sleep(500)

        verifyResponse(200, "<too large: $size bytes>")
        assertEquals(0, bufferedBytes(isOutbound = false))
    }

    @Test
    fun `the message behind an oversized body in the same payload is parsed`() {
        sendRequest("GET", "/big")
        sendRequest("GET", "/next")
        val size = 2_000_000

        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: $size\r\n\r\n".toByteArray())
        feedBody(size - 100, isOutbound = false)
        // the last 100 body bytes and the next response arrive together
        httpConnection.unwrapInbound(ByteArray(100) { 'b'.code.toByte() } + "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\ngone".toByteArray())
        Thread.sleep(500)

        verifyResponse(200, "<too large: $size bytes>")
        verifyResponse(404, "gone")
    }
}
