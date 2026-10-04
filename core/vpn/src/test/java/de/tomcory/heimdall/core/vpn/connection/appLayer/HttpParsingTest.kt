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
import java.io.ByteArrayOutputStream
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
    private lateinit var transportLayer: TransportLayerConnection

    private val sizeLimit = HttpConnection.DEFAULT_MAX_BODY_SIZE

    @Before
    fun setup() {
        connector = mockk(relaxed = true)
        coEvery {
            connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        } returns 42

        componentManager = mockk(relaxed = true)
        every { componentManager.databaseConnector } returns connector
        // a relaxed mock would return 0, and no body would be kept (PKT-59)
        every { componentManager.maxHttpBodySize } returns HttpConnection.DEFAULT_MAX_BODY_SIZE

        val remoteAddr = mockk<InetAddress>(relaxed = true)
        val localAddr = mockk<InetAddress>(relaxed = true)
        every { remoteAddr.hostAddress } returns "93.184.216.34"
        every { localAddr.hostAddress } returns "10.0.0.1"

        val ipPacketBuilder = mockk<IpPacketBuilder>(relaxed = true)
        every { ipPacketBuilder.remoteAddress } returns remoteAddr
        every { ipPacketBuilder.localAddress } returns localAddr

        transportLayer = mockk(relaxed = true)
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
                content = "".toByteArray(),
                contentLength = 0,
                method = "GET",
                remoteHost = "example.com",
                remotePath = "/index.html",
                remoteIp = "93.184.216.34",
                remotePort = 80,
                localIp = "10.0.0.1",
                localPort = 12345,
                initiatorId = 1000,
                initiatorPkg = "com.example.test", contentTruncated = any()
            )
        }
    }

    // ---- docs/vpn-mitm-audit.md PKT-58: the Host header names an unnamed connection ----

    @Test
    fun `a connection without a hostname is named after the request's Host header`() {
        every { transportLayer.remoteHost } returns null
        httpConnection.unwrapOutbound("GET / HTTP/1.1\r\nHost: API.Example.org:8080\r\n\r\n".toByteArray())
        verify { transportLayer.fillMissingRemoteHost("api.example.org") }
    }

    @Test
    fun `a Host header with an IP address names nothing`() {
        every { transportLayer.remoteHost } returns null
        httpConnection.unwrapOutbound("GET / HTTP/1.1\r\nHost: 93.184.216.34\r\n\r\n".toByteArray())
        httpConnection.unwrapOutbound("GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n".toByteArray())
        verify(exactly = 0) { transportLayer.fillMissingRemoteHost(any()) }
    }

    @Test
    fun `a connection that has a hostname keeps it`() {
        httpConnection.unwrapOutbound("GET / HTTP/1.1\r\nHost: other.example\r\n\r\n".toByteArray())
        verify(exactly = 0) { transportLayer.fillMissingRemoteHost(any()) }
    }

    @Test
    fun `POST request with body captures content correctly`() {
        val body = "name=Alice&age=30"
        httpConnection.unwrapOutbound("POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: ${body.length}\r\n\r\n$body".toByteArray())
        Thread.sleep(500)

        coVerify {
            connector.persistHttpRequest(
                content = body.toByteArray(),
                contentLength = body.length,
                method = "POST",
                remotePath = "/submit",
                connectionId = any(), timestamp = any(), headers = any(),
                remoteHost = any(), remoteIp = any(), remotePort = any(),
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
            )
        }
    }

    @Test
    fun `request with a body over the size limit keeps its first bytes`() {
        val bigBody = "X".repeat(sizeLimit + 1)
        httpConnection.unwrapOutbound("POST /big HTTP/1.1\r\nHost: example.com\r\nContent-Length: ${bigBody.length}\r\n\r\n$bigBody".toByteArray())
        Thread.sleep(500)

        coVerify {
            connector.persistHttpRequest(
                content = bigBody.substring(0, sizeLimit).toByteArray(),
                contentLength = sizeLimit + 1,
                contentTruncated = true,
                connectionId = any(), timestamp = any(), headers = any(),
                method = any(), remoteHost = any(), remotePath = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    @Test
    fun `fragmented headers are accumulated before persistence`() {
        httpConnection.unwrapOutbound("GET /partial HTTP/1.1\r\nHost: example".toByteArray())
        Thread.sleep(200)

        coVerify(exactly = 0) { connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }

        httpConnection.unwrapOutbound(".com\r\n\r\n".toByteArray())
        Thread.sleep(500)

        coVerify(exactly = 1) { connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }
    }

    @Test
    fun `chunked request body is dechunked before persistence`() {
        // First payload: headers + first chunk; sets chunked=true and caches
        httpConnection.unwrapOutbound("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n".toByteArray())
        Thread.sleep(200)

        coVerify(exactly = 0) { connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }

        // The zero-size chunk and the empty line after it end the body
        httpConnection.unwrapOutbound("0\r\n\r\n".toByteArray())
        Thread.sleep(500)

        coVerify {
            connector.persistHttpRequest(
                content = "Hello".toByteArray(),
                method = "POST",
                connectionId = any(), timestamp = any(), headers = any(), contentLength = any(),
                remoteHost = any(), remotePath = any(), remoteIp = any(), remotePort = any(),
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
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
        coVerify(exactly = 0) { connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }

        httpConnection.unwrapOutbound("0\r\n\r\n".toByteArray())
        Thread.sleep(500)

        coVerify {
            connector.persistHttpRequest(
                content = chunkData.toByteArray(),
                method = "POST",
                connectionId = any(), timestamp = any(), headers = any(), contentLength = any(),
                remoteHost = any(), remotePath = any(), remoteIp = any(), remotePort = any(),
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
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
                content = "".toByteArray(),
                connectionId = any(), requestId = any(), timestamp = any(), headers = any(),
                contentLength = any(), remoteHost = any(), remoteIp = any(), remotePort = any(),
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
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
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
            )
        }
    }

    @Test
    fun `response requestId correlates with request persistence result`() {
        coEvery {
            connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
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
                initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
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
                content = responseBody.toByteArray(),
                statusCode = 200,
                connectionId = any(), requestId = any(), timestamp = any(), headers = any(),
                contentLength = any(), statusMsg = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
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
        coVerify(exactly = 1) { connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }

        // the first request's response arrives while the second (POST) request is still
        // mid-body - with shared reassembly state this used to be misread as a continuation of
        // the outbound overflow instead of a brand new inbound message
        val responseBody = "OK"
        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: ${responseBody.length}\r\n\r\n$responseBody".toByteArray())
        Thread.sleep(500)

        coVerify {
            connector.persistHttpResponse(
                content = responseBody.toByteArray(),
                statusCode = 200,
                connectionId = any(), requestId = any(), timestamp = any(), headers = any(),
                contentLength = any(), statusMsg = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
            )
        }

        // complete the still-in-flight outbound request body - must still resolve to the full,
        // uncorrupted body despite the inbound response that arrived in the middle of it
        httpConnection.unwrapOutbound(secondHalf.toByteArray())
        Thread.sleep(500)

        coVerify {
            connector.persistHttpRequest(
                content = requestBody.toByteArray(),
                contentLength = requestBody.length,
                method = "POST",
                remotePath = "/submit",
                connectionId = any(), timestamp = any(), headers = any(),
                remoteHost = any(), remoteIp = any(), remotePort = any(),
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
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
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
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
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
            )
        } returns 202L

        // two requests pipelined back-to-back, before either response arrives
        httpConnection.unwrapOutbound("GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
        httpConnection.unwrapOutbound("GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
        Thread.sleep(600)

        coVerify(exactly = 2) { connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }

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
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
            )
        }
        coVerify {
            connector.persistHttpResponse(
                requestId = 202L,
                statusCode = 201,
                connectionId = any(), timestamp = any(), headers = any(), content = any(),
                contentLength = any(), statusMsg = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
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
                content = content.toByteArray(),
                statusCode = statusCode,
                requestId = requestId ?: any(),
                connectionId = any(), timestamp = any(), headers = any(),
                contentLength = any(), statusMsg = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
            )
        }
    }

    private fun verifyNoResponse() {
        coVerify(exactly = 0) {
            connector.persistHttpResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
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
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
            )
        } returns 101L
        coEvery {
            connector.persistHttpRequest(
                remotePath = "/second",
                connectionId = any(), timestamp = any(), headers = any(), content = any(), contentLength = any(),
                method = any(), remoteHost = any(), remoteIp = any(), remotePort = any(),
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
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
    fun `chunked body over the size limit is stored truncated to the limit`() {
        sendRequest()
        val chunk = ByteArray(64 * 1024) { 'a'.code.toByte() }
        val chunkCount = 20 // 1.25 MB, above the limit

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
                content = ByteArray(sizeLimit) { 'a'.code.toByte() },
                contentLength = total,
                contentTruncated = true,
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
        val body = state.javaClass.getDeclaredField("body").apply { isAccessible = true }.get(state)
        val kept = body?.let { it.javaClass.getDeclaredField("kept").apply { isAccessible = true }.get(it) as ByteArrayOutputStream }
        return previousPayload.size + (kept?.size() ?: 0)
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
            connector.persistHttpResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
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
                    content = "".toByteArray(),
                    connectionId = any(), timestamp = any(), headers = any(), contentLength = any(),
                    remoteHost = any(), remoteIp = any(), remotePort = any(),
                    localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
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
            connector.persistHttpResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
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
        coVerify(exactly = 1) { connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }
        coVerify(exactly = 1) {
            connector.persistHttpResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
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
    // docs/vpn-mitm-audit.md PKT-37 (V-52), PKT-59 (V-64): of a body above the size limit only
    // the first limit bytes are kept; the rest is counted, not buffered
    // -----------------------------------------------------------------------

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
    fun `large response with Content-Length is kept only up to the limit`() {
        sendRequest("GET", "/big")
        sendRequest("GET", "/next")
        val size = 5_000_000
        var maxBuffered = 0

        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: $size\r\n\r\n".toByteArray())
        feedBody(size, isOutbound = false) { maxBuffered = maxOf(maxBuffered, bufferedBytes(isOutbound = false)) }
        Thread.sleep(500)

        assertTrue("no more than the limit may be held in memory, held $maxBuffered", maxBuffered <= sizeLimit)
        coVerify(exactly = 1) {
            connector.persistHttpResponse(
                content = ByteArray(sizeLimit) { 'b'.code.toByte() },
                contentLength = size,
                contentTruncated = true,
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
    fun `large request with Content-Length is kept only up to the limit`() {
        val size = 5_000_000
        var maxBuffered = 0

        httpConnection.unwrapOutbound("POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: $size\r\n\r\n".toByteArray())
        feedBody(size, isOutbound = true) { maxBuffered = maxOf(maxBuffered, bufferedBytes(isOutbound = true)) }
        Thread.sleep(500)

        assertTrue(maxBuffered <= sizeLimit)
        coVerify(exactly = 1) {
            connector.persistHttpRequest(
                content = ByteArray(sizeLimit) { 'b'.code.toByte() },
                contentLength = size,
                contentTruncated = true,
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
                localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any(), contentTruncated = any()
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

        assertTrue("a storable body is buffered, but never more than the limit", maxBuffered in 1..sizeLimit)
        coVerify(exactly = 1) {
            connector.persistHttpResponse(
                content = ByteArray(sizeLimit) { 'b'.code.toByte() },
                contentLength = sizeLimit,
                contentTruncated = false,
                statusCode = 200,
                connectionId = any(), requestId = any(), timestamp = any(), headers = any(),
                statusMsg = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    @Test
    fun `a body one byte over the size limit is stored truncated`() {
        sendRequest("GET", "/")
        val size = sizeLimit + 1

        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: $size\r\n\r\n".toByteArray())
        feedBody(size, isOutbound = false)
        Thread.sleep(500)

        coVerify(exactly = 1) {
            connector.persistHttpResponse(
                content = ByteArray(sizeLimit) { 'b'.code.toByte() },
                contentLength = size,
                contentTruncated = true,
                statusCode = 200,
                connectionId = any(), requestId = any(), timestamp = any(), headers = any(),
                statusMsg = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
        assertEquals("the message is done, nothing of it may be held on to", 0, bufferedBytes(isOutbound = false))
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

        coVerify(exactly = 1) {
            connector.persistHttpResponse(
                contentLength = size,
                contentTruncated = true,
                statusCode = 200,
                content = any(), connectionId = any(), requestId = any(), timestamp = any(), headers = any(),
                statusMsg = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
        verifyResponse(404, "gone")
    }

    // -----------------------------------------------------------------------
    // docs/vpn-mitm-audit.md PKT-59 (V-64): bodies are stored as bytes, unchanged
    // -----------------------------------------------------------------------

    /** Every byte value, including CR, LF and bytes that are not valid UTF-8. */
    private val binaryBody = ByteArray(256) { it.toByte() } + ByteArray(256) { (255 - it).toByte() }

    private fun verifyResponseBody(content: ByteArray, contentLength: Int, contentTruncated: Boolean) {
        coVerify(exactly = 1) {
            connector.persistHttpResponse(
                content = content,
                contentLength = contentLength,
                contentTruncated = contentTruncated,
                statusCode = 200,
                connectionId = any(), requestId = any(), timestamp = any(), headers = any(),
                statusMsg = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    @Test
    fun `a binary body with Content-Length is stored byte for byte`() {
        sendRequest("GET", "/image")
        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: ${binaryBody.size}\r\n\r\n".toByteArray() + binaryBody)
        Thread.sleep(500)
        verifyResponseBody(binaryBody, binaryBody.size, contentTruncated = false)
    }

    @Test
    fun `a binary body split across payloads is stored byte for byte`() {
        sendRequest("GET", "/image")
        httpConnection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: ${binaryBody.size}\r\n\r\n".toByteArray() + binaryBody.copyOf(100))
        httpConnection.unwrapInbound(binaryBody.copyOfRange(100, binaryBody.size))
        Thread.sleep(500)
        verifyResponseBody(binaryBody, binaryBody.size, contentTruncated = false)
    }

    @Test
    fun `a chunked binary body is decoded and stored byte for byte`() {
        sendRequest("GET", "/image")
        val first = binaryBody.copyOf(300)
        val second = binaryBody.copyOfRange(300, binaryBody.size)
        httpConnection.unwrapInbound(
            chunkedHeaders.toByteArray() +
                "${first.size.toString(16)}\r\n".toByteArray() + first + "\r\n".toByteArray() +
                "${second.size.toString(16)}\r\n".toByteArray() + second + "\r\n0\r\n\r\n".toByteArray()
        )
        Thread.sleep(500)
        verifyResponseBody(binaryBody, binaryBody.size, contentTruncated = false)
    }

    @Test
    fun `a binary body delimited by connection close keeps its start and is marked truncated`() {
        sendRequest("GET", "/stream")
        httpConnection.unwrapInbound("HTTP/1.0 200 OK\r\n\r\n".toByteArray() + binaryBody)
        Thread.sleep(500)
        verifyResponseBody(binaryBody, binaryBody.size, contentTruncated = true)
    }

    @Test
    fun `the size limit comes from the preference`() {
        every { componentManager.maxHttpBodySize } returns 100
        val connection = HttpConnection(0, encryptionLayer, componentManager)
        connection.unwrapOutbound("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
        Thread.sleep(300)
        connection.unwrapInbound("HTTP/1.1 200 OK\r\nContent-Length: ${binaryBody.size}\r\n\r\n".toByteArray() + binaryBody)
        Thread.sleep(500)
        verifyResponseBody(binaryBody.copyOf(100), binaryBody.size, contentTruncated = true)
    }

}
