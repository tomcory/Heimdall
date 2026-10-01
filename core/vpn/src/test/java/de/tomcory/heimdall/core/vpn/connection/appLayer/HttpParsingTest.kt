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
}
