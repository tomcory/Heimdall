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

        // Terminating chunk on its own line triggers last-chunk detection
        httpConnection.unwrapOutbound("0\r\n".toByteArray())
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
}
