package de.tomcory.heimdall.core.vpn.connection.appLayer

import org.junit.Assert.assertTrue
import de.tomcory.heimdall.core.vpn.integration.support.RecordingTree
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.components.DatabaseConnector
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import de.tomcory.heimdall.core.vpn.connection.inetLayer.IpPacketBuilder
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import java.net.InetAddress
import java.util.concurrent.CopyOnWriteArrayList

/**
 * A response waits for its request's row however
 * long the database takes, and a connection's writes happen one at a time, in wire order. Runs on
 * virtual time, so waits of minutes take none.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class HttpPersistenceTest {

    private lateinit var connector: DatabaseConnector
    private lateinit var componentManager: ComponentManager
    private lateinit var encryptionLayer: EncryptionLayerConnection

    @Before
    fun setup() {
        connector = mockk(relaxed = true)
        componentManager = mockk(relaxed = true)
        every { componentManager.databaseConnector } returns connector
        every { componentManager.maxHttpBodySize } returns HttpConnection.DEFAULT_MAX_BODY_SIZE

        val address = mockk<InetAddress>(relaxed = true)
        every { address.hostAddress } returns "10.0.0.1"
        val ipPacketBuilder = mockk<IpPacketBuilder>(relaxed = true)
        every { ipPacketBuilder.remoteAddress } returns address
        every { ipPacketBuilder.localAddress } returns address
        val transportLayer = mockk<TransportLayerConnection>(relaxed = true)
        every { transportLayer.ipPacketBuilder } returns ipPacketBuilder
        every { transportLayer.remoteHost } returns "example.com"
        encryptionLayer = mockk(relaxed = true)
        every { encryptionLayer.transportLayer } returns transportLayer
    }

    private fun TestScope.connection() = HttpConnection(0, encryptionLayer, componentManager, StandardTestDispatcher(testScheduler))

    private fun HttpConnection.request(path: String) =
        unwrapOutbound("GET $path HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())

    private fun HttpConnection.response(status: Int = 200) =
        unwrapInbound("HTTP/1.1 $status OK\r\nContent-Length: 2\r\n\r\nok".toByteArray())

    private fun verifyResponses(times: Int, requestId: Long? = null) {
        coVerify(exactly = times) {
            connector.persistHttpResponse(
                requestId = requestId ?: any(),
                connectionId = any(), timestamp = any(), headers = any(), content = any(), contentLength = any(),
                contentTruncated = any(), statusCode = any(), statusMsg = any(), remoteHost = any(), remoteIp = any(),
                remotePort = any(), localIp = any(), localPort = any(), initiatorId = any(), initiatorPkg = any()
            )
        }
    }

    private fun requestWrite(answer: suspend () -> Long) {
        coEvery {
            connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        } coAnswers { answer() }
    }

    @Test
    fun `a response whose request row takes longer than 30 s is still persisted`() = runTest {
        requestWrite { delay(45_000); 7L }
        val http = connection()

        http.request("/slow")
        http.response()
        advanceTimeBy(40_000)
        runCurrent()
        verifyResponses(0)

        advanceUntilIdle()
        verifyResponses(1, requestId = 7L)
    }

    @Test
    fun `a response whose request could not be written is dropped, and nothing hangs`() = runTest {
        requestWrite { throw IllegalStateException("database gone") }
        val http = connection()

        http.request("/failing")
        http.response()
        advanceUntilIdle()

        verifyResponses(0)
    }

    @Test
    fun `a write that never returns is given up after the safety bound and does not block the connection`() = runTest {
        var calls = 0
        requestWrite { if (++calls == 1) awaitCancellation() else 8L }
        val http = connection()

        http.request("/stuck")
        http.response()
        advanceTimeBy(9 * 60_000L)
        runCurrent()
        assertEquals("the stuck request write and the response behind it are waiting", 2, queuedWrites(http))

        // after the 10-minute bound the stuck write is given up, and its response with it
        val tree = RecordingTree().plant()
        try {
            advanceTimeBy(2 * 60_000L)
            runCurrent()
            // the request write rethrows the cancellation, so the bound sees it (PKT-63)
            assertTrue("the safety bound must say that it gave a write up", tree.anyContains("did not finish within 10 minutes"))
            assertTrue("the response must be dropped as a failed request, not silently", tree.anyContains("could not be written, discarding the response"))
        } finally {
            tree.uproot()
        }
        assertEquals(0, queuedWrites(http))
        verifyResponses(0)

        // the connection's next messages are written as usual
        http.request("/next")
        http.response()
        advanceUntilIdle()
        verifyResponses(1, requestId = 8L)
    }

    private fun queuedWrites(http: HttpConnection): Int {
        val field = HttpConnection::class.java.getDeclaredField("queuedWrites")
        field.isAccessible = true
        return (field.get(http) as java.util.concurrent.atomic.AtomicInteger).get()
    }

    @Test
    fun `a connection's writes happen one at a time, in wire order`() = runTest {
        val order = CopyOnWriteArrayList<String>()
        var running = 0
        var maxRunning = 0
        coEvery {
            connector.persistHttpRequest(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        } coAnswers {
            running++
            maxRunning = maxOf(maxRunning, running)
            // the first write is the slowest; with concurrent writes it would finish last
            delay(if (arg<String>(8) == "/1") 3_000L else 100L)
            order.add(arg(8))
            running--
            order.size.toLong()
        }
        val http = connection()

        (1..5).forEach { http.request("/$it") }
        advanceUntilIdle()

        assertEquals(listOf("/1", "/2", "/3", "/4", "/5"), order)
        assertEquals("writes must not overlap", 1, maxRunning)
    }

    @Test
    fun `pipelined responses are paired with their requests while writes are queued`() = runTest {
        var next = 100L
        requestWrite { delay(1_000); next++ }
        val http = connection()

        http.request("/a")
        http.request("/b")
        http.response(200)
        http.response(201)
        advanceUntilIdle()

        verifyResponses(1, requestId = 100L)
        verifyResponses(1, requestId = 101L)
    }
}
