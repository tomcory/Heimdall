package de.tomcory.heimdall.core.vpn.components

import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.dao.ConnectionDao
import de.tomcory.heimdall.core.database.dao.RequestDao
import de.tomcory.heimdall.core.database.entity.Connection
import de.tomcory.heimdall.core.database.entity.Protocol
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Tests for docs/vpn-mitm-audit.md PKT-41 (V-51): storing a new connection must not make the
 * caller wait for the database, and whatever is written about that connection afterwards must
 * still reach the database after the connection's row.
 */
class RoomDatabaseConnectorTest {

    private val connectionDao: ConnectionDao = mockk(relaxed = true)
    private val requestDao: RequestDao = mockk(relaxed = true)
    private val database: HeimdallDatabase = mockk(relaxed = true)

    /** What reached the database, in order. */
    private val events = CopyOnWriteArrayList<String>()

    /** Holds every connection insert back until it is completed. */
    private val insertGate = CompletableDeferred<Unit>()

    @Before
    fun setup() {
        every { database.connectionDao() } returns connectionDao
        every { database.requestDao() } returns requestDao
        coEvery { connectionDao.maxId() } returns 41L
        coEvery { connectionDao.insert(*anyVararg()) } coAnswers {
            val connection = args[0].let { (it as Array<*>)[0] as Connection }
            events.add("insert ${connection.id} waiting")
            insertGate.await()
            events.add("insert ${connection.id}")
            listOf(connection.id)
        }
        coEvery { connectionDao.updateHost(any(), any(), any()) } coAnswers { events.add("updateHost ${firstArg<Long>()}") }
        coEvery { connectionDao.updateBytesOut(any(), any()) } coAnswers { events.add("updateBytesOut ${firstArg<Long>()}") }
        coEvery { connectionDao.delete(any()) } coAnswers { events.add("delete ${firstArg<Long>()}"); 1 }
        coEvery { requestDao.insert(*anyVararg()) } coAnswers { events.add("request"); listOf(7L) }
    }

    private fun RoomDatabaseConnector.persistConnection(): Long = persistTransportLayerConnection(
        sessionId = 1,
        protocol = Protocol.TCP,
        ipVersion = 4,
        initialTimestamp = 0,
        initiatorId = 1000,
        initiatorPkg = "com.example.test",
        localPort = 40000,
        remoteHost = "example.com",
        remoteIp = "93.184.216.34",
        remotePort = 443,
        isTracker = false
    )

    private fun awaitUntil(message: String, timeoutMs: Long = 5000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline && !condition()) {
            Thread.sleep(10)
        }
        assertTrue(message, condition())
    }

    @Test
    fun `a connection gets its ID without waiting for its row to be written`() {
        val connector = RoomDatabaseConnector(database)

        // the inserts cannot finish yet, and still both calls return
        val first = connector.persistConnection()
        val second = connector.persistConnection()

        assertEquals("IDs continue after the highest stored one", 42L, first)
        assertEquals(43L, second)
        awaitUntil("both inserts must have been started") { events.count { it.endsWith("waiting") } == 2 }
        assertTrue("no insert may have finished", events.none { it == "insert 42" || it == "insert 43" })

        insertGate.complete(Unit)
        awaitUntil("both rows must be written in the end") { events.contains("insert 42") && events.contains("insert 43") }
    }

    @Test
    fun `writes about a connection wait for its row`() {
        val connector = RoomDatabaseConnector(database)
        val id = connector.persistConnection()

        val scope = CoroutineScope(Dispatchers.IO)
        val host = scope.launch { connector.updateConnectionHost(id, "example.org", false) }
        val bytes = scope.launch { connector.updateConnectionBytesOut(id, 100) }
        val request = scope.launch {
            connector.persistHttpRequest(id, 0, emptyMap(), "", 0, "GET", "example.org", "/", "93.184.216.34", 443, "10.0.0.1", 40000, 1000, "com.example.test")
        }
        val delete = scope.launch { connector.deleteTransportLayerConnection(id) }

        // give them every chance to overtake the insert
        Thread.sleep(300)
        assertEquals("nothing may reach the database before the connection's row", listOf("insert $id waiting"), events.toList())

        insertGate.complete(Unit)
        runBlocking { withTimeout(5000) { host.join(); bytes.join(); request.join(); delete.join() } }

        assertEquals("insert $id", events[1])
        assertEquals(setOf("updateHost $id", "updateBytesOut $id", "request", "delete $id"), events.drop(2).toSet())
    }

    @Test
    fun `writes about a stored connection do not wait for other connections`() {
        val connector = RoomDatabaseConnector(database)
        connector.persistConnection() // its insert stays blocked

        runBlocking { withTimeout(5000) { connector.updateConnectionHost(7, "example.org", false) } }

        assertTrue(events.contains("updateHost 7"))
    }
}
