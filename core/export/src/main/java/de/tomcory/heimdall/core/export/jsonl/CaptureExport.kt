package de.tomcory.heimdall.core.export.jsonl

import de.tomcory.heimdall.core.database.dao.ConnectionDao
import de.tomcory.heimdall.core.database.dao.RequestDao
import de.tomcory.heimdall.core.database.dao.ResponseDao
import de.tomcory.heimdall.core.database.dao.SessionDao
import de.tomcory.heimdall.core.database.entity.Session
import java.io.Writer

/**
 * Writes the messages and connections of a capture as JSON Lines, page by page, so that a large
 * capture is never held in memory.
 *
 * @param sessionId The session to export, or null for all sessions.
 * @param apps If not empty, only the traffic of these packages is exported.
 * @param version Heimdall's version name, written into every record.
 */
class CaptureExport(
    private val sessionDao: SessionDao,
    private val connectionDao: ConnectionDao,
    private val requestDao: RequestDao,
    private val responseDao: ResponseDao,
    private val sessionId: Long?,
    private val apps: List<String>,
    private val version: String
) {
    private val sessions = HashMap<Long, Session?>()

    private suspend fun session(id: Long): Session? = sessions.getOrPut(id) { sessionDao.getById(id) }

    /** @return the number of records written. */
    suspend fun writeMessages(out: Writer): Int {
        var written = 0
        var offset = 0
        while (true) {
            val requests = requestDao.getForExport(sessionId ?: ALL_SESSIONS, apps.isNotEmpty(), apps, PAGE_SIZE, offset)
            if (requests.isEmpty()) {
                return written
            }
            val connections = connectionDao.getByIds(requests.map { it.connectionId }.distinct()).associateBy { it.id }
            val responses = responseDao.getForRequests(requests.map { it.id }).associateBy { it.requestId }
            for (request in requests) {
                val connection = connections[request.connectionId] ?: continue
                out.write(CaptureRecords.message(request, responses[request.id], connection, session(connection.sessionId), version).toString())
                out.write("\n")
                written++
            }
            offset += requests.size
        }
    }

    /** @return the number of records written. */
    suspend fun writeConnections(out: Writer): Int {
        var written = 0
        var offset = 0
        while (true) {
            val connections = connectionDao.getForExport(sessionId ?: ALL_SESSIONS, apps.isNotEmpty(), apps, PAGE_SIZE, offset)
            if (connections.isEmpty()) {
                return written
            }
            for (connection in connections) {
                out.write(CaptureRecords.connection(connection, session(connection.sessionId), version).toString())
                out.write("\n")
                written++
            }
            offset += connections.size
        }
    }

    companion object {
        /** The value of the DAOs' session parameter that selects every session. */
        const val ALL_SESSIONS = -1L

        // bodies can be large; a page of requests has to fit into a CursorWindow comfortably
        private const val PAGE_SIZE = 50
    }
}
