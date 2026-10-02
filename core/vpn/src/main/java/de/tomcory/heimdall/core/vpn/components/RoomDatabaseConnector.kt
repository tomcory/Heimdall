package de.tomcory.heimdall.core.vpn.components

import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.Connection
import de.tomcory.heimdall.core.database.entity.Protocol
import de.tomcory.heimdall.core.database.entity.Request
import de.tomcory.heimdall.core.database.entity.Response
import de.tomcory.heimdall.core.database.entity.SecurityProtocol
import de.tomcory.heimdall.core.database.entity.Session
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import timber.log.Timber
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class RoomDatabaseConnector(
    val database: HeimdallDatabase
): DatabaseConnector {

    private val insertScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * The ID given to the most recent connection. Connection IDs are assigned here rather than
     * by the database, so that a new connection has its ID without waiting for its row to be
     * written. Seeded once from the stored connections; nothing else inserts connections while
     * the VPN is running.
     */
    private val lastConnectionId = AtomicLong(
        try {
            runBlocking { database.connectionDao().maxId() }
        } catch (e: Exception) {
            Timber.e(e, "Error while reading the highest connection ID")
            0L
        }
    )

    /** Inserts of connection rows that are still under way, by connection ID. */
    private val pendingConnectionInserts = ConcurrentHashMap<Long, Job>()

    /**
     * Waits until the row of the connection with the given ID has been written, if its insert
     * is still under way. Everything that refers to a connection by ID calls this first.
     */
    private suspend fun awaitConnection(id: Long) {
        pendingConnectionInserts[id]?.join()
    }
    override suspend fun persistSession(startTime: Long): Long {
        val ids = try {
            database.sessionDao().insert(Session(startTime = startTime))
        } catch (e: Exception) {
            Timber.e(e, "Error while persisting session")
            emptyList()
        }
        return if (ids.isNotEmpty()) ids.first() else -1
    }

    override suspend fun updateSession(id: Long, endTime: Long): Int {
        return try {
            database.sessionDao().updateEndTime(id, endTime)
        } catch (e: Exception) {
            Timber.e(e, "Error while updating session")
            -1
        }
    }

    override fun persistTransportLayerConnection(
        sessionId: Long,
        protocol: Protocol,
        ipVersion: Int,
        initialTimestamp: Long,
        initiatorId: Int,
        initiatorPkg: String,
        localPort: Int,
        remoteHost: String?,
        remoteIp: String,
        remotePort: Int,
        isTracker: Boolean
    ): Long {
        val id = lastConnectionId.incrementAndGet()
        val insert = insertScope.launch(start = CoroutineStart.LAZY) {
            try {
                database.connectionDao().insert(
                    Connection(
                        id = id,
                        sessionId = sessionId,
                        protocol = protocol,
                        ipVersion = ipVersion,
                        initialTimestamp = initialTimestamp,
                        initiatorId = initiatorId,
                        initiatorPkg = initiatorPkg,
                        localPort = localPort,
                        remoteHost = remoteHost,
                        remoteIp = remoteIp,
                        remotePort = remotePort,
                        isTracker = isTracker
                    )
                )
            } catch (e: Exception) {
                Timber.e(e, "Error while persisting transport layer connection (cID: $id, sID: $sessionId)")
            }
        }
        // registered before it starts, so that no later call for this ID can miss it
        pendingConnectionInserts[id] = insert
        insert.invokeOnCompletion { pendingConnectionInserts.remove(id, insert) }
        insert.start()
        return id
    }

    override suspend fun deleteTransportLayerConnection(id: Long): Int {
        awaitConnection(id)
        return try {
            database.connectionDao().delete(id)
        } catch (e: Exception) {
            Timber.e(e, "Error while deleting transport layer connection")
            -1
        }
    }

    override suspend fun updateConnectionBytesOut(id: Long, delta: Long) {
        awaitConnection(id)
        try {
            database.connectionDao().updateBytesOut(id, delta)
        } catch (e: Exception) {
            Timber.e(e, "Error while updating connection bytesOut (cID: $id)")
        }
    }

    override suspend fun updateConnectionBytesIn(id: Long, delta: Long) {
        awaitConnection(id)
        try {
            database.connectionDao().updateBytesIn(id, delta)
        } catch (e: Exception) {
            Timber.e(e, "Error while updating connection bytesIn (cID: $id)")
        }
    }

    override suspend fun updateConnectionSecurity(
        id: Long,
        securityProtocol: SecurityProtocol,
        sni: String?,
        alpn: String?,
        echOffered: Boolean
    ) {
        awaitConnection(id)
        try {
            database.connectionDao().updateSecurity(id, securityProtocol, sni, alpn, echOffered)
        } catch (e: Exception) {
            Timber.e(e, "Error while updating connection security metadata (cID: $id)")
        }
    }

    override suspend fun updateConnectionHost(id: Long, remoteHost: String, isTracker: Boolean) {
        awaitConnection(id)
        try {
            database.connectionDao().updateHost(id, remoteHost, isTracker)
        } catch (e: Exception) {
            Timber.e(e, "Error while updating connection host (cID: $id)")
        }
    }

    override suspend fun markConnectionBlocked(id: Long) {
        awaitConnection(id)
        try {
            database.connectionDao().markBlocked(id)
        } catch (e: Exception) {
            Timber.e(e, "Error while marking connection as blocked (cID: $id)")
        }
    }

    override suspend fun persistHttpRequest(
        connectionId: Long,
        timestamp: Long,
        headers: Map<String, String>,
        content: String,
        contentLength: Int,
        method: String,
        remoteHost: String,
        remotePath: String,
        remoteIp: String,
        remotePort: Int,
        localIp: String,
        localPort: Int,
        initiatorId: Int,
        initiatorPkg: String
    ): Long {
        awaitConnection(connectionId)
        val ids = try {
            database.requestDao().insert(
                Request(
                    connectionId = connectionId,
                    timestamp = timestamp,
                    headers = headers.entries.joinToString("\n") { "${it.key}: ${it.value}" },
                    content = content,
                    contentLength = contentLength,
                    method = method,
                    remoteHost = remoteHost,
                    remotePath = remotePath,
                    remoteIp = remoteIp,
                    remotePort = remotePort,
                    localIp = localIp,
                    localPort = localPort,
                    initiatorId = initiatorId,
                    initiatorPkg = initiatorPkg
                )
            )
        } catch (e: Exception) {
            Timber.e(e, "Error while persisting http request (cID: $connectionId)")
            emptyList()
        }
        return if (ids.isNotEmpty()) ids.first() else -1
    }

    override suspend fun persistHttpResponse(
        connectionId: Long,
        requestId: Long,
        timestamp: Long,
        headers: Map<String, String>,
        content: String,
        contentLength: Int,
        statusCode: Int,
        statusMsg: String,
        remoteHost: String,
        remoteIp: String,
        remotePort: Int,
        localIp: String,
        localPort: Int,
        initiatorId: Int,
        initiatorPkg: String
    ): Long {
        awaitConnection(connectionId)
        val ids = try {
            database.responseDao().insert(
                Response(
                    requestId = requestId,
                    timestamp = timestamp,
                    headers = headers.entries.joinToString("\n") { "${it.key}: ${it.value}" },
                    content = content,
                    contentLength = contentLength,
                    statusCode = statusCode,
                    statusMsg = statusMsg,
                    remoteHost = remoteHost,
                    remoteIp = remoteIp,
                    remotePort = remotePort,
                    localIp = localIp,
                    localPort = localPort,
                    initiatorId = initiatorId,
                    initiatorPkg = initiatorPkg
                )
            )
        } catch (e: Exception) {
            Timber.e(e, "Error while persisting http response (cID: $connectionId, rID: $requestId)")
            emptyList()
        }
        return if (ids.isNotEmpty()) ids.first() else -1
    }
}
