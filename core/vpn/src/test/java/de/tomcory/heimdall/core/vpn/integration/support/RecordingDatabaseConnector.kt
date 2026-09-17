package de.tomcory.heimdall.core.vpn.integration.support

import de.tomcory.heimdall.core.vpn.components.DatabaseConnector
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

data class RecordedConnection(
    val id: Int,
    val sessionId: Int,
    val protocol: String,
    val ipVersion: Int,
    val initialTimestamp: Long,
    val initiatorId: Int,
    val initiatorPkg: String,
    val localPort: Int,
    val remoteHost: String,
    val remoteIp: String,
    val remotePort: Int,
    val isTracker: Boolean,
    @Volatile var deleted: Boolean = false
)

data class RecordedRequest(
    val id: Int,
    val connectionId: Int,
    val timestamp: Long,
    val headers: Map<String, String>,
    val content: String,
    val contentLength: Int,
    val method: String,
    val remoteHost: String,
    val remotePath: String,
    val remoteIp: String,
    val remotePort: Int,
    val localIp: String,
    val localPort: Int,
    val initiatorId: Int,
    val initiatorPkg: String
)

data class RecordedResponse(
    val connectionId: Int,
    val requestId: Int,
    val timestamp: Long,
    val headers: Map<String, String>,
    val content: String,
    val contentLength: Int,
    val statusCode: Int,
    val statusMsg: String,
    val remoteHost: String,
    val remoteIp: String,
    val remotePort: Int,
    val localIp: String,
    val localPort: Int,
    val initiatorId: Int,
    val initiatorPkg: String
)

/**
 * Hand-rolled, in-memory [DatabaseConnector] fake used by integration tests in place of a real
 * Room database. Avoids needing Robolectric/Context just to exercise persistence call sites.
 */
class RecordingDatabaseConnector : DatabaseConnector {

    private val connectionIdCounter = AtomicInteger(1)
    private val requestIdCounter = AtomicInteger(1)

    val connections = CopyOnWriteArrayList<RecordedConnection>()
    val requests = CopyOnWriteArrayList<RecordedRequest>()
    val responses = CopyOnWriteArrayList<RecordedResponse>()

    @Volatile
    var sessionStart: Long = -1
    @Volatile
    var sessionEnd: Long = -1

    override suspend fun persistSession(startTime: Long): Int {
        sessionStart = startTime
        return 1
    }

    override suspend fun updateSession(id: Int, endTime: Long): Int {
        sessionEnd = endTime
        return id
    }

    override suspend fun persistTransportLayerConnection(
        sessionId: Int,
        protocol: String,
        ipVersion: Int,
        initialTimestamp: Long,
        initiatorId: Int,
        initiatorPkg: String,
        localPort: Int,
        remoteHost: String,
        remoteIp: String,
        remotePort: Int,
        isTracker: Boolean
    ): Int {
        val id = connectionIdCounter.getAndIncrement()
        connections.add(
            RecordedConnection(
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
        return id
    }

    override suspend fun deleteTransportLayerConnection(id: Int): Int {
        connections.find { it.id == id }?.deleted = true
        return id
    }

    override suspend fun persistHttpRequest(
        connectionId: Int,
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
    ): Int {
        val id = requestIdCounter.getAndIncrement()
        requests.add(
            RecordedRequest(
                id = id,
                connectionId = connectionId,
                timestamp = timestamp,
                headers = headers,
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
        return id
    }

    override suspend fun persistHttpResponse(
        connectionId: Int,
        requestId: Int,
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
    ): Int {
        responses.add(
            RecordedResponse(
                connectionId = connectionId,
                requestId = requestId,
                timestamp = timestamp,
                headers = headers,
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
        return requestId
    }
}
