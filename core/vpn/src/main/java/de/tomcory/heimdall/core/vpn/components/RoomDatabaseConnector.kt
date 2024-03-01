package de.tomcory.heimdall.core.vpn.components

import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.Connection
import de.tomcory.heimdall.core.database.entity.Request
import de.tomcory.heimdall.core.database.entity.Response
import de.tomcory.heimdall.core.database.entity.Session
import timber.log.Timber

class RoomDatabaseConnector(
    val database: HeimdallDatabase
): DatabaseConnector {
    override suspend fun persistSession(startTime: Long): Int {
        val ids = try {
            database.sessionDao().insert(Session(startTime = startTime))
        } catch (e: Exception) {
            Timber.e(e, "Error while persisting session")
            emptyList()
        }
        return if (ids.isNotEmpty()) ids.first().toInt() else -1
    }

    override suspend fun updateSession(id: Int, endTime: Long): Int {
        return try {
            database.sessionDao().updateEndTime(id, endTime)
        } catch (e: Exception) {
            Timber.e(e, "Error while updating session")
            -1
        }
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
        val ids = try {
            database.connectionDao().insert(
                Connection(
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
            Timber.e(e, "Error while persisting transport layer connection (sID: $sessionId)")
            emptyList()
        }
        return if (ids.isNotEmpty()) ids.first().toInt() else -1
    }

    override suspend fun deleteTransportLayerConnection(id: Int): Int {
        return try {
            database.connectionDao().delete(id)
        } catch (e: Exception) {
            Timber.e(e, "Error while deleting transport layer connection")
            -1
        }
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
        val ids = try {
            database.requestDao().insert(
                Request(
                    connectionId = connectionId,
                    timestamp = timestamp,
                    headers = if(headers.isNotEmpty()) headers.map { "${it.key}: ${it.value}" }.reduce { acc, s -> "$acc$s\n" } else "",
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
        return if (ids.isNotEmpty()) ids.first().toInt() else -1
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
        val ids = try {
            database.responseDao().insert(
                Response(
                    connectionId = connectionId,
                    requestId = requestId,
                    timestamp = timestamp,
                    headers = if(headers.isNotEmpty()) headers.map { "${it.key}: ${it.value}" }.reduce { acc, s -> "$acc$s\n" } else "",
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
        return if (ids.isNotEmpty()) ids.first().toInt() else -1
    }
}