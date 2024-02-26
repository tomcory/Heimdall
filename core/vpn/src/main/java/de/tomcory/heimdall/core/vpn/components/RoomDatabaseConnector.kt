package de.tomcory.heimdall.core.vpn.components

import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.Connection
import de.tomcory.heimdall.core.database.entity.Request
import de.tomcory.heimdall.core.database.entity.Response
import de.tomcory.heimdall.core.database.entity.Session

class RoomDatabaseConnector(
    val database: HeimdallDatabase
): DatabaseConnector {
    override suspend fun persistSession(startTime: Long): Int {
        val ids = database.sessionDao().insert(Session(startTime = startTime))
        return if (ids.isNotEmpty()) ids.first().toInt() else -1
    }

    override suspend fun updateSession(id: Int, endTime: Long): Int {
        return database.sessionDao().updateEndTime(id, endTime)
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
        val ids = database.connectionDao().insert(
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
        return if (ids.isNotEmpty()) ids.first().toInt() else -1
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
        val ids = database.requestDao().insert(
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
        val ids = database.responseDao().insert(
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
        return if (ids.isNotEmpty()) ids.first().toInt() else -1
    }
}