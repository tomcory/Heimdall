package de.tomcory.heimdall.core.vpn.components

import de.tomcory.heimdall.core.database.entity.Protocol

interface DatabaseConnector {

    suspend fun persistSession(
        startTime: Long
    ): Long

    suspend fun updateSession(
        id: Long,
        endTime: Long
    ): Int

    suspend fun persistTransportLayerConnection(
        sessionId : Long,
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
    ): Long

    suspend fun deleteTransportLayerConnection(
        id: Long
    ): Int

    suspend fun persistHttpRequest(
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
    ): Long

    suspend fun persistHttpResponse(
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
    ): Long
}
