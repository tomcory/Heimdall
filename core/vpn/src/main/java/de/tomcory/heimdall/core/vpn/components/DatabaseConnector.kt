package de.tomcory.heimdall.core.vpn.components

interface DatabaseConnector {

    suspend fun persistSession(
        startTime: Long
    ): Int

    suspend fun updateSession(
        id: Int,
        endTime: Long
    ): Int

    suspend fun persistTransportLayerConnection(
        sessionId : Int,
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
    ): Int

    suspend fun deleteTransportLayerConnection(
        id: Int
    ): Int

    suspend fun persistHttpRequest(
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
    ): Int

    suspend fun persistHttpResponse(
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
    ): Int
}