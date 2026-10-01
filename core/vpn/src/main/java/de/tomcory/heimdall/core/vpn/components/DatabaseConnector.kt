package de.tomcory.heimdall.core.vpn.components

import de.tomcory.heimdall.core.database.entity.Protocol
import de.tomcory.heimdall.core.database.entity.SecurityProtocol

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

    suspend fun updateConnectionBytesOut(
        id: Long,
        delta: Long
    )

    suspend fun updateConnectionBytesIn(
        id: Long,
        delta: Long
    )

    /**
     * Records what the encryption layer learned about a connection from its first payload.
     *
     * @param alpn The application protocols the client offered, comma-separated.
     * @param echOffered Whether the ClientHello carried an Encrypted Client Hello extension.
     */
    suspend fun updateConnectionSecurity(
        id: Long,
        securityProtocol: SecurityProtocol,
        sni: String?,
        alpn: String?,
        echOffered: Boolean
    )

    /**
     * Replaces a connection's hostname and tracker label once a better hostname than the one
     * known at creation time is available.
     */
    suspend fun updateConnectionHost(
        id: Long,
        remoteHost: String,
        isTracker: Boolean
    )

    /**
     * Marks a connection whose traffic was dropped instead of forwarded.
     */
    suspend fun markConnectionBlocked(
        id: Long
    )

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
