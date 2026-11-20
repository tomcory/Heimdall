package de.tomcory.heimdall.core.database.entity

/**
 * What an export needs to know about a [Connection] to tell whether its traffic could be observed:
 * how it was carried and secured, whether it was blocked or passed through undecrypted, and whether
 * an HTTP request was recorded on it. Read by [de.tomcory.heimdall.core.database.dao.ConnectionDao.getFactsForExport].
 */
data class ConnectionFacts(
    val protocol: Protocol,
    val securityProtocol: SecurityProtocol?,
    val remotePort: Int,
    val bytesOut: Long,
    val blocked: Boolean,
    val blockReason: String?,
    val passthroughReason: String?,
    val hasRequest: Boolean
)
