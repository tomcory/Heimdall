package de.tomcory.heimdall.core.database.entity

/**
 * Transport-layer protocol of a captured [Connection], taken from `TransportLayerConnection`'s
 * `protocol` (overridden by `TcpConnection`/`UdpConnection`). What runs on top of it is recorded
 * separately as [Connection.securityProtocol]. A closed, small set — a good fit for a
 * Room-converted enum rather than a raw [String] column.
 */
enum class Protocol {
    TCP,
    UDP
}
