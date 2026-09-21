package de.tomcory.heimdall.core.database.entity

/**
 * Transport-layer protocol of a captured [Connection]. Only `TransportLayerConnection`'s own
 * `protocol` (overridden by `TcpConnection`/`UdpConnection`) ever reaches the database — the
 * encryption layer's separate "TLS"/"QUIC"/"PLAIN" labels (`EncryptionLayerConnection.protocol`)
 * are logging-only and are never persisted. A closed, small set — a good fit for a Room-converted
 * enum rather than a raw [String] column.
 */
enum class Protocol {
    TCP,
    UDP
}
