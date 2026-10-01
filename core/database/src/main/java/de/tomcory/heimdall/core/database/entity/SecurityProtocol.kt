package de.tomcory.heimdall.core.database.entity

/**
 * How a captured [Connection]'s payload is secured, as classified by the VPN's encryption layer
 * from the connection's first outbound payload. Complements [Protocol], which is the transport
 * the connection runs over.
 */
enum class SecurityProtocol {
    /** No encryption layer was recognised. The payload may still be encrypted by the application itself. */
    PLAIN,
    TLS,
    QUIC
}
