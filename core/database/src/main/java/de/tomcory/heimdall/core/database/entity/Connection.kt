package de.tomcory.heimdall.core.database.entity

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    foreignKeys = [
        ForeignKey(
            entity = Session::class,
            parentColumns = ["id"],
            childColumns = ["sessionId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [
        Index(value = ["sessionId"])
    ]
)
data class Connection(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val sessionId: Long,
    val protocol: Protocol,
    val ipVersion: Int,
    val initialTimestamp: Long,
    val initiatorId: Int,
    // deliberately not an @ForeignKey to App.packageName: this is a historical record that must
    // survive the initiating app being uninstalled
    val initiatorPkg: String,
    val localPort: Int,
    // null: hostname not yet resolved; empty string: resolved, no reverse-DNS name available
    val remoteHost: String?,
    val remoteIp: String,
    val remotePort: Int,
    val isTracker: Boolean = false,
    val bytesOut: Long = 0,
    val bytesIn: Long = 0,
    // null: the connection carried no payload yet, so nothing was classified
    val securityProtocol: SecurityProtocol? = null,
    // server name the client asked for in its TLS or QUIC ClientHello, if it sent one
    val sni: String? = null,
    // application protocols the client offered in its ClientHello, comma-separated in the
    // client's order of preference (e.g. "h2,http/1.1")
    val alpn: String? = null,
    // the ClientHello carried an Encrypted Client Hello extension. Clients also send it as
    // GREASE, so this alone does not mean the real server name was hidden.
    val echOffered: Boolean = false,
    // Heimdall dropped this connection's traffic instead of forwarding it
    val blocked: Boolean = false,
    // why it was dropped: "host_rule" (its host is on the block list) or "quic_policy" (HTTP/3
    // blocked so that the client falls back to TLS). Null when it was not blocked.
    val blockReason: String? = null,
    // why a TLS connection was not decrypted although MitM was on: the passthrough reason
    // learned for its app and host (e.g. CLIENT_HANDSHAKE_ERROR), OUT_OF_SCOPE, or
    // UPSTREAM_HANDSHAKE_FAILED for a connection whose own upstream handshake failed. Null when it
    // was decrypted, or when MitM was off.
    val passthroughReason: String? = null
)
