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
    val bytesIn: Long = 0
)
