package de.tomcory.heimdall.core.database.entity

import androidx.room.Entity
import androidx.room.ForeignKey
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
        androidx.room.Index(value = ["sessionId"])
    ]
)
data class Connection(
    @PrimaryKey(autoGenerate = true)
    val id: Int = 0,
    val sessionId: Int,
    val protocol: String,
    val ipVersion: Int,
    val initialTimestamp: Long,
    val initiatorId: Int,
    val initiatorPkg: String,
    val localPort: Int,
    val remoteHost: String = "",
    val remoteIp: String,
    val remotePort: Int,
    val isTracker: Boolean = false,
    val bytesOut: Long = 0,
    val bytesIn: Long = 0
)
