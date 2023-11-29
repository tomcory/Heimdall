package de.tomcory.heimdall.core.database.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity
data class Connection(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val protocol: String,
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
