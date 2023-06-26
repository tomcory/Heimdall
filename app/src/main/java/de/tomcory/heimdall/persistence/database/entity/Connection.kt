package de.tomcory.heimdall.persistence.database.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity
data class Connection(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val protocol: String,
    val initialTimestamp: Long,
    val initiator: String,
    val localPort: Int,
    val remoteHost: String = "",
    val remoteIp: String,
    val remotePort: Int,
    val bytesOut: Long = 0,
    val bytesIn: Long = 0
)
