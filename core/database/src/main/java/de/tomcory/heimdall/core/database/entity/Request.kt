package de.tomcory.heimdall.core.database.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity
data class Request(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val timestamp: Long,
    val reqResId: Int,
    val headers: String,
    val content: String,
    val contentLength: Int,
    val method: String,
    val remoteHost: String,
    val remotePath: String,
    val remoteIp: String,
    val remotePort: Int,
    val localIp: String,
    val localPort: Int,
    val initiatorId: Int,
    val initiatorPkg: String,
    val isTracker: Boolean = false
)
