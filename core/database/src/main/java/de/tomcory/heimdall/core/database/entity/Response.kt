package de.tomcory.heimdall.core.database.entity

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.PrimaryKey

@Entity(
    foreignKeys = [
        ForeignKey(
            entity = Request::class,
            parentColumns = ["id"],
            childColumns = ["requestId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [
        androidx.room.Index(value = ["requestId"])
    ]
)
data class Response(
    @PrimaryKey(autoGenerate = true)
    val id: Int = 0,
    val connectionId: Int,
    val requestId: Int,
    val timestamp: Long,
    val headers: String,
    val content: String,
    val contentLength: Int,
    val statusCode: Int,
    val statusMsg: String,
    val remoteHost: String,
    val remoteIp: String,
    val remotePort: Int,
    val localIp: String,
    val localPort: Int,
    val initiatorId: Int,
    val initiatorPkg: String,
    val isTracker: Boolean = false
)
