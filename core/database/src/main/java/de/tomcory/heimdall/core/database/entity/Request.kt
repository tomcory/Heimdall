package de.tomcory.heimdall.core.database.entity

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.PrimaryKey

@Entity(
    foreignKeys = [
        ForeignKey(
            entity = Connection::class,
            parentColumns = ["id"],
            childColumns = ["connectionId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [
        androidx.room.Index(value = ["connectionId"])
    ]
)
@Suppress("ArrayInDataClass") // never compared; rows are identified by id
data class Request(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val connectionId: Long,
    val timestamp: Long,
    val headers: String,
    // the body as received (bytes, so binary and compressed bodies survive), at most the
    // configured limit; contentLength is the body's real length
    val content: ByteArray,
    val contentLength: Int,
    // the body was longer than the limit, or ran until the connection closed, so content holds
    // only its start
    val contentTruncated: Boolean = false,
    val method: String,
    val remoteHost: String,
    val remotePath: String,
    val remoteIp: String,
    val remotePort: Int,
    val localIp: String,
    val localPort: Int,
    val initiatorId: Int,
    val initiatorPkg: String
)
