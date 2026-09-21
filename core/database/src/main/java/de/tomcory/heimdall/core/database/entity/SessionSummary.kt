package de.tomcory.heimdall.core.database.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * A rolled-up summary of a [Session] that has been pruned (its raw [Connection]/[Request]/
 * [Response] rows deleted per the traffic retention policy). Deliberately not a foreign key to
 * [Session] — it must survive after the session it summarises is gone.
 */
@Entity
data class SessionSummary(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val sessionStartTime: Long,
    val sessionEndTime: Long,
    val connectionCount: Int,
    val uniqueHostCount: Int,
    val trackerConnectionCount: Int,
    val bytesOut: Long,
    val bytesIn: Long
)
