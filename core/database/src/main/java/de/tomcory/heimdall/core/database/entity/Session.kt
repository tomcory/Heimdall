package de.tomcory.heimdall.core.database.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity
data class Session(
    @PrimaryKey(autoGenerate = true)
    val id: Int = 0,
    val startTime: Long = System.currentTimeMillis(),
    var endTime: Long = -1
)
