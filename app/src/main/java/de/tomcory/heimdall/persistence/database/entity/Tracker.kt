package de.tomcory.heimdall.persistence.database.entity

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity
data class Tracker(
    @PrimaryKey
    @ColumnInfo(index = true)
    val className: String,
    val name: String,
    val web: String)