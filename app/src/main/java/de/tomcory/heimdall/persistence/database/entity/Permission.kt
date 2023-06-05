package de.tomcory.heimdall.persistence.database.entity

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity
data class Permission(
    @PrimaryKey
    @ColumnInfo(index = true)
    val permissionName: String,
    val dangerous: Boolean
)
