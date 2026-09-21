package de.tomcory.heimdall.core.database.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity
data class Permission(
    @PrimaryKey
    val permissionName: String,
    val dangerous: Boolean
)
