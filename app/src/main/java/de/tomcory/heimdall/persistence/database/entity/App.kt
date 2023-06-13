package de.tomcory.heimdall.persistence.database.entity

import android.graphics.drawable.Drawable
import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Ignore
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity
data class App(
    @PrimaryKey
    @ColumnInfo(index = true)
    val packageName: String,
    val label: String,
    val versionName: String,
    val versionCode: Long,
    val isInstalled: Boolean = true
)