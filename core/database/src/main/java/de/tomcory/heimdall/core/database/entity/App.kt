package de.tomcory.heimdall.core.database.entity

import android.graphics.drawable.Drawable
import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Ignore
import androidx.room.PrimaryKey

@Entity
data class App(
    @PrimaryKey
    @ColumnInfo(index = true)
    val packageName: String,
    val label: String,
    val versionName: String,
    val versionCode: Long,
    val isInstalled: Boolean = true,
    val isSystem: Boolean = false,
    val flags: Int = 0
) {
    @Ignore
    var icon: Drawable? = null
}