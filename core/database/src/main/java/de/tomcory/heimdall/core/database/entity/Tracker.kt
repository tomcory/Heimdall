package de.tomcory.heimdall.core.database.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity
data class Tracker(
    @PrimaryKey(autoGenerate = true)
    val id: Int = 0,
    val name: String,
    val categories: String,
    val codeSignature: String,
    val networkSignature: String,
    val creationDate: String,
    val web: String
)