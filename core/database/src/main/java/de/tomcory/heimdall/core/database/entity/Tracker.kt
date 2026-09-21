package de.tomcory.heimdall.core.database.entity

import androidx.room.Entity
import androidx.room.PrimaryKey
import kotlinx.serialization.Serializable

/**
 * [id] is the tracker's stable identifier as assigned by the Exodus Privacy API (not
 * auto-generated locally) so that repeat catalogue refreshes upsert existing rows instead of
 * reassigning ids and orphaning [AppXTracker] associations.
 */
@Serializable
@Entity
data class Tracker(
    @PrimaryKey
    val id: Long,
    val name: String,
    val codeSignature: String,
    val networkSignature: String,
    val creationDate: String,
    val web: String
)
