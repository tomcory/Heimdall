package de.tomcory.heimdall.persistence.database.entity

import androidx.room.ColumnInfo
import androidx.room.Embedded
import androidx.room.Entity
import androidx.room.Junction
import androidx.room.Relation

@Entity(primaryKeys = ["packageName", "id"])
data class AppXTracker(
    @ColumnInfo(index = true)
    val packageName: String,
    @ColumnInfo(index = true, name = "id")
    val trackerId: Int
)

data class AppWithTrackers(
    @Embedded val app: App,
    @Relation(
        parentColumn = "packageName",
        entityColumn = "id",
        associateBy = Junction(AppXTracker::class)
    )
    val trackers: List<Tracker>
)

data class TrackerWithApps(
    @Embedded val tracker: Tracker,
    @Relation(
        parentColumn = "id",
        entityColumn = "packageName",
        associateBy = Junction(AppXTracker::class)
    )
    val apps: List<App>
)