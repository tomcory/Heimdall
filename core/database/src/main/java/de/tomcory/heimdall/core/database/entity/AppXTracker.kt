package de.tomcory.heimdall.core.database.entity

import androidx.room.Embedded
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.Junction
import androidx.room.Relation

@Entity(
    primaryKeys = ["packageName", "trackerId"],
    foreignKeys = [
        ForeignKey(
            entity = App::class,
            parentColumns = ["packageName"],
            childColumns = ["packageName"],
            onDelete = ForeignKey.CASCADE
        ),
        ForeignKey(
            entity = Tracker::class,
            parentColumns = ["id"],
            childColumns = ["trackerId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [Index(value = ["trackerId"])]
)
data class AppXTracker(
    val packageName: String,
    val trackerId: Long
)

data class AppWithTrackers(
    @Embedded val app: App,
    @Relation(
        parentColumn = "packageName",
        entityColumn = "id",
        associateBy = Junction(
            AppXTracker::class,
            parentColumn = "packageName",
            entityColumn = "trackerId"
        )
    )
    val trackers: List<Tracker>
)

data class TrackerWithApps(
    @Embedded val tracker: Tracker,
    @Relation(
        parentColumn = "id",
        entityColumn = "packageName",
        associateBy = Junction(
            AppXTracker::class,
            parentColumn = "trackerId",
            entityColumn = "packageName"
        )
    )
    val apps: List<App>
)
