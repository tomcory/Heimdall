package de.tomcory.heimdall.core.database.entity

import androidx.room.ColumnInfo
import androidx.room.Embedded
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.Junction
import androidx.room.PrimaryKey
import androidx.room.Relation

/**
 * A tracker category as reported by the Exodus Privacy API (e.g. "Analytics", "Advertisement").
 * Replaces the previous delimiter-joined [Tracker.categories] string with a proper relation.
 */
@Entity
data class Category(
    @PrimaryKey
    val name: String
)

@Entity(
    primaryKeys = ["trackerId", "categoryName"],
    foreignKeys = [
        ForeignKey(
            entity = Tracker::class,
            parentColumns = ["id"],
            childColumns = ["trackerId"],
            onDelete = ForeignKey.CASCADE
        ),
        ForeignKey(
            entity = Category::class,
            parentColumns = ["name"],
            childColumns = ["categoryName"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [Index(value = ["categoryName"])]
)
data class TrackerXCategory(
    val trackerId: Long,
    @ColumnInfo(index = false)
    val categoryName: String
)

data class TrackerWithCategories(
    @Embedded val tracker: Tracker,
    @Relation(
        parentColumn = "id",
        entityColumn = "name",
        associateBy = Junction(
            TrackerXCategory::class,
            parentColumn = "trackerId",
            entityColumn = "categoryName"
        )
    )
    val categories: List<Category>
)
