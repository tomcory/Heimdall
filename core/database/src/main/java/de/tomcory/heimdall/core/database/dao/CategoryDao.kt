package de.tomcory.heimdall.core.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Transaction
import de.tomcory.heimdall.core.database.entity.Category
import de.tomcory.heimdall.core.database.entity.Tracker
import de.tomcory.heimdall.core.database.entity.TrackerXCategory

@Dao
interface CategoryDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertCategories(vararg categories: Category)

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertCrossRefs(vararg crossRefs: TrackerXCategory)

    /**
     * Convenience for [de.tomcory.heimdall.core.scanner.ExodusUpdater]: persists a tracker's
     * category names and links them, inserting any new [Category] rows as needed.
     */
    @Transaction
    suspend fun setCategoriesForTracker(tracker: Tracker, categoryNames: List<String>) {
        insertCategories(*categoryNames.map { Category(it) }.toTypedArray())
        insertCrossRefs(*categoryNames.map { TrackerXCategory(tracker.id, it) }.toTypedArray())
    }
}
