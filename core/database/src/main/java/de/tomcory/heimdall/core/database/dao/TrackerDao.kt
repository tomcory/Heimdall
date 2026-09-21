package de.tomcory.heimdall.core.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import de.tomcory.heimdall.core.database.entity.Tracker

@Dao
interface TrackerDao {
    /**
     * Upserts by [Tracker.id] (the stable Exodus-provided identifier) so a catalogue refresh
     * updates existing rows in place instead of reassigning ids and orphaning [de.tomcory.heimdall.core.database.entity.AppXTracker]
     * associations.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertTrackers(vararg tracker: Tracker)

    @Query("SELECT * FROM Tracker")
    suspend fun getAll(): List<Tracker>

    /**
     * Deletes trackers that are no longer present in the latest catalogue fetch. Their
     * [de.tomcory.heimdall.core.database.entity.AppXTracker] associations cascade-delete via the
     * foreign key, which is correct here: a tracker genuinely removed upstream should take its
     * associations with it.
     */
    @Query("DELETE FROM Tracker WHERE id NOT IN (:idsToKeep)")
    suspend fun deleteTrackersNotIn(idsToKeep: List<Long>)
}
