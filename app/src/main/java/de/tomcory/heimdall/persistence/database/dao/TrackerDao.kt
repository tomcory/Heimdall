package de.tomcory.heimdall.persistence.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import de.tomcory.heimdall.persistence.database.entity.Tracker

@Dao
interface TrackerDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertTrackers(vararg tracker: Tracker)

    @Query("SELECT * FROM Tracker")
    suspend fun getAll(): List<Tracker>

    @Query("DELETE FROM tracker")
    suspend fun deleteAllTrackers()
}