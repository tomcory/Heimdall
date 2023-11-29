package de.tomcory.heimdall.core.database.dao

import androidx.room.*
import de.tomcory.heimdall.core.database.entity.AppXTracker
import de.tomcory.heimdall.core.database.entity.AppWithTrackers
import de.tomcory.heimdall.core.database.entity.TrackerWithApps

@Dao
interface AppXTrackerDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(vararg crossRef: AppXTracker)

    @Transaction
    @Query("SELECT * FROM App WHERE packageName = :packageName")
    suspend fun getAppWithTrackers(packageName: String): AppWithTrackers

    @Transaction
    @Query("SELECT * FROM App")
    suspend fun getAppsWithTrackers(): List<AppWithTrackers>

    @Transaction
    @Query("SELECT * FROM Tracker WHERE id = :trackerId")
    suspend fun getTrackerWithApps(trackerId: Int): TrackerWithApps

    @Transaction
    @Query("SELECT * FROM Tracker")
    suspend fun getTrackersWithApps(): List<TrackerWithApps>
}