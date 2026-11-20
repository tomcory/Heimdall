package de.tomcory.heimdall.core.database.dao

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert
import de.tomcory.heimdall.core.database.entity.App
import kotlinx.coroutines.flow.Flow

@Dao
interface AppDao {
    /**
     * Updates an existing row in place. A replace would delete it first, and the delete would cascade to the
     * app's [de.tomcory.heimdall.core.database.entity.AppXPermission] and
     * [de.tomcory.heimdall.core.database.entity.AppXTracker] rows, losing its scan results.
     */
    @Upsert
    suspend fun insertApps(vararg app: App)

    @Query("UPDATE App SET isInstalled = 0 WHERE packageName = :packageName")
    suspend fun updateIsInstalled(packageName: String)

    @Query("UPDATE App SET isInstalled = 0 WHERE packageName IN (:packageNames)")
    suspend fun updateIsInstalled(packageNames: List<String>)

    @Query("SELECT * FROM App")
    suspend fun getAll(): List<App>

    @Query("SELECT * FROM App")
    fun getAllObservable(): Flow<List<App>>

    @Query("SELECT packageName FROM App")
    suspend fun getAllPackageNames(): List<String>

    @Query("SELECT * FROM App WHERE packageName = :packageName")
    suspend fun getAppByPackageName(packageName: String): App?
}
