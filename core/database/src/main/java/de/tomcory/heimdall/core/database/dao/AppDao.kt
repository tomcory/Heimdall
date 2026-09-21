package de.tomcory.heimdall.core.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import de.tomcory.heimdall.core.database.entity.App
import kotlinx.coroutines.flow.Flow

@Dao
interface AppDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
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
