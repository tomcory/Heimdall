package de.tomcory.heimdall.persistence.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import de.tomcory.heimdall.persistence.database.entity.App

@Dao
interface AppDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertApps(vararg app: App)

    @Query("UPDATE App SET isInstalled = 0 WHERE packageName = :packageName")
    suspend fun updateIsInstalled(packageName: String)

    @Query("SELECT * FROM App")
    suspend fun getAll(): List<App>
}