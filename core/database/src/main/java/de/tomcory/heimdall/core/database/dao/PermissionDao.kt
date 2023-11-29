package de.tomcory.heimdall.core.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import de.tomcory.heimdall.core.database.entity.Permission

@Dao
interface PermissionDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(vararg permissions: Permission)
}