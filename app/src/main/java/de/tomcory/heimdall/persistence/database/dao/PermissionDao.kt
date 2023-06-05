package de.tomcory.heimdall.persistence.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import de.tomcory.heimdall.persistence.database.entity.Permission

@Dao
interface PermissionDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(vararg permissions: Permission)
}