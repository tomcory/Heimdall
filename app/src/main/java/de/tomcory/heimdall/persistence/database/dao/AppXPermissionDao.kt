package de.tomcory.heimdall.persistence.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import de.tomcory.heimdall.persistence.database.entity.AppWithPermissions
import de.tomcory.heimdall.persistence.database.entity.AppXPermission
import de.tomcory.heimdall.persistence.database.entity.PermissionWithApps

@Dao
interface AppXPermissionDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(vararg crossRef: AppXPermission)

    @Transaction
    @Query("SELECT * FROM App WHERE packageName = :packageName")
    suspend fun getAppWithPermissions(packageName: String): AppWithPermissions

    @Transaction
    @Query("SELECT * FROM App")
    suspend fun getAppWithPermissions(): List<AppWithPermissions>

    @Transaction
    @Query("SELECT * FROM Permission WHERE permissionName = :permissionName")
    suspend fun getPermissionWithApps(permissionName: String): PermissionWithApps

    @Transaction
    @Query("SELECT * FROM Permission")
    suspend fun getPermissionsWithApps(): List<PermissionWithApps>
}