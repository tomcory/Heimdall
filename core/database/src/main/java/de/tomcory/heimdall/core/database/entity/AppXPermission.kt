package de.tomcory.heimdall.core.database.entity

import androidx.room.ColumnInfo
import androidx.room.Embedded
import androidx.room.Entity
import androidx.room.Junction
import androidx.room.Relation

@Entity(primaryKeys = ["packageName", "permissionName"])
data class AppXPermission(
    @ColumnInfo(index = true)
    var packageName: String,
    @ColumnInfo(index = true)
    val permissionName: String
)

data class AppWithPermissions(
    @Embedded val app: App,
    @Relation(
        parentColumn = "packageName",
        entityColumn = "permissionName",
        associateBy = Junction(AppXPermission::class)
    )
    val permissions: List<Permission>
)

data class PermissionWithApps(
    @Embedded val permission: Permission,
    @Relation(
        parentColumn = "permissionName",
        entityColumn = "packageName",
        associateBy = Junction(AppXPermission::class)
    )
    val apps: List<App>
)