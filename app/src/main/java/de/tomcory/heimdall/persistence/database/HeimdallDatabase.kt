package de.tomcory.heimdall.persistence.database

import android.content.Context
import androidx.room.Database
import androidx.room.Room.databaseBuilder
import androidx.room.RoomDatabase
import de.tomcory.heimdall.persistence.database.dao.AppDao
import de.tomcory.heimdall.persistence.database.dao.AppXPermissionDao
import de.tomcory.heimdall.persistence.database.dao.AppXTrackerDao
import de.tomcory.heimdall.persistence.database.dao.PermissionDao
import de.tomcory.heimdall.persistence.database.dao.RequestDao
import de.tomcory.heimdall.persistence.database.dao.ResponseDao
import de.tomcory.heimdall.persistence.database.dao.SessionDao
import de.tomcory.heimdall.persistence.database.dao.TrackerDao
import de.tomcory.heimdall.persistence.database.entity.App
import de.tomcory.heimdall.persistence.database.entity.AppXPermission
import de.tomcory.heimdall.persistence.database.entity.AppXTracker
import de.tomcory.heimdall.persistence.database.entity.Permission
import de.tomcory.heimdall.persistence.database.entity.Request
import de.tomcory.heimdall.persistence.database.entity.Response
import de.tomcory.heimdall.persistence.database.entity.Session
import de.tomcory.heimdall.persistence.database.entity.Tracker

@Database(
    version = 4,
    entities = [
        App::class,
        AppXPermission::class,
        AppXTracker::class,
        Permission::class,
        Request::class,
        Response::class,
        Session::class,
        Tracker::class],
    exportSchema = false
)
abstract class HeimdallDatabase : RoomDatabase() {
    abstract val appDao: AppDao?
    abstract val appXPermissionDao: AppXPermissionDao?
    abstract val appXTrackerDao: AppXTrackerDao?
    abstract val permissionDao: PermissionDao?
    abstract val requestDao: RequestDao?
    abstract val responseDao: ResponseDao?
    abstract val sessionDao: SessionDao?
    abstract val trackerDao: TrackerDao?

    companion object {
        var instance: HeimdallDatabase? = null
            private set

        @JvmStatic
        fun init(context: Context?): Boolean {
            return if (instance == null) {
                instance = context?.let { databaseBuilder(it, HeimdallDatabase::class.java, "heimdall").fallbackToDestructiveMigration().build() }
                true
            } else {
                false
            }
        }
    }
}