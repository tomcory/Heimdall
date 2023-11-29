package de.tomcory.heimdall.core.database

import android.content.Context
import androidx.room.Database
import androidx.room.Room.databaseBuilder
import androidx.room.RoomDatabase
import de.tomcory.heimdall.core.database.dao.AppDao
import de.tomcory.heimdall.core.database.dao.AppXPermissionDao
import de.tomcory.heimdall.core.database.dao.AppXTrackerDao
import de.tomcory.heimdall.core.database.dao.ConnectionDao
import de.tomcory.heimdall.core.database.dao.PermissionDao
import de.tomcory.heimdall.core.database.dao.RequestDao
import de.tomcory.heimdall.core.database.dao.ResponseDao
import de.tomcory.heimdall.core.database.dao.SessionDao
import de.tomcory.heimdall.core.database.dao.TrackerDao
import de.tomcory.heimdall.core.database.entity.App
import de.tomcory.heimdall.core.database.entity.AppXPermission
import de.tomcory.heimdall.core.database.entity.AppXTracker
import de.tomcory.heimdall.core.database.entity.Connection
import de.tomcory.heimdall.core.database.entity.Permission
import de.tomcory.heimdall.core.database.entity.Request
import de.tomcory.heimdall.core.database.entity.Response
import de.tomcory.heimdall.core.database.entity.Session
import de.tomcory.heimdall.core.database.entity.Tracker

@Database(
    version = 6,
    entities = [
        App::class,
        AppXPermission::class,
        AppXTracker::class,
        Connection::class,
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
    abstract val connectionDao: ConnectionDao?
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