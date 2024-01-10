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
import de.tomcory.heimdall.core.database.dao.ReportDao
import de.tomcory.heimdall.core.database.dao.RequestDao
import de.tomcory.heimdall.core.database.dao.ResponseDao
import de.tomcory.heimdall.core.database.dao.SessionDao
import de.tomcory.heimdall.core.database.dao.SubReportDao
import de.tomcory.heimdall.core.database.dao.TrackerDao
import de.tomcory.heimdall.core.database.entity.App
import de.tomcory.heimdall.core.database.entity.AppXPermission
import de.tomcory.heimdall.core.database.entity.AppXTracker
import de.tomcory.heimdall.core.database.entity.Connection
import de.tomcory.heimdall.core.database.entity.Permission
import de.tomcory.heimdall.core.database.entity.Report
import de.tomcory.heimdall.core.database.entity.Request
import de.tomcory.heimdall.core.database.entity.Response
import de.tomcory.heimdall.core.database.entity.Session
import de.tomcory.heimdall.core.database.entity.SubReport
import de.tomcory.heimdall.core.database.entity.Tracker

@Database(
    version = 6,
    entities = [
        App::class,
        AppXPermission::class,
        AppXTracker::class,
        Connection::class,
        Permission::class,
        Report::class,
        Request::class,
        Response::class,
        Session::class,
        SubReport::class,
        Tracker::class],
    exportSchema = false
)
abstract class HeimdallDatabase : RoomDatabase() {
    abstract fun appDao(): AppDao
    abstract fun appXPermissionDao(): AppXPermissionDao
    abstract fun appXTrackerDao(): AppXTrackerDao
    abstract fun connectionDao(): ConnectionDao
    abstract fun permissionDao(): PermissionDao
    abstract fun reportDao(): ReportDao
    abstract fun requestDao(): RequestDao
    abstract fun responseDao(): ResponseDao
    abstract fun sessionDao(): SessionDao
    abstract fun subReportDao(): SubReportDao
    abstract fun trackerDao(): TrackerDao

    @Deprecated("Use function call instead.")
    val appDao = appDao()
    @Deprecated("Use function call instead.")
    val appXPermissionDao = appXPermissionDao()
    @Deprecated("Use function call instead.")
    val appXTrackerDao = appXTrackerDao()
    @Deprecated("Use function call instead.")
    val connectionDao = connectionDao()
    @Deprecated("Use function call instead.")
    val permissionDao = permissionDao()
    @Deprecated("Use function call instead.")
    val requestDao = requestDao()
    @Deprecated("Use function call instead.")
    val responseDao = responseDao()
    @Deprecated("Use function call instead.")
    val sessionDao = sessionDao()
    @Deprecated("Use function call instead.")
    val trackerDao = trackerDao()

    companion object {
        @Deprecated("Use Hilt dependency injection instead.")
        var instance: HeimdallDatabase? = null
            private set

        @JvmStatic
        @Deprecated("Use Hilt dependency injection instead.")
        fun init(context: Context?): Boolean {
            return if (instance == null) {
                instance = context?.let {
                    databaseBuilder(
                        it,
                        HeimdallDatabase::class.java,
                        "heimdall"
                    ).fallbackToDestructiveMigration().build() }
                true
            } else {
                false
            }
        }
    }
}