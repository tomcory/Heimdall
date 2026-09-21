package de.tomcory.heimdall.core.database

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import de.tomcory.heimdall.core.database.dao.AppDao
import de.tomcory.heimdall.core.database.dao.AppXPermissionDao
import de.tomcory.heimdall.core.database.dao.AppXTrackerDao
import de.tomcory.heimdall.core.database.dao.CategoryDao
import de.tomcory.heimdall.core.database.dao.ConnectionDao
import de.tomcory.heimdall.core.database.dao.PermissionDao
import de.tomcory.heimdall.core.database.dao.ReportDao
import de.tomcory.heimdall.core.database.dao.RequestDao
import de.tomcory.heimdall.core.database.dao.ResponseDao
import de.tomcory.heimdall.core.database.dao.SessionDao
import de.tomcory.heimdall.core.database.dao.SessionSummaryDao
import de.tomcory.heimdall.core.database.dao.SubReportDao
import de.tomcory.heimdall.core.database.dao.TrackerDao
import de.tomcory.heimdall.core.database.entity.App
import de.tomcory.heimdall.core.database.entity.AppXPermission
import de.tomcory.heimdall.core.database.entity.AppXTracker
import de.tomcory.heimdall.core.database.entity.Category
import de.tomcory.heimdall.core.database.entity.Connection
import de.tomcory.heimdall.core.database.entity.Permission
import de.tomcory.heimdall.core.database.entity.Report
import de.tomcory.heimdall.core.database.entity.Request
import de.tomcory.heimdall.core.database.entity.Response
import de.tomcory.heimdall.core.database.entity.Session
import de.tomcory.heimdall.core.database.entity.SessionSummary
import de.tomcory.heimdall.core.database.entity.SubReport
import de.tomcory.heimdall.core.database.entity.Tracker
import de.tomcory.heimdall.core.database.entity.TrackerXCategory

@Database(
    version = 7,
    entities = [
        App::class,
        AppXPermission::class,
        AppXTracker::class,
        Category::class,
        Connection::class,
        Permission::class,
        Report::class,
        Request::class,
        Response::class,
        Session::class,
        SessionSummary::class,
        SubReport::class,
        Tracker::class,
        TrackerXCategory::class],
    exportSchema = false
)
@TypeConverters(HeimdallTypeConverters::class)
abstract class HeimdallDatabase : RoomDatabase() {
    abstract fun appDao(): AppDao
    abstract fun appXPermissionDao(): AppXPermissionDao
    abstract fun appXTrackerDao(): AppXTrackerDao
    abstract fun categoryDao(): CategoryDao
    abstract fun connectionDao(): ConnectionDao
    abstract fun permissionDao(): PermissionDao
    abstract fun reportDao(): ReportDao
    abstract fun requestDao(): RequestDao
    abstract fun responseDao(): ResponseDao
    abstract fun sessionDao(): SessionDao
    abstract fun sessionSummaryDao(): SessionSummaryDao
    abstract fun subReportDao(): SubReportDao
    abstract fun trackerDao(): TrackerDao
}
