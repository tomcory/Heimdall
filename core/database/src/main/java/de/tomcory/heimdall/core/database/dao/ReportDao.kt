package de.tomcory.heimdall.core.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import de.tomcory.heimdall.core.database.entity.AppWithReports
import de.tomcory.heimdall.core.database.entity.AppWithReportsAndSubReports
import de.tomcory.heimdall.core.database.entity.Report
import de.tomcory.heimdall.core.database.entity.SubReport
import kotlinx.coroutines.flow.Flow

/**
 * Data access object for handling [Report]-related database operations.
 * Offers single entity insertion, as well as different fetching queries returning [List] or [Flow] of all Reports or filtering by [Report.reportId] or [Report.appPackageName].
 * Also features [ReportWithSubReport] transaction, combining one Report with corresponding [SubReport]s
 */
@Dao
interface ReportDao {

    /**
     * Inserts a single [Report] into the database and returns the rowId of the entry. Overrides on conflict.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE, entity = Report::class)
    suspend fun insertReport(report: Report): Long

    /**
     * Returns a [List] of all [Report]s ordered by timestamps.
     */
    @Query("SELECT * FROM Report ORDER BY timestamp DESC")
    fun getAll(): List<Report>

    /**
     * Returns a [Flow] of all observable [ReportWithSubReport].
     */
    @Query("SELECT * FROM Report")
    fun getAllObservable(): Flow<List<Report>>

    /**
     * Returns a [Flow] of all observable [AppWithReports].
     */
    @Transaction
    @Query("SELECT * FROM App")
    fun getAllAppsWithReports(): Flow<List<AppWithReports>>

    /**
     * Returns a [Flow] of all observable [AppWithReportsAndSubReports].
     *
     * Note: loads every report and sub-report ever created for every app — unbounded. Prefer
     * [getLatestReportsObservable] for anything that only needs current status per app (e.g. a live
     * dashboard); this is kept for a future full-history view.
     */
    @Transaction
    @Query("SELECT * FROM App")
    fun getAllAppsWithReportsAndSubReports(): Flow<List<AppWithReportsAndSubReports>>

    /**
     * The most recent [Report] per [Report.appPackageName], computed in SQL rather than by loading
     * every report ever created and reducing in Kotlin. Reactive: re-emits whenever the Report
     * table changes.
     */
    @Query("""
        SELECT r.* FROM Report r
        INNER JOIN (
            SELECT appPackageName, MAX(timestamp) AS maxTimestamp
            FROM Report GROUP BY appPackageName
        ) latest
        ON r.appPackageName = latest.appPackageName AND r.timestamp = latest.maxTimestamp
    """)
    fun getLatestReportsObservable(): Flow<List<Report>>

    /**
     * Deletes all reports for [packageName] (used by the "latest only" report-retention mode before
     * inserting a fresh report). [SubReport] rows cascade-delete via their foreign key to `Report`.
     */
    @Query("DELETE FROM Report WHERE appPackageName = :packageName")
    suspend fun deleteAllForPackage(packageName: String)
}
