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
     */
    @Transaction
    @Query("SELECT * FROM App")
    fun getAllAppsWithReportsAndSubReports(): Flow<List<AppWithReportsAndSubReports>>
}