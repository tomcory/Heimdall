package de.tomcory.heimdall.core.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import de.tomcory.heimdall.core.database.entity.Report
import de.tomcory.heimdall.core.database.entity.SubReport
import kotlinx.coroutines.flow.Flow

/**
 * Data access object for handling [SubReport]-related database operations.
 * Offers single or multiple entity insertion, as well as different fetching queries returning [List] or [Flow] of all SubReports or filtering by [SubReport.reportId], [SubReport.packageName], and [SubReport.module].
 * Consider [ReportWithSubReport] class for handling a combination of [Report] and SubReports.
 */
@Dao
interface SubReportDao {

    /**
     * Inserts a single [SubReport] into the database and returns the rowId of the entry.
     * Overrides on conflict.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSubReport(subReport: SubReport): Long

    /**
     * Inserts multiple [SubReport]s into the database and returns a [List] with their rowIds.
     * Overrides on conflict.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSubReport(subReport: List<SubReport>): List<Long>

    /**
     * Returns a [List] of all [SubReport]s in ascending order.
     */
    @Query("SELECT * FROM SubReport ORDER BY packageName ASC")
    fun getAll(): List<SubReport>

    /**
     * Returns a [List] of all [SubReport]s with the given [packageName].
     */
    @Query("SELECT * FROM SubReport WHERE packageName = :packageName")
    fun getSubReportsByPackageName(packageName: String): List<SubReport>

    /**
     * Returns a [List] of all [SubReport]s issued by the the given [module].
     */
    @Query("SELECT * FROM SubReport WHERE module = :module")
    fun getSubReportsByModule(module: String): List<SubReport>

    /**
     * Returns a [SubReport] matching the given [packageName] and [moduleName].
     */
    @Query("SELECT * FROM SubReport WHERE packageName = :packageName AND module = :moduleName")
    fun getSubReportsByPackageNameAndModule(packageName: String, moduleName: String): SubReport

    /**
     * Returns a [List] of [SubReport] relating to the given [reportId].
     */
    @Query("SELECT * FROM SubReport WHERE reportId = :reportId")
    fun getSubReportsByReportId(reportId: Long): List<SubReport>

    /**
     * Returns [Flow] of al observable [SubReport]s.
     */
    @Query("Select * FROM SubReport")
    fun getAllObservable(): Flow<List<SubReport>>
}