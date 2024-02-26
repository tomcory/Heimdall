package de.tomcory.heimdall.core.database.entity

import androidx.room.ColumnInfo
import androidx.room.Embedded
import androidx.room.Entity
import androidx.room.PrimaryKey
import androidx.room.Relation
import kotlinx.serialization.Serializable

/**
 * Data class and database entity for storing privacy reports about apps.
 * Primary key is [reportId] is generated automatically on insert and should not be set manually.
 * Expecting [appPackageName] as app name that is reported about and [timestamp] usually as current time in Milliseconds.
 * [mainScore] is the total score of the app and should be between 0 and 1.
 *
 * Offers [toString] for pretty debugging output.
 * For querying together with app info or sub-reports, consider [de.tomcory.heimdall.persistence.database.dao.AppWithReports].or [de.tomcory.heimdall.persistence.database.dao.ReportWithSubReport].
 */
@Serializable
@Entity
data class Report(
    // auto generate id
    @PrimaryKey(autoGenerate = true)
    @ColumnInfo(index = true)
    val reportId: Long = 0,
    val appPackageName: String,

    // generate Timestamp from database if not set
    @ColumnInfo(defaultValue = "CURRENT_TIMESTAMP")
    val timestamp: Long,
    val mainScore: Double
) {
    override fun toString(): String {
        return """
                        Score Evaluation Report of $reportId:
                                package: $appPackageName
                                timestamp: $timestamp
                                Score: $mainScore
                """.trimIndent()
    }
}

/**
 * Data class combining a single embedded [Report] with related [SubReport]s, matched by [Report.reportId].
 * To use this class, define it as return type of a @Transaction @Query.
 */
data class ReportWithSubReports(
    @Embedded
    val report: Report,
    @Relation(
        parentColumn = "reportId",
        entityColumn = "reportId"
    )
    val subReports: List<SubReport>
)

data class AppWithReports(
    @Embedded val app: App,
    @Relation(
        parentColumn = "packageName",
        entityColumn = "appPackageName"
    )
    val reports: List<Report>,
) : Comparable<AppWithReports> {

    fun getLatestReport(): Report? {
        return reports.maxByOrNull { it.timestamp }
    }

    override operator fun compareTo(other: AppWithReports): Int {
        if (this.app.packageName > other.app.packageName) return 1
        if (this.app.packageName < other.app.packageName) return -1
        if ((this.getLatestReport()?.mainScore ?: 0.0) > (other.getLatestReport()?.mainScore
                ?: 0.0)
        ) return 1
        if ((this.getLatestReport()?.mainScore ?: 0.0) < (other.getLatestReport()?.mainScore
                ?: 0.0)
        ) return -1
        return 0
    }
}

data class AppWithReportsAndSubReports(
    @Embedded val app: App,
    @Relation(
        entity = Report::class,
        parentColumn = "packageName",
        entityColumn = "appPackageName"
    )
    val reports: List<ReportWithSubReports>,
) : Comparable<AppWithReports> {

    fun getLatestReport(): ReportWithSubReports? {
        return reports.maxByOrNull { it.report.timestamp }
    }

    override operator fun compareTo(other: AppWithReports): Int {
        if (this.app.packageName > other.app.packageName) return 1
        if (this.app.packageName < other.app.packageName) return -1
        if ((this.getLatestReport()?.report?.mainScore ?: 0.0) > (other.getLatestReport()?.mainScore
                ?: 0.0)
        ) return 1
        if ((this.getLatestReport()?.report?.mainScore ?: 0.0) < (other.getLatestReport()?.mainScore
                ?: 0.0)
        ) return -1
        return 0
    }
}