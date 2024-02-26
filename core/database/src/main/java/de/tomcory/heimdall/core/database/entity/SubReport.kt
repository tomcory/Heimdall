package de.tomcory.heimdall.core.database.entity

import androidx.room.ColumnInfo
import androidx.room.Embedded
import androidx.room.Entity
import androidx.room.PrimaryKey
import androidx.room.Relation
import kotlinx.serialization.Serializable

/**
 * Sub-report data class for storing and encapsulating metric results of modules in database.
 * Modules are later handed these for export or creating UI elements.
 *
 * @property reportId Reference to the corresponding main [Report]
 * @property packageName On what package is this reporting
 * @property module Name of the module issuing this sub-report
 * @property score Score the package got in this specific metric; ranges from 0 to 1 (inclusive)
 * @property timestamp Timestamp this sub-report was created, device time in MilliSeconds
 * @property weight Factor for how the score of this report is weighted in computation; default is 1
 * @property additionalDetails The module can store more report details here in a String, e.g. encoded as JSON. This could be information that is later to be displayed in UI.
 * @constructor Offers two constructors, one from plain values, one from an [ModuleResult], copying ist values.
 *
 * @see Report
 */
@Serializable
@Entity(primaryKeys = ["reportId", "module"])
data class SubReport(
    @ColumnInfo(index = true)
    val reportId: Long,
    val packageName: String,
    val module: String,
    val score: Float,
    @ColumnInfo(defaultValue = "CURRENT_TIMESTAMP")
    val timestamp: Long?,
    val weight: Double = 1.0,
    val additionalDetails: String = "",
)