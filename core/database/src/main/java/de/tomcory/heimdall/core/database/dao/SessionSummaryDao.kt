package de.tomcory.heimdall.core.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import de.tomcory.heimdall.core.database.entity.SessionSummary
import kotlinx.coroutines.flow.Flow

@Dao
interface SessionSummaryDao {
    @Insert
    suspend fun insert(summary: SessionSummary): Long

    @Query("SELECT * FROM SessionSummary ORDER BY sessionStartTime DESC")
    fun getAllObservable(): Flow<List<SessionSummary>>
}
