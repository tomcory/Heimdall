package de.tomcory.heimdall.core.database.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import de.tomcory.heimdall.core.database.entity.Session
import kotlinx.coroutines.flow.Flow

@Dao
interface SessionDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(vararg sessions: Session) : List<Long>

    @Update
    suspend fun update(vararg sessions: Session)

    @Query("UPDATE Session SET endTime = :endTime WHERE id = :id")
    suspend fun updateEndTime(id: Long, endTime: Long): Int

    @Delete
    suspend fun delete(session: Session)

    @Query("DELETE FROM Session WHERE id = :id")
    suspend fun delete(id: Long)

    @Query("DELETE FROM Session")
    suspend fun deleteAll()

    @Query("Select * FROM Session")
    suspend fun getAll(): List<Session>

    @Query("SELECT * FROM Session LIMIT :limit OFFSET :offset")
    suspend fun getAllPaginated(limit: Int, offset: Int): List<Session>

    @Query("Select * FROM Session")
    fun getAllObservable(): Flow<List<Session>>

    @Query("SELECT * FROM Session ORDER BY startTime DESC LIMIT 1")
    suspend fun getLatestSession(): Session?

    /** Sessions whose [Session.endTime] has passed (i.e. finished) and started before [cutoff]. */
    @Query("SELECT * FROM Session WHERE endTime >= 0 AND startTime < :cutoff")
    suspend fun getEndedSessionsStartedBefore(cutoff: Long): List<Session>

    /** Finished sessions beyond the newest [keepCount], oldest first. */
    @Query("""
        SELECT * FROM Session WHERE endTime >= 0 ORDER BY startTime DESC
        LIMIT -1 OFFSET :keepCount
    """)
    suspend fun getEndedSessionsBeyondNewest(keepCount: Int): List<Session>
}
