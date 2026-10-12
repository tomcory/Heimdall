package de.tomcory.heimdall.core.database.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import de.tomcory.heimdall.core.database.entity.Request
import kotlinx.coroutines.flow.Flow

@Dao
interface RequestDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(vararg requests: Request): List<Long>

    @Update
    suspend fun update(vararg requests: Request)

    @Delete
    suspend fun delete(request: Request)

    @Query("Select * FROM Request")
    suspend fun getAll(): List<Request>

    @Query("SELECT COUNT(*) FROM Request r JOIN Connection c ON r.connectionId = c.id WHERE c.sessionId = :sessionId")
    suspend fun countForSession(sessionId: Long): Int

    /**
     * The requests of a session in the order they were recorded, page by page.
     *
     * @param sessionId The session, or -1 for all sessions.
     * @param filterApps Whether only the requests of [apps] are returned.
     */
    @Query("""
        SELECT r.* FROM Request r
        JOIN Connection c ON r.connectionId = c.id
        WHERE (:sessionId < 0 OR c.sessionId = :sessionId)
          AND (:filterApps = 0 OR c.initiatorPkg IN (:apps))
        ORDER BY r.id ASC
        LIMIT :limit OFFSET :offset
    """)
    suspend fun getForExport(sessionId: Long, filterApps: Boolean, apps: List<String>, limit: Int, offset: Int): List<Request>

    @Query("Select * FROM Request")
    fun getAllObservable(): Flow<List<Request>>

    @Query("SELECT * FROM Request WHERE connectionId = :connectionId ORDER BY timestamp ASC")
    fun getForConnectionObservable(connectionId: Long): Flow<List<Request>>
}
