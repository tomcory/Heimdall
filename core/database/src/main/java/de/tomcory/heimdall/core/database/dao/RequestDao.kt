package de.tomcory.heimdall.core.database.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import de.tomcory.heimdall.core.database.entity.Request
import kotlinx.coroutines.flow.Flow

/**
 * [Request] joined with its parent [de.tomcory.heimdall.core.database.entity.Connection]'s
 * [de.tomcory.heimdall.core.database.entity.Connection.isTracker] flag — `Request` itself no
 * longer stores this (see the removed `Request.isTracker` field); the connection is the single
 * source of truth.
 */
data class RequestWithConnectionIsTracker(
    val id: Long,
    val connectionId: Long,
    val timestamp: Long,
    val headers: String,
    val content: String,
    val contentLength: Int,
    val method: String,
    val remoteHost: String,
    val remotePath: String,
    val remoteIp: String,
    val remotePort: Int,
    val localIp: String,
    val localPort: Int,
    val initiatorId: Int,
    val initiatorPkg: String,
    val connectionIsTracker: Boolean
)

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

    @Query("""
        SELECT r.id, r.connectionId, r.timestamp, r.headers, r.content, r.contentLength, r.method,
               r.remoteHost, r.remotePath, r.remoteIp, r.remotePort, r.localIp, r.localPort,
               r.initiatorId, r.initiatorPkg, c.isTracker AS connectionIsTracker
        FROM Request r
        JOIN Connection c ON r.connectionId = c.id
        LIMIT :limit OFFSET :offset
    """)
    suspend fun getAllWithConnectionIsTrackerPaginated(limit: Int, offset: Int): List<RequestWithConnectionIsTracker>

    @Query("Select * FROM Request")
    fun getAllObservable(): Flow<List<Request>>

    @Query("SELECT * FROM Request WHERE connectionId = :connectionId ORDER BY timestamp ASC")
    fun getForConnectionObservable(connectionId: Long): Flow<List<Request>>
}
