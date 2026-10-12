package de.tomcory.heimdall.core.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import de.tomcory.heimdall.core.database.entity.Connection
import de.tomcory.heimdall.core.database.entity.SecurityProtocol

@Dao
interface ConnectionDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(vararg connections: Connection): List<Long>

    @Update
    suspend fun update(vararg connections: Connection)

    @Query("DELETE FROM Connection WHERE id = :id")
    suspend fun delete(id: Long): Int

    @Query("DELETE FROM Connection WHERE initiatorPkg = :packageName")
    suspend fun deleteForApp(packageName: String): Int

    @Query("UPDATE Connection SET bytesOut = bytesOut + :delta WHERE id = :id")
    suspend fun updateBytesOut(id: Long, delta: Long)

    @Query("UPDATE Connection SET bytesIn = bytesIn + :delta WHERE id = :id")
    suspend fun updateBytesIn(id: Long, delta: Long)

    @Query("UPDATE Connection SET securityProtocol = :securityProtocol, sni = :sni, alpn = :alpn, echOffered = :echOffered WHERE id = :id")
    suspend fun updateSecurity(id: Long, securityProtocol: SecurityProtocol, sni: String?, alpn: String?, echOffered: Boolean)

    @Query("UPDATE Connection SET remoteHost = :remoteHost, isTracker = :isTracker WHERE id = :id")
    suspend fun updateHost(id: Long, remoteHost: String, isTracker: Boolean)

    @Query("UPDATE Connection SET blocked = 1, blockReason = :reason WHERE id = :id")
    suspend fun markBlocked(id: Long, reason: String)

    @Query("UPDATE Connection SET passthroughReason = :reason WHERE id = :id")
    suspend fun updatePassthroughReason(id: Long, reason: String)

    @Query("SELECT COALESCE(MAX(id), 0) FROM Connection")
    suspend fun maxId(): Long

    @Query("SELECT * FROM Connection")
    suspend fun getAll(): List<Connection>

    @Query("SELECT * FROM Connection WHERE id IN (:ids)")
    suspend fun getByIds(ids: List<Long>): List<Connection>

    /**
     * The connections of a session in the order they were opened, page by page.
     *
     * @param sessionId The session, or -1 for all sessions.
     * @param filterApps Whether only the connections of [apps] are returned.
     */
    @Query("""
        SELECT * FROM Connection
        WHERE (:sessionId < 0 OR sessionId = :sessionId)
          AND (:filterApps = 0 OR initiatorPkg IN (:apps))
        ORDER BY id ASC
        LIMIT :limit OFFSET :offset
    """)
    suspend fun getForExport(sessionId: Long, filterApps: Boolean, apps: List<String>, limit: Int, offset: Int): List<Connection>

    @Query("SELECT * FROM Connection ORDER BY initialTimestamp DESC")
    fun getAllObservable(): kotlinx.coroutines.flow.Flow<List<Connection>>

    @Query("SELECT * FROM Connection WHERE sessionId = :sessionId ORDER BY initialTimestamp ASC")
    fun getForSessionObservable(sessionId: Long): kotlinx.coroutines.flow.Flow<List<Connection>>

    @Query("SELECT COUNT(*) FROM Connection WHERE sessionId = :sessionId")
    suspend fun countForSession(sessionId: Long): Int

    @Query("SELECT COUNT(DISTINCT remoteHost) FROM Connection WHERE sessionId = :sessionId")
    suspend fun countUniqueHostsForSession(sessionId: Long): Int

    @Query("SELECT COUNT(*) FROM Connection WHERE sessionId = :sessionId AND isTracker = 1")
    suspend fun countTrackerConnectionsForSession(sessionId: Long): Int

    @Query("SELECT COALESCE(SUM(bytesOut), 0) FROM Connection WHERE sessionId = :sessionId")
    suspend fun sumBytesOutForSession(sessionId: Long): Long

    @Query("SELECT COALESCE(SUM(bytesIn), 0) FROM Connection WHERE sessionId = :sessionId")
    suspend fun sumBytesInForSession(sessionId: Long): Long
}
