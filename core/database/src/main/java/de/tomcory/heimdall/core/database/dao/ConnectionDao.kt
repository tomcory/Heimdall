package de.tomcory.heimdall.core.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import de.tomcory.heimdall.core.database.entity.Connection

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
    suspend fun updateBytesOut(id: Long, delta: Int)

    @Query("UPDATE Connection SET bytesIn = bytesIn + :delta WHERE id = :id")
    suspend fun updateBytesIn(id: Long, delta: Int)

    @Query("SELECT * FROM Connection")
    suspend fun getAll(): List<Connection>

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
