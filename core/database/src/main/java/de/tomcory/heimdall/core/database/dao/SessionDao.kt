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
    suspend fun updateEndTime(id: Int, endTime: Long): Int

    @Delete
    suspend fun delete(session: Session)

    @Query("Select * FROM Session")
    suspend fun getAll(): List<Session>

    @Query("SELECT * FROM Session LIMIT :limit OFFSET :offset")
    suspend fun getAllPaginated(limit: Int, offset: Int): List<Session>

    @Query("Select * FROM Session")
    fun getAllObservable(): Flow<List<Session>>
}