package de.tomcory.heimdall.persistence.database.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import de.tomcory.heimdall.persistence.database.entity.Request
import kotlinx.coroutines.flow.Flow

@Dao
interface RequestDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(vararg requests: Request)

    @Update
    suspend fun update(vararg requests: Request)

    @Delete
    suspend fun delete(request: Request)

    @Query("Select * FROM Request")
    suspend fun getAll(): List<Request>

    @Query("SELECT * FROM Request LIMIT :limit OFFSET :offset")
    suspend fun getAllPaginated(limit: Int, offset: Int): List<Request>

    @Query("Select * FROM Request")
    fun getAllObservable(): Flow<List<Request>>
}