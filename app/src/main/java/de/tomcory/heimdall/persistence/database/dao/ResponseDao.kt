package de.tomcory.heimdall.persistence.database.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import de.tomcory.heimdall.persistence.database.entity.Response
import kotlinx.coroutines.flow.Flow

@Dao
interface ResponseDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(vararg responses: Response): List<Long>

    @Update
    suspend fun update(vararg responses: Response)

    @Delete
    suspend fun delete(request: Response)

    @Query("Select * FROM Response")
    suspend fun getAll(): List<Response>

    @Query("SELECT * FROM Response LIMIT :limit OFFSET :offset")
    suspend fun getAllPaginated(limit: Int, offset: Int): List<Response>

    @Query("Select * FROM Response")
    fun getAllObservable(): Flow<List<Response>>
}