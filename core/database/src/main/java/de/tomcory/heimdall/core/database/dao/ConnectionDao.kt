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
    suspend fun delete(id: Int): Int

    @Query("UPDATE Connection SET bytesOut = bytesIn + :delta WHERE id = :id")
    suspend fun updateBytesOut(id: Int, delta: Int)

    @Query("UPDATE Connection SET bytesIn = bytesIn + :delta WHERE id = :id")
    suspend fun updateBytesIn(id: Int, delta: Int)

    @Query("SELECT * FROM Connection")
    suspend fun getAll(): List<Connection>
}