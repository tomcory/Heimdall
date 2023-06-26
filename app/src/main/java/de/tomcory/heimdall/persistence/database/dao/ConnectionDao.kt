package de.tomcory.heimdall.persistence.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import de.tomcory.heimdall.persistence.database.entity.Connection

@Dao
interface ConnectionDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(vararg connections: Connection): List<Long>

    @Update
    suspend fun update(vararg connections: Connection)

    @Query("SELECT * FROM Connection")
    suspend fun getAll(): List<Connection>
}