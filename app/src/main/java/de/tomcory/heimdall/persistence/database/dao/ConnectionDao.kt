package de.tomcory.heimdall.persistence.database.dao

import androidx.room.*
import de.tomcory.heimdall.persistence.database.entity.Connection
import io.reactivex.Completable
import io.reactivex.Flowable
import io.reactivex.Single
import kotlinx.coroutines.flow.Flow

@Dao
abstract class ConnectionDao {
    // Queries
    @get:Query("SELECT * FROM Connection")
    abstract val all: Flowable<List<Connection?>?>?

    @get:Query("SELECT * FROM Connection")
    abstract val allSync: List<Connection?>?

    @Query("SELECT * FROM Connection WHERE appPackage = :appPackage AND hostname = :hostname")
    abstract operator fun get(appPackage: String?, hostname: String?): Flowable<Connection?>?

    @Query("SELECT * FROM Connection WHERE appPackage = :appPackage AND hostname = :hostname")
    abstract fun getSync(appPackage: String?, hostname: String?): Connection?

    @Query("SELECT count(*) FROM Connection")
    abstract fun getTotalConnectionCount(): Flow<Long>

    @Query("SELECT count(*) FROM Connection WHERE appPackage = :appPackage")
    abstract fun getConnectionCountForApp(appPackage: String?): Flow<Long>

    // Insert
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    abstract fun insert(connection: Connection?): Single<Long?>?

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    abstract fun insertSync(connection: Connection?): Long

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    abstract fun insert(connections: List<Connection?>?): Single<List<Long?>?>?

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    abstract fun insertSync(connections: List<Connection?>?): List<Long?>?

    @Transaction
    open fun upsertSync(connection: Connection?) {
        if (insertSync(connection) == -1L) {
            updateSync(connection)
        }
    }

    // Update
    @Update
    abstract fun update(connection: Connection?): Completable?
    @Update
    abstract fun updateSync(connection: Connection?)

    // Delete
    @Delete
    abstract fun delete(connection: Connection?): Completable?
    @Delete
    abstract fun deleteSync(connection: Connection?)
}