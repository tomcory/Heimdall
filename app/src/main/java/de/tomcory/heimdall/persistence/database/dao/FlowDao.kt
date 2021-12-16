package de.tomcory.heimdall.persistence.database.dao

import androidx.room.*
import de.tomcory.heimdall.persistence.database.entity.Flow
import io.reactivex.Completable
import io.reactivex.Flowable
import io.reactivex.Single
import java.util.*
import java.util.stream.Collectors

@Dao
abstract class FlowDao {
    // Queries
    @get:Query("SELECT * FROM Flow")
    abstract val all: Flowable<List<Flow?>?>?

    @get:Query("SELECT * FROM Flow")
    abstract val allSync: List<Flow?>?
    @Query("SELECT * FROM Flow WHERE flowId = :flowId")
    abstract operator fun get(flowId: Long): Flowable<Flow?>?
    @Query("SELECT * FROM Flow WHERE flowId = :flowId")
    abstract fun getSync(flowId: Long): Flow?

    /*
     * Queries used by AppPageFragment and AppDetailFragment
     */
    @Query("SELECT count(*) FROM Flow")
    abstract fun getTotalFlowCount(): kotlinx.coroutines.flow.Flow<Long>

    @Query("SELECT sum(totalBytesOut + totalBytesIn) as totalValue FROM Flow")
    abstract fun getTotalTrafficVolume(): kotlinx.coroutines.flow.Flow<Long>

    @Query("SELECT sum(totalBytesOut) as totalValue FROM Flow")
    abstract fun getTotalUploadVolume(): kotlinx.coroutines.flow.Flow<Long>

    @Query("SELECT sum(totalBytesIn) as totalValue FROM Flow")
    abstract fun getTotalDownloadVolume(): kotlinx.coroutines.flow.Flow<Long>

    @Query("SELECT sum(totalBytesOut + totalBytesIn) as totalValue FROM Flow WHERE appPackage = :appPackage")
    abstract fun getTrafficForApp(appPackage: String?): kotlinx.coroutines.flow.Flow<Long>

    @Query("SELECT sum(totalBytesOut) as totalValue FROM Flow WHERE appPackage = :appPackage")
    abstract fun getUploadForApp(appPackage: String?): kotlinx.coroutines.flow.Flow<Long>

    @Query("SELECT sum(totalBytesIn) as totalValue FROM Flow WHERE appPackage = :appPackage")
    abstract fun getDownloadForApp(appPackage: String?): kotlinx.coroutines.flow.Flow<Long>

    // Insert
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    abstract fun insert(flow: Flow?): Single<Long?>?
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    abstract fun insertSync(flow: Flow?): Long
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    abstract fun insert(flows: List<Flow?>?): Single<List<Long?>?>?
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    abstract fun insertSync(flows: List<Flow?>?): List<Long>
    @Transaction
    open fun upsertSync(flow: Flow?) {
        if (insertSync(flow) == -1L) {
            updateSync(flow)
        }
    }

    @Transaction
    open fun upsertSync(flows: MutableList<Flow?>): Int {
        val rowIds = insertSync(flows)
        for (i in rowIds.indices) {
            if (rowIds[i] != -1L) {
                flows[i] = null
            }
        }
        return updateSync(flows.stream().filter { obj: Flow? -> Objects.nonNull(obj) }.collect(Collectors.toList()))
    }

    // Update
    @Update
    abstract fun update(flow: Flow?): Completable?
    @Update
    abstract fun updateSync(flow: Flow?)
    @Update
    abstract fun update(flows: List<Flow?>?): Single<Int?>?
    @Update
    abstract fun updateSync(flows: List<Flow?>?): Int

    // Delete
    @Delete
    abstract fun delete(flow: Flow?): Completable?
    @Delete
    abstract fun deleteSync(flow: Flow?)
}