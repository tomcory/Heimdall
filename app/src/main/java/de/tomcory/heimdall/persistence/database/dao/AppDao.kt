package de.tomcory.heimdall.persistence.database.dao

import androidx.room.*
import de.tomcory.heimdall.persistence.database.entity.App
import de.tomcory.heimdall.persistence.database.entity.App.AppGrouped
import de.tomcory.heimdall.persistence.database.entity.App.AppWithHosts
import io.reactivex.Completable
import io.reactivex.Flowable
import io.reactivex.Single
import kotlinx.coroutines.flow.Flow

@Dao
abstract class AppDao {
    // Queries
    @get:Query("SELECT * FROM App")
    abstract val all: Flowable<List<App?>?>?

    @get:Query("SELECT * FROM App")
    abstract val allSync: List<App?>?

    @Query("SELECT * FROM App WHERE appPackage = :appPackage LIMIT 1")
    abstract fun get(appPackage: String): Flow<App>

    @Query("SELECT * FROM App WHERE appPackage = :appPackage")
    abstract fun getSync(appPackage: String?): App?

    @Query("SELECT * FROM App")
    @Transaction
    abstract fun appWithHosts(): Flow<AppWithHosts?>?

    @Query("SELECT count(*) FROM App")
    abstract fun getAppCount(): Flow<Long>

    @Query("SELECT App.appPackage, App.appLabel, App.logoUrl, count(*) as value, (1.0 * count(*) / (SELECT count(*) FROM Connection)) as percentage, '' as unit FROM Connection INNER JOIN App ON Connection.appPackage = App.appPackage WHERE App.appPackage != 'unknown' GROUP BY App.appPackage ORDER BY value DESC")
    abstract fun getAppConnectionCount(): Flow<List<AppGrouped>>

    @Query("SELECT App.appPackage, App.appLabel, App.logoUrl, count(*) as value, (1.0 * count(*) / (SELECT count(*) FROM Flow)) as percentage, '' as unit FROM Flow INNER JOIN App ON Flow.appPackage = App.appPackage WHERE App.appPackage != 'unknown' GROUP BY App.appPackage ORDER BY value DESC")
    abstract fun getAppFlowCount(): Flow<List<AppGrouped>>

    @Query("SELECT App.appPackage as appPackage, App.appLabel, App.logoUrl, sum(Flow.totalBytesOut + Flow.totalBytesIn) as value, (1.0 * sum(Flow.totalBytesOut + Flow.totalBytesIn) / (SELECT sum(totalBytesOut + totalBytesIn) as totalValue FROM Flow)) as percentage, 'B' as unit FROM Flow INNER JOIN App ON Flow.appPackage = App.appPackage WHERE App.appPackage != 'unknown' GROUP BY App.appPackage ORDER BY value DESC")
    abstract fun getAppTrafficVolume(): Flow<List<AppGrouped>>

    @Query("SELECT App.appPackage, App.appLabel, App.logoUrl, sum(Flow.totalBytesOut) as value, (1.0 * sum(Flow.totalBytesOut) / (SELECT sum(totalBytesOut) as totalValue FROM Flow)) as percentage, 'B' as unit FROM Flow INNER JOIN App ON Flow.appPackage = App.appPackage WHERE App.appPackage != 'unknown' GROUP BY App.appPackage ORDER BY value DESC")
    abstract fun getAppUploadVolume(): Flow<List<AppGrouped>>

    @Query("SELECT App.appPackage, App.appLabel, App.logoUrl, sum(Flow.totalBytesIn) as value, (1.0 * sum(Flow.totalBytesIn) / (SELECT sum(totalBytesIn) as totalValue FROM Flow)) as percentage, 'B' as unit FROM Flow INNER JOIN App ON Flow.appPackage = App.appPackage WHERE App.appPackage != 'unknown' GROUP BY App.appPackage ORDER BY value DESC")
    abstract fun getAppDownloadVolume(): Flow<List<AppGrouped>>

    // Insert
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    abstract fun insert(app: App?): Single<Long?>?
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    abstract fun insertSync(app: App?): Long
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    abstract fun insert(apps: List<App?>?): Single<List<Long?>?>?
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    abstract fun insertSync(apps: List<App?>?): List<Long?>?
    @Transaction
    open fun upsertSync(app: App?) {
        if (insertSync(app) == -1L) {
            updateSync(app)
        }
    }

    // Update
    @Update
    abstract fun update(app: App?): Completable?
    @Update
    abstract fun updateSync(app: App?)

    // Delete
    @Delete
    abstract fun delete(app: App?): Completable?
    @Delete
    abstract fun deleteSync(app: App?)
}