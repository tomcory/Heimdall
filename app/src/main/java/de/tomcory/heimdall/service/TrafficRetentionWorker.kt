package de.tomcory.heimdall.service

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.android.EntryPointAccessors
import dagger.hilt.components.SingletonComponent
import de.tomcory.heimdall.TrafficRetentionUnit
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.Session
import de.tomcory.heimdall.core.database.entity.SessionSummary
import de.tomcory.heimdall.core.datastore.PreferencesDataSource
import kotlinx.coroutines.flow.first
import timber.log.Timber
import java.util.concurrent.TimeUnit

/**
 * Periodically prunes old captured traffic ([Session]/[de.tomcory.heimdall.core.database.entity.Connection]/
 * [de.tomcory.heimdall.core.database.entity.Request]/[de.tomcory.heimdall.core.database.entity.Response])
 * per the user-configurable retention policy, rolling each pruned session up into a
 * [SessionSummary] first so historical trend data survives the deletion (PKT-07).
 *
 * Only sessions that have already ended (`endTime >= 0`) are ever pruned — an in-progress session
 * is never touched.
 */
class TrafficRetentionWorker(
    private val context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    @EntryPoint
    @InstallIn(SingletonComponent::class)
    interface TrafficRetentionWorkerEntryPoint {
        fun database(): HeimdallDatabase
        fun preferences(): PreferencesDataSource
    }

    private val entryPoint by lazy {
        EntryPointAccessors.fromApplication(context, TrafficRetentionWorkerEntryPoint::class.java)
    }

    private val database by lazy { entryPoint.database() }
    private val preferences by lazy { entryPoint.preferences() }

    override suspend fun doWork(): Result {
        return try {
            if (!preferences.trafficRetentionEnabled.first()) {
                return Result.success()
            }

            val unit = preferences.trafficRetentionUnit.first()
            val value = preferences.trafficRetentionValue.first()

            val sessionsToPrune = when (unit) {
                TrafficRetentionUnit.TRAFFIC_RETENTION_AGE_DAYS -> {
                    val cutoff = System.currentTimeMillis() - value.toLong() * 24 * 60 * 60 * 1000
                    database.sessionDao().getEndedSessionsStartedBefore(cutoff)
                }
                TrafficRetentionUnit.TRAFFIC_RETENTION_SESSION_COUNT ->
                    database.sessionDao().getEndedSessionsBeyondNewest(value)
                else -> emptyList()
            }

            Timber.d("Pruning ${sessionsToPrune.size} session(s) per traffic retention policy")
            sessionsToPrune.forEach { session -> summariseAndDelete(session) }

            Result.success()
        } catch (e: Exception) {
            Timber.e(e, "Traffic retention worker failed")
            Result.failure()
        }
    }

    private suspend fun summariseAndDelete(session: Session) {
        val connectionDao = database.connectionDao()
        val summary = SessionSummary(
            sessionStartTime = session.startTime,
            sessionEndTime = session.endTime,
            connectionCount = connectionDao.countForSession(session.id),
            uniqueHostCount = connectionDao.countUniqueHostsForSession(session.id),
            trackerConnectionCount = connectionDao.countTrackerConnectionsForSession(session.id),
            bytesOut = connectionDao.sumBytesOutForSession(session.id),
            bytesIn = connectionDao.sumBytesInForSession(session.id)
        )
        database.sessionSummaryDao().insert(summary)
        // cascades away Connection/Request/Response for this session
        database.sessionDao().delete(session.id)
    }

    companion object {
        private const val UNIQUE_WORK_NAME = "traffic-retention"

        /**
         * Registers the periodic retention check. Safe to call on every app launch —
         * [ExistingPeriodicWorkPolicy.KEEP] leaves an already-scheduled job untouched.
         */
        fun enqueuePeriodic(context: Context) {
            val work = PeriodicWorkRequestBuilder<TrafficRetentionWorker>(1, TimeUnit.DAYS).build()
            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork(UNIQUE_WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, work)
        }
    }
}
