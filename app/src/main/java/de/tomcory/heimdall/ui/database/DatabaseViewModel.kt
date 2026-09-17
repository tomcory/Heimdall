package de.tomcory.heimdall.ui.database

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.Connection
import de.tomcory.heimdall.core.database.entity.Request
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

enum class DbFilter { ALL, TRACKERS_ONLY, TCP, UDP }

data class AnalyticsData(
    val timelineBuckets: List<Int> = emptyList(),       // connection count per minute, last 30 min
    val topApps: List<Pair<String, Int>> = emptyList(),  // packageName → count, top 5
    val topTrackerHosts: List<Pair<String, Int>> = emptyList(), // host → count, top 5
)

@HiltViewModel
class DatabaseViewModel @Inject constructor(
    private val database: HeimdallDatabase,
) : ViewModel() {

    private val allConnections: StateFlow<List<Connection>> =
        database.connectionDao().getAllObservable()
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    // ── Filter state ───────────────────────────────────────────────────────────

    private val _activeFilter = MutableStateFlow(DbFilter.ALL)
    val activeFilter: StateFlow<DbFilter> = _activeFilter.asStateFlow()

    fun setFilter(filter: DbFilter) {
        _activeFilter.value = if (_activeFilter.value == filter) DbFilter.ALL else filter
    }

    // ── Filtered connections ───────────────────────────────────────────────────

    val filteredConnections: StateFlow<List<Connection>> =
        combine(allConnections, _activeFilter) { conns, filter ->
            when (filter) {
                DbFilter.ALL           -> conns
                DbFilter.TRACKERS_ONLY -> conns.filter { it.isTracker }
                DbFilter.TCP           -> conns.filter { it.protocol.contains("TCP", ignoreCase = true) }
                DbFilter.UDP           -> conns.filter { it.protocol.contains("UDP", ignoreCase = true) }
            }
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    // ── Analytics ──────────────────────────────────────────────────────────────

    val analyticsData: StateFlow<AnalyticsData> = allConnections.map { conns ->
        if (conns.isEmpty()) return@map AnalyticsData()

        // Timeline: last 30 minutes, 1-minute buckets
        val buckets = 30
        val bucketMs = 60_000L
        val windowMs = buckets * bucketMs
        val now = System.currentTimeMillis()
        val timeline = IntArray(buckets)
        conns.forEach { conn ->
            val age = now - conn.initialTimestamp
            if (age in 0 until windowMs) {
                val idx = ((windowMs - age) / bucketMs).toInt().coerceIn(0, buckets - 1)
                timeline[idx]++
            }
        }

        // Top 5 apps by connection count
        val topApps = conns.groupBy { it.initiatorPkg }
            .map { (pkg, list) -> pkg to list.size }
            .sortedByDescending { it.second }
            .take(5)

        // Top 5 tracker hosts
        val topTrackerHosts = conns.filter { it.isTracker && it.remoteHost.isNotEmpty() }
            .groupBy { it.remoteHost }
            .map { (host, list) -> host to list.size }
            .sortedByDescending { it.second }
            .take(5)

        AnalyticsData(timeline.toList(), topApps, topTrackerHosts)
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), AnalyticsData())

    // ── Request expansion ──────────────────────────────────────────────────────

    private val _expandedConnectionId = MutableStateFlow<Int?>(null)

    fun expandConnection(connectionId: Int) {
        _expandedConnectionId.value =
            if (_expandedConnectionId.value == connectionId) null else connectionId
    }

    fun isExpanded(connectionId: Int): Boolean = _expandedConnectionId.value == connectionId

    fun requestsFor(connectionId: Int): Flow<List<Request>> =
        database.requestDao().getForConnectionObservable(connectionId)

    suspend fun responseStatusFor(requestId: Int): Int? =
        database.responseDao().getForRequest(requestId)?.statusCode
}
