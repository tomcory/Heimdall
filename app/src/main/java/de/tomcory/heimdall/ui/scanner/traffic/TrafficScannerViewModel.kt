package de.tomcory.heimdall.ui.scanner.traffic

import android.annotation.SuppressLint
import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.Connection
import de.tomcory.heimdall.core.database.entity.Session
import de.tomcory.heimdall.core.proxy.HeimdallHttpProxyServer
import de.tomcory.heimdall.core.proxy.littleshoot.mitm.CertificateSniffingMitmManager
import de.tomcory.heimdall.core.util.InetAddressUtils
import de.tomcory.heimdall.service.HeimdallVpnService
import de.tomcory.heimdall.ui.scanner.ScannerRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import timber.log.Timber
import java.io.File
import javax.inject.Inject

data class SessionStats(
    val durationMs: Long,
    val connectionCount: Int,
    val uniqueHosts: Int,
    val trackerCount: Int,
)

@HiltViewModel
class TrafficScannerViewModel @Inject constructor(
    @SuppressLint("StaticFieldLeak") @ApplicationContext private val context: Context,
    private val repository: ScannerRepository,
    private val database: HeimdallDatabase,
) : ViewModel() {

    val scanActiveInitial = false
    val scanSetupInitial = false
    val lastUpdatedInitial = 0L

    private var proxyServer: HeimdallHttpProxyServer? = null

    val preferences = repository.preferences
    val prefInit = repository.preferences.initialValues

    // ── Core scan state ────────────────────────────────────────────────────────

    private val _scanActive = MutableStateFlow(scanActiveInitial)
    val scanActive = _scanActive.asStateFlow()

    private val _scanSetup = MutableStateFlow(scanSetupInitial)
    val scanSetup = _scanSetup.asStateFlow()

    val lastUpdated = repository.preferences.vpnLastUpdated

    private val _vpnPermissionRequestEvent = MutableSharedFlow<Unit>()
    val vpnPermissionRequestEvent = _vpnPermissionRequestEvent.asSharedFlow()

    enum class VpnMode { BASE, MITM_VPN, MITM_PROXY }

    private val _vpnMode = MutableStateFlow(VpnMode.BASE)
    val vpnMode = _vpnMode.asStateFlow()

    // ── Session tracking ───────────────────────────────────────────────────────

    private val _currentSessionId = MutableStateFlow<Int?>(null)

    val liveConnections: StateFlow<List<Connection>> = _currentSessionId
        .flatMapLatest { sessionId ->
            if (sessionId != null) database.connectionDao().getForSessionObservable(sessionId)
            else flowOf(emptyList())
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _lastSessionStats = MutableStateFlow<SessionStats?>(null)
    val lastSessionStats: StateFlow<SessionStats?> = _lastSessionStats.asStateFlow()

    // ── Init ───────────────────────────────────────────────────────────────────

    init {
        viewModelScope.launch {
            val useProxy = repository.preferences.vpnUseProxy.first()
            val mitmEnabled = repository.preferences.mitmEnable.first()
            _vpnMode.value = when {
                !useProxy && !mitmEnabled -> VpnMode.BASE
                useProxy && mitmEnabled  -> VpnMode.MITM_PROXY
                !useProxy && mitmEnabled -> VpnMode.MITM_VPN
                else                    -> VpnMode.BASE
            }
            loadLastSessionStats()
        }
    }

    private suspend fun loadLastSessionStats() {
        withContext(Dispatchers.IO) {
            val session = database.sessionDao().getLatestSession() ?: return@withContext
            val connCount  = database.connectionDao().countForSession(session.id)
            val hosts      = database.connectionDao().countUniqueHostsForSession(session.id)
            val trackers   = database.connectionDao().countTrackerConnectionsForSession(session.id)
            val duration   = if (session.endTime > 0) session.endTime - session.startTime
                             else System.currentTimeMillis() - session.startTime
            _lastSessionStats.value = SessionStats(duration, connCount, hosts, trackers)
        }
    }

    // ── Event handlers ─────────────────────────────────────────────────────────

    fun onScan(onShowSnackbar: (String) -> Unit) {
        Timber.d("TrafficScannerViewModel.onScan()")
        viewModelScope.launch(Dispatchers.IO) {
            if (!scanSetup.first()) {
                _scanSetup.emit(true)
                val useProxy = repository.preferences.vpnUseProxy.first()
                if ((!repository.preferences.proxyActive.first() || !useProxy) &&
                    !repository.preferences.vpnActive.first()
                ) {
                    val vpnIntent = VpnService.prepare(context)
                    if (vpnIntent != null) {
                        _vpnPermissionRequestEvent.emit(Unit)
                    } else {
                        startVpnStack(useProxy, onShowSnackbar)
                    }
                } else {
                    stopProxyAndVpn(context, proxyServer)
                    onShowSnackbar("VPN setup failed")
                }
            }
        }
    }

    fun onScanCancel() {
        viewModelScope.launch { stopProxyAndVpn(context, proxyServer) }
    }

    fun onShowDetails() = Unit
    fun onShowHelp() = Unit

    fun onVpnModeChanged(mode: VpnMode) {
        viewModelScope.launch {
            _vpnMode.value = mode
            when (mode) {
                VpnMode.BASE       -> { repository.preferences.setVpnUseProxy(false); repository.preferences.setMitmEnable(false) }
                VpnMode.MITM_VPN   -> { repository.preferences.setVpnUseProxy(false); repository.preferences.setMitmEnable(true) }
                VpnMode.MITM_PROXY -> { repository.preferences.setVpnUseProxy(true);  repository.preferences.setMitmEnable(true) }
            }
        }
    }

    fun onVpnPermissionResult(resultCode: Int, onShowSnackbar: (String) -> Unit) {
        viewModelScope.launch {
            if (resultCode == Activity.RESULT_OK) {
                val useProxy = repository.preferences.vpnUseProxy.first()
                startVpnStack(useProxy, onShowSnackbar)
            } else {
                Timber.e("VPN permission denied: %s", resultCode)
                onShowSnackbar("VPN permission denied")
            }
            _scanSetup.emit(false)
        }
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    private suspend fun startVpnStack(useProxy: Boolean, onShowSnackbar: (String) -> Unit) {
        val doMitm = repository.preferences.mitmEnable.first()
        if (useProxy) {
            proxyServer = try { launchProxy(context) } catch (e: Exception) { null }
            repository.preferences.setProxyActive(proxyServer != null)
        }
        if (!useProxy || repository.preferences.proxyActive.first()) {
            val sessionId = persistSession(System.currentTimeMillis())
            _currentSessionId.value = sessionId
            if (launchVpn(context, useProxy) != null) {
                repository.preferences.setVpnActive(true)
                repository.preferences.setVpnLastUpdated(System.currentTimeMillis())
                _scanActive.emit(true)
                val mitmString = if (doMitm) " with MitM" else ""
                onShowSnackbar("Traffic scanner enabled$mitmString")
            } else {
                onShowSnackbar("VPN setup failed")
            }
        } else {
            onShowSnackbar("Proxy setup failed")
        }
        delay(500)
        _scanSetup.emit(false)
    }

    private fun launchVpn(context: Context, useProxy: Boolean): ComponentName? {
        return context.startService(
            Intent(context, HeimdallVpnService::class.java)
                .putExtra(HeimdallVpnService.VPN_ACTION, HeimdallVpnService.START_SERVICE)
        )
    }

    private suspend fun launchProxy(context: Context): HeimdallHttpProxyServer {
        return withContext(Dispatchers.IO) {
            val oldAuth = de.tomcory.heimdall.core.proxy.littleshoot.mitm.Authority(
                File(context.filesDir, "keystore"),
                repository.preferences.certAlias.first(),
                repository.preferences.certPassword.first().toCharArray(),
                repository.preferences.certIssuerCn.first(),
                repository.preferences.certIssuerO.first(),
                repository.preferences.certIssuerOu.first(),
                repository.preferences.certSubjectO.first(),
                repository.preferences.certSubjectOu.first()
            )
            val server = HeimdallHttpProxyServer(
                InetAddressUtils.stringToInetSocketAddress(repository.preferences.vpnProxyAddress.first()),
                CertificateSniffingMitmManager(oldAuth),
                context,
                database,
            )
            val sessionId = persistSession(System.currentTimeMillis())
            _currentSessionId.value = sessionId
            server.start(sessionId)
            server
        }
    }

    private suspend fun persistSession(startTime: Long): Int {
        val ids = try {
            database.sessionDao().insert(Session(startTime = startTime))
        } catch (e: Exception) {
            Timber.e(e, "Error persisting session")
            emptyList()
        }
        return if (ids.isNotEmpty()) ids.first().toInt() else -1
    }

    private suspend fun stopProxyAndVpn(context: Context, proxyServer: HeimdallHttpProxyServer?) {
        _scanSetup.emit(true)
        context.startService(
            Intent(context, HeimdallVpnService::class.java)
                .putExtra(HeimdallVpnService.VPN_ACTION, HeimdallVpnService.STOP_SERVICE)
        )
        withContext(Dispatchers.IO) { proxyServer?.stop() }

        repository.preferences.setProxyActive(false)
        repository.preferences.setVpnActive(false)
        repository.preferences.setVpnLastUpdated(System.currentTimeMillis())

        // Refresh last session stats now that the session is ending
        loadLastSessionStats()
        _currentSessionId.value = null

        delay(500)
        _scanSetup.emit(false)
        _scanActive.emit(false)
    }
}
