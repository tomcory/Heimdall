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
import de.tomcory.heimdall.core.database.entity.Session
import de.tomcory.heimdall.core.proxy.HeimdallHttpProxyServer
import de.tomcory.heimdall.core.proxy.littleshoot.mitm.CertificateSniffingMitmManager
import de.tomcory.heimdall.core.util.InetAddressUtils
import de.tomcory.heimdall.service.HeimdallVpnService
import de.tomcory.heimdall.ui.scanner.ScannerRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import timber.log.Timber
import java.io.File
import javax.inject.Inject

@HiltViewModel
class TrafficScannerViewModel @Inject constructor(
    @SuppressLint("StaticFieldLeak") @ApplicationContext private val context: Context,
    private val repository: ScannerRepository,
    private val database: HeimdallDatabase
) : ViewModel() {

    val scanActiveInitial = false
    val scanSetupInitial = false
    val lastUpdatedInitial = 0L

    private var proxyServer: HeimdallHttpProxyServer? = null

    val preferences = repository.preferences
    val prefInit = repository.preferences.initialValues

    ///////////////////////////////
    // State variables
    ///////////////////////////////

    private val _scanActive = MutableStateFlow(scanActiveInitial)
    val scanActive = _scanActive.asStateFlow()

    private val _scanSetup = MutableStateFlow(scanSetupInitial)
    val scanSetup = _scanSetup.asStateFlow()

    val lastUpdated = repository.preferences.vpnLastUpdated

    private val _vpnPermissionRequestEvent = MutableSharedFlow<Unit>()
    val vpnPermissionRequestEvent = _vpnPermissionRequestEvent.asSharedFlow()

    ///////////////////////////////
    // Event handlers
    ///////////////////////////////

    fun onScan(onShowSnackbar: (String) -> Unit) {
        Timber.d("TrafficScannerViewModel.onScan()")
        viewModelScope.launch {
            if(!scanSetup.first()) {
                _scanSetup.emit(true)
                val useProxy = repository.preferences.vpnUseProxy.first()
                if((!repository.preferences.proxyActive.first() || !useProxy) && !repository.preferences.vpnActive.first()) {
                    Timber.d("Preparing VpnService...")
                    val vpnIntent = VpnService.prepare(context)
                    if (vpnIntent != null) {
                        // Need to ask for permission
                        _vpnPermissionRequestEvent.emit(Unit)
                    } else {
                        // Permission already granted, launch proxy and VPN
                        if(useProxy) {
                            Timber.d("Starting proxy server...")
                            proxyServer = try {
                                launchProxy(context)
                            } catch (e: Exception) {
                                null
                            }
                            repository.preferences.setProxyActive(proxyServer != null)
                        }

                        if(!useProxy || repository.preferences.proxyActive.first()) {
                            Timber.d("Starting VpnService with existing VPN permission...")
                            if(launchVpn(context, useProxy) != null) {
                                repository.preferences.setVpnActive(true)
                                _scanActive.emit(true)
                            }
                        }

                        _scanSetup.emit(false)
                        onShowSnackbar("Traffic scanner enabled")
                    }
                } else {
                    stopProxyAndVpn(context, proxyServer)
                    onShowSnackbar("VPN setup failed")
                }
            }

        }
    }

    fun onScanCancel() {
        Timber.d("TrafficScannerViewModel.onScanCancel()")
        viewModelScope.launch {
            stopProxyAndVpn(context, proxyServer)
        }
    }

    fun onShowDetails() {
        TODO("Not yet implemented")
    }

    fun onShowHelp() {
        TODO("Not yet implemented")
    }

    fun onVpnPermissionResult(resultCode: Int, onShowSnackbar: (String) -> Unit) {
        Timber.d("TrafficScannerViewModel.onVpnPermissionResult()")
        viewModelScope.launch {
            if(resultCode == Activity.RESULT_OK) {
                val useProxy = repository.preferences.vpnUseProxy.first()
                val doMitm = repository.preferences.mitmEnable.first()
                if(useProxy) {
                    Timber.d("Starting proxy server...")
                    proxyServer = try {
                        launchProxy(context)
                    } catch (e: Exception) {
                        null
                    }
                    repository.preferences.setProxyActive(proxyServer != null)
                }

                if(!useProxy || repository.preferences.proxyActive.first()) {
                    Timber.d("Starting VpnService with fresh VPN permission...")
                    if(launchVpn(context, useProxy) != null) {
                        repository.preferences.setVpnActive(true)
                        _scanActive.emit(true)
                        val mitmString = if(doMitm) " with MitM" else ""
                        onShowSnackbar("Traffic scanner enabled$mitmString")
                    } else {
                        onShowSnackbar("VPN setup failed")
                    }
                } else {
                    onShowSnackbar("Proxy setup failed")
                }

                _scanSetup.emit(false)
            } else {
                Timber.e("VPN permission request returned result code %s", resultCode)
                onShowSnackbar("Error: result code %resultCode")
            }

            _scanSetup.emit(false)
        }
    }

    ///////////////////////////////
    // Private methods
    ///////////////////////////////

    private fun launchVpn(context: Context, useProxy: Boolean) : ComponentName? {
        Timber.d("TrafficScannerViewModel.launchVpn()")
        return context.startService(
            Intent(context, HeimdallVpnService::class.java)
                .putExtra(
                    HeimdallVpnService.VPN_ACTION,
                    HeimdallVpnService.START_SERVICE
                )
        )
    }

    private suspend fun launchProxy(context: Context) : HeimdallHttpProxyServer {
        Timber.d("TrafficScannerViewModel.launchProxy()")
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
            val proxyServer = HeimdallHttpProxyServer(
                InetAddressUtils.stringToInetSocketAddress(repository.preferences.vpnProxyAddress.first()),
                CertificateSniffingMitmManager(oldAuth),
                context,
                database
            )

            val sessionId = persistSession(System.currentTimeMillis())
            proxyServer.start(sessionId)
            proxyServer
        }
    }

    private suspend fun persistSession(startTime: Long): Int {
        val ids = try {
            database.sessionDao().insert(Session(startTime = startTime))
        } catch (e: Exception) {
            Timber.e(e, "Error while persisting session")
            emptyList()
        }
        return if (ids.isNotEmpty()) ids.first().toInt() else -1
    }

    private suspend fun stopProxyAndVpn(context: Context, proxyServer: HeimdallHttpProxyServer?) {
        Timber.d("TrafficScannerViewModel.stopProxyAndVpn()")
        _scanSetup.emit(true)
        context.startService(
            Intent(context, HeimdallVpnService::class.java).putExtra(
                HeimdallVpnService.VPN_ACTION, HeimdallVpnService.STOP_SERVICE))
        withContext(Dispatchers.IO) {
            Timber.d("Stopping proxy")
            proxyServer?.stop()
        }

        repository.preferences.setProxyActive(false)
        repository.preferences.setVpnActive(false)
        _scanSetup.emit(false)
        _scanActive.emit(false)
    }
}