package de.tomcory.heimdall.ui.traffic

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.outlined.Face
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.rememberVectorPainter
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import de.tomcory.heimdall.persistence.datastore.PreferencesSerializer
import de.tomcory.heimdall.ui.main.preferencesStore
import de.tomcory.heimdall.ui.settings.PreferencesScreen
import de.tomcory.heimdall.ui.theme.HeimdallTheme
import de.tomcory.heimdall.scanner.traffic.components.HeimdallVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.littleshoot.proxy.mitm.Authority
import org.littleshoot.proxy.mitm.CertificateSniffingMitmManager
import proxy.HeimdallHttpProxyServer
import timber.log.Timber
import java.net.InetSocketAddress

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrafficScreen() {
    var openPreferences by remember { mutableStateOf(false) }
    var proxyRunning by remember { mutableStateOf(false) }
    var vpnRunning by remember { mutableStateOf(false) }
    var proxyServer : HeimdallHttpProxyServer? by remember { mutableStateOf(null) }
    var switchingMonitoringState by remember {
        mutableStateOf(false)
    }

    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    val dataStore = LocalContext.current.preferencesStore
    val preferences = dataStore.data.collectAsState(initial = PreferencesSerializer.defaultValue)

    val startForResult = rememberLauncherForActivityResult(contract = ActivityResultContracts.StartActivityForResult()) {
        if(it.resultCode == Activity.RESULT_OK) {
            coroutineScope.launch {
                val useProxy = preferences.value.vpnUseProxy
                if(useProxy) {
                    Timber.d("Starting proxy server...")
                    proxyServer = try {
                        launchProxy(context)
                    } catch (e: Exception) {
                        null
                    }
                    proxyRunning = proxyServer != null
                }

                if(!useProxy || proxyRunning) {
                    Timber.d("Starting VpnService with fresh VPN permission...")
                    if(launchVpn(context, useProxy) != null) {
                        vpnRunning = true
                    }
                }

                switchingMonitoringState = false
            }
        } else {
            Timber.e("VPN permission request returned result code %s", it.resultCode)
        }

        switchingMonitoringState = false
    }

    HeimdallTheme {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text(text = "Heimdall") },
                    actions = {
                        IconButton(onClick = { openPreferences = true }) {
                            Icon(Icons.Filled.Settings, null)
                        }
                    }
                )
            },
            floatingActionButton = {
                ExtendedFloatingActionButton(
                    containerColor = if(!switchingMonitoringState) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.secondaryContainer,
                    contentColor = if(!switchingMonitoringState) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSecondaryContainer,
                    onClick = {
                        if(!switchingMonitoringState) {
                            val useProxy = preferences.value.vpnUseProxy
                            switchingMonitoringState = true
                            coroutineScope.launch {
                                if((!proxyRunning || !useProxy) && !vpnRunning) {
                                    Timber.d("Preparing VpnService...")
                                    val vpnIntent = VpnService.prepare(context)
                                    if (vpnIntent != null) {
                                        // Need to ask for permission
                                        startForResult.launch(vpnIntent)
                                    } else {
                                        // Permission already granted, launch proxy and VPN
                                        coroutineScope.launch {
                                            if(useProxy) {
                                                Timber.d("Starting proxy server...")
                                                proxyServer = try {
                                                    launchProxy(context)
                                                } catch (e: Exception) {
                                                    null
                                                }
                                                proxyRunning = proxyServer != null
                                            }

                                            if(!useProxy || proxyRunning) {
                                                Timber.d("Starting VpnService with existing VPN permission...")
                                                if(launchVpn(context, useProxy) != null) {
                                                    vpnRunning = true
                                                }
                                            }

                                            switchingMonitoringState = false
                                        }
                                    }
                                } else {
                                    coroutineScope.launch {
                                        stopProxyAndVpn(context, proxyServer)
                                        proxyRunning = false
                                        vpnRunning = false
                                        switchingMonitoringState = false
                                    }
                                }
                            }
                        }
                    }) {
                    if(switchingMonitoringState) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(24.dp)
                        )
                    } else {
                        Icon(painter = rememberVectorPainter(image = Icons.Outlined.Face), contentDescription = "Traffic icon")
                    }
                    Spacer(modifier = Modifier.width(16.dp))
                    Text(text = if((proxyRunning || !preferences.value.vpnUseProxy) && vpnRunning) "Stop Monitoring" else "Start Monitoring")
                }
            }
        ) {
            if (openPreferences) {
                PreferencesScreen { openPreferences = false }
            }
            Column(
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(it)
                    .background(MaterialTheme.colorScheme.surface)
            ) {

            }
        }
    }
}

fun launchVpn(context: Context, useProxy: Boolean) : ComponentName? {
    return context.startService(
        Intent(context, HeimdallVpnService::class.java)
            .putExtra(
                HeimdallVpnService.VPN_ACTION,
                if(useProxy) HeimdallVpnService.START_SERVICE_PROXY else HeimdallVpnService.START_SERVICE
            )
    )
}

suspend fun launchProxy(context: Context) : HeimdallHttpProxyServer {
    return withContext(Dispatchers.IO) {
        val newAuth = de.tomcory.heimdall.scanner.traffic.mitm.Authority.getDefaultInstance(context)
        val oldAuth = Authority(newAuth.keyStoreDir, newAuth.alias, newAuth.password, newAuth.issuerCN, newAuth.issuerO, newAuth.issuerOU, newAuth.subjectO, newAuth.subjectOU)
        val proxyServer = HeimdallHttpProxyServer(InetSocketAddress("127.0.0.1", 9090), CertificateSniffingMitmManager(oldAuth), context)
        proxyServer.start()
        proxyServer
    }
}

suspend fun stopProxyAndVpn(context: Context, proxyServer: HeimdallHttpProxyServer?) {
    Timber.d("Stopping VPN service")
    //val stopped = context.stopService(Intent(context, HeimdallVpnService::class.java))
    //Timber.d("$stopped")
    context.startService(Intent(context, HeimdallVpnService::class.java).putExtra(HeimdallVpnService.VPN_ACTION, HeimdallVpnService.STOP_SERVICE))
    withContext(Dispatchers.IO) {
        Timber.d("Stopping proxy")
        proxyServer?.stop()
    }
}

@Preview(showBackground = true)
@Composable
fun TrafficScreenPreview() {
    TrafficScreen()
}