package de.tomcory.heimdall.ui.scanner.traffic

import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.hilt.navigation.compose.hiltViewModel
import de.tomcory.heimdall.core.util.InetAddressUtils
import de.tomcory.heimdall.ui.settings.ActionPreference
import de.tomcory.heimdall.ui.settings.BooleanPreference
import de.tomcory.heimdall.ui.settings.CategoryHeadline
import de.tomcory.heimdall.ui.settings.MagiskExportPreference
import de.tomcory.heimdall.ui.settings.MonitoringScopePreference
import de.tomcory.heimdall.ui.settings.StringPreference

@Composable
fun TrafficScannerPreferences(
    viewModel: TrafficScannerViewModel = hiltViewModel(),
    onShowSnackbar: (String) -> Unit
) {
    Column {
        VpnPreferences(onShowSnackbar = onShowSnackbar)
        MitMPreferences(onShowSnackbar = onShowSnackbar)
    }
}

@Composable
fun VpnPreferences(
    viewModel: TrafficScannerViewModel = hiltViewModel(),
    onShowSnackbar: (String) -> Unit
) {
    Column {

        CategoryHeadline(
            text = "VPN core preferences"
        )

        BooleanPreference(
            text = "Start VPN on boot",
            value = viewModel.preferences.bootVpnService.collectAsState(initial = viewModel.prefInit.bootVpnServiceInitial).value,
            onValueChange = { value -> viewModel.preferences.setBootVpnService(value) }
        )

        MonitoringScopePreference(
            text = "VPN monitoring scope",
            dialogText = "VPN monitoring scope",
            value = viewModel.preferences.vpnMonitoringScope.collectAsState(initial = viewModel.prefInit.vpnMonitoringScopeInitial).value,
            onValueChange = { value -> viewModel.preferences.setVpnMonitoringScope(value) }
        )

        BooleanPreference(
            text = "Persist transport-layer packets",
            value = viewModel.preferences.vpnPersistTransportLayer.collectAsState(initial = viewModel.prefInit.vpnPersistTransportLayerInitial).value,
            onValueChange = { value -> viewModel.preferences.setVpnPersistTransportLayer(value) }
        )

        StringPreference(
            text = "VPN DNS server address",
            dialogText = "VPN DNS server address",
            value = viewModel.preferences.vpnDnsServer.collectAsState(initial = viewModel.prefInit.vpnDnsServerInitial).value,
            valueVerifier = { value -> InetAddressUtils.isValidInetAddressWithPort(value) },
            onValueChange = { value -> viewModel.preferences.setVpnDnsServer(value) }
        )

        StringPreference(
            text = "VPN base address",
            dialogText = "VPN base address",
            value = viewModel.preferences.vpnBaseAddress.collectAsState(initial = viewModel.prefInit.vpnBaseAddressInitial).value,
            valueVerifier = { value -> InetAddressUtils.isValidInetAddressWithPort(value) },
            onValueChange = { value -> viewModel.preferences.setVpnBaseAddress(value) }
        )

        StringPreference(
            text = "VPN capture route",
            dialogText = "VPN capture route",
            value = viewModel.preferences.vpnRoute.collectAsState(initial = viewModel.prefInit.vpnRouteInitial).value,
            valueVerifier = { value -> InetAddressUtils.isValidInetAddressWithPort(value) },
            onValueChange = { value -> viewModel.preferences.setVpnRoute(value) }
        )

        BooleanPreference(
            text = "Use proxy",
            value = viewModel.preferences.vpnUseProxy.collectAsState(initial = viewModel.prefInit.vpnUseProxyInitial).value,
            onValueChange = { value -> viewModel.preferences.setVpnUseProxy(value) }
        )

        StringPreference(
            text = "Proxy address",
            dialogText = "Proxy address",
            value = viewModel.preferences.vpnProxyAddress.collectAsState(initial = viewModel.prefInit.vpnProxyAddressInitial).value,
            valueVerifier = { value -> InetAddressUtils.isValidInetAddressWithPort(value) },
            onValueChange = { value -> viewModel.preferences.setVpnProxyAddress(value) }
        )
    }
}

@Composable
fun MitMPreferences(
    viewModel: TrafficScannerViewModel = hiltViewModel(),
    onShowSnackbar: (String) -> Unit
) {
    Column {

        CategoryHeadline(
            text = "MitM-VPN preferences"
        )

        BooleanPreference(
            text = "Enable MitM-VPN",
            value = viewModel.preferences.mitmEnable.collectAsState(initial = viewModel.prefInit.mitmEnableInitial).value,
            onValueChange = { value ->
                viewModel.preferences.setMitmEnable(value)
            }
        )

        BooleanPreference(
            text = "App-layer passthrough",
            value = viewModel.preferences.mitmAppLayerPassthrough.collectAsState(initial = viewModel.prefInit.mitmAppLayerPassthroughInitial).value,
            onValueChange = { value -> viewModel.preferences.setMitmAppLayerPassthrough(value) }
        )

        MonitoringScopePreference(
            text = "Monitoring scope (apps)",
            dialogText = "Monitoring scope (apps)",
            value = viewModel.preferences.mitmMonitoringScopeApps.collectAsState(initial = viewModel.prefInit.mitmMonitoringScopeAppsInitial).value,
            onValueChange = { value ->
                viewModel.preferences.setMitmMonitoringScopeApps(value)
            }
        )

        MagiskExportPreference(onShowSnackbar = onShowSnackbar)
    }
}

