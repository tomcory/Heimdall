package de.tomcory.heimdall.ui.scanner.traffic

import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.hilt.navigation.compose.hiltViewModel
import de.tomcory.heimdall.ui.settings.BooleanPreference
import de.tomcory.heimdall.ui.settings.CategoryHeadline
import de.tomcory.heimdall.ui.settings.MonitoringScopePreference
import de.tomcory.heimdall.ui.settings.StringPreference

@Composable
fun TrafficScannerPreferences(
    viewModel: TrafficScannerViewModel = hiltViewModel(),
    onShowSnackbar: (String) -> Unit
) {
    Column {

        CategoryHeadline(
            text = "VPN preferences"
        )

        MonitoringScopePreference(
            text = "VPN monitoring scope",
            dialogText = "VPN monitoring scope",
            value = viewModel.preferences.vpnMonitoringScope.collectAsState(initial = viewModel.prefInit.vpnMonitoringScopeInitial).value,
            onValueChange = { value ->
                viewModel.preferences.setVpnMonitoringScope(value)
            }
        )

        BooleanPreference(
            text = "Persist transport-layer packets",
            value = viewModel.preferences.vpnPersistTransportLayer.collectAsState(initial = viewModel.prefInit.vpnPersistTransportLayerInitial).value,
            onValueChange = { value ->
                viewModel.preferences.setVpnPersistTransportLayer(value)
            }
        )

        //TODO: assert valid IP address
        StringPreference(
            text = "VPN DNS server address",
            dialogText = "VPN DNS server address",
            value = viewModel.preferences.vpnDnsServer.collectAsState(initial = viewModel.prefInit.vpnDnsServerInitial).value,
            onValueChange = { value ->
                viewModel.preferences.setVpnDnsServer(value)
            }
        )

        //TODO: assert valid IP address
        StringPreference(
            text = "VPN base address",
            dialogText = "VPN base address",
            value = viewModel.preferences.vpnBaseAddress.collectAsState(initial = viewModel.prefInit.vpnBaseAddressInitial).value,
            onValueChange = { value ->
                viewModel.preferences.setVpnBaseAddress(value)
            }
        )

        //TODO: assert valid IP address
        StringPreference(
            text = "VPN capture route",
            dialogText = "VPN capture route",
            value = viewModel.preferences.vpnRoute.collectAsState(initial = viewModel.prefInit.vpnRouteInitial).value,
            onValueChange = { value ->
                viewModel.preferences.setVpnRoute(value)
            }
        )

        BooleanPreference(
            text = "Use proxy",
            value = viewModel.preferences.vpnUseProxy.collectAsState(initial = viewModel.prefInit.vpnUseProxyInitial).value,
            onValueChange = { value ->
                viewModel.preferences.setVpnUseProxy(value)
            }
        )

        //TODO: assert valid IP address
        StringPreference(
            text = "Proxy address",
            dialogText = "Proxy address",
            value = viewModel.preferences.vpnProxyAddress.collectAsState(initial = viewModel.prefInit.vpnProxyAddressInitial).value,
            onValueChange = { value ->
                viewModel.preferences.setVpnProxyAddress(value)
            }
        )

        BooleanPreference(
            text = "Enable MitM",
            value = viewModel.preferences.mitmEnable.collectAsState(initial = viewModel.prefInit.mitmEnableInitial).value,
            onValueChange = { value ->
                viewModel.preferences.setMitmEnable(value)
            }
        )

        BooleanPreference(
            text = "App-layer passthrough",
            value = viewModel.preferences.mitmAppLayerPassthrough.collectAsState(initial = viewModel.prefInit.vpnPersistTransportLayerInitial).value,
            onValueChange = { value ->
                viewModel.preferences.setVpnPersistTransportLayer(value)
            }
        )
    }
}