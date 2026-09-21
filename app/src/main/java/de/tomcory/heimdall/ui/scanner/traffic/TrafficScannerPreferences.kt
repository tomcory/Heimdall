package de.tomcory.heimdall.ui.scanner.traffic

import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.hilt.navigation.compose.hiltViewModel
import de.tomcory.heimdall.TrafficRetentionUnit
import de.tomcory.heimdall.core.util.InetAddressUtils
import de.tomcory.heimdall.ui.settings.ActionPreference
import de.tomcory.heimdall.ui.settings.BooleanPreference
import de.tomcory.heimdall.ui.settings.CategoryHeadline
import de.tomcory.heimdall.ui.settings.CACertExportPreference
import de.tomcory.heimdall.ui.settings.IntPreference
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
        TrafficRetentionPreferences(onShowSnackbar = onShowSnackbar)
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

        CACertExportPreference(onShowSnackbar = onShowSnackbar)
    }
}

@Composable
fun TrafficRetentionPreferences(
    viewModel: TrafficScannerViewModel = hiltViewModel(),
    onShowSnackbar: (String) -> Unit
) {
    Column {

        CategoryHeadline(
            text = "Traffic retention",
            description = "Older captured traffic is rolled up into a summary and removed once it falls outside this window."
        )

        val retentionEnabled = viewModel.preferences.trafficRetentionEnabled
            .collectAsState(initial = viewModel.prefInit.trafficRetentionEnabledInitial).value

        BooleanPreference(
            text = "Limit captured traffic history",
            value = retentionEnabled,
            onValueChange = { value -> viewModel.preferences.setTrafficRetentionEnabled(value) }
        )

        if (retentionEnabled) {
            val unit = viewModel.preferences.trafficRetentionUnit
                .collectAsState(initial = viewModel.prefInit.trafficRetentionUnitInitial).value

            BooleanPreference(
                text = "Limit by number of sessions instead of age",
                value = unit == TrafficRetentionUnit.TRAFFIC_RETENTION_SESSION_COUNT,
                onValueChange = { value ->
                    viewModel.preferences.setTrafficRetentionUnit(
                        if (value) TrafficRetentionUnit.TRAFFIC_RETENTION_SESSION_COUNT
                        else TrafficRetentionUnit.TRAFFIC_RETENTION_AGE_DAYS
                    )
                }
            )

            IntPreference(
                text = if (unit == TrafficRetentionUnit.TRAFFIC_RETENTION_SESSION_COUNT)
                    "Sessions to keep" else "Days to keep",
                dialogText = if (unit == TrafficRetentionUnit.TRAFFIC_RETENTION_SESSION_COUNT)
                    "Number of most recent sessions to keep" else "Number of days of traffic to keep",
                value = viewModel.preferences.trafficRetentionValue
                    .collectAsState(initial = viewModel.prefInit.trafficRetentionValueInitial).value,
                valueVerifier = { value -> value > 0 },
                onValueChange = { value -> viewModel.preferences.setTrafficRetentionValue(value) }
            )
        }
    }
}

