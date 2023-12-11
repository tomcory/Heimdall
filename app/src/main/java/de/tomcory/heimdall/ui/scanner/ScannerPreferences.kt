package de.tomcory.heimdall.ui.scanner

import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.Composable
import de.tomcory.heimdall.ui.scanner.traffic.TrafficScannerPreferences
import de.tomcory.heimdall.ui.settings.CategoryHeadline

@Composable
fun ScannerPreferences() {

    Column {
        CategoryHeadline(text = "Traffic scanner preferences")

        TrafficScannerPreferences(
            onShowSnackbar = {}
        )
    }
}