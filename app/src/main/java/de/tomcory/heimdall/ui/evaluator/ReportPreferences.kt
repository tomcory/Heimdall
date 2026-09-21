package de.tomcory.heimdall.ui.evaluator

import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.hilt.navigation.compose.hiltViewModel
import de.tomcory.heimdall.ReportRetentionMode
import de.tomcory.heimdall.ui.settings.BooleanPreference
import de.tomcory.heimdall.ui.settings.CategoryHeadline

@Composable
fun ReportPreferences(
    viewModel: ScoreViewModel = hiltViewModel(),
) {
    Column {
        CategoryHeadline(
            text = "Report retention",
            description = "Controls whether re-scanning an app keeps its full score history or only the latest result."
        )

        BooleanPreference(
            text = "Keep only the latest report per app",
            value = viewModel.reportRetentionMode
                .collectAsState(initial = ReportRetentionMode.REPORT_RETENTION_ALL_TIME).value ==
                ReportRetentionMode.REPORT_RETENTION_LATEST_ONLY,
            onValueChange = { value ->
                viewModel.setReportRetentionMode(
                    if (value) ReportRetentionMode.REPORT_RETENTION_LATEST_ONLY
                    else ReportRetentionMode.REPORT_RETENTION_ALL_TIME
                )
            }
        )
    }
}
