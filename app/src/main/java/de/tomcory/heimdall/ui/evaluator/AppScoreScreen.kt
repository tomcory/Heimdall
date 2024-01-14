package de.tomcory.heimdall.ui.evaluator

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconToggleButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.google.accompanist.drawablepainter.rememberDrawablePainter
import kotlinx.coroutines.launch
import timber.log.Timber

/**
 * Fullscreen View Composable responsible for displaying details of a selected app, including
 * score and metric information.
 * It is not advised to override other parameters.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppScoreScreen(
    snackbarHostState: SnackbarHostState,
    onDismissRequest: () -> Unit,
    /**
     * ViewModel for this Composable. Holds the UI State and performance heavy operations.
     * If existing, the same ViewModel instance is assigned throughout recompositions.
     */
    viewModel: ScoreViewModel = hiltViewModel()
) {
    // CoroutineScope for UI animations, like snackbar notification
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    // state of drop down menu
    var dropdownExpanded by remember { mutableStateOf(false) }

    val selectedAppPackageName = viewModel.selectedAppPackageName.collectAsState("")
    val selectedAppLabel = viewModel.selectedAppPackageLabel.collectAsState("")
    val selectedAppIcon = viewModel.selectedAppPackageIcon.collectAsState(null)
    val selectedAppReports = viewModel.selectedAppReports.collectAsState(listOf())
    val selectedAppLatestReport = viewModel.selectedAppLatestReport.collectAsState(null)

    // logging Composable creation
    Timber.d("Showing Details of ${selectedAppPackageName.value} with ${selectedAppReports.value.size} reports, the latest report has id ${selectedAppLatestReport.value?.report?.reportId}")

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        // header bar
        topBar = {
            TopAppBar(
                modifier = Modifier.padding(0.dp, 0.dp, 12.dp, 0.dp),
                title = {
                    ListItem(headlineContent = { Text(text = selectedAppLabel.value) },
                        supportingContent = {
                            Text(
                                text = selectedAppPackageName.value,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        },
                        leadingContent = {
                            Image(
                                painter = rememberDrawablePainter(drawable = selectedAppIcon.value),
                                contentDescription = "App icon",
                                modifier = Modifier.size(40.dp)
                            )
                        })
                },
                navigationIcon = {
                    IconButton(
                        onClick = onDismissRequest,
                        modifier = Modifier.padding(0.dp, 0.dp)
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Outlined.ArrowBack,
                            contentDescription = "Close dialog"
                        )
                    }
                },
                // drop menu and toggle for additional actions
                actions = {
                    IconToggleButton(
                        checked = false,
                        onCheckedChange = { dropdownExpanded = !dropdownExpanded },
                        content = {
                            Icon(
                                imageVector = Icons.Filled.MoreVert,
                                contentDescription = "More AppDetail Options"
                            )
                        })
                    DropdownMenu(
                        expanded = dropdownExpanded,
                        onDismissRequest = { dropdownExpanded = false }
                    ) {
                        DropdownMenuItem(
                            text = { Text("Rescan") },
                            onClick = {
                                // notify user via snackbar notification
                                scope.launch {
                                    viewModel.scoreSelectedApp()
                                    snackbarHostState.showSnackbar("App re-scanned")
                                }
                            }
                        )
                        DropdownMenuItem(
                            text = { Text("Uninstall") },
                            onClick = {
                                viewModel.uninstallApp(context)
                            }
                        )
                        DropdownMenuItem(
                            text = { Text("Export") },
                            onClick = {
                                // notify user
                                scope.launch {
                                    viewModel.exportToJson()
                                    snackbarHostState.showSnackbar("Export printed to debugging log")
                                }
                            }
                        )
                        HorizontalDivider()
                        DropdownMenuItem(
                            text = { Text("Send Feedback") },
                            onClick = {
                                scope.launch {
                                    snackbarHostState.showSnackbar("Sorry, not yet implemented")
                                }
                            }
                        )
                    }
                }
            )
        },
        snackbarHost = {
            SnackbarHost(hostState = snackbarHostState)
        },
    ) { padding ->
        Column(Modifier.padding(padding)) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(8.dp, 0.dp)
            ) {
                item {
                    Spacer(modifier = Modifier.height(8.dp))
                }
                item {
                    // score
                    ScoreCard(report = selectedAppLatestReport.value)
                }
                item {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceEvenly
                    ) {
                        // action buttons
                        FilledTonalButton(
                            onClick = { viewModel.uninstallApp(context) }) {
                            //Row {
                            Icon(Icons.Default.Delete, contentDescription = "Uninstall Icon")
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(text = "Uninstall")
                            // }
                        }
                        FilledTonalButton(
                            onClick = {
                                scope.launch {
                                    viewModel.exportToJson()
                                    snackbarHostState.showSnackbar("Report exported to debugging-log")
                                }
                            }) {
                            Icon(Icons.Default.Share, contentDescription = "Export Icon")
                            Spacer(modifier = Modifier.width(5.dp))
                            Text(text = "Export")
                        }
                    }
                }
                // create item for each module and request their metric detail cards
                items(viewModel.evaluatorModules) { module ->
                    module.BuildUICard(report = selectedAppLatestReport.value)

                    // buffer padding between cards
                    Spacer(modifier = Modifier.height(9.dp))
                }
            }
        }
    }
}

/**
 * Debugging Preview
 */
@Preview
@Composable
fun AppScoreScreenPreview() {
    AppScoreScreen(
        snackbarHostState = SnackbarHostState(),
        onDismissRequest = { }
    )
}