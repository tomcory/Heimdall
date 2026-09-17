package de.tomcory.heimdall.ui.evaluator

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.google.accompanist.drawablepainter.rememberDrawablePainter
import kotlinx.coroutines.launch
import timber.log.Timber

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppScoreScreen(
    snackbarHostState: SnackbarHostState,
    onDismissRequest: () -> Unit,
    viewModel: ScoreViewModel = hiltViewModel(),
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var dropdownExpanded by remember { mutableStateOf(false) }

    val packageName by viewModel.selectedAppPackageName.collectAsState()
    val label by viewModel.selectedAppPackageLabel.collectAsState()
    val icon by viewModel.selectedAppPackageIcon.collectAsState()
    val latestReport by viewModel.selectedAppLatestReport.collectAsState()

    Timber.d("AppScoreScreen: $packageName, report=${latestReport?.report?.reportId}")

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = MaterialTheme.colorScheme.surface,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainer,
                ),
                title = {
                    ListItem(
                        headlineContent = {
                            Text(
                                text = label,
                                style = MaterialTheme.typography.titleMedium,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        },
                        supportingContent = {
                            Text(
                                text = packageName,
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = de.tomcory.heimdall.ui.theme.MonoFont,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                ),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        },
                        leadingContent = {
                            Image(
                                painter = rememberDrawablePainter(drawable = icon),
                                contentDescription = null,
                                modifier = Modifier.size(36.dp),
                            )
                        },
                        colors = ListItemDefaults.colors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainer,
                        ),
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onDismissRequest) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Outlined.ArrowBack,
                            contentDescription = "Back",
                        )
                    }
                },
                actions = {
                    IconButton(onClick = { dropdownExpanded = true }) {
                        Icon(
                            imageVector = Icons.Filled.MoreVert,
                            contentDescription = "More options",
                        )
                    }
                    DropdownMenu(
                        expanded = dropdownExpanded,
                        onDismissRequest = { dropdownExpanded = false },
                    ) {
                        DropdownMenuItem(
                            text = { Text("Rescan") },
                            onClick = {
                                dropdownExpanded = false
                                scope.launch {
                                    viewModel.scoreSelectedApp()
                                    snackbarHostState.showSnackbar("App re-scanned")
                                }
                            },
                        )
                        DropdownMenuItem(
                            text = { Text("Export") },
                            onClick = {
                                dropdownExpanded = false
                                scope.launch {
                                    viewModel.exportToJson()
                                }
                            },
                        )
                        HorizontalDivider()
                        DropdownMenuItem(
                            text = { Text("Uninstall") },
                            onClick = {
                                dropdownExpanded = false
                                viewModel.uninstallApp(context)
                            },
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                .padding(padding)
                .padding(horizontal = 12.dp),
        ) {
            item {
                Spacer(modifier = Modifier.height(12.dp))
                ScoreCard(report = latestReport)
            }
            items(viewModel.evaluatorModules) { module ->
                Spacer(modifier = Modifier.height(10.dp))
                module.BuildUICard(report = latestReport)
            }
            item { Spacer(modifier = Modifier.height(24.dp)) }
        }
    }
}

@Preview
@Composable
private fun AppScoreScreenPreview() {
    AppScoreScreen(
        snackbarHostState = SnackbarHostState(),
        onDismissRequest = {},
    )
}
