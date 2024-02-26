package de.tomcory.heimdall.ui.evaluator

import android.graphics.drawable.Drawable
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SearchBar
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.ColorMatrix
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.hilt.navigation.compose.hiltViewModel
import com.google.accompanist.drawablepainter.rememberDrawablePainter
import de.tomcory.heimdall.R
import de.tomcory.heimdall.core.database.entity.App
import de.tomcory.heimdall.core.database.entity.AppWithReportsAndSubReports
import de.tomcory.heimdall.core.database.entity.Report
import de.tomcory.heimdall.core.database.entity.ReportWithSubReports
import de.tomcory.heimdall.core.database.entity.SubReport
import kotlinx.coroutines.launch

/**
 * View Composable listing all apps.
 * Works with [ScoreViewModel] for UI State.
 * Default arguments should not be overwritten.
 */
@Composable
fun ScoreScreen(
    viewModel: ScoreViewModel = hiltViewModel()
) {

    val apps by viewModel.apps.collectAsState(initial = emptyList())
    val snackbarHostState = remember { SnackbarHostState() }

    Scaffold(
        snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
        topBar = { ScoreTopBar() }
    ) {
        // show loading animation while viewmodel fetches icons
        AnimatedVisibility(visible = false, enter = fadeIn(), exit = fadeOut()) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
                modifier = Modifier.fillMaxSize()
            ) {
                CircularProgressIndicator()
                Text(text = "Loading apps... size ${apps.size}")
            }
        }
        // when loading done show list
        AnimatedVisibility(visible = true, enter = fadeIn(), exit = fadeOut()) {
            AppInfoList(
                paddingValues = it,
                snackbarHostState = snackbarHostState,
                apps = apps
            )
        }
    }
}

/**
 * Top Bar of [ScoreScreen] with potential filter and search functionality.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScoreTopBar() {
    var searchActive by remember { mutableStateOf(false) }
    val viewModel: ScoreViewModel = hiltViewModel()
    val coroutineScope = rememberCoroutineScope()

    Row(horizontalArrangement = Arrangement.Center, modifier = Modifier.fillMaxWidth()) {
        SearchBar(
            placeholder = { Text(text = "Search apps") },
            query = "",
            onQueryChange = {},
            onSearch = {},
            active = searchActive,
            onActiveChange = { searchActive = it },
            leadingIcon = {
                IconButton(onClick = {
                    coroutineScope.launch {
                        viewModel.scoreAllApps()
                    }
                }) {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_scanner),
                        contentDescription = "Settings icon"
                    )
                }
            },
            trailingIcon = {
                IconButton(onClick = {
                    /* TODO: implement settings */
                }) {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_settings),
                        contentDescription = "Settings icon"
                    )
                }
            },
        ) {}
    }
}

/**
 * Listing [apps] as [AppListItem] with lazy loading.
 */
@Composable
fun AppInfoList(
    paddingValues: PaddingValues,
    snackbarHostState: SnackbarHostState,
    apps: List<AppWithReportsAndSubReports>,
    viewModel: ScoreViewModel = hiltViewModel()) {
    val coroutineScope = rememberCoroutineScope()

    if (apps.isEmpty()) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            Text(
                text = "No apps found in Database. Consider rescanning",
                modifier = Modifier.align(Alignment.Center),
                style = MaterialTheme.typography.labelMedium
            )
        }
    } else {
        LazyColumn(modifier = Modifier.padding(paddingValues)) {
            items(apps) {
                var showAppDetailDialog by remember { mutableStateOf(false) }
                AppListItem(
                    appWithReports = it,
                    modifier = Modifier.clickable {
                        coroutineScope.launch {
                            viewModel.selectApp(it)
                            showAppDetailDialog = true
                        }
                    }
                )

                if (showAppDetailDialog) {
                    Dialog(
                        onDismissRequest = { showAppDetailDialog = false },
                        properties = DialogProperties(usePlatformDefaultWidth = false)
                    ) {
                        AppScoreScreen(
                            snackbarHostState = snackbarHostState,
                            onDismissRequest = { showAppDetailDialog = false })
                    }
                }
            }
        }
    }
}

/**
 * List item for [AppInfoList] representing one app.
 * Contains icon, name and score indicator for that app.
 */
@Composable
fun AppListItem(
    appWithReports: AppWithReportsAndSubReports,
    modifier: Modifier,
    viewModel: ScoreViewModel = hiltViewModel()
) {
    val app = remember {
        appWithReports.app
    }

    var icon: Drawable? by remember {
        mutableStateOf(null)
    }

    LaunchedEffect(key1 = "k1") {
        icon = viewModel.getAppIcon(app.packageName)

        if(appWithReports.reports.isEmpty()) {
            viewModel.scoreApp(app.packageName)
        }
    }


    ListItem(
        // label
        headlineContent = {
            if (!app.isInstalled) {
                StrikethroughText(text = app.label)
            } else {
                Text(text = app.label)
            }

        },
        // packageName
        supportingContent = {
            if(!app.isInstalled) {
                StrikethroughText(text = app.packageName)
            } else {
                Text(text = app.packageName)
            }
        },
        // icon
        leadingContent = @Composable {
            val painter = if (icon == null) {
                painterResource(R.drawable.ic_cancel)
            } else {
                rememberDrawablePainter(drawable = icon)
            }

            val colorFilter = remember {
                if (!app.isInstalled) {
                    ColorFilter.colorMatrix(ColorMatrix().apply {
                        setToSaturation(0f) // setting saturation to 0 will convert image to grayscale
                    })
                } else {
                    null
                }
            }

            Image(painter = painter, contentDescription = "App icon", modifier = Modifier.size(40.dp), colorFilter = colorFilter)
        },
        // score indicator
        trailingContent = {
            val score: Double? = remember { appWithReports.getLatestReport()?.report?.mainScore }
            score?.let {
                SmallScoreIndicator(score = score)
            }

        },
        modifier = modifier
    )
}

@Composable
fun StrikethroughText(text: String, modifier: Modifier = Modifier) {
    val annotatedString = remember {
        buildAnnotatedString {
            withStyle(style = SpanStyle(textDecoration = TextDecoration.LineThrough)) {
                append(text)
            }
        }
    }

    Text(text = annotatedString, modifier = modifier)
}


/**
 * Preview for [ScoreScreen].
 */
@Preview(showBackground = true)
@Composable
fun ScoreScreenPreview() {
    ScoreScreen()
}

/**
 * Preview for [AppListItem]
 */
@Preview
@Composable
fun AppListItemPreview() {
    val app = App("test.package.com", "TestApp", "0.1", 1)
    val reports =
        listOf(ReportWithSubReports(Report(appPackageName = "test.package.com", timestamp = 1234, mainScore = 0.76), listOf<SubReport>()))
    val appWithReports = AppWithReportsAndSubReports(app, reports)
    AppListItem(
        appWithReports,
        Modifier
            .height(60.dp)
            .fillMaxWidth()
    )
}