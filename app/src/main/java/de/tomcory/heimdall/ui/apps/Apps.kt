package de.tomcory.heimdall.ui.apps

import android.content.Context
import android.content.pm.ApplicationInfo
import android.graphics.drawable.Drawable
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.google.accompanist.drawablepainter.rememberDrawablePainter
import de.tomcory.heimdall.R
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.navigation.NavHostController
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class, ExperimentalComposeUiApi::class)
@Composable
fun AppInfoList(paddingValues: PaddingValues, apps: List<AppInfo>) {
    LazyColumn(modifier = Modifier.padding(paddingValues)) {
        items(apps) {
            var showAppDetailDialog by remember { mutableStateOf(false) }
            ListItem(
                headlineContent = {
                    Text(text = it.label)
                },
                supportingContent = {
                    Text(text = it.pkg)
                },
                leadingContent = {
                    Image(painter = rememberDrawablePainter(drawable = it.icon), contentDescription = "App icon", modifier = Modifier.size(40.dp))
                },
                modifier = Modifier.clickable { showAppDetailDialog = true }
            )

            if(showAppDetailDialog) {
                Dialog(
                    onDismissRequest = { showAppDetailDialog = false },
                    properties = DialogProperties(usePlatformDefaultWidth = false)
                ) {
                    AppDetailScreen(packageName = it.pkg, onDismissRequest = { showAppDetailDialog = false })
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppsScreen(navController: NavHostController?) {
    val context = LocalContext.current
    var loadingApps by remember { mutableStateOf(true) }

    var apps by remember { mutableStateOf(listOf<AppInfo>()) }

    LaunchedEffect(key1 = null, block = {
        apps = getApps(context)
        loadingApps = false
    })

    Scaffold(
        topBar = {
            AppsTopBar()
        }
    ) {
        AnimatedVisibility(visible = loadingApps, enter = fadeIn(), exit = fadeOut()) {
            Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center, modifier = Modifier.fillMaxSize()) {
                CircularProgressIndicator()
                Text(text = "Loading apps...")
            }
        }

        AnimatedVisibility(visible = !loadingApps, enter = fadeIn(), exit = fadeOut()) {
            AppInfoList(it, apps = apps)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppsTopBar() {
    var searchActive by remember { mutableStateOf(false) }

    Row(horizontalArrangement = Arrangement.Center, modifier = Modifier.fillMaxWidth()) {
        SearchBar(
            placeholder = { Text(text = "Search apps") },
            query = "",
            onQueryChange = {},
            onSearch = {},
            active = searchActive,
            onActiveChange = { searchActive = it },
            leadingIcon = {
                if (searchActive) {
                    IconButton(onClick = { searchActive = false }) {
                        Icon(
                            imageVector = Icons.Outlined.Close,
                            contentDescription = ""
                        )
                    }
                } else {
                    IconButton(onClick = { searchActive = true }) {
                        Icon(
                            imageVector = Icons.Outlined.Search,
                            contentDescription = ""
                        )
                    }
                }
            },
            trailingIcon = {
                IconButton(onClick = { /*TODO*/ }) {
                    Icon(
                        imageVector = Icons.Outlined.Settings,
                        contentDescription = ""
                    )
                }
            },
        ) {}
    }
}

@Preview(showBackground = true)
@Composable
fun AppsScreenPreview() {
    AppsScreen(null)
}

@Composable
fun AppInfoCard(appInfo: AppInfo) {

    var isSelected by remember { mutableStateOf(false) }
    val surfaceColor by animateColorAsState(
        if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.secondary, label = "surfaceColorSelected"
    )
    Row(
        modifier = Modifier
            .height(88.dp)
            .clickable {

            }
            .padding(16.dp, 12.dp, 24.dp, 12.dp)
            .fillMaxWidth()
    ) {
        Image(
            painter = if (appInfo.icon == null) {
                painterResource(id = R.drawable.robot)
            } else {
                rememberDrawablePainter(drawable = appInfo.icon)
            },
            contentDescription = "App Icon",
            modifier = Modifier
                .size(56.dp)
        )

        Spacer(modifier = Modifier.width(16.dp))

        Column(verticalArrangement = Arrangement.Center, modifier = Modifier.fillMaxHeight()) {
            Text(
                text = appInfo.label,
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )

            Text(
                text = appInfo.pkg,
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )

            Text(
                text = "16 Permissions (8 dangerous)",
                color = MaterialTheme.colorScheme.primary,
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

data class AppInfo(val pkg: String, val aid: Int, val label: String, val icon: Drawable?, val flags: Int)

suspend fun getApps(context: Context): List<AppInfo> = withContext(Dispatchers.IO) {
    val pm = context.packageManager
    val apps = pm.getInstalledApplications(0)

    apps.filter { app -> app.flags and ApplicationInfo.FLAG_SYSTEM == 0 }
        .map { app ->
            AppInfo(
                app.packageName,
                app.uid,
                app.loadLabel(pm).toString(),
                app.loadIcon(pm),
                0
            )
        }
        .sortedBy { app -> app.label }
}