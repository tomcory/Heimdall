package de.tomcory.heimdall.ui.settings

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager.ApplicationInfoFlags
import android.os.Build
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.selection.selectable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import com.google.accompanist.drawablepainter.rememberDrawablePainter
import de.tomcory.heimdall.R
import de.tomcory.heimdall.ui.apps.AppInfo
import kotlinx.coroutines.launch
import timber.log.Timber

suspend fun getAllPackages(context: Context): List<AppInfo> {
    val pm = context.packageManager
    val apps = pm.getInstalledApplications(0)

    return apps
        .map { app ->
            AppInfo(
                app.packageName,
                app.loadLabel(pm).toString(),
                app.loadIcon(pm),
                app.flags
            )
        }
        .sortedBy { app -> app.label }
}

fun getAppInfo(packageName: String, context: Context): AppInfo {
    val pm = context.packageManager
    val app = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        pm.getApplicationInfo(packageName, ApplicationInfoFlags.of(0))
    } else {
        pm.getApplicationInfo(packageName, 0)
    }

    return AppInfo(
        app.packageName,
        app.loadLabel(pm).toString(),
        app.loadIcon(pm),
        app.flags
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BlackWhitelistPreference(
    text: String,
    whitelistSource: () -> List<String>,
    blacklistSource: () -> List<String>,
    onSave: suspend (List<String>?, List<String>?) -> Unit
) {
    val coroutineScope = rememberCoroutineScope()

    var openDialog by remember { mutableStateOf(false) }
    var openWhitelistDialog by remember { mutableStateOf(false) }
    var openBlacklistDialog by remember { mutableStateOf(false) }

    val whitelist by remember { mutableStateOf(whitelistSource()) }
    val blacklist by remember { mutableStateOf(blacklistSource()) }

    val mutableWhitelist = remember { mutableStateListOf(*whitelist.toTypedArray()) }
    val mutableBlacklist = remember { mutableStateListOf(*blacklist.toTypedArray()) }


    ListItem(
        headlineContent = { Text(text = text) },
        modifier = Modifier.clickable { openDialog = true }
    )

    if (openDialog) {
        Dialog(
            onDismissRequest = { openDialog = false },
            properties = DialogProperties(usePlatformDefaultWidth = false)
        ) {
            Scaffold(
                modifier = Modifier.fillMaxSize(),
                topBar = {
                    TopAppBar(
                        title = {},
                        navigationIcon = {
                            IconButton(onClick = { openDialog = false }, modifier = Modifier.padding(0.dp, 0.dp)) {
                                Icon(imageVector = Icons.Outlined.Close, contentDescription = "Close dialog")
                            }
                        },
                        actions = {
                            TextButton(onClick = {
                                openDialog = false
                                coroutineScope.launch {
                                    onSave(mutableWhitelist, mutableBlacklist)
                                }
                            }) {
                                Text(text = "Save")
                            }
                        }
                    )
                }
            ) { paddingValues ->
                Surface(modifier = Modifier.padding(paddingValues)) {
                    LazyColumn {

                        item {
                            BlackWhiteListHeadline(
                                text = "Whitelist",
                                onAddButtonClick = { openWhitelistDialog = true }
                            )
                        }

                        if (mutableWhitelist.isEmpty()) {
                            item { BlackWhitelistEmptyItem { openWhitelistDialog = true } }
                        } else {
                            mutableWhitelist.forEach {
                                this.item {
                                    val context = LocalContext.current
                                    SelectedAppListItem(appInfo = getAppInfo(it, context)) { mutableWhitelist.remove(it) }
                                }
                            }
                        }

                        item {
                            Divider()
                        }

                        item {
                            BlackWhiteListHeadline(
                                text = "Blacklist",
                                onAddButtonClick = { openBlacklistDialog = true }
                            )
                        }

                        if (mutableBlacklist.isEmpty()) {
                            item { BlackWhitelistEmptyItem { openBlacklistDialog = true } }
                        } else {
                            mutableBlacklist.forEach {
                                this.item {
                                    val context = LocalContext.current
                                    SelectedAppListItem(appInfo = getAppInfo(it, context)) { mutableWhitelist.remove(it) }
                                }
                            }
                        }
                    }
                }

                if (openWhitelistDialog) {
                    Dialog(
                        onDismissRequest = { openWhitelistDialog = false },
                        properties = DialogProperties(usePlatformDefaultWidth = false)
                    ) {
                        Scaffold(
                            modifier = Modifier.fillMaxSize(),
                            topBar = {
                                TopAppBar(
                                    title = {},
                                    navigationIcon = {
                                        IconButton(onClick = { openWhitelistDialog = false }, modifier = Modifier.padding(0.dp, 0.dp)) {
                                            Icon(imageVector = Icons.Outlined.Close, contentDescription = "Close dialog")
                                        }
                                    },
                                    actions = {
                                        TextButton(onClick = {
                                            openWhitelistDialog = false
                                            mutableWhitelist.forEach { Timber.w(it) }
                                        }) {
                                            Text(text = "Done")
                                        }
                                    }
                                )
                            }
                        ) {
                            val context = LocalContext.current
                            val focusManager = LocalFocusManager.current

                            var allApps by remember { mutableStateOf(listOf<AppInfo>()) }
                            var filteredApps by remember { mutableStateOf(listOf<AppInfo>()) }

                            var rememberFilterSystem by remember { mutableStateOf(true) }
                            var rememberFilterUpdatedSystem by remember { mutableStateOf(false) }
                            var rememberFilterBlacklist by remember { mutableStateOf(false) }
                            var rememberSearchActive by remember { mutableStateOf(false) }
                            var rememberSearchQuery by remember { mutableStateOf("") }
                            var filterFlags by remember { mutableStateOf(128) }

                            LaunchedEffect(key1 = "") {
                                allApps = getAllPackages(context)
                                filteredApps =
                                    allApps
                                        .filter { app -> app.flags and filterFlags == 0 }
                                        .filter { app -> rememberFilterBlacklist || !mutableBlacklist.contains(app.packageName) }
                            }

                            Surface(modifier = Modifier.padding(it)) {

                                LazyColumn {
                                    item {
                                        Row(horizontalArrangement = Arrangement.Center, modifier = Modifier.fillMaxWidth()) {
                                            FilterChip(
                                                selected = rememberFilterSystem,
                                                onClick = {
                                                    rememberFilterSystem = !rememberFilterSystem
                                                    filterFlags = filterFlags xor ApplicationInfo.FLAG_SYSTEM
                                                    Timber.w("FilterFlags: %s", filterFlags)
                                                    filteredApps = allApps
                                                        .filter { app -> app.flags and filterFlags == 0 }
                                                        .filter { app -> rememberFilterBlacklist || !mutableBlacklist.contains(app.packageName) }
                                                },
                                                label = { Text(text = "System") },
                                                leadingIcon = {
                                                    AnimatedVisibility(visible = rememberFilterSystem) {
                                                        Icon(imageVector = Icons.Outlined.Check, contentDescription = "", modifier = Modifier.size(18.dp))
                                                    }
                                                }
                                            )

                                            FilterChip(
                                                selected = rememberFilterUpdatedSystem,
                                                onClick = {
                                                    rememberFilterUpdatedSystem = !rememberFilterUpdatedSystem
                                                    filterFlags = filterFlags xor ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
                                                    Timber.w("FilterFlags: %s", filterFlags)
                                                    filteredApps = allApps.filter { app -> app.flags and filterFlags == 0 }
                                                        .filter { app -> rememberFilterBlacklist || !mutableBlacklist.contains(app.packageName) }
                                                },
                                                label = { Text(text = "Preinstalled") },
                                                leadingIcon = {
                                                    AnimatedVisibility(visible = rememberFilterUpdatedSystem) {
                                                        Icon(imageVector = Icons.Outlined.Check, contentDescription = "", modifier = Modifier.size(18.dp))
                                                    }
                                                },
                                                modifier = Modifier.padding(8.dp, 0.dp)
                                            )

                                            FilterChip(
                                                selected = rememberFilterBlacklist,
                                                onClick = {
                                                    rememberFilterBlacklist = !rememberFilterBlacklist
                                                    filteredApps = allApps
                                                        .filter { app -> app.flags and filterFlags == 0 }
                                                        .filter { app -> rememberFilterBlacklist || !mutableBlacklist.contains(app.packageName) }
                                                },
                                                label = { Text(text = "Blacklisted") },
                                                leadingIcon = {
                                                    AnimatedVisibility(visible = rememberFilterBlacklist) {
                                                        Icon(imageVector = Icons.Outlined.Check, contentDescription = "", modifier = Modifier.size(18.dp))
                                                    }
                                                }
                                            )
                                        }
                                    }

                                    filteredApps.forEach {
                                        item {
                                            SelectableAppItem(
                                                appInfo = it,
                                                selected = mutableWhitelist.contains(it.packageName),
                                                onSelect = { mutableWhitelist.add(it.packageName) },
                                                onDeselect = { mutableWhitelist.remove(it.packageName) })
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun SelectableAppItem(appInfo: AppInfo, selected: Boolean, onSelect: () -> Unit, onDeselect: () -> Unit) {
    var rememberSelected by remember { mutableStateOf(selected) }
    ListItem(
        headlineContent = { Text(appInfo.label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        supportingContent = { Text(appInfo.packageName, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        leadingContent = {
            Box(modifier = Modifier.size(40.dp)) {
                Image(painter = rememberDrawablePainter(drawable = appInfo.icon), contentDescription = "App Icon", modifier = Modifier.size(40.dp))
                AnimatedVisibility(visible = rememberSelected, enter = fadeIn(), exit = fadeOut()) {
                    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.surface.copy(0.8f)) {}
                    Icon(imageVector = Icons.Rounded.Check, contentDescription = "Selected", modifier = Modifier.fillMaxSize(), tint = MaterialTheme.colorScheme.primary)
                }
            }
        },
        modifier = Modifier.selectable(rememberSelected) {
            rememberSelected = !rememberSelected
            if (rememberSelected) {
                Timber.w("Item selected: %s", appInfo.packageName)
                onSelect()
            } else {
                Timber.w("Item deselected: %s", appInfo.packageName)
                onDeselect()
            }
        }
    )
}

@Composable
fun BlackWhitelistEmptyItem(onclick: () -> Unit) {
    ListItem(
        headlineContent = {
            Text(text = "No apps selected")//Button(onClick = onclick) { Text(text = "Add apps") }
        }
    )
}

@Composable
fun BlackWhiteListHeadline(text: String, onAddButtonClick: () -> Unit) {
    ListItem(
        headlineContent = {
            Text(
                text = text,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.primary
            )
        },
        trailingContent = {
            IconButton(onClick = onAddButtonClick) {
                Icon(imageVector = Icons.Outlined.Add, contentDescription = "Info", tint = MaterialTheme.colorScheme.primary)
            }
        }
    )
}

@Composable
fun SelectedAppListItem(appInfo: AppInfo, onDeleteItem: suspend (String) -> Unit) {
    val coroutineScope = rememberCoroutineScope()
    ListItem(
        headlineContent = { Text(appInfo.label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        supportingContent = { Text(appInfo.packageName, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        leadingContent = { Image(painter = rememberDrawablePainter(drawable = appInfo.icon), contentDescription = "App Icon", modifier = Modifier.size(40.dp)) },
        trailingContent = {
            IconButton(onClick = { coroutineScope.launch { onDeleteItem(appInfo.packageName) } }) {
                Icon(imageVector = Icons.Outlined.Delete, contentDescription = "Delete ")
            }
        }
    )
}

@Preview
@Composable
fun BlackWhitelistPreferencePreview() {
    BlackWhitelistPreference(
        text = "Configure blacklist/whitelist",
        whitelistSource = { listOf("com.google.maps", "de.tchibo.coffee", "com.facebook.katana") },
        blacklistSource = { listOf() },
        onSave = { _, _ -> })
}

@Preview
@Composable
fun BlackWhitelistEmptyItemPreview() {
    BlackWhitelistEmptyItem {}
}

@Preview
@Composable
fun BlackWhiteListHeadlinePreview() {
    BlackWhiteListHeadline(text = "Whitelist") {}
}

@Preview
@Composable
fun SelectedAppListItemPreview() {
    val context = LocalContext.current
    val drawable = ContextCompat.getDrawable(context, R.drawable.robot)

    SelectedAppListItem(appInfo = AppInfo("com.example.test", "Example App", drawable!!, 0)) {}
}

@Preview
@Composable
fun SelectableAppItemPreview() {
    val context = LocalContext.current
    val drawable = ContextCompat.getDrawable(context, R.drawable.robot)

    SelectableAppItem(
        appInfo = AppInfo("com.example.test", "Example App", drawable!!, 0),
        selected = true,
        onSelect = {},
        onDeselect = {}
    )
}