package de.tomcory.heimdall.ui.apps

import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.os.Build
import android.provider.CalendarContract.Colors
import androidx.annotation.RequiresApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.ScrollableDefaults
import androidx.compose.foundation.gestures.scrollable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.layout.Arrangement.SpaceAround
import androidx.compose.foundation.layout.Arrangement.SpaceBetween
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.google.accompanist.drawablepainter.rememberDrawablePainter
import de.tomcory.heimdall.dex.DexAnalyser
import de.tomcory.heimdall.ui.settings.CategoryHeadline
import net.dongliu.apk.parser.parser.DexParser
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class, ExperimentalComposeUiApi::class)
@Composable
fun AppMetadataScreen(packageName: String) {
    val context = LocalContext.current
    val pm = context.packageManager
    val pkgInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
    } else {
        pm.getPackageInfo(packageName, 4096)
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                modifier = Modifier.padding(0.dp, 0.dp, 12.dp, 0.dp),
                title = {
                    ListItem(
                        headlineContent = { Text(text = pkgInfo.applicationInfo.loadLabel(pm).toString()) },
                        supportingContent = { Text(text = pkgInfo.packageName) }
                    )
                },
                navigationIcon = {
                    IconButton(
                        onClick = {},
                        modifier = Modifier.padding(0.dp, 0.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.ArrowBack,
                            contentDescription = "Close dialog"
                        )
                    }
                },
                actions = {
                    Image(painter = rememberDrawablePainter(drawable = pkgInfo.applicationInfo.loadIcon(pm)), modifier = Modifier.size(40.dp), contentDescription = "App logo")
                }
            )
        }
    ) {
        LazyColumn(
            modifier = Modifier
                .padding(it)
                .fillMaxSize()
        ) {

            item {
                Spacer(modifier = Modifier.height(8.dp))
            }

            item {
                PermissionCard(pkgInfo = pkgInfo, pm = pm)
            }

            item {
                Spacer(modifier = Modifier.height(8.dp))
            }

            item {
                LibraryCard(pkgInfo = pkgInfo, pm = pm)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppMetadata(pkgInfo: PackageInfo, pm: PackageManager) {
    Column(modifier = Modifier.padding(16.dp, 8.dp, 24.dp, 8.dp)) {
        Text(text = "Version: " + pkgInfo.versionName)
        Text(text = "Installed: " + getDateTime(pkgInfo.firstInstallTime))
        Text(text = "Last updated: " + getDateTime(pkgInfo.lastUpdateTime))
    }
}

private fun getDateTime(timestamp: Long): String? {
    try {
        val sdf = SimpleDateFormat("dd.MM.yyyy hh:mm:ss", Locale.getDefault())
        val netDate = Date(timestamp)
        return sdf.format(netDate)
    } catch (e: Exception) {
        return e.toString()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppPermissions(pkgInfo: PackageInfo, pm: PackageManager) {

    val countDangerous =
        pkgInfo.requestedPermissions
            .map { perm -> pm.getPermissionInfo(perm, PackageManager.GET_META_DATA).protection }
            .count { perm -> perm == PermissionInfo.PROTECTION_DANGEROUS }

    val countSignature =
        pkgInfo.requestedPermissions
            .map { perm -> pm.getPermissionInfo(perm, PackageManager.GET_META_DATA).protection }
            .count { perm -> perm == PermissionInfo.PROTECTION_SIGNATURE }

    val countNormal =
        pkgInfo.requestedPermissions
            .map { perm -> pm.getPermissionInfo(perm, PackageManager.GET_META_DATA).protection }
            .count { perm -> perm == PermissionInfo.PROTECTION_NORMAL }

    var showDangerous by remember { mutableStateOf(true) }
    var showSignature by remember { mutableStateOf(true) }
    var showNormal by remember { mutableStateOf(true) }

    var showList by remember { mutableStateOf(false) }
/*
    Column(
        modifier = Modifier
            .padding(16.dp, 0.dp)
            .fillMaxWidth()
    ) {

        Text(
            text = "Permissions",
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.primary
        )
        
        Spacer(modifier = Modifier.height(8.dp))

        Row(
            horizontalArrangement = SpaceBetween,
            modifier = Modifier.fillMaxWidth()
        ) {

            FilterChip(
                label = { Text(text = "Dangerous ($countDangerous)") },
                selected = showDangerous,
                onClick = { showDangerous = !showDangerous },
                enabled = showList
            )

            FilterChip(
                label = { Text(text = "Normal ($countNormal)") },
                selected = showNormal,
                onClick = { showNormal = !showNormal },
                enabled = showList
            )

            FilterChip(
                label = { Text(text = "Signature ($countSignature)") },
                selected = showSignature,
                onClick = { showSignature = !showSignature },
                enabled = showList
            )
        }
    }

    if(!showList) {
        TextButton(onClick = { showList = true }) {
            Text(text = "Show all")
        }
    } else {
        for (perm in pkgInfo.requestedPermissions.withIndex()) {
            val granted = pkgInfo.requestedPermissionsFlags[perm.index] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0
            val permInfo = pm.getPermissionInfo(perm.value, PackageManager.GET_META_DATA)
            val permGroup = permInfo.group
            /*
             * 0 - normal
             * 1 - dangerous
             * 2 - signature
             * 3 - +deprecated+
             * 4 - internal
             */
            val permType = permInfo.protection

            ListItem(
                headlineText = { Text(text = perm.value.replace("android.permission.", "")) },
                supportingText = {
                    Text(
                        text = if (granted) "granted" else "not granted",
                        color = if (granted) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.secondary
                    )
                },
                trailingContent = {
                    when (permType) {
                        PermissionInfo.PROTECTION_DANGEROUS -> {
                            Icon(imageVector = Icons.Outlined.Warning, tint = Color.Red, contentDescription = "")
                        }
                        PermissionInfo.PROTECTION_INTERNAL -> {
                            Icon(imageVector = Icons.Outlined.Info, tint = Color.Blue, contentDescription = "")
                        }
                        PermissionInfo.PROTECTION_NORMAL -> {
                            Icon(imageVector = Icons.Outlined.Info, tint = Color.Green, contentDescription = "")
                        }
                        PermissionInfo.PROTECTION_SIGNATURE -> {
                            Icon(imageVector = Icons.Outlined.Lock, tint = Color.Blue, contentDescription = "")
                        }
                        PermissionInfo.PROTECTION_SIGNATURE_OR_SYSTEM -> {
                            Icon(imageVector = Icons.Outlined.Lock, tint = Color.Magenta, contentDescription = "")
                        }
                    }
                }
            )
        }
    }
*/
}