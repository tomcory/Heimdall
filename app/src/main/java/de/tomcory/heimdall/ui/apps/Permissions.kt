package de.tomcory.heimdall.ui.apps

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.graphics.drawable.Drawable
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import de.tomcory.heimdall.dex.ManifestXMLParser
import net.dongliu.apk.parser.ApkFile
import timber.log.Timber
import java.io.File

data class AppPermissions(
    val app: AppInfo,
    val permissions: List<PermissionInfo>
)

data class PermInfo(
    val packageName: String,
    val name: String,
    val description: String?,
    val protection: Int,
    val icon: Drawable?
)

fun getPermissionInfos(packageName: String, context: Context): List<PermInfo> {
    val pm = context.packageManager

    val pkg = pm.getPackageInfo(packageName, 0)
    val apk = pkg.applicationInfo.publicSourceDir

    // parse the APK file
    val apkFile = ApkFile(File(apk))

    // extract the app's permissions
    return ManifestXMLParser.parser(apkFile.manifestXml).map {
        try {
            val info = pm.getPermissionInfo(it, PackageManager.GET_META_DATA)
            val label = info.loadLabel(pm).toString()
            val description = info.loadDescription(pm).toString()
            val icon = try {
                pm.getDrawable(info.packageName, info.icon, null)
            } catch (e: java.lang.Exception) {
                null
            }

            Timber.w(
                "%s %s %s %s %s %s",
                info.packageName,
                label,
                description,
                info.group,
                info.protection,
                info.icon
            )

            PermInfo(
                info.name,
                label,
                description,
                info.protection,
                icon
            )
        } catch (e: java.lang.Exception) {
            PermInfo(
                it,
                it,
                null,
                0,
                null
            )
        }
    }.sortedBy { it.packageName }
}

@Composable
fun PermissionsScreen(navController: NavHostController, packageName: String?) {
    val context = LocalContext.current
    val perms = getPermissionInfos(packageName ?: "de.tomcory.heimdall", context)
    PermissionInfoList(perms = perms)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PermissionInfoList(perms: List<PermInfo>) {
    Column() {
        TopAppBar(
            title = {
                Text("I'm a TopAppBar")
            },
            navigationIcon = {
                IconButton(onClick = {/* Do Something*/ }) {
                    Icon(Icons.Filled.ArrowBack, null)
                }
            }, actions = {
                IconButton(onClick = {/* Do Something*/ }) {
                    Icon(Icons.Filled.Share, null)
                }
                IconButton(onClick = {/* Do Something*/ }) {
                    Icon(Icons.Filled.Settings, null)
                }
            })

        LazyColumn {


            items(perms) {
                PermissionInfoCard(it)
            }
        }
    }
}

@Composable
fun PermissionInfoCard(info: PermInfo, showAll: Boolean = false) {

    var isSelected by remember { mutableStateOf(false) }

    Column(verticalArrangement = Arrangement.Center, modifier = Modifier
        .wrapContentHeight()
        .clickable { isSelected = !isSelected }
        .padding(16.dp, 12.dp, 24.dp, 12.dp)
        .fillMaxWidth()) {
        
        Row {
            if(info.protection == 1) {
                Icon(imageVector = Icons.Outlined.Warning, contentDescription = "", tint = MaterialTheme.colorScheme.error)

                Spacer(modifier = Modifier.width(8.dp))
            }

            Text(
                text = info.packageName.replace("android.permission.", ""),
                style = MaterialTheme.typography.bodyLarge,
                softWrap = true
            )
        }
        
        

        if(isSelected || showAll) {
            Text(
                text = if (info.description.isNullOrEmpty() || info.description == "null") info.name else info.description,
                color = MaterialTheme.colorScheme.primary,
                style = MaterialTheme.typography.bodyMedium,
                softWrap = true
            )
        }

    }
}

@Preview
@Composable
fun PermissionInfoCardPreview() {
    PermissionInfoCard(
        info = PermInfo(
            "com.example.permission",
            "Example Permission",
            "Example Group",
            1,
            null
        )
    )
}