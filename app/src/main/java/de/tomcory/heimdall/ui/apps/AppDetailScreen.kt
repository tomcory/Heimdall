package de.tomcory.heimdall.ui.apps

import android.content.pm.PackageManager
import android.os.Build
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.google.accompanist.drawablepainter.rememberDrawablePainter

@OptIn(ExperimentalMaterial3Api::class, ExperimentalComposeUiApi::class)
@Composable
fun AppDetailScreen(packageName: String, onDismissRequest: () -> Unit) {
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
                title = {ListItem(headlineContent = { Text(text = pkgInfo.applicationInfo.loadLabel(pm).toString()) },
                    supportingContent = { Text(text = pkgInfo.packageName, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    leadingContent = { Image(painter = rememberDrawablePainter(drawable = pkgInfo.applicationInfo.loadIcon(pm)), contentDescription = "App icon", modifier = Modifier.size(40.dp)) })},
                navigationIcon = {
                    IconButton(
                        onClick = onDismissRequest,
                        modifier = Modifier.padding(0.dp, 0.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.ArrowBack,
                            contentDescription = "Close dialog"
                        )
                    }
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