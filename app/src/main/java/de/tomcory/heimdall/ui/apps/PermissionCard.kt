package de.tomcory.heimdall.ui.apps

import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import androidx.compose.foundation.layout.*
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import timber.log.Timber

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PermissionCard(pkgInfo: PackageInfo, pm: PackageManager) {

    val permProts = pkgInfo.requestedPermissions.map { perm ->
            try {
                pm.getPermissionInfo(perm, PackageManager.GET_META_DATA).protection
            } catch (e: Exception) {
                Timber.w("Unknown permission: %s", perm)
                PermissionInfo.PROTECTION_NORMAL
            }
        }

    val countDangerous = permProts.count { perm -> perm == PermissionInfo.PROTECTION_DANGEROUS }

    val countSignature = permProts.count { perm -> perm == PermissionInfo.PROTECTION_SIGNATURE }

    val countNormal = permProts.count { perm -> perm == PermissionInfo.PROTECTION_NORMAL }

    ElevatedCard(
        onClick = { /*TODO*/ },
        modifier = Modifier.padding(8.dp, 0.dp).fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(12.dp, 12.dp)
        ) {

            Text(
                text = "Permissions",
                style = MaterialTheme.typography.titleLarge
            )

            Spacer(modifier = Modifier.height(8.dp))

            DonutChart(
                values = listOf(countDangerous.toFloat(), countNormal.toFloat(), countSignature.toFloat()),
                legend = listOf("Dangerous", "Normal", "Signature"),
                size = 200.dp,
                colors = listOf(MaterialTheme.colorScheme.primary, MaterialTheme.colorScheme.secondary, MaterialTheme.colorScheme.tertiary)
            )
        }
    }
}