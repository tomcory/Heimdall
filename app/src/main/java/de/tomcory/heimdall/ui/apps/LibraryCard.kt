package de.tomcory.heimdall.ui.apps

import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import androidx.compose.animation.*
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat.startActivity
import de.tomcory.heimdall.dex.identifyTrackerLibs
import de.tomcory.heimdall.persistence.database.entity.Tracker
import kotlinx.coroutines.delay


suspend fun testSuspend() {
    delay(5000L)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LibraryCard(pkgInfo: PackageInfo, pm: PackageManager) {

    val context = LocalContext.current
    var trackers = listOf<Tracker>()
    var loadingTrackers by remember { mutableStateOf(true) }

    LaunchedEffect(key1 = null, block = {
        //trackers = identifyTrackerLibs(pkgInfo, context)
        trackers = identifyTrackerLibs(pkgInfo, context)

        loadingTrackers = false
    })

    ElevatedCard(
        onClick = { /*TODO*/ },
        modifier = Modifier
            .padding(8.dp, 0.dp)
            .fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(12.dp, 12.dp)
        ) {

            Text(
                text = "Tracker Libraries",
                style = MaterialTheme.typography.titleLarge
            )

            Spacer(modifier = Modifier.height(8.dp))

            AnimatedVisibility(visible = loadingTrackers, enter = fadeIn(), exit = fadeOut()) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }

            AnimatedVisibility(visible = !loadingTrackers, enter = slideInVertically(), exit = slideOutVertically()) {
                Column {
                    if (trackers.isNotEmpty()) {
                        for (tracker in trackers) {
                            ListItem(
                                headlineContent = { Text(text = tracker.name) },
                                supportingContent = { Text(text = tracker.web) },
                                modifier = Modifier.clickable(tracker.web.isNotEmpty()) {
                                    // open the tracker's URL in the browser
                                    val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse(tracker.web))
                                    startActivity(context, browserIntent, null)
                                }
                            )
                        }
                    } else {
                        Text(text = "0 tracker libraries found")
                    }
                }
            }
        }
    }
}