package de.tomcory.heimdall.ui.settings

import android.content.Context
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import de.tomcory.heimdall.core.util.FileUtils
import de.tomcory.heimdall.core.vpn.mitm.Authority
import de.tomcory.heimdall.core.vpn.mitm.KeyStoreHelper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import timber.log.Timber
import java.io.File

@Composable
fun MagiskExportPreference(onShowSnackbar: (String) -> Unit) {
    val coroutineScope = rememberCoroutineScope()
    val context = LocalContext.current

    var isGenerating by remember { mutableStateOf(false) }

    val headlineText = "Magisk"
    val supportingText = "Generate Magisk module"

    var filename by remember {
        mutableStateOf("")
    }

    val startForResult = rememberLauncherForActivityResult(contract = ActivityResultContracts.CreateDocument("application/zip")) {
        coroutineScope.launch {
            val success = FileUtils.copyFile(context, File(context.cacheDir, filename), it)
            isGenerating = false

            if (success) {
                Timber.d("Successfully copied Magisk module")
                onShowSnackbar("Magisk module created")
            } else {
                Timber.e("Error copying Magisk module")
                onShowSnackbar("Could not export Magisk module")
            }
        }
    }

    ListItem(
        headlineContent = { Text(headlineText, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        supportingContent = {
            Text(supportingText, maxLines = 1, overflow = TextOverflow.Ellipsis)
        },
        modifier = Modifier.clickable(enabled = !isGenerating) {
            isGenerating = true
            coroutineScope.launch {
                withContext(Dispatchers.IO) {
                    filename = generateMagiskModule(context)
                    if (filename.isEmpty()) {
                        Timber.e("Module creation failed")
                        onShowSnackbar("Could not create Magisk module")
                        isGenerating = false
                    } else {
                        Timber.d("Module creation successful")
                    }
                    startForResult.launch(filename)
                }
            }
        }
    )

    if (isGenerating) {
        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
    }
}

/**
 * Generates a Magisk module based on the default Authority credentials and writes it to the app's internal cache directory.
 */
private suspend fun generateMagiskModule(context: Context): String {
    Timber.d("Generating authority...")
    val authority = Authority.getDefaultInstance(context)
    Timber.d("Loading KeyStore...")
    val keyStore = KeyStoreHelper.initialiseOrLoadKeyStore(authority)
    Timber.d("Building Magisk module...")
    return KeyStoreHelper.createMagiskModuleWithCertificate(context, keyStore, authority) ?: ""
}