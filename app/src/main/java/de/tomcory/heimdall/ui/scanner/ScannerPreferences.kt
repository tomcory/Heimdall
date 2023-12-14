package de.tomcory.heimdall.ui.scanner

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import de.tomcory.heimdall.ui.scanner.traffic.TrafficScannerPreferences
import de.tomcory.heimdall.ui.settings.CategoryHeadline
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScannerPreferencesDialog(onDismiss: () -> Unit) {

    val snackbarHostState = remember { SnackbarHostState() }
    val coroutineScope = rememberCoroutineScope()

    // Function to show a snackbar message
    val showSnackbar: (String) -> Unit = { message ->
        // Launch a coroutine to show a snackbar
        coroutineScope.launch {
            snackbarHostState.showSnackbar(message)
        }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(
            usePlatformDefaultWidth = false // Ensures fullscreen width
        )
    ) {
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            topBar = {
                TopAppBar(
                    title = { Text(text = "Scanner configuration") },
                    navigationIcon = {
                        IconButton(
                            onClick = onDismiss,
                            modifier = Modifier.padding(0.dp, 0.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Outlined.ArrowBack,
                                contentDescription = "Close preferences dialog"
                            )
                        }
                    }
                )
            },
            snackbarHost = {
                SnackbarHost(snackbarHostState)
            }
        ) {
            LazyColumn(modifier = Modifier.padding(it)) {
                item {
                    CategoryHeadline(text = "Traffic scanner preferences")
                }

                item {
                    TrafficScannerPreferences(onShowSnackbar = { message ->
                        showSnackbar(message)
                    })
                }
            }
        }
    }
}