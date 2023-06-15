package de.tomcory.heimdall.ui.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import de.tomcory.heimdall.MonitoringScopeApps
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun CategoryHeadline(text: String, description: String = "") {
    var openDialog by remember { mutableStateOf(false) }

    ListItem(
        headlineContent = {
            Text(
                text = text,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.primary
            )
        },
        trailingContent = {
            if (description.isNotEmpty()) {
                IconButton(onClick = { openDialog = true }) {
                    Icon(imageVector = Icons.Outlined.Info, contentDescription = "Info", tint = MaterialTheme.colorScheme.primary)
                }
            }
        }
    )

    if (openDialog) {
        AlertDialog(
            onDismissRequest = { openDialog = false },
            title = { Text(text = text) },
            text = { Text(text = description) },
            confirmButton = {
                TextButton(onClick = {
                    openDialog = false
                }) {
                    Text("Got it")
                }
            }
        )
    }
}

@Composable
fun ActionPreference(text: String, onClick: suspend () -> Unit) {
    val coroutineScope = rememberCoroutineScope()
    var showProgress by remember { mutableStateOf(false) }

    ListItem(
        headlineContent = { Text(text, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        trailingContent = {
            if(showProgress) {
                CircularProgressIndicator()
            }
        },
        modifier = Modifier.clickable {
            coroutineScope.launch {
                withContext(Dispatchers.IO) {
                    showProgress = true
                    onClick()
                    showProgress = false
                }
            }
        }
    )
}

@Composable
fun BooleanPreference(text: String, value: Boolean, onValueChange: suspend (Boolean) -> Unit) {
    var rememberedValue by remember { mutableStateOf(value) }
    val coroutineScope = rememberCoroutineScope()

    rememberedValue = value

    ListItem(
        headlineContent = { Text(text, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        trailingContent = {
            Switch(checked = rememberedValue, onCheckedChange = {
                rememberedValue = it
                coroutineScope.launch {
                    withContext(Dispatchers.IO) {
                        onValueChange(it)
                    }
                }
            })
        }
    )
}

@Composable
fun IntPreference(text: String, dialogText: String, value: Int, onValueChange: suspend (Int) -> Unit) {
    var rememberedValue by remember { mutableStateOf(value) }
    var openDialog by remember { mutableStateOf(false) }
    val coroutineScope = rememberCoroutineScope()

    rememberedValue = value

    ListItem(
        headlineContent = { Text(text, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        supportingContent = {
            Text(rememberedValue.toString(), maxLines = 1, overflow = TextOverflow.Ellipsis)
        },
        modifier = Modifier.clickable { openDialog = true }
    )

    if (openDialog) {
        AlertDialog(
            onDismissRequest = { openDialog = false },
            title = { Text(text = dialogText) },
            text = {
                TextField(
                    value = rememberedValue.toString(),
                    keyboardOptions = KeyboardOptions.Default.copy(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    onValueChange = { rememberedValue = it.toInt() })
            },
            confirmButton = {
                TextButton(onClick = {
                    coroutineScope.launch {
                        withContext(Dispatchers.IO) {
                            onValueChange(rememberedValue)
                            openDialog = false
                        }
                    }
                }) {
                    Text("Confirm")
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    openDialog = false
                }) {
                    Text("Dismiss")
                }
            }
        )
    }
}



@Composable
fun StringPreference(text: String, dialogText: String, value: String, onValueChange: suspend (String) -> Unit) {
    var rememberedValue by remember { mutableStateOf(value) }
    var openDialog by remember { mutableStateOf(false) }
    val coroutineScope = rememberCoroutineScope()

    rememberedValue = value

    ListItem(
        headlineContent = { Text(text, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        supportingContent = {
            Text(rememberedValue, maxLines = 1, overflow = TextOverflow.Ellipsis)
        },
        modifier = Modifier.clickable { openDialog = true }
    )

    if (openDialog) {
        AlertDialog(
            onDismissRequest = { openDialog = false },
            title = { Text(text = dialogText) },
            text = {
                TextField(
                    value = rememberedValue,
                    singleLine = true,
                    onValueChange = {
                        rememberedValue = it
                    }
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    coroutineScope.launch {
                        withContext(Dispatchers.IO) {
                            onValueChange(rememberedValue)
                            openDialog = false
                        }
                    }
                }) {
                    Text("Confirm")
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    openDialog = false
                }) {
                    Text("Dismiss")
                }
            }
        )
    }
}

@Composable
fun MonitoringScopePreference(text: String, dialogText: String, value: MonitoringScopeApps, onValueChange: suspend (MonitoringScopeApps) -> Unit) {
    var rememberedValue by remember { mutableStateOf(value) }
    val radioOptions = listOf(MonitoringScopeApps.APPS_ALL, MonitoringScopeApps.APPS_NON_SYSTEM, MonitoringScopeApps.APPS_WHITELIST, MonitoringScopeApps.APPS_BLACKLIST)
    val (selectedOption, onOptionSelected) = remember { mutableStateOf(value) }

    var openDialog by remember { mutableStateOf(false) }
    val coroutineScope = rememberCoroutineScope()

    rememberedValue = value

    Box {
        ListItem(
            headlineContent = { Text(text, maxLines = 1, overflow = TextOverflow.Ellipsis) },
            supportingContent = {
                Text(
                    when (rememberedValue) {
                        MonitoringScopeApps.APPS_ALL -> "All apps"
                        MonitoringScopeApps.APPS_NON_SYSTEM -> "Non-system apps"
                        MonitoringScopeApps.APPS_WHITELIST -> "Whitelist"
                        MonitoringScopeApps.APPS_BLACKLIST -> "Blacklist"
                        MonitoringScopeApps.UNRECOGNIZED -> "ERROR: UNRECOGNIZED"
                    }, maxLines = 1, overflow = TextOverflow.Ellipsis
                )
            },
            modifier = Modifier.clickable { openDialog = true }
        )

        if (openDialog) {
            AlertDialog(
                onDismissRequest = { openDialog = false },
                title = { Text(text = dialogText) },
                text = {
                    Column {
                        radioOptions.forEach {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .selectable(
                                        selected = it == selectedOption,
                                        onClick = { onOptionSelected(it) })
                            ) {
                                RadioButton(selected = it == selectedOption, onClick = { onOptionSelected(it) })
                                Text(
                                    when (it) {
                                        MonitoringScopeApps.APPS_ALL -> "All apps"
                                        MonitoringScopeApps.APPS_NON_SYSTEM -> "Non-system apps"
                                        MonitoringScopeApps.APPS_WHITELIST -> "Whitelist"
                                        MonitoringScopeApps.APPS_BLACKLIST -> "Blacklist"
                                        MonitoringScopeApps.UNRECOGNIZED -> "ERROR: UNRECOGNIZED"
                                    }, maxLines = 1, overflow = TextOverflow.Ellipsis
                                )
                            }
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = {
                        coroutineScope.launch {
                            withContext(Dispatchers.IO) {
                                onValueChange(selectedOption)
                                openDialog = false
                            }
                        }
                    }) { Text("Confirm") }
                },
                dismissButton = {
                    TextButton(onClick = {
                        openDialog = false
                    }) {
                        Text("Dismiss")
                    }
                }
            )
        }
    }
}

@Preview
@Composable
fun CategoryHeadlinePreview() {
    CategoryHeadline(text = "VPN preferences", description = "Lorem impsum dolor sit in nominem padri ed filii et spiritus sanctus. El mundo es en una situation paranormal.")
}

@Preview
@Composable
fun BooleanPreferencePreview() {
    BooleanPreference("Enable MitM", true) {}
}

@Preview
@Composable
fun ActionPreferencePreview() {
    ActionPreference("Launch the missiles!") {}
}

@Preview
@Composable
fun IntPreferencePreview() {
    IntPreference("Numeric preference", "Select DNS server", 1234) {}
}

@Preview
@Composable
fun StringPreferencePreview() {
    StringPreference("DNS server", "Select DNS server", "1.1.1.1") {}
}

@Preview
@Composable
fun MonitoringScopePreferencePreview() {
    MonitoringScopePreference("VPN monitoring scope", "VPN monitoring scope", MonitoringScopeApps.APPS_ALL) {}
}