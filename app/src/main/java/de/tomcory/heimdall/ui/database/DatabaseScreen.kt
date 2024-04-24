package de.tomcory.heimdall.ui.database

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.hilt.navigation.compose.hiltViewModel

@Composable
fun DatabaseScreen(
    viewModel: DatabaseViewModel = hiltViewModel()
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.surface)
            .wrapContentSize(Alignment.Center)
    ) {
        val requests by viewModel.requests.collectAsState(initial = emptyList())
        Text(text = "Database contains ${requests.size} requests.")

        val responses by viewModel.responses.collectAsState(initial = emptyList())
        Text(text = "Database contains ${responses.size} responses.")
    }
}

@Preview
@Composable
fun DatabaseScreenPreview() {
    DatabaseScreen()
}