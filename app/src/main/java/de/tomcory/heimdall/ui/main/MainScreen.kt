package de.tomcory.heimdall.ui.main

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.navigation.compose.rememberNavController
import de.tomcory.heimdall.ui.nav.BottomNavigationBar
import de.tomcory.heimdall.ui.nav.Navigation
import de.tomcory.heimdall.ui.theme.HeimdallTheme

@Composable
fun MainScreen() {
    val navController = rememberNavController()

    HeimdallTheme {
        Scaffold(
            bottomBar = { BottomNavigationBar(navController) },
            content = { padding -> // We have to pass the scaffold inner padding to our content. That's why we use Box.
                Box(modifier = Modifier.padding(padding)) {
                    Navigation(navController = navController)
                }
            },
            containerColor = MaterialTheme.colorScheme.surface // Set background color to avoid the white flashing when you switch between screens
        )
    }
}

@Preview(showBackground = true)
@Composable
fun MainScreenPreview() {
    MainScreen()
}