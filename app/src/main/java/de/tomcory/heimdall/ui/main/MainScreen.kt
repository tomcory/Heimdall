package de.tomcory.heimdall.ui.main

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.tooling.preview.Preview
import androidx.navigation.compose.rememberNavController
import de.tomcory.heimdall.ui.nav.BottomNavigationBar
import de.tomcory.heimdall.ui.nav.Navigation
import de.tomcory.heimdall.ui.nav.NavigationRailBar
import de.tomcory.heimdall.ui.theme.HeimdallTheme

@Composable
fun MainScreen() {
    val navController = rememberNavController()
    val useRail = LocalConfiguration.current.screenWidthDp >= 600

    if (useRail) {
        // Medium / expanded: NavigationRail on the left, content to the right
        Row(modifier = Modifier.fillMaxSize()) {
            NavigationRailBar(navController = navController)
            Box(modifier = Modifier.weight(1f)) {
                Navigation(navController = navController)
            }
        }
    } else {
        // Compact: bottom navigation bar
        Scaffold(
            bottomBar = { BottomNavigationBar(navController) },
            containerColor = MaterialTheme.colorScheme.surface,
        ) { padding ->
            Box(modifier = Modifier.padding(padding)) {
                Navigation(navController = navController)
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun MainScreenPreview() {
    HeimdallTheme {
        MainScreen()
    }
}
