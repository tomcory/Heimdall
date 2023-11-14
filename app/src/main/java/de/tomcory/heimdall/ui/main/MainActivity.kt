package de.tomcory.heimdall.ui.main

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.datastore.core.DataStore
import androidx.datastore.dataStore
import androidx.navigation.compose.rememberNavController
import de.tomcory.heimdall.Preferences
import de.tomcory.heimdall.persistence.datastore.PreferencesSerializer
import de.tomcory.heimdall.ui.nav.BottomNavigationBar
import de.tomcory.heimdall.ui.nav.Navigation
import de.tomcory.heimdall.ui.theme.HeimdallTheme

val Context.preferencesStore: DataStore<Preferences> by dataStore(
    fileName = "proto/preferences.proto",
    serializer = PreferencesSerializer
)

//@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            HeimdallTheme {
                MainScreen()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen() {
    val navController = rememberNavController()

    HeimdallTheme {
        Scaffold(
            //topBar = { TopBar() },
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