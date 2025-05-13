package de.tomcory.heimdall.ui.main

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import dagger.hilt.android.AndroidEntryPoint
import de.tomcory.heimdall.ui.splash.SplashScreen
import de.tomcory.heimdall.ui.theme.HeimdallTheme

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Start scanning when the activity is created
        viewModel.startScan()

        setContent {
            HeimdallTheme {
                // Collect state from ViewModel as Compose state
                val scanProgress by viewModel.scanProgress.collectAsState()
                val showSplashScreen by viewModel.showSplashScreen.collectAsState()

                // Show the appropriate screen based on the state
                if (showSplashScreen) {
                    SplashScreen(progress = scanProgress)
                } else {
                    MainScreen()
                }
            }
        }
    }
}