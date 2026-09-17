package de.tomcory.heimdall.ui.main

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import dagger.hilt.android.AndroidEntryPoint
import de.tomcory.heimdall.ui.theme.HeimdallTheme

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        val splashScreen = installSplashScreen()

        super.onCreate(savedInstanceState)

        // Keep the splash screen visible until the initial scan completes
        splashScreen.setKeepOnScreenCondition { viewModel.showSplashScreen.value }

        viewModel.observeScanProgress()

        setContent {
            HeimdallTheme {
                MainScreen()
            }
        }
    }
}
