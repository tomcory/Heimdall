package de.tomcory.heimdall.ui.nav

import androidx.compose.runtime.Composable
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import de.tomcory.heimdall.R
import de.tomcory.heimdall.ui.apps.PermissionsScreen
import de.tomcory.heimdall.ui.database.DatabaseScreen
import de.tomcory.heimdall.ui.evaluator.ScoreScreen
import de.tomcory.heimdall.ui.scanner.ScannerScreen

/**
 * How to add a new screen to the bottom navigation bar:
 *
 * 1) add a new data object to the NavigationItem class. Define a route (select a unique string), icons and title.
 * 2) add the new navigation item to the navigationItems list below
 * 3) add a new composable to the Navigation NavHost below that maps your defined route to your screen.
 */
sealed class NavigationItem(var route: String, var unselectedIcon: Int, var selectedIcon: Int, var title: String) {
    data object Traffic : NavigationItem("traffic", R.drawable.ic_scanner, R.drawable.ic_scanner_filled, "Scanners")
    data object Score : NavigationItem("score", R.drawable.ic_score, R.drawable.ic_score_filled, "Score")
    data object Database : NavigationItem("database", R.drawable.ic_insights, R.drawable.ic_insights_filled, "Insights")
}

/**
 * List of navigation items used by the BottomNavigationBar.
 */
val navigationItems = listOf(
    NavigationItem.Traffic,
    NavigationItem.Score,
    NavigationItem.Database
)

@Composable
fun Navigation(navController: NavHostController) {
    NavHost(navController = navController, startDestination = NavigationItem.Traffic.route) {

        /*
         * Map navigation items for the BottomNavigationBar to their destination screen here.
         */
        composable(NavigationItem.Traffic.route) {
            ScannerScreen()
        }
        composable(NavigationItem.Score.route) {
            ScoreScreen()
        }
        composable(NavigationItem.Database.route) {
            DatabaseScreen()
        }

        /*
         * Add other destinations, e.g. nested screens, here.
         */
        composable("permissions/{packageName}") {
            PermissionsScreen(navController, it.arguments?.getString("packageName"))
        }
    }
}

