package de.tomcory.heimdall.ui.nav

import de.tomcory.heimdall.R

sealed class NavigationItem(var route: String, var unselectedIcon: Int, var selectedIcon: Int, var title: String) {
    object Traffic : NavigationItem("traffic", R.drawable.ic_m3_traffic_24px, R.drawable.ic_m3_traffic_filled_24px, "Traffic")
    object Apps : NavigationItem("apps", R.drawable.ic_m3_apps_24px, R.drawable.ic_m3_apps_24px, "Apps")
    object Database : NavigationItem("database", R.drawable.ic_m3_database_24px, R.drawable.ic_m3_database_24px, "Database")
}
