package de.tomcory.heimdall.ui.scanner

import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.App
import de.tomcory.heimdall.core.datastore.PreferencesDataSource
import javax.inject.Inject

class ScannerRepository @Inject constructor(
    val preferences: PreferencesDataSource,
    private val database: HeimdallDatabase
) {
    suspend fun persistApp(app: App) {
        database.appDao().insertApps(app)
    }
}