package de.tomcory.heimdall.ui.scanner.traffic

import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.datastore.PreferencesDataSource
import javax.inject.Inject

class TrafficScannerRepository @Inject constructor(
    val preferences: PreferencesDataSource,
    private val database: HeimdallDatabase
)