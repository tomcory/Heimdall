package de.tomcory.heimdall.ui.main

import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.App
import de.tomcory.heimdall.core.datastore.PreferencesDataSource
import javax.inject.Inject

class MainRepository @Inject constructor(
    val preferences: PreferencesDataSource,
    private val database: HeimdallDatabase
)