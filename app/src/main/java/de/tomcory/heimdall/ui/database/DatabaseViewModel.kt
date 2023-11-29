package de.tomcory.heimdall.ui.database

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.Request
import de.tomcory.heimdall.core.database.entity.Response
import kotlinx.coroutines.flow.Flow

class DatabaseViewModel : ViewModel() {
    private val db: HeimdallDatabase? = HeimdallDatabase.instance
    val requests: Flow<List<Request>>? = db?.requestDao?.getAllObservable()
    val responses: Flow<List<Response>>? = db?.responseDao?.getAllObservable()
}