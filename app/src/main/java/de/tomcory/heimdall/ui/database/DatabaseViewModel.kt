package de.tomcory.heimdall.ui.database

import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.Request
import de.tomcory.heimdall.core.database.entity.Response
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

@HiltViewModel
class DatabaseViewModel @Inject constructor(
    database: HeimdallDatabase
): ViewModel() {
    val requests: Flow<List<Request>> = database.requestDao().getAllObservable()
    val responses: Flow<List<Response>> = database.responseDao().getAllObservable()
}