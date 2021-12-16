package de.tomcory.heimdall.ui.apps.page

import android.app.Application
import android.graphics.Color
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.asLiveData
import de.tomcory.heimdall.R
import de.tomcory.heimdall.persistence.database.TrafficDatabase
import de.tomcory.heimdall.persistence.database.entity.App
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.onStart
import timber.log.Timber

const val ARG_POS = "position"
const val APP_PAGE_COUNT = 4

class AppsPageViewModel(
        application: Application,
        position: Int = 0,
        database: TrafficDatabase
) : AndroidViewModel(application) {
    
    var firstLoad = position == 0
        get() {
            return if(field) {
                firstLoad = false
                true
            } else {
                false
            }
        }

    val totalValue = when (position) {
        0 -> database.flowDao.getTotalFlowCount()
        1 -> database.flowDao.getTotalTrafficVolume()
        2 -> database.flowDao.getTotalUploadVolume()
        else -> database.flowDao.getTotalDownloadVolume()
    }.onStart { emit(0) }.asLiveData()

    val appCount = database.appDao.getAppCount().asLiveData()

    val data = when (position) {
        0 -> database.appDao.getAppFlowCount()
        1 -> database.appDao.getAppTrafficVolume()
        2 -> database.appDao.getAppUploadVolume()
        else -> database.appDao.getAppDownloadVolume()
    }.onStart {
        emit(emptyList())
    }.onEach { apps ->
        apps.forEach { app ->
            if (app.icon == null) {
                app.icon =
                        try {
                            getApplication<Application>().packageManager.getApplicationIcon(app.appPackage)
                        } catch (e: Exception) {
                            //TODO: replace with custom icon for apps that are not installed
                            getApplication<Application>().packageManager.defaultActivityIcon
                        }
            }
        }
    }.map {
        apps -> if(apps.isNotEmpty()) {
                    listOf(App.AppGrouped("", "", "", 0, ITEM_VIEW_TYPE_HEADER)) + apps
                } else {
                    apps
                }
    }.asLiveData()

    val unit = if(position > 0) { "B" } else { "Flows" }

    val colors = when(position % APP_PAGE_COUNT) {
        0 -> getApplication<Application>().resources.getStringArray(R.array.paletteRed50)
        1 -> getApplication<Application>().resources.getStringArray(R.array.paletteAmber50)
        2 -> getApplication<Application>().resources.getStringArray(R.array.paletteGreen50)
        else -> getApplication<Application>().resources.getStringArray(R.array.paletteLightBlue50)
    }.map { string -> Color.parseColor(string) }
}

class AppsPageViewModelFactory(
        private val application: Application,
        private val position: Int,
        private val database: TrafficDatabase) : ViewModelProvider.Factory {

    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(AppsPageViewModel::class.java)) {
            return AppsPageViewModel(application, position, database) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}