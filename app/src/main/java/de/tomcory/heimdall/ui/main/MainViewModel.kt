package de.tomcory.heimdall.ui.main

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.work.WorkInfo
import androidx.work.WorkManager
import dagger.hilt.android.lifecycle.HiltViewModel
import de.tomcory.heimdall.service.ScanWorker
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(
    application: Application,
    private val repository: MainRepository,
) : AndroidViewModel(application) {

    private val workManager = WorkManager.getInstance(application)

    private val _showSplashScreen = MutableStateFlow(true)
    val showSplashScreen: StateFlow<Boolean> = _showSplashScreen

    fun observeScanProgress() {
        viewModelScope.launch {
            workManager.getWorkInfosForUniqueWorkFlow(ScanWorker.UNIQUE_WORK_NAME)
                .collectLatest { workInfoList ->
                    if (workInfoList.isNotEmpty()) {
                        val workInfo = workInfoList[0]
                        val progress = workInfo.progress.getInt(ScanWorker.KEY_PROGRESS, 0)
                        if (progress >= 100 || workInfo.state == WorkInfo.State.SUCCEEDED) {
                            _showSplashScreen.value = false
                        }
                    } else {
                        _showSplashScreen.value = false
                    }
                }
        }
    }
}
