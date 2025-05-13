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
import java.util.UUID
import javax.inject.Inject

/**
 * ViewModel for MainActivity that handles application logic including scan operations
 * and exposing UI state
 */
@HiltViewModel
class MainViewModel @Inject constructor(
    application: Application
) : AndroidViewModel(application) {

    // WorkManager instance
    private val workManager = WorkManager.getInstance(application)

    // Track current work ID
    private var currentWorkId: UUID? = null

    // UI state
    private val _scanProgress = MutableStateFlow(0)
    val scanProgress: StateFlow<Int> = _scanProgress

    private val _showSplashScreen = MutableStateFlow(true)
    val showSplashScreen: StateFlow<Boolean> = _showSplashScreen

    /**
     * Start the initial scan and observe its progress
     */
    fun startScan() {

        // Schedule a scan
        val workId = ScanWorker.enqueue(getApplication<Application>().applicationContext)
        currentWorkId = workId

        // Observe work progress
        viewModelScope.launch {
            workManager.getWorkInfoByIdFlow(workId).collectLatest { workInfo ->
                val progress = workInfo?.progress?.getInt(ScanWorker.KEY_PROGRESS, 0) ?: 0
                _scanProgress.value = progress

                // Switch to main screen when work is finished or progress is 100%
                if (progress >= 100 || workInfo?.state == WorkInfo.State.SUCCEEDED) {
                    _showSplashScreen.value = false
                }
            }
        }
    }
}