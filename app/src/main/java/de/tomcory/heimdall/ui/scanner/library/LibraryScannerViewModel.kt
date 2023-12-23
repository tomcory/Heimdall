package de.tomcory.heimdall.ui.scanner.library

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import de.tomcory.heimdall.core.scanner.ExodusUpdater
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

class LibraryScannerViewModel : ViewModel() {

    val scanActiveInitial = false
    val scanProgressInitial = 0f
    val lastUpdatedInitial = 0L

    @Inject lateinit var exodusUpdater: ExodusUpdater

    ///////////////////////////////
    // State variables
    ///////////////////////////////

    private val _scanActive = MutableStateFlow(scanActiveInitial)
    val scanActive = _scanActive.asStateFlow()

    private val _scanProgress = MutableStateFlow(scanProgressInitial)
    val scanProgress = _scanProgress.asStateFlow()

    private val _lastUpdated = MutableStateFlow(lastUpdatedInitial)
    val lastUpdated = _lastUpdated.asStateFlow()

    ///////////////////////////////
    // Event handlers
    ///////////////////////////////

    fun onScan(onShowSnackbar: (String) -> Unit) {
        viewModelScope.launch {
            var scanCancelled = false
            _scanActive.emit(true)
            _scanProgress.emit(0f)
            for (i in 0..100) {
                if (!scanActive.value) {
                    scanCancelled = true
                    break
                }
                _scanProgress.emit(scanProgress.value + 0.01f)
                delay(30)
            }
            if (scanCancelled) {
                onShowSnackbar("Scan cancelled.")
            }
            _scanActive.emit(false)
        }
    }

    fun onScanCancel() {
        viewModelScope.launch {
            _scanActive.emit(false)
        }
    }

    fun onShowDetails() {
        TODO("Not yet implemented")
    }

    fun onShowHelp() {
        TODO("Not yet implemented")
    }

    ///////////////////////////////
    // Private methods
    ///////////////////////////////



    private fun updateExodus(onShowSnackbar: (String) -> Unit) {
        viewModelScope.launch {
            try {
                exodusUpdater.updateAll()
                onShowSnackbar("Tracker signatures updated.")
            } catch (e: Exception) {
                onShowSnackbar("Error updating tracker signatures.")
            }
        }
    }
}