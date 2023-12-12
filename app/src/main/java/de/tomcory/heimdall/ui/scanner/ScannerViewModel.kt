package de.tomcory.heimdall.ui.scanner

import android.annotation.SuppressLint
import android.content.Context
import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import de.tomcory.heimdall.ui.scanner.traffic.TrafficScannerRepository
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject

@HiltViewModel
class ScannerViewModel @Inject constructor(
    @SuppressLint("StaticFieldLeak") @ApplicationContext private val context: Context
) : ViewModel() {

    val showPreferencesDialogInitial = false
    val showExportDialogInitial = false

    private val _showPreferencesDialog = MutableStateFlow(showPreferencesDialogInitial)
    val showPreferencesDialog = _showPreferencesDialog.asStateFlow()

    private val _showExportDialog = MutableStateFlow(showExportDialogInitial)
    val showExportDialog = _showExportDialog.asStateFlow()

    fun onShowPreferencesDialog() {
        _showPreferencesDialog.value = true
    }

    fun onDismissPreferencesDialog() {
        _showPreferencesDialog.value = false
    }

    fun onShowExportDialog() {
        _showExportDialog.value = true
    }

    fun onDismissExportDialog() {
        _showExportDialog.value = false
    }
}