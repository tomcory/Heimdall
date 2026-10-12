package de.tomcory.heimdall.ui.scanner

import android.annotation.SuppressLint
import android.content.Context
import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject

@HiltViewModel
class ScannerViewModel @Inject constructor(
    @field:SuppressLint("StaticFieldLeak") @param:ApplicationContext private val context: Context
) : ViewModel() {

    val showPreferencesDialogInitial = false

    private val _showPreferencesDialog = MutableStateFlow(showPreferencesDialogInitial)
    val showPreferencesDialog = _showPreferencesDialog.asStateFlow()

    fun onShowPreferencesDialog() {
        _showPreferencesDialog.value = true
    }

    fun onDismissPreferencesDialog() {
        _showPreferencesDialog.value = false
    }
}