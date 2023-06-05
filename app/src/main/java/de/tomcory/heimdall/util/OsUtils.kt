package de.tomcory.heimdall.util

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Uri
import android.system.OsConstants
import androidx.annotation.RequiresApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber
import java.io.File
import java.io.IOException
import java.io.OutputStream
import java.net.InetSocketAddress

object OsUtils {
    @JvmStatic
    @RequiresApi(29)
    fun getAidQ(local: InetSocketAddress, remote: InetSocketAddress, context: Context): Int {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager?
        return cm?.getConnectionOwnerUid(OsConstants.IPPROTO_TCP, local, remote) ?: -1
    }

    fun getSystemApps(context: Context): List<String> {
        val packageManager: PackageManager = context.packageManager
        val apps = packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
        return apps.filter { app ->
            app.flags and ApplicationInfo.FLAG_SYSTEM != 0
        }.map { app ->
            app.packageName
        }
    }
}