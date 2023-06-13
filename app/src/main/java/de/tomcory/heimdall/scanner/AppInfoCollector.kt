package de.tomcory.heimdall.scanner

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import de.tomcory.heimdall.persistence.database.HeimdallDatabase
import de.tomcory.heimdall.persistence.database.entity.App
import timber.log.Timber

class AppInfoCollector {
    suspend fun scanApp(context: Context, packageName: String): App {
        Timber.d("Collecting app info of $packageName")

        val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.packageManager.getPackageInfo(
                packageName,
                PackageManager.PackageInfoFlags.of(PackageManager.GET_META_DATA.toLong())
            )
        } else {
            context.packageManager.getPackageInfo(
                packageName,
                0
            )
        }

        val app = App(
            packageName = packageName,
            label = packageInfo.applicationInfo.loadLabel(context.packageManager).toString(),
            versionName = packageInfo.versionName,
            versionCode = packageInfo.longVersionCode
        )

        HeimdallDatabase.instance?.appDao?.insertApps(app)

        return app
    }
}