package de.tomcory.heimdall.dex

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.text.TextUtils
import de.tomcory.heimdall.R
import de.tomcory.heimdall.persistence.database.HeimdallDatabase
import de.tomcory.heimdall.persistence.database.entity.App
import de.tomcory.heimdall.persistence.database.entity.AppXPermission
import de.tomcory.heimdall.persistence.database.entity.AppXTracker
import de.tomcory.heimdall.persistence.database.entity.Permission
import de.tomcory.heimdall.persistence.database.entity.Tracker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import net.dongliu.apk.parser.ApkFile
import timber.log.Timber
import java.io.File
import java.io.IOException

suspend fun identifyTrackerLibs(pkgInfo: PackageInfo, context: Context) : List<Tracker> = withContext(Dispatchers.IO) {
    identifyTrackerLibsBlocking(pkgInfo, context)
}

private fun identifyTrackerLibsBlocking(pkgInfo: PackageInfo, context: Context) : List<Tracker> {

    Timber.w("Starting identification")

    val apkFile = ApkFile(File(pkgInfo.applicationInfo.publicSourceDir))

    //TODO: replace with DataStore and enable updatability
    val classes = context.resources.getStringArray(R.array.trackers)
    val names = context.resources.getStringArray(R.array.tname)
    val web = context.resources.getStringArray(R.array.tweb)

    val trackers: MutableSet<Tracker> = HashSet()
    for (classDef in apkFile.dexClasses) {
        val className = classDef.packageName
        if (className.length > 8) {
            if (className.contains(".")) {
                for (i in classes.indices) {
                    if (className.contains(classes[i])) {
                        if (names[i].startsWith("µ?")) // exclude "good" trackers
                            continue
                        val name = names[i].replace("[°²?µ]".toRegex(), "").trim { it <= ' ' }
                        trackers.add(Tracker(classes[i], name, web[i]))
                        break
                    }
                }
            }
        }
    }

    apkFile.close()

    Timber.w("Identified %s trackers", trackers.size)

    return trackers.toList().sortedBy { t -> t.name }
}

class DexAnalyser(private val context: Context) {
    private val pm: PackageManager = context.packageManager

    private val dangerPermissionList = arrayOf("POST_NOTIFICATIONS",
            "ACCEPT_HANDOVER", "ACCESS_BACKGROUND_LOCATION", "ACCESS_COARSE_LOCATION",
            "ACCESS_FINE_LOCATION", "ACCESS_MEDIA_LOCATION", "ACTIVITY_RECOGNITION", "ADD_VOICEMAIL",
            "ANSWER_PHONE_CALLS", "BLUETOOTH_ADVERTISE", "BLUETOOTH_CONNECT", "BLUETOOTH_SCAN",
            "BODY_SENSORS", "BODY_SENSORS_BACKGROUND", "CALL_PHONE", "CAMERA", "GET_ACCOUNTS", "NEARBY_WIFI_DEVICES",
            "PROCESS_OUTGOING_CALLS", "READ_BASIC_PHONE_STATE", "READ_CALENDAR", "READ_CALL_LOG", "READ_CONTACTS",
            "READ_EXTERNAL_STORAGE", "READ_MEDIA_AUDIO", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_PHONE_NUMBERS",
            "READ_PHONE_STATE", "READ_SMS", "RECEIVE_MMS", "RECEIVE_SMS", "RECEIVE_WAP_PUSH", "RECORD_AUDIO", "SEND_SMS",
            "USE_SIP", "UWB_RANGING", "WRITE_CALENDAR", "WRITE_CALL_LOG", "WRITE_CONTACTS", "WRITE_EXTERNAL_STORAGE")

    suspend fun analyseAllApps() {
        Timber.d("Scanning all apps for tracker libraries:")
        val apps = pm.getInstalledPackages(0)
        for (app in apps) {
            if (app.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM == 0) {
                val trackers = try {
                    findTrackers(app.packageName)
                } catch (e: Exception) {
                    arrayOf(Tracker("dex.error", "error", "error"))
                }
                val appLabel = app.applicationInfo.loadLabel(pm).toString()
                if (trackers.isNotEmpty()) {
                    Timber.d("%s (%s)\n - %s", appLabel, app.packageName, TextUtils.join("\n - ", trackers.map { x -> x.name }))
                    // persist in database
                    HeimdallDatabase.instance?.appDao?.insertApps(App(app.packageName, appLabel, app.longVersionCode))
                    HeimdallDatabase.instance?.trackerDao?.insertTrackers(*trackers)
                    for (tracker in trackers) {
                        HeimdallDatabase.instance?.appXTrackerDao?.insertAppXTracker(AppXTracker(app.packageName, tracker.className))
                    }
                } else {
                    Timber.d("%s (%s) is clean", appLabel, app.packageName)
                    HeimdallDatabase.instance?.appDao?.insertApps(App(app.packageName, appLabel, app.longVersionCode))
                }
            }
        }
        Timber.d("Scan complete")
    }



    /**
     * Does the tracker library analysis.
     *
     *
     * Matches class names of the app to be analysed against the Exodus tracker database, which
     * contains information on known class of tracker libraries.
     *
     * @param appId AID of the app to analyse
     * @return Found trackers
     * @throws IOException      I/O errors
     * @throws RuntimeException Non I/O errors
     */
    @Throws(IOException::class, RuntimeException::class)
    private suspend fun findTrackers(appId: String): Array<Tracker> {
        val pkg = pm.getPackageInfo(appId, 0)
        val apk = pkg.applicationInfo.publicSourceDir

        val apkFile = ApkFile(File(apk))
        // apkFile.dexClasses.forEach { x -> Timber.d("PARSED " + x.packageName) }
        Timber.d(apkFile.manifestXml)
        //Timber.d(pkg.packageName);

        // Parse manifest to extract permission
        val permissions = ManifestXMLParser.parser(apkFile.manifestXml)
        val permissionsList: ArrayList<Permission> = ArrayList()

        for (permission in permissions) {
            permissionsList.add(Permission(permissionName = permission, dangerous = permission in dangerPermissionList))
        }
        // add permissions to database
        HeimdallDatabase.instance?.permissionDao?.insert(*(permissionsList.toTypedArray()))

        //val dx = MultiDexIO.readDexFile(true, File(apk), BasicDexFileNamer(), null, null)
        val classes = context.resources.getStringArray(R.array.trackers)
        val names = context.resources.getStringArray(R.array.tname)
        val web = context.resources.getStringArray(R.array.tweb)

        val trackers: MutableSet<Tracker> = HashSet()
        for (classDef in apkFile.dexClasses) {
            val className = classDef.packageName
            /*for (classDef in dx.classes) {
                var className = classDef.type
                className = className.replace('/', '.')
                className = className.substring(1, className.length - 1)*/
            if (className.length > 8) {
                if (className.contains(".")) {
                    for (i in classes.indices) {
                        if (className.contains(classes[i])) {
                            if (names[i].startsWith("µ?")) // exclude "good" trackers
                                continue
                            val name = names[i].replace("[°²?µ]".toRegex(), "").trim { it <= ' ' }
                            trackers.add(Tracker(classes[i], name, web[i]))
                            break
                        }
                    }
                }
            }
        }
        return trackers.toTypedArray()
    }

    suspend fun analyseAllApps2() {
        Timber.d("Scanning all apps for their permissions and packages:")
        val apps = pm.getInstalledPackages(0)
        var i = 1
        for (app in apps) {
            if (app.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM == 0) {
                val packages = try {
                    findPackages(app.packageName)
                } catch (e: Exception) {
                    listOf(Tracker("dex.error", "error", "error"))
                }
                val appLabel = app.applicationInfo.loadLabel(pm).toString()
                if (packages.isNotEmpty()) {
                    Timber.d("%s/%s %s (%s) has %s packages", i++, apps.size, appLabel, app.packageName, packages.size)
                    // persist in database
                    HeimdallDatabase.instance?.appDao?.insertApps(App(app.packageName, appLabel, app.longVersionCode))
                    HeimdallDatabase.instance?.trackerDao?.insertTrackers(*packages.toTypedArray())
                    for (tracker in packages) {
                        HeimdallDatabase.instance?.appXTrackerDao?.insertAppXTracker(AppXTracker(app.packageName, tracker.className))
                    }
                } else {
                    Timber.d("%s (%s) is empty", appLabel, app.packageName)
                    HeimdallDatabase.instance?.appDao?.insertApps(App(app.packageName, appLabel, app.longVersionCode))
                }
            }
        }
        Timber.d("Scan complete")
    }

    /**
     * Does the tracker library analysis.
     *
     *
     * Matches class names of the app to be analysed against the Exodus tracker database, which
     * contains information on known class of tracker libraries.
     *
     * @param pkgName AID of the app to analyse
     * @return Found trackers
     * @throws IOException      I/O errors
     * @throws RuntimeException Non I/O errors
     */
    @Throws(IOException::class, RuntimeException::class)
    private fun findPackages(pkgName: String): List<Tracker> {
        val pkg = pm.getPackageInfo(pkgName, 0)
        val apk = pkg.applicationInfo.publicSourceDir

        Timber.d("Scanning %s", pkg.packageName)

        // parse the APK file
        val apkFile = ApkFile(File(apk))

        // extract the app's permissions
        val perms = ManifestXMLParser.parser(apkFile.manifestXml).map {
            Permission(permissionName = it, dangerous = it in dangerPermissionList)
        }

        Timber.d("Permissions:\n - %s", TextUtils.join("\n - ", perms.map { it.permissionName }))

        val uniquePackages = mutableSetOf<String>()
        apkFile.dexClasses.forEach { uniquePackages.add(it.packageName) }

        return uniquePackages.map { Tracker(it, "", "") }
    }
}