package de.tomcory.heimdall.scanner.library

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import de.tomcory.heimdall.persistence.database.HeimdallDatabase
import de.tomcory.heimdall.persistence.database.entity.AppXTracker
import de.tomcory.heimdall.persistence.database.entity.Tracker
import de.tomcory.heimdall.util.Trie
import net.dongliu.apk.parser.ApkFile
import timber.log.Timber
import java.io.File

class LibraryScanner private constructor(val trackers: List<Tracker>) {

    private val trackerSignatures = mapSignatures(trackers)
    private val shortestSignatureLength = trackerSignatures.keys.reduce { acc, s -> if(s.length < acc.length) s else acc }.length
    private val trackerTrie: Trie<Tracker> = Trie { it.removeSuffix(".").split(".") }

    init {
        trackerSignatures.forEach { (signature, tracker) -> trackerTrie.insert(signature, tracker) }
    }

    suspend fun scanApp(context: Context, packageName: String) {

        Timber.d("Scanning dex classes of $packageName")

        val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.packageManager.getPackageInfo(
                packageName,
                PackageManager.PackageInfoFlags.of(0L)
            )
        } else {
            context.packageManager.getPackageInfo(
                packageName,
                0
            )
        }

        val apkFile = ApkFile(File(packageInfo.applicationInfo.publicSourceDir))

        val containedTrackers = mutableSetOf<AppXTracker>()

        for (dexClass in apkFile.dexClasses) {
            val className = dexClass.packageName
            if (className.length >= shortestSignatureLength && className.contains(".")) {
                trackerTrie.search(className)?.let {
                    if(containedTrackers.add(AppXTracker(packageName, it.id))) {
                        Timber.d("Found tracker: %s", it.name)
                    }
                }
            }
        }

        apkFile.close()

        Timber.d("Identified %s trackers", containedTrackers.size)

        HeimdallDatabase.instance?.appXTrackerDao?.insert(*containedTrackers.toTypedArray())
    }

    private fun mapSignatures(trackers: List<Tracker>): Map<String, Tracker> {
        val map = mutableMapOf<String, Tracker>()

        for(tracker in trackers) {
            if(tracker.codeSignature.contains('|')) {
                val signatures = tracker.codeSignature.split('|')
                for(signature in signatures) {
                    map[signature] = tracker
                }
            } else {
                map[tracker.codeSignature] = tracker
            }
        }

        return map
    }

    companion object {
        suspend fun create(): LibraryScanner? {
            val trackers = HeimdallDatabase.instance?.trackerDao?.getAll()

            return if(trackers.isNullOrEmpty()) {
                 null
            } else {
                LibraryScanner(trackers)
            }
        }
    }
}