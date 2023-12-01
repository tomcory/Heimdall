package de.tomcory.heimdall.core.scanner

import android.content.pm.PackageInfo
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.AppXTracker
import de.tomcory.heimdall.core.database.entity.Tracker
import de.tomcory.heimdall.core.util.Trie
import net.dongliu.apk.parser.ApkFile
import timber.log.Timber
import java.io.File
import javax.inject.Inject

class LibraryScanner private constructor(trackers: List<Tracker>) {

    @Inject lateinit var database: HeimdallDatabase

    private val trackerSignatures = mapSignatures(trackers)
    private val shortestSignatureLength = trackerSignatures.keys.reduce { acc, s -> if(s.length < acc.length) s else acc }.length
    private val trackerTrie: Trie<Tracker> = Trie { it.removeSuffix(".").split(".") }

    init {
        trackerSignatures.forEach { (signature, tracker) -> trackerTrie.insert(signature, tracker) }
    }

    suspend fun scanApp(packageInfo: PackageInfo) {

        Timber.d("Scanning dex classes of ${packageInfo.packageName}")

        val apkFile = ApkFile(File(packageInfo.applicationInfo.publicSourceDir))

        Timber.d("${packageInfo.packageName} comprises %s dex classes", apkFile.dexClasses.size)

        val containedTrackers = mutableSetOf<AppXTracker>()

        for (dexClass in apkFile.dexClasses) {
            val className = dexClass.packageName
            if (className.length >= shortestSignatureLength && className.contains(".")) {
                trackerTrie.search(className)?.let {
                    if(containedTrackers.add(AppXTracker(packageInfo.packageName, it.id))) {
                        Timber.d("Found tracker: %s", it.name)
                    }
                }
            }
        }

        apkFile.close()

        Timber.d("Identified %s trackers", containedTrackers.size)

        database.appXTrackerDao().insert(*containedTrackers.toTypedArray())
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
//        suspend fun create(autoPopulate: Boolean = false): LibraryScanner? {
//            var trackers = HeimdallDatabase.instance?.trackerDao?.getAll()
//
//            if(autoPopulate && trackers.isNullOrEmpty()) {
//                Timber.d("No trackers found. Auto-populating database.")
//                ExodusUpdater.updateAll()
//            }
//
//            trackers = HeimdallDatabase.instance?.trackerDao?.getAll()
//
//            return if(trackers.isNullOrEmpty()) {
//                 null
//            } else {
//                LibraryScanner(trackers)
//            }
//        }
    }
}