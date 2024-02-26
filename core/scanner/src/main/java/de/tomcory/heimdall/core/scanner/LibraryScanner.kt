package de.tomcory.heimdall.core.scanner

import android.content.pm.PackageInfo
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.AppXTracker
import de.tomcory.heimdall.core.database.entity.Tracker
import de.tomcory.heimdall.core.datastore.PreferencesDataSource
import de.tomcory.heimdall.core.util.Trie
import net.dongliu.apk.parser.ApkFile
import timber.log.Timber
import java.io.File
import javax.inject.Inject

class LibraryScanner @Inject constructor(
    val database: HeimdallDatabase,
    val preferences: PreferencesDataSource,
    private val exodusUpdater: ExodusUpdater
) {
    private var initialised = false
    private var shortestSignatureLength = 0
    private val trackerTrie: Trie<Tracker> = Trie { it.removeSuffix(".").split(".") }

    suspend fun scanApp(packageInfo: PackageInfo) {

        // the trie needs to be populated with tracker signatures before it can be used
        // this is done lazily on the first scan
        if(!initialised) {
            init()
        }

        Timber.d("Scanning dex classes of ${packageInfo.packageName}...")

        // open the APK file of the app
        val apkFile = try {
            ApkFile(File(packageInfo.applicationInfo.publicSourceDir))
        } catch (e: Exception) {
            Timber.w("Failed to open APK file of ${packageInfo.packageName}: ${e.message}")
            return
        }

        // get all dex classes of the app
        val dexClasses = try {
           apkFile.dexClasses
        } catch (e: Exception) {
            Timber.w("Failed to open Dex file of ${packageInfo.packageName}: ${e.message}")
            return
        }

        Timber.d("${packageInfo.packageName} comprises $dexClasses classes")

        val containedTrackers = mutableSetOf<AppXTracker>()

        // search for tracker signatures in the dex classes of the app
        for (dexClass in dexClasses) {
            val className = dexClass.packageName
            // only search for signatures that are at least as long as the shortest signature in the database
            if (className.length >= shortestSignatureLength && className.contains(".")) {
                // search for the longest matching signature in the trie
                trackerTrie.search(className)?.let {
                    // if a signature is found, add the tracker to the list of trackers contained in the app
                    if(containedTrackers.add(AppXTracker(packageInfo.packageName, it.id))) {
                        Timber.d("Found tracker: ${it.name}")
                    }
                }
            }
        }

        // always remember to close IO resources!
        // note: due to a probable bug in the parser library, the system still complains about unclosed resources
        apkFile.close()

        Timber.d("Identified ${containedTrackers.size} trackers in ${packageInfo.packageName}")

        // insert the list of trackers contained in the app into the database
        database.appXTrackerDao().insert(*containedTrackers.toTypedArray())
    }

    private suspend fun init() {
        Timber.d("Cache of tracker signatures not initialised. Initialising now.")

        // load trackers from database or update them from Exodus API if the database is empty
        val trackers = database.trackerDao().getAll().let {
            it.ifEmpty {
                Timber.d("No trackers found in database. Populating from Exodus API.")
                exodusUpdater.updateAll()
                database.trackerDao().getAll()
            }
        }

        // map tracker signatures to trackers and insert them into a trie for fast lookup
        val trackerSignatures = mapSignatures(trackers)
        trackerSignatures.forEach { (signature, tracker) -> trackerTrie.insert(signature, tracker) }

        // knowing the shortest tracker signature length allows us to skip the search for signatures that are too short
        shortestSignatureLength = trackerSignatures.keys.minOf { it.length }

        initialised = true
        Timber.d("Tracker signatures initialised.")
    }

    private fun mapSignatures(trackers: List<Tracker>): Map<String, Tracker> {
        val map = mutableMapOf<String, Tracker>()

        // split tracker signatures that contain multiple signatures separated by a pipe and map each of them to their tracker
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
}