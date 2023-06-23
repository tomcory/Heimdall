package de.tomcory.heimdall.util

import android.content.Context
import android.net.Uri
import de.tomcory.heimdall.scanner.traffic.mitm.Authority
import de.tomcory.heimdall.scanner.traffic.mitm.KeyStoreHelper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber
import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStream

object FileUtils {
    /**
     * Copies a file from the app's internal storage to a location in the device's shared storage.
     */
    suspend fun copyFile(context: Context, input: File, output: Uri?): Boolean {
        withContext(Dispatchers.IO) {
            try {
                if (!input.exists()) {
                    Timber.e("Input file does not exist: ${input.absolutePath}")
                    return@withContext false
                }
            } catch (e: SecurityException) {
                return@withContext false
            }

            if (output == null) {
                println("Output Uri is null")
                return@withContext false
            }

            try {
                val outputStream: OutputStream? = context.contentResolver.openOutputStream(output)
                if (outputStream == null) {
                    println("Unable to open output stream")
                    return@withContext false
                }

                outputStream.use { outStream ->
                    input.inputStream().use { inStream ->
                        inStream.copyTo(outStream)
                    }

                }
            } catch (e: IOException) {
                Timber.e("Error copying file: ${e.localizedMessage}")
                return@withContext false
            }
        }

        return true
    }

    /**
     * Generates a Magisk module based on the default Authority credentials and writes it to the app's internal cache directory.
     */
    suspend fun generateMagiskModule(context: Context): String {
        Timber.d("Generating authority...")
        val authority = Authority.getDefaultInstance(context)
        Timber.d("Loading KeyStore...")
        val keyStore = KeyStoreHelper.initialiseOrLoadKeyStore(authority)
        Timber.d("Building Magisk module...")
        return KeyStoreHelper.createMagiskModuleWithCertificate(context, keyStore, authority) ?: ""
    }

    fun populateTrieFromRawFile(context: Context, resId: Int, trie: Trie<String>) {
        val startTime = System.currentTimeMillis()

        val inputStream = context.resources.openRawResource(resId)
        val reader = BufferedReader(InputStreamReader(inputStream))
        var lineCounter = 0

        reader.use { r ->
            r.forEachLine { line ->
                trie.insert(line, line)
                lineCounter++
            }
        }

        reader.close()

        Timber.d("Inserted $lineCounter entries into trie in ${System.currentTimeMillis() - startTime}ms")
    }
}