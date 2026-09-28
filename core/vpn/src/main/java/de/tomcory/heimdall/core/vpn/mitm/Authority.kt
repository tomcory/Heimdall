package de.tomcory.heimdall.core.vpn.mitm

import timber.log.Timber
import java.io.*
import java.lang.Exception
import java.lang.StringBuilder
import java.security.SecureRandom

/**
 * Parameter object holding personal informations given to a SSLEngineSource.
 *
 * XXX consider to inline within the interface SslEngineSource, if MITM is core
 */
class Authority (
    val keyStoreDir: File,
    val alias: String,
    val password: CharArray,
    val issuerCN: String,
    val issuerO: String,
    val issuerOU: String,
    val subjectCN: String,
    val subjectO: String,
    val subjectOU: String
) {

    fun aliasFile(fileExtension: String): File {
        val outFile = File(keyStoreDir, alias + fileExtension)
        // Get the parent directory: / aaa / bbb / ccc /
        // Create a folder through the parent directory, not through outFile
        return if (!keyStoreDir.exists()) {
            // Create a file when the file does not exist
            if (keyStoreDir.mkdirs() && !outFile.exists()) {
                //Create a file
                try {
                    if (!outFile.createNewFile()) Timber.e("File to create failure!")
                } catch (e: IOException) {
                    e.printStackTrace()
                }
            }
            outFile
        } else {
            outFile
        }
    }

    companion object {

        /** Extension of the file that stores an alias's generated keystore password. */
        private const val PASSWORD_FILE_EXTENSION = ".pwd"

        /** Bytes of randomness used to generate a keystore password (256 bits). */
        private const val PASSWORD_LENGTH_BYTES = 32

        fun getDefaultInstance(keyStoreDir: File) : Authority {
            return Authority(
                    keyStoreDir = keyStoreDir,
                    alias = "heimdallmitm",
                    password = loadOrCreatePassword(keyStoreDir, "heimdallmitm"),
                    issuerCN = "Heimdall",
                    issuerO = "TU Berlin",
                    issuerOU = "SNET",
                    subjectCN = "Heimdall",
                    subjectO = "HeimdallCert",
                    subjectOU = "HeimdallCertUnit")
        }

        /**
         * Loads the keystore password for [alias] from a private file next to the keystore
         * itself, generating and persisting a fresh random one on first use. The password used
         * to be the hardcoded literal "changeit" (the well-known Java default cacerts password),
         * which provided no real protection for the CA's private key. The app's private storage
         * directory isn't readable by other apps without root, and (see AndroidManifest.xml's
         * backup rules) is excluded from Android's auto-backup, so a per-install random password
         * stored here is meaningfully harder to obtain than that hardcoded literal was.
         */
        private fun loadOrCreatePassword(keyStoreDir: File, alias: String): CharArray {
            val passwordFile = File(keyStoreDir, alias + PASSWORD_FILE_EXTENSION)

            val existing = if (passwordFile.exists()) passwordFile.readText().trim() else ""
            if (existing.isNotEmpty()) {
                return existing.toCharArray()
            }

            val randomBytes = ByteArray(PASSWORD_LENGTH_BYTES)
            SecureRandom().nextBytes(randomBytes)
            val generated = randomBytes.joinToString("") { "%02x".format(it) }

            try {
                keyStoreDir.mkdirs()
                passwordFile.writeText(generated)
            } catch (e: IOException) {
                Timber.e(e, "Error persisting the MitM CA keystore password for alias $alias")
            }

            return generated.toCharArray()
        }

        //TODO: proper Android file management
        @JvmStatic
        fun generateCertificate(file: File): String {
            Timber.d(file.absolutePath)
            if (file.exists()) {
                file.delete()
            }
            file.mkdirs()
            Timber.d("generateCertificate")
            val authority = Authority(
                file,
                "heimdall-proxy",
                loadOrCreatePassword(file, "heimdall-proxy"),
                "Heimdall",
                "HeimdallOrga",
                "HeimdallOrgaUnit",
                "Heimdall",
                "HeimdallCert",
                "HeimdallCertUnit"
            )
            return try {
                CertificateSniffingMitmManager.createSingleton(authority)
                getStringFromFile(File(file, "heimdall-proxy.pem").path)
            } catch (e: Exception) {
                e.printStackTrace()
                ""
            }
        }

        @Throws(Exception::class)
        private fun getStringFromFile(filePath: String): String {
            Timber.d("getStringFromFile")
            val fl = File(filePath)
            return FileInputStream(fl).use { fin ->
                convertStreamToString(fin)
            }
        }

        @Throws(Exception::class)
        private fun convertStreamToString(`is`: InputStream): String {
            Timber.d("convertStreamToString")
            return BufferedReader(InputStreamReader(`is`)).use { reader ->
                val sb = StringBuilder()
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    sb.append(line).append("\n")
                }
                sb.toString()
            }
        }
    }
}