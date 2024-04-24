package de.tomcory.heimdall.core.vpn.mitm

import timber.log.Timber
import java.io.*
import java.lang.Exception
import java.lang.StringBuilder

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

        fun getDefaultInstance(keyStoreDir: File) : Authority {
            //TODO: get values from secure storage
            return Authority(
                    keyStoreDir = keyStoreDir,
                    alias = "heimdallmitm",
                    password = "changeit".toCharArray(),
                    issuerCN = "Heimdall",
                    issuerO = "TU Berlin",
                    issuerOU = "SNET",
                    subjectCN = "Heimdall",
                    subjectO = "HeimdallCert",
                    subjectOU = "HeimdallCertUnit")
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
                "changeit".toCharArray(),
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
            val fin = FileInputStream(fl)
            val ret = convertStreamToString(fin)
            fin.close()
            return ret
        }

        @Throws(Exception::class)
        private fun convertStreamToString(`is`: InputStream): String {
            Timber.d("convertStreamToString")
            val reader = BufferedReader(InputStreamReader(`is`))
            val sb = StringBuilder()
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                sb.append(line).append("\n")
            }
            reader.close()
            return sb.toString()
        }
    }
}