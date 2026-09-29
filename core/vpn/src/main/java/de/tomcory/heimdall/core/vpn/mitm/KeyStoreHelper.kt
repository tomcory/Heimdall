package de.tomcory.heimdall.core.vpn.mitm

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.OperatorCreationException
import timber.log.Timber
import java.io.*
import java.net.URL
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.Certificate
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.util.Date
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

object KeyStoreHelper {

    /**
     * The P12 format has to be implemented by every vendor. Oracles proprietary
     * JKS type is not available in Android.
     */
    private const val KEY_STORE_TYPE = "PKCS12"
    private const val KEY_STORE_FILE_EXTENSION = ".p12"

    /**
     * Initialises a key store containing a root CA certificate (if there isn't already a *valid*
     * key store). An existing key store whose CA certificate has expired (or isn't valid yet) is
     * not reused - it's regenerated the same way a missing key store would be, since continuing
     * to sign fake leaf certificates with an expired CA would otherwise fail every TLS handshake
     * silently. Regeneration invalidates any copy of the CA certificate the user has already
     * installed on the device, so the caller should prompt them to reinstall it when this
     * happens (see [Timber.w] calls below for the specific condition).
     *
     * Reuse is decided from the `.p12` keystore alone - a missing `.pem` export (the keystore's
     * certificate re-exported for the user to install) is *not* treated as a reason to
     * regenerate; it's simply re-derived from the still-valid keystore instead, since the `.pem`
     * is a derived artifact that can go missing independently of the keystore itself.
     */
    @Throws(GeneralSecurityException::class, OperatorCreationException::class, IOException::class)
    fun initialiseOrLoadKeyStore(
        authority: Authority
    ): KeyStore {

        val existing = if (authority.aliasFile(KEY_STORE_FILE_EXTENSION).exists()) {
            loadIfValid(authority)
        } else {
            null
        }

        if (existing != null) {
            return existing
        }

        // no existing (valid) key store - create a new one containing our root CA certificate
        // step 1: create the certificate
        val keyStore = CertificateHelper.createRootCertificate(authority, KEY_STORE_TYPE)

        // step 2: store the certificate in the key store
        FileOutputStream(authority.aliasFile(KEY_STORE_FILE_EXTENSION)).use { outputStream ->
            keyStore.store(outputStream, authority.password)
        }

        Timber.d("Created new root certificate authority key store")

        // export the root CA certificate to a .pem file
        exportPem(authority.aliasFile(".pem"), keyStore.getCertificate(authority.alias))

        return keyStore
    }

    /**
     * Loads the existing key store for [authority] and returns it if its CA certificate is
     * currently valid, or `null` if the key store can't be loaded at all, is missing a
     * certificate entry, or that certificate isn't currently valid (in every case, the caller
     * should regenerate instead of reusing it).
     */
    private fun loadIfValid(authority: Authority): KeyStore? {
        val keyStore = KeyStore.getInstance(KEY_STORE_TYPE)
        try {
            FileInputStream(authority.aliasFile(KEY_STORE_FILE_EXTENSION)).use { stream ->
                keyStore.load(stream, authority.password)
            }
        } catch (e: IOException) {
            // Typically "PKCS12 key store mac invalid - wrong password or corrupted file" - e.g.
            // a keystore created before per-install random passwords replaced the old hardcoded
            // literal (so there's no .pwd file, and a freshly-generated random password doesn't
            // match what the file was actually encrypted with), or genuine on-disk corruption.
            // Either way this keystore can't be read at all, so it's unusable - treat it the same
            // as a missing/invalid certificate entry below and regenerate, rather than letting
            // this crash VPN startup entirely.
            Timber.w(e, "Existing root CA key store for alias ${authority.alias} could not be loaded (wrong password or corrupted file), regenerating")
            return null
        } catch (e: GeneralSecurityException) {
            Timber.w(e, "Existing root CA key store for alias ${authority.alias} could not be loaded, regenerating")
            return null
        }

        val cert = keyStore.getCertificate(authority.alias) as? X509Certificate
        if (cert == null) {
            Timber.w("Existing root CA key store for alias ${authority.alias} has no certificate entry, regenerating")
            return null
        }

        return try {
            cert.checkValidity(Date())
            Timber.d("Loaded existing root certificate authority key store")

            // the .pem export is derived from the keystore and can go missing independently of
            // it (e.g. storage cleanup, a partial write) - re-export it here instead of treating
            // its absence as a reason to regenerate the whole CA, which would invalidate any copy
            // of the CA certificate the user has already installed on the device
            if (!authority.aliasFile(".pem").exists()) {
                Timber.d("Root CA .pem export missing for alias ${authority.alias}, re-exporting it from the existing keystore")
                exportPem(authority.aliasFile(".pem"), cert)
            }

            keyStore
        } catch (e: CertificateExpiredException) {
            Timber.w(e, "Root CA certificate for alias ${authority.alias} expired on ${cert.notAfter} - regenerating. The user will need to reinstall the new CA certificate for MitM inspection to keep working.")
            null
        } catch (e: CertificateNotYetValidException) {
            Timber.w(e, "Root CA certificate for alias ${authority.alias} is not valid until ${cert.notBefore} - regenerating.")
            null
        }
    }

    /**
     * Initialises and exports fake server certificates for a given server's common and alternative names.
     * The fake server certificate(s) can be used to impersonate the server in a client-facing SSL session.
     */
    @Throws(GeneralSecurityException::class, OperatorCreationException::class, IOException::class)
    fun initializeServerCertificates(
        authority: Authority,
        caCertificate: Certificate,
        caPrivateKey: PrivateKey,
        commonName: String,
        subjectAlternativeNames: SubjectAlternativeNameHolder?
    ) {

        val keyStore = CertificateHelper.createServerCertificate(
            commonName,
            subjectAlternativeNames!!,
            authority,
            caCertificate,
            caPrivateKey
        )

        val key = keyStore.getKey(authority.alias, authority.password) as PrivateKey
        val certs: Array<Certificate> = keyStore.getCertificateChain(authority.alias)

        exportPem(authority.aliasFile("-$commonName-key.pem"), key)
        exportPem(authority.aliasFile("-$commonName-cert.pem"), *certs)
    }

    private fun calculateSubjectHashOld(x509Certificate: X509Certificate): String {
        val asn1EncodedSubject = x509Certificate.subjectX500Principal.encoded
        val hash = MessageDigest.getInstance("MD5").digest(asn1EncodedSubject)

        val bytes = hash.copyOfRange(0, 4)
        bytes.reverse()

        return bytes.joinToString("") { String.format("%02x", it) }
    }

    /**
     * Exports the given certificates to the specified .pem file.
     */
    @Throws(IOException::class)
    private fun exportPem(exportFile: File, vararg certs: Any) {
        FileWriter(exportFile).use { sw ->
            JcaPEMWriter(sw).use { pw ->
                for (cert in certs) {
                    pw.writeObject(cert)
                    pw.flush()
                }
            }
        }
    }

    /**
     * Creates a Magisk module installer for the Heimdall CA Certificate Mounter module.
     *
     * A Magisk module installer is a Magisk module packaged in a zip file that can be flashed in the Magisk app or custom recoveries such as TWRP.
     * See https://topjohnwu.github.io/Magisk/guides.html for more information on Magisk modules.
     *
     * Here's the module's file structure:
     *
     * <module_id>.zip
     * │
     * ├── META-INF
     * │   └── com
     * │       └── google
     * │           └── android
     * │               ├── update-binary        <--- The module_installer.sh you downloaded
     * │               └── updater-script       <--- Should only contain the string "#MAGISK"
     * │
     * ├── system
     * │   └── etc
     * │       └── security
     * │           └── cacerts
     * │               └── <subject_hash_old>.0 <--- The X509 root CA certificate of Heimdall
     * │
     * └── module.prop
     */
    suspend fun createMagiskModuleWithCertificate(
        context: Context,
        keyStore: KeyStore,
        authority: Authority
    ): String? {

        // required module information
        //TODO: make all of the information user-customisable
        val moduleId = "heimdall_ca_cert"
        val moduleName = "Heimdall CA Certificate Mounter"
        val moduleVersion = "0.1"
        val moduleVersionCode = 1
        val moduleAuthor = "tomcory"
        val moduleDescription = "Adds the root CA certificate of Heimdall to the system CA store"
        val moduleTemplate = 3

        return withContext(Dispatchers.IO) {
            // get the certificate from the keystore
            val x509Certificate = keyStore.getCertificate(authority.alias) as X509Certificate

            // create Magisk module folder structure inside app's internal cache directory
            val modulePath = File(context.cacheDir, moduleId).apply {
                if (!mkdirs()) {
                    // delete preexisting module folder
                    if (deleteRecursively()) {
                        Timber.d("Deleted existing module folder")
                        mkdirs()
                    } else {
                        Timber.e("Error creating module folder: could not delete existing folder")
                        return@withContext null
                    }

                }
            }

            val cacertsPath = File(modulePath, "system/etc/security/cacerts").apply { mkdirs() }
            val metaPath = File(modulePath, "META-INF/com/google/android").apply { mkdirs() }

            // export certificate to PEM file named <subject_old_hash>.0 and write it to system/etc/security/cacerts
            val pemFile = File(cacertsPath, "${calculateSubjectHashOld(x509Certificate)}.0")
            FileWriter(pemFile).use { fileWriter ->
                JcaPEMWriter(fileWriter).use { pemWriter ->
                    pemWriter.writeObject(x509Certificate)
                }
            }

            // create module.prop file with module information
            val modulePropContent = """
                |id=$moduleId
                |name=$moduleName
                |version=$moduleVersion
                |versionCode=$moduleVersionCode
                |author=$moduleAuthor
                |description=$moduleDescription
                |template=$moduleTemplate
                """.trimMargin()

            val modulePropFile = File(modulePath, "module.prop")
            FileWriter(modulePropFile).use { fileWriter ->
                fileWriter.write(modulePropContent)
            }

            // create update-binary containing the installer script
            val updateBinaryFile = File(metaPath, "update-binary")
            FileWriter(updateBinaryFile).use { fileWriter ->
                fileWriter.write(fetchUrlContent("https://raw.githubusercontent.com/topjohnwu/Magisk/master/scripts/module_installer.sh", defaultInstallerScript))
            }

            // create updater-script containing only the string "#MAGISK"
            val updaterScriptFile = File(metaPath, "updater-script")
            FileWriter(updaterScriptFile).use { fileWriter ->
                fileWriter.write("#MAGISK")
            }

            // create a .zip file from the Magisk module folder
            val zipFileName = "$moduleId-${moduleVersion.replace('.', '_')}.zip"
            val moduleZipFile = File(context.cacheDir, zipFileName)
            FileOutputStream(moduleZipFile).use { fileOutputStream ->
                ZipOutputStream(fileOutputStream).use { zipOutputStream ->
                    modulePath.walk().filter { it.isFile }.forEach { file ->
                        val entryName = file.relativeTo(modulePath).path
                        zipOutputStream.putNextEntry(ZipEntry(entryName))
                        file.inputStream().use { inputStream ->
                            inputStream.copyTo(zipOutputStream)
                        }
                        zipOutputStream.closeEntry()
                    }
                }
            }

            // delete Magisk module folder structure after creating the zip file
            modulePath.deleteRecursively()

            //return
            zipFileName
        }
    }

    /**
     * Exports just the X509 root CA certificate of Heimdall as a PEM-encoded `.crt` file written to
     * the app's internal cache directory.
     *
     * Unlike [createMagiskModuleWithCertificate], this produces a plain certificate file that the user
     * can install through Android's settings as a *User-installed* CA (Settings → Security → Encryption
     * & credentials → Install a certificate → CA certificate). This works on non-rooted devices, but
     * note that apps targeting Android 7+ (API 24) do not trust user-installed CAs by default unless they
     * opt in via a network security configuration.
     *
     * @return the name of the created file within the cache directory, or `null` if the export failed.
     */
    suspend fun exportRootCertificate(
        context: Context,
        keyStore: KeyStore,
        authority: Authority
    ): String? {
        return withContext(Dispatchers.IO) {
            try {
                // get the certificate from the keystore
                val x509Certificate = keyStore.getCertificate(authority.alias) as X509Certificate

                // export the root CA certificate to a PEM-encoded .crt file in the cache directory
                val certFileName = "${authority.alias}.crt"
                val certFile = File(context.cacheDir, certFileName)
                exportPem(certFile, x509Certificate)

                Timber.d("Exported root CA certificate to %s", certFile.absolutePath)

                certFileName
            } catch (e: Exception) {
                Timber.e(e, "Error exporting root CA certificate")
                null
            }
        }
    }

    private suspend fun fetchUrlContent(urlString: String, default: String = ""): String =
        withContext(Dispatchers.IO) {
            try {
                Timber.d("Fetching string resource from URL $urlString")
                URL(urlString).readText()
            } catch (e: Exception) {
                Timber.e("Error fetching string resource from URL, using default")
                default
            }
        }

    private val defaultInstallerScript = """
        |#!/sbin/sh
        |
        |#################
        |# Initialization
        |#################
        |
        |umask 022
        
        |# echo before loading util_functions
        |ui_print() { echo "${'$'}1"; }
        |
        |require_new_magisk() {
        |  ui_print "*******************************"
        |  ui_print " Please install Magisk v20.4+! "
        |  ui_print "*******************************"
        |  exit 1
        |}
        |
        |#########################
        |# Load util_functions.sh
        |#########################
        |
        |OUTFD=${'$'}2
        |ZIPFILE=${'$'}3
        |
        |mount /data 2>/dev/null
        |
        |[ -f /data/adb/magisk/util_functions.sh ] || require_new_magisk
        |. /data/adb/magisk/util_functions.sh
        |[ ${'$'}MAGISK_VER_CODE -lt 20400 ] && require_new_magisk
        |
        |install_module
        |exit 0
        """.trimMargin()
}