package de.tomcory.heimdall.core.vpn.mitm

import com.google.common.cache.Cache
import com.google.common.cache.CacheBuilder
import timber.log.Timber
import org.bouncycastle.operator.OperatorCreationException
import java.io.*
import java.security.GeneralSecurityException
import java.security.PrivateKey
import java.security.cert.Certificate
import java.util.*
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import javax.net.ssl.*

/**
 * A SslEngineSource which creates a key store with a Root Certificate
 * Authority. The certificates are generated lazily if the given key store file
 * doesn't yet exist.
 *
 * The root certificate is exported in PEM format to be used in a browser. The
 * proxy application presents for every host a dynamically created certificate
 * to the browser, signed by this certificate authority.
 *
 * This facilitates the proxy to handle as a "Man In The Middle" to filter the
 * decrypted content in clear text.
 *
 * The hard part was done by mawoki. It's derived from Zed Attack Proxy (ZAP).
 * ZAP is an HTTP/HTTPS proxy for assessing web application security. Copyright
 * 2011 mawoki@ymail.com Licensed under the Apache License, Version 2.0
 */
class SSLEngineSource (

    /**
     * a parameter object to provide personal information of the
     * Certificate Authority and the dynamic certificates.
     */
    private val authority: Authority,

    /**
     * when set to true, [InsecureTrustManager] is used - generally not recommended
     * in production, but it's fine to use here because it's not our job to verify
     * remote hosts
     */
    private val trustAllServers: Boolean,

    /**
     * when set to true ???
     */
    private val sendCerts: Boolean,

    /**
     * a cache to store dynamically created server certificates.
     * Generation takes between 50 to 500ms, but only once per
     * thread, since there is a connection cache too. It's safe to
     * give a null cache to prevent memory or locking issues.
     */
    private val serverSSLContexts: Cache<String?, SSLContext>? = initDefaultCertificateCache()
) {

    private lateinit var sslContext: SSLContext
    private lateinit var caCert: Certificate
    private lateinit var caPrivateKey: PrivateKey

    init {
        initialiseSSLContext()
    }

    private fun filterWeakCipherSuites(sslEngine: SSLEngine) {
        val ciphers: MutableList<String> = LinkedList()
        for (each in sslEngine.enabledCipherSuites) {
            if (each == "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" || each == "TLS_DHE_RSA_WITH_AES_256_CBC_SHA") {
                Timber.d("Removed cipher %s", each)
            } else {
                ciphers.add(each)
            }
        }
        sslEngine.enabledCipherSuites = ciphers.toTypedArray()
    }

    fun newSSLEngine(clientMode: Boolean): SSLEngine {
        val sslEngine = sslContext.createSSLEngine()
        sslEngine.useClientMode = clientMode
        filterWeakCipherSuites(sslEngine)
        return sslEngine
    }

    fun newSSLEngine(remoteHost: String, remotePort: Int): SSLEngine {
        val sslEngine = sslContext.createSSLEngine(remoteHost, remotePort)
        sslEngine.useClientMode = true
        enableHostnameVerification(sslEngine)
        filterWeakCipherSuites(sslEngine)
        return sslEngine
    }

    /**
     * Makes [sslEngine] verify that the server's certificate matches the host it connects to,
     * keeping the engine's other parameters (docs/vpn-mitm-audit.md PKT-64). The method used to
     * be looked up by reflection, for Java 7, and replaced all parameters with a fresh set.
     */
    private fun enableHostnameVerification(sslEngine: SSLEngine) {
        sslEngine.sslParameters = sslEngine.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
    }

    @Throws(GeneralSecurityException::class, IOException::class)
    private fun initialiseSSLContext() {
        val ks = KeyStoreHelper.initialiseOrLoadKeyStore(
            authority
        )
        caCert = ks.getCertificate(authority.alias)
        caPrivateKey = ks.getKey(authority.alias, authority.password) as PrivateKey

        val trustManagers: Array<TrustManager> = if (trustAllServers) {
            arrayOf(InsecureTrustManager)
        } else {
            arrayOf(MergeTrustManager(ks))
        }
        val keyManagers: Array<KeyManager?> = if (sendCerts) {
            CertificateHelper.getKeyManagers(ks, authority)
        } else {
            arrayOfNulls(0)
        }
        sslContext = CertificateHelper.newClientContext(keyManagers, trustManagers)
    }

    /**
     * Returns a server-mode engine that presents a certificate for [commonName] and
     * [subjectAlternativeNames], forged and signed with the CA. The certificate's key is an RSA key
     * of [CertificateHelper]'s fake key size (2048 bits). The engine's context is cached per
     * common name.
     *
     * Derived from Zed Attack Proxy (ZAP). ZAP is an HTTP/HTTPS proxy for
     * assessing web application security. Copyright 2011 mawoki@ymail.com
     * Licensed under the Apache License, Version 2.0
     *
     * @param commonName
     * the common name to use in the server certificate
     *
     * @param subjectAlternativeNames
     * a List of the subject alternative names to use in the server
     * certificate, could be empty, but must not be null
     */
    @Throws(
        GeneralSecurityException::class,
        OperatorCreationException::class,
        IOException::class,
        ExecutionException::class
    )
    fun createCertForHost(commonName: String?, subjectAlternativeNames: SubjectAlternativeNameHolder?): SSLEngine {

        requireNotNull(commonName) { "Error, 'commonName' is not allowed to be null!" }
        requireNotNull(subjectAlternativeNames) { "Error, 'subjectAlternativeNames' is not allowed to be null!" }

        val ctx: SSLContext = if (serverSSLContexts == null) {
            createServerContext(commonName, subjectAlternativeNames)
        } else {
            //TODO: what is going on here?
            serverSSLContexts[commonName, Callable {
                createServerContext(commonName, subjectAlternativeNames)
            }]
        }
        return ctx.createSSLEngine()
    }

    @Throws(GeneralSecurityException::class, IOException::class, OperatorCreationException::class)
    private fun createServerContext(
        commonName: String,
        subjectAlternativeNames: SubjectAlternativeNameHolder
    ): SSLContext {

        // create a fake certificate with the commonName of the remote server, thus impersonating it
        val ks = CertificateHelper.createServerCertificate(
            commonName,
            subjectAlternativeNames,
            authority,
            caCert,
            caPrivateKey
        )

        // initialise a new SSLContext using the fake server certificate
        val result =
            CertificateHelper.newServerContext(CertificateHelper.getKeyManagers(ks, authority))

        Timber.d("Created fake certificate to impersonate %s", commonName)

        return result
    }

    companion object {

        private fun initDefaultCertificateCache(): Cache<String?, SSLContext> {
            return CacheBuilder.newBuilder()
                .expireAfterAccess(5, TimeUnit.MINUTES)
                .concurrencyLevel(16)
                .build()
        }
    }
}