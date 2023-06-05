package de.tomcory.heimdall.vpn.mitm

import com.google.common.cache.Cache
import com.google.common.cache.CacheBuilder
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import timber.log.Timber
import org.bouncycastle.operator.OperatorCreationException
import java.io.*
import java.lang.reflect.InvocationTargetException
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
     * when set to true, an InsecureTrustManager is used - generally not recommended
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

    fun newSSLSocket(): SSLSocket {
        return sslContext.socketFactory.createSocket() as SSLSocket
    }

    fun newSSLSocket(remoteHost: String, remotePort: Int): SSLSocket {
        return sslContext.socketFactory.createSocket(remoteHost, remotePort) as SSLSocket
    }

    fun newSSLEngine(remoteHost: String, remotePort: Int): SSLEngine {
        val sslEngine = sslContext.createSSLEngine(remoteHost, remotePort)
        sslEngine.useClientMode = true
        if (!tryHostNameVerificationJava7(sslEngine)) {
            Timber.d("Host Name Verification is not supported, causes insecure HTTPS connection")
        }
        filterWeakCipherSuites(sslEngine)
        return sslEngine
    }

    private fun tryHostNameVerificationJava7(sslEngine: SSLEngine): Boolean {
        for (method in SSLParameters::class.java.methods) {
            // method is available since Java 7
            if ("setEndpointIdentificationAlgorithm" == method.name) {
                val sslParams = SSLParameters()
                try {
                    method.invoke(sslParams, "HTTPS")
                } catch (e: IllegalAccessException) {
                    Timber.e(e, "SSLParameters#setEndpointIdentificationAlgorithm")
                    return false
                } catch (e: InvocationTargetException) {
                    Timber.e(e, "SSLParameters#setEndpointIdentificationAlgorithm")
                    return false
                }
                sslEngine.sslParameters = sslParams
                return true
            }
        }
        return false
    }

    @Throws(GeneralSecurityException::class, IOException::class)
    private fun initialiseSSLContext() {
        val ks = KeyStoreHelper.initialiseOrLoadKeyStore(
            authority
        )
        caCert = ks.getCertificate(authority.alias)
        caPrivateKey = ks.getKey(authority.alias, authority.password) as PrivateKey

        //TODO: can we get rid of the InsecureTrustManagerFactory (with the goal of eliminating Netty)?
        val trustManagers: Array<TrustManager> = if (trustAllServers) {
            //val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            //trustManagerFactory.init(ks)
            //trustManagerFactory.trustManagers //TODO: -> did this do the trick?
            InsecureTrustManagerFactory.INSTANCE.trustManagers
        } else {
            arrayOf(MergeTrustManager(ks))
        }
        val keyManagers: Array<KeyManager?> = if (sendCerts) {
            CertificateHelper.getKeyManagers(ks, authority)
        } else {
            arrayOfNulls(0)
        }
        sslContext = CertificateHelper.newClientContext(keyManagers, trustManagers)
        val sslEngine = sslContext.createSSLEngine()
        if (!tryHostNameVerificationJava7(sslEngine)) {
            Timber.w("Host Name Verification is not supported, causes insecure HTTPS connection to upstream servers.")
        }
    }

    /**
     * Generates an 1024 bit RSA key pair using SHA1PRNG. Thoughts: 2048 takes
     * much longer time on older CPUs. And for almost every client, 1024 is
     * sufficient.
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