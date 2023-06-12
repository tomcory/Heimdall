package de.tomcory.heimdall.scanner.traffic.mitm

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.cert.bc.BcX509ExtensionUtils
import org.bouncycastle.cert.X509CertificateHolder
import android.os.Build
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import timber.log.Timber
import java.io.ByteArrayInputStream
import java.io.IOException
import java.math.BigInteger
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.*

object CertificateHelper {

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    private const val KEYGEN_ALGORITHM = "RSA"
    private const val SECURE_RANDOM_ALGORITHM = "SHA1PRNG"

    private const val PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME

    /**
     * The signature algorithm starting with the message digest to use when
     * signing certificates. On 64-bit systems this should be set to SHA512, on
     * 32-bit systems this is SHA256. On 64-bit systems, SHA512 generally
     * performs better than SHA256; see this question for details:
     * http://crypto.stackexchange.com/questions/26336/sha512-faster-than-sha256
     */
    private val SIGNATURE_ALGORITHM = (if (is32BitJvm()) "SHA256" else "SHA512") + "WithRSAEncryption"

    /** Size of the keypair used for the root CA certificate */
    private const val ROOT_KEY_SIZE = 2048

    /** Size of the keypairs used for fake server certificates */
    private const val FAKE_KEY_SIZE = 2048

    /** The milliseconds of a day  */
    private const val ONE_DAY = 86400000L

    /**
     * Current time minus 1 year, just in case software clock goes back due to
     * time synchronization
     */
    private val NOT_BEFORE = Date(System.currentTimeMillis() - ONE_DAY * 365)

    /**
     * The maximum possible value in X.509 specification: 9999-12-31 23:59:59,
     * new Date(253402300799000L), but Apple iOS 8 fails with a certificate
     * expiration date grater than Mon, 24 Jan 6084 02:07:59 GMT (issue #6).
     *
     * Hundred years in the future from starting the proxy should be enough.
     */
    private val NOT_AFTER = Date(System.currentTimeMillis() + ONE_DAY * 365)

    /**
     * Enforce TLS 1.2 if available, since it's not default up to Java 8.
     *
     *
     * Java 7 disables TLS 1.1 and 1.2 for clients. From [Java Cryptography Architecture Oracle Providers Documentation:](http://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html)
     * Although SunJSSE in the Java SE 7 release supports TLS 1.1 and TLS 1.2,
     * neither version is enabled by default for client connections. Some
     * servers do not implement forward compatibility correctly and refuse to
     * talk to TLS 1.1 or TLS 1.2 clients. For interoperability, SunJSSE does
     * not enable TLS 1.1 or TLS 1.2 by default for client connections.
     */
    private const val SSL_CONTEXT_PROTOCOL = "TLSv1.2"

    @JvmStatic
    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        IOException::class,
        OperatorCreationException::class,
        CertificateException::class,
        KeyStoreException::class
    )
    fun createRootCertificate(
        authority: Authority,
        keyStoreType: String?
    ): KeyStore {

        // generate a 2048-bit public/private key pair to use with the certificate
        val keyPair: KeyPair = generateKeyPair(ROOT_KEY_SIZE)

        // create a X509 name to represent the issuer (we're our own issuer, yay!)
        val issuer = X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.CN, authority.issuerCN)
            .addRDN(BCStyle.O, authority.issuerO)
            .addRDN(BCStyle.OU, authority.issuerOU)
            .build()

        // create a serial number for the certificate
        val serial = BigInteger.valueOf(initRandomSerial())

        // prepare the builder for the certificate
        val certificateBuilder: X509v3CertificateBuilder = JcaX509v3CertificateBuilder(
            issuer,
            serial,
            NOT_BEFORE,
            NOT_AFTER,
            issuer, // subject = issuer in this case, since we're issuing our own certificate
            keyPair.public)

        // add the Subject Key Identifier extension to the certificate
        certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(keyPair.public))

        // add the Basic Constraints extension to the certificate
        certificateBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))

        // add the Key Usage extension to the certificate
        val usage = KeyUsage(KeyUsage.keyCertSign
                    or KeyUsage.digitalSignature
                    or KeyUsage.keyEncipherment
                    or KeyUsage.dataEncipherment
                    or KeyUsage.cRLSign)
        certificateBuilder.addExtension(Extension.keyUsage, false, usage)

        // add the Extended Key Usage extension to the certificate
        val purposes = ASN1EncodableVector()
        purposes.add(KeyPurposeId.id_kp_serverAuth)
        purposes.add(KeyPurposeId.id_kp_clientAuth)
        purposes.add(KeyPurposeId.anyExtendedKeyUsage)
        certificateBuilder.addExtension(Extension.extendedKeyUsage, false, DERSequence(purposes))

        // generate the certificate and sign it with the private key
        val cert = signCertificate(certificateBuilder, keyPair.private)

        // store the certificate in our key store
        val result = KeyStore.getInstance(keyStoreType)
        result.load(null, null)
        result.setKeyEntry(authority.alias, keyPair.private, authority.password, arrayOf<Certificate>(cert))

        return result
    }

    @JvmStatic
    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        IOException::class,
        OperatorCreationException::class,
        CertificateException::class,
        InvalidKeyException::class,
        SignatureException::class,
        KeyStoreException::class
    )
    fun createServerCertificate(
        commonName: String?,
        subjectAlternativeNames: SubjectAlternativeNameHolder,
        authority: Authority,
        caCert: Certificate,
        caPrivateKey: PrivateKey
    ): KeyStore {

        // generate a 2048-bit public/private key pair to use with the certificate
        val keyPair = generateKeyPair(FAKE_KEY_SIZE)

        // the issuer of the server certificate is the subject of the CA certificate
        val issuer = X509CertificateHolder(caCert.encoded).subject

        // create a serial number for the certificate
        val serial = BigInteger.valueOf(initRandomSerial())

        // create a X509 name to represent the subject of the certificate
        val subject = X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.CN, commonName)
            .addRDN(BCStyle.O, authority.subjectO)
            .addRDN(BCStyle.OU, authority.subjectOU)
            .build()

        val certificateBuilder: X509v3CertificateBuilder = JcaX509v3CertificateBuilder(
            issuer,
            serial,
            NOT_BEFORE,
            Date(System.currentTimeMillis() + ONE_DAY),
            subject,
            keyPair.public
        )

        // add the Subject Key Identifier extension to the certificate
        certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(keyPair.public))

        // add the Basic Constraints extension to the certificate
        certificateBuilder.addExtension(Extension.basicConstraints, false, BasicConstraints(false))

        // add the subject's alternative names to the certificate
        subjectAlternativeNames.fillInto(certificateBuilder)

        // generate the certificate and sign it with the CA's private key
        val cert = signCertificate(certificateBuilder, caPrivateKey)

        // validate the certificate, throwing exceptions if anything is wrong
        cert.checkValidity(Date())
        cert.verify(caCert.publicKey)

        // store the certificate in our key store
        val result = KeyStore.getInstance(KeyStore.getDefaultType())
        result.load(null, null)
        val chain = arrayOf(cert, caCert) // chain of trust
        result.setKeyEntry(authority.alias, keyPair.private, authority.password, chain)

        return result
    }

    @JvmStatic
    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        UnrecoverableKeyException::class,
        KeyStoreException::class
    )
    fun getKeyManagers(keyStore: KeyStore?, authority: Authority): Array<KeyManager?> {
        val keyManagementAlgorithm = KeyManagerFactory.getDefaultAlgorithm()
        val kmf = KeyManagerFactory.getInstance(keyManagementAlgorithm)
        kmf.init(keyStore, authority.password)
        return kmf.keyManagers
    }

    @JvmStatic
    @Throws(
        NoSuchAlgorithmException::class,
        KeyManagementException::class,
        NoSuchProviderException::class
    )
    fun newClientContext(keyManagers: Array<KeyManager?>, trustManagers: Array<TrustManager>): SSLContext {
        val result = newSSLContext()
        result.init(keyManagers, trustManagers, null)
        return result
    }

    @JvmStatic
    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        KeyManagementException::class
    )
    fun newServerContext(keyManagers: Array<KeyManager?>): SSLContext {
        val result = newSSLContext()
        val random = SecureRandom()
        result.init(keyManagers, null, random)
        return result
    }

    /**
     * [SSLContext]: Every implementation of the Java platform is required
     * to support the following standard SSLContext protocol: TLSv1
     */
    private const val SSL_CONTEXT_FALLBACK_PROTOCOL = "TLSv1"

    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class
    )
    fun generateKeyPair(keySize: Int): KeyPair {
        val generator = KeyPairGenerator.getInstance(KEYGEN_ALGORITHM)
        val secureRandom = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM)
        generator.initialize(keySize, secureRandom)
        return generator.generateKeyPair()
    }

    /**
     * Uses the non-portable system property sun.arch.data.model to help
     * determine if we are running on a 32-bit JVM. Since the majority of modern
     * systems are 64 bits, this method "assumes" 64 bits and only returns true
     * if sun.arch.data.model explicitly indicates a 32-bit JVM.
     *
     * @return true if we can determine definitively that this is a 32-bit JVM,
     * otherwise false
     */
    private fun is32BitJvm(): Boolean {
        val bits = Integer.getInteger("sun.arch.data.model")
        return bits != null && bits == 32
    }

    @Throws(IOException::class)
    private fun createSubjectKeyIdentifier(key: Key): SubjectKeyIdentifier {
        val bIn = ByteArrayInputStream(key.encoded)
        ASN1InputStream(bIn).use { stream ->
            val seq = stream.readObject() as ASN1Sequence
            val info = SubjectPublicKeyInfo.getInstance(seq)
            return BcX509ExtensionUtils().createSubjectKeyIdentifier(info)
        }
    }

    @Throws(NoSuchAlgorithmException::class)
    private fun newSSLContext(): SSLContext {
        return try {
            Timber.d("Using protocol %s", SSL_CONTEXT_PROTOCOL)
            SSLContext.getInstance(SSL_CONTEXT_PROTOCOL)
        } catch (e: NoSuchAlgorithmException) {
            Timber.w("Protocol %s not available, falling back to %s", SSL_CONTEXT_PROTOCOL, SSL_CONTEXT_FALLBACK_PROTOCOL)
            SSLContext.getInstance(SSL_CONTEXT_FALLBACK_PROTOCOL)
        }
    }

    private fun initRandomSerial(): Long {
        val rnd = Random()
        rnd.setSeed(System.currentTimeMillis())
        // prevent browser certificate caches, cause of doubled serial numbers
        // using 48bit random number
        var sl = rnd.nextInt().toLong() shl 32 or (rnd.nextInt().toLong() and 0xFFFFFFFFL)
        // let reserve of 16 bit for increasing, serials have to be positive
        sl = sl and 0x0000FFFFFFFFFFFFL
        return sl
    }

    @Throws(
        OperatorCreationException::class,
        CertificateException::class
    )
    private fun signCertificate(
        certificateBuilder: X509v3CertificateBuilder,
        signedWithPrivateKey: PrivateKey
    ): X509Certificate {

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signer = JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .build(signedWithPrivateKey)
            JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer))
        } else {
            val signer = JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(PROVIDER_NAME)
                .build(signedWithPrivateKey)
            JcaX509CertificateConverter()
                .setProvider(PROVIDER_NAME)
                .getCertificate(certificateBuilder.build(signer))
        }
    }
}