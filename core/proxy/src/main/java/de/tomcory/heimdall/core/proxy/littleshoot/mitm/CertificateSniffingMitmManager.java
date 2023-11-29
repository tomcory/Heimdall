package de.tomcory.heimdall.core.proxy.littleshoot.mitm;

import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import de.tomcory.heimdall.core.proxy.littleshoot.MitmManager;

import de.tomcory.heimdall.core.util.ByteUtils;
import io.netty.handler.codec.http.HttpRequest;
import timber.log.Timber;

/**
 * {@link MitmManager} that uses the common name and subject alternative names
 * from the upstream certificate to create a dynamic certificate with it.
 */
public class CertificateSniffingMitmManager implements MitmManager {

    private BouncyCastleSslEngineSource sslEngineSource;

    public CertificateSniffingMitmManager() throws RootCertificateException {
        this(new Authority());
    }

    public CertificateSniffingMitmManager(Authority authority)
            throws RootCertificateException {
        try {
            sslEngineSource = new BouncyCastleSslEngineSource(authority, true, true);
        } catch (final Exception e) {
            throw new RootCertificateException(
                    "Errors during assembling root CA.", e);
        }
    }

    public SSLEngine serverSslEngine(String peerHost, int peerPort) {
        return sslEngineSource.newSslEngine(peerHost, peerPort);
    }

    public SSLEngine serverSslEngine() {
        return sslEngineSource.newSslEngine();
    }

    public SSLEngine clientSslEngineFor(HttpRequest httpRequest, SSLSession serverSslSession) {
        try {
            X509Certificate upstreamCert = getCertificateFromSession(serverSslSession);
            // TODO store the upstream cert by commonName to review it later

            // A reasons to not use the common name and the alternative names
            // from upstream certificate from serverSslSession to create the
            // dynamic certificate:
            //
            // It's not necessary. The host name is accepted by the browser.
            //
            String commonName = getCommonName(upstreamCert);

            SubjectAlternativeNameHolder san = new SubjectAlternativeNameHolder();

            san.addAll(upstreamCert.getSubjectAlternativeNames());

            Timber.d("Subject Alternative Names: $san");
            return sslEngineSource.createCertForHost(commonName, san);

        } catch (Exception e) {
            throw new FakeCertificateException(
                    "Creation dynamic certificate failed", e);
        }
    }

    private X509Certificate getCertificateFromSession(SSLSession sslSession)
            throws SSLPeerUnverifiedException {
        Certificate[] peerCerts = sslSession.getPeerCertificates();
        Certificate peerCert = peerCerts[0];
        if (peerCert instanceof X509Certificate) {
            return (X509Certificate) peerCert;
        }
        throw new IllegalStateException(
                "Required java.security.cert.X509Certificate, found: "
                        + peerCert);
    }

    public String getCommonName(X509Certificate c) {
        Timber.d("Subject DN principal name: ${c.getSubjectDN().getName()}");
        Timber.d("DN " + c.getSubjectX500Principal().getName() + " hash is " + ByteUtils.bytesToHex(ByteBuffer.allocate(4).putInt(c.getSubjectX500Principal().hashCode()).array()));
        for (String each : c.getSubjectDN().getName().split(",\\s*")) {
            if (each.startsWith("CN=")) {
                String result = each.substring(3);
                Timber.d("Common Name: $result");
                return result;
            }
        }
        throw new IllegalStateException("Missed CN in Subject DN: "
                + c.getSubjectDN());
    }
}
