package de.tomcory.heimdall.core.proxy.littleshoot.mitm;

public class RootCertificateException extends Exception {

    private static final long serialVersionUID = 1L;

    public RootCertificateException(String message, Throwable t) {
        super(message, t);
    }

}
