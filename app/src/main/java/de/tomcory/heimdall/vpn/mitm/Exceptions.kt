package de.tomcory.heimdall.vpn.mitm

import java.lang.RuntimeException
import kotlin.Exception

class FakeCertificateException(message: String?, t: Throwable?) : RuntimeException(message, t)
class RootCertificateException(message: String?, t: Throwable?) : Exception(message, t)
class VpnComponentLaunchException(message: String?, t: Throwable?) : Exception(message, t)