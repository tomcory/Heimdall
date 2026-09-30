package de.tomcory.heimdall.core.vpn.integration.support

import android.os.Handler
import android.os.Message
import de.tomcory.heimdall.core.util.AppFinder
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.components.DatabaseConnector
import de.tomcory.heimdall.core.vpn.metadata.DnsCache
import de.tomcory.heimdall.core.vpn.metadata.TlsPassthroughCache
import de.tomcory.heimdall.core.vpn.mitm.Authority
import de.tomcory.heimdall.core.vpn.mitm.CertificateSniffingMitmManager
import de.tomcory.heimdall.core.vpn.mitm.MitmScope
import io.mockk.every
import io.mockk.mockk
import java.io.File
import java.net.DatagramSocket
import java.net.Socket
import java.nio.channels.Selector
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Records every [Message] handed to a relaxed-mocked [Handler], standing in for the real
 * DeviceWriteThread's handler. TcpConnection/UdpConnection call `obtainMessage(what, obj)` then
 * `sendMessage(msg)`; both are stubbed here using a real [Message] instance (its no-arg
 * constructor is plain field init, safe under isReturnDefaultValues) so that `.what`/`.obj` are
 * preserved for inspection.
 */
class RecordingDeviceWriter {
    val handler: Handler = mockk(relaxed = true)
    val sentMessages = CopyOnWriteArrayList<Message>()

    init {
        every { handler.obtainMessage(any<Int>(), any()) } answers {
            Message().apply {
                what = firstArg<Int>()
                obj = secondArg<Any?>()
            }
        }
        every { handler.sendMessage(any()) } answers {
            sentMessages.add(firstArg<Message>())
            true
        }
    }
}

/**
 * Builds a [ComponentManager] test double: a `mockk(relaxed = true)` (which bypasses the real
 * constructor/init block via Objenesis, sidestepping the `Os.pipe()` NPE under
 * `isReturnDefaultValues = true`) with real collaborators wired in for everything the
 * transport/encryption/application layers actually touch.
 */
object ComponentManagerFixtures {

    fun buildTestComponentManager(
        keyStoreDir: File,
        doMitm: Boolean = true,
        databaseConnector: DatabaseConnector = RecordingDatabaseConnector(),
        appId: Int = 1000,
        appPackage: String = "com.example.test",
        labelAsTracker: Boolean = false,
        sessionId: Long = 1,
        maxPacketSize: Int = 16413,
        mitmScope: MitmScope = MitmScope.ALL,
        learnPassthrough: Boolean = true
    ): ComponentManager {
        val componentManager: ComponentManager = mockk(relaxed = true)

        val selector = Selector.open()
        val authority = Authority.getDefaultInstance(keyStoreDir)
        // trustAllServers=true: these tests connect to FakeTlsServer/other test doubles whose
        // certs are self-signed and not chained to any system-trusted CA - upstream cert
        // validation is orthogonal to what these tests exercise (MITM interception logic), so
        // this intentionally diverges from the strict production default (see PKT-07).
        val mitmManager = CertificateSniffingMitmManager(authority, trustAllServers = true)
        val dnsCache = DnsCache()
        val tlsPassthroughCache = TlsPassthroughCache()

        val appFinder: AppFinder = mockk(relaxed = true)
        every { appFinder.getAppId(any(), any(), any(), any(), any()) } returns appId
        every { appFinder.getAppPackage(any()) } returns appPackage

        every { componentManager.selector } returns selector
        every { componentManager.mitmManager } returns mitmManager
        every { componentManager.databaseConnector } returns databaseConnector
        every { componentManager.doMitm } returns doMitm
        every { componentManager.appFinder } returns appFinder
        every { componentManager.maxPacketSize } returns maxPacketSize
        every { componentManager.dnsCache } returns dnsCache
        every { componentManager.tlsPassthroughCache } returns tlsPassthroughCache
        // must be stubbed explicitly: a relaxed mock would return a MitmScope mock whose
        // shouldIntercept() is false, and false for learnPassthrough, silently disabling MitM
        every { componentManager.mitmScope } returns mitmScope
        every { componentManager.learnPassthrough } returns learnPassthrough
        every { componentManager.sessionId } returns sessionId
        every { componentManager.protectSocket } returns { _: Socket -> }
        every { componentManager.protectDatagramSocket } returns { _: DatagramSocket -> }
        every { componentManager.labelConnection(any()) } returns labelAsTracker

        return componentManager
    }
}
