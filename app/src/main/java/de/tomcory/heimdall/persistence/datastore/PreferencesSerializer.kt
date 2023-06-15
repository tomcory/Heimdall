package de.tomcory.heimdall.persistence.datastore

import androidx.datastore.core.CorruptionException
import androidx.datastore.core.Serializer
import com.google.protobuf.InvalidProtocolBufferException
import de.tomcory.heimdall.Preferences
import timber.log.Timber
import java.io.InputStream
import java.io.OutputStream

object PreferencesSerializer : Serializer<Preferences> {
    override val defaultValue: Preferences = Preferences.newBuilder()
        .setVpnDnsServer("1.1.1.1")
        .setVpnBaseAddress("10.120.0.1/32")
        .setVpnRoute("0.0.0.0/0")
        .setVpnProxyAddress("127.0.0.1:9090")
        .addVpnBlacklistedApps("de.tomcory.heimdall")
        .setScanEnable(true)
        .setScanPermissionScannerEnable(true)
        .setScanLibraryScannerEnable(true)
        .setScanLibraryScannerPrepopulate(true)
        .build()

    override suspend fun readFrom(input: InputStream): Preferences {
        try {
            val t = Preferences.parseFrom(input)
            Timber.w("Reading from DataStore:\n%s", t.toString())
            return t
        } catch (exception: InvalidProtocolBufferException) {
            throw CorruptionException("Cannot read proto.", exception)
        }
    }

    override suspend fun writeTo(t: Preferences, output: OutputStream) {
        Timber.w("Writing to DataStore:\n%s", t.toString())
        t.writeTo(output)
    }
}