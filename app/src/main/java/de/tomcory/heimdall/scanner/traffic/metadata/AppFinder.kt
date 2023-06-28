package de.tomcory.heimdall.scanner.traffic.metadata

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import android.system.OsConstants
import androidx.annotation.RequiresApi
import timber.log.Timber
import java.io.*
import java.net.InetAddress
import java.net.InetSocketAddress

class AppFinder(
    context: Context?,
    private val tcp4File: File = File("/proc/net/tcp"),
    private val tcp6File: File = File("/proc/net/tcp6"),
    private val udp4File: File = File("/proc/net/udp"),
    private val udp6File: File = File("/proc/net/udp6")
) {

    private val pm: PackageManager? = context?.packageManager
    private val cm: ConnectivityManager? = context?.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager?

    fun getAppId(localAddress: InetAddress, remoteAddress: InetAddress, localPort: Int, remotePort: Int, protocol: Int): Int? {
        val aid = try {
            if(Build.VERSION.SDK_INT < Build.VERSION_CODES.Q)
                getAid(
                    localPort = localPort,
                    protocol = protocol)
            else
                getAidQ(
                    localAddress = localAddress,
                    remoteAddress = remoteAddress,
                    localPort = localPort,
                    remotePort = remotePort,
                    protocol = protocol)
        } catch (e: UnsupportedOperationException) {
            Timber.e(e)
            return null
        }
        return aid
    }

    fun getAppPackage(aid: Int?): String? {
        return if(aid != null && aid >= 0) pm?.getPackagesForUid(aid)?.get(0) else null
    }

    @RequiresApi(api = Build.VERSION_CODES.Q)
    private fun getAidQ(localAddress: InetAddress, remoteAddress: InetAddress, localPort: Int, remotePort: Int, protocol: Int): Int {

        if(protocol != OsConstants.IPPROTO_TCP && protocol != OsConstants.IPPROTO_UDP) {
            return -1
        }

        val local = InetSocketAddress(localAddress, localPort)
        val remote = InetSocketAddress(remoteAddress, remotePort)

        return cm?.getConnectionOwnerUid(protocol, local, remote) ?: -1
    }

    private fun getAid(localPort: Int, protocol: Int): Int {

        // select the relevant /proc/net files based on the connection's transport protocol
        //TODO: does the IP version matter (or do we always have to query both files)?
        val queryFiles = when(protocol) {
            OsConstants.IPPROTO_TCP -> arrayOf(tcp6File, tcp4File)
            OsConstants.IPPROTO_UDP -> arrayOf(udp6File, udp4File)
            else -> throw java.lang.UnsupportedOperationException("Unsupported transport protocol")
        }

        for (file in queryFiles) {

            // open a reader on the file
            val reader: BufferedReader = try {
                BufferedReader(FileReader(file))
            } catch (e: FileNotFoundException) {
                Timber.e(e, "Error opening /proc/net reader")
                return -1
            }

            // iterate over all entries to find one with a local port matching the supplied connection's
            try {
                for(line in reader.lines()) {
                    val splitLine = line.replace("[ ]{2,}".toRegex(), " ").trim { it <= ' ' }
                        .split(" ").toTypedArray()
                    val entryPort = splitLine[1].substring(splitLine[1].indexOf(':') + 1).toInt(16)
                    if (entryPort == localPort) {
                        return splitLine[7].toInt()
                    }
                }
            } catch (e: IOException) {
                Timber.e(e, "Error reading from /proc/net")
                return -1
            }
        }
        return -1
    }
}