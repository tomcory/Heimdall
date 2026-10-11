package de.tomcory.heimdall.core.vpn.integration.support

import timber.log.Timber
import java.util.concurrent.CopyOnWriteArrayList

/**
 * A Timber tree that keeps every log line, for tests of what is (and is not) logged.
 * Plant it with [plant] and remove it with [uproot].
 */
class RecordingTree : Timber.Tree() {

    val lines = CopyOnWriteArrayList<String>()

    override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
        lines.add(message)
    }

    fun plant(): RecordingTree {
        Timber.plant(this)
        return this
    }

    fun uproot() {
        Timber.uproot(this)
    }

    fun anyContains(text: String): Boolean = lines.any { it.contains(text) }
}
