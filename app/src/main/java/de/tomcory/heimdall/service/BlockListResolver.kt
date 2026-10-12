package de.tomcory.heimdall.service

import de.tomcory.heimdall.core.vpn.rules.BlockList

/**
 * Turns the stored block list and the hosts a session was started with into the [BlockList] the
 * VPN applies. Kept free of Android dependencies so it can be unit tested.
 */
object BlockListResolver {

    // a hostname, optionally with a leading "*.", or an IPv4 or IPv6 literal
    private val HOST_PATTERN = Regex("(\\*\\.)?[a-z0-9]([a-z0-9._-]*[a-z0-9])?\\.?|[0-9a-f:.]+")

    /**
     * @param stored The user's block list (the `vpnBlockedHosts` preference).
     * @param session The hosts of this session only, see [CaptureSessionOptions.blockHosts].
     */
    fun resolve(stored: List<String>, session: List<String>): BlockList = BlockList(hosts(stored, session))

    /** The hosts of both lists, without repetitions. */
    fun hosts(stored: List<String>, session: List<String>): List<String> =
        (stored + session).map { it.trim().lowercase() }.filter { it.isNotEmpty() }.distinct()

    /**
     * Splits a list of hosts separated by commas, as typed into the preference or passed from adb.
     *
     * @return the hosts in lower case without repetitions, or null if one of them is neither a
     * hostname nor an IP address. Nothing is dropped silently: a mistyped host must not leave
     * the user with a list that lacks it.
     */
    fun parse(text: String?): List<String>? {
        val hosts = text?.split(',')?.map { it.trim().lowercase() }?.filter { it.isNotEmpty() }?.distinct() ?: emptyList()
        return if (hosts.all { HOST_PATTERN.matches(it) }) hosts else null
    }
}
