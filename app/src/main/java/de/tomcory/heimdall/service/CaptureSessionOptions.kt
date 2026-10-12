package de.tomcory.heimdall.service

/**
 * What a capture started from adb asks for beyond the stored preferences. Everything here applies
 * to that one session and changes no preference. Kept free of Android dependencies so it can be
 * unit tested.
 *
 * @param tag A label stored with the session and written into its exports, or null.
 * @param apps If not empty, only these packages are routed through the VPN, whatever the stored
 * monitoring scope says.
 * @param blockHosts Hosts blocked in addition to the stored block list.
 * @param mitm Whether the session intercepts TLS, or null to follow the preference.
 * @param quicPolicy The QUIC policy, see [QuicPolicyResolver], or null to follow the preference.
 */
data class CaptureSessionOptions(
    val tag: String? = null,
    val apps: List<String> = emptyList(),
    val blockHosts: List<String> = emptyList(),
    val mitm: Boolean? = null,
    val quicPolicy: String? = null
) {

    /** A value of an adb extra that cannot be used; [reason] goes into the command's result. */
    class InvalidOptionException(val reason: String) : IllegalArgumentException(reason)

    companion object {
        /** The session without any options: the stored preferences apply. */
        val NONE = CaptureSessionOptions()

        const val MAX_TAG_LENGTH = 64

        private val TAG_PATTERN = Regex("[A-Za-z0-9._:-]+")
        private val PACKAGE_PATTERN = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")
        // a hostname, optionally with a leading "*.", or an IPv4 or IPv6 literal
        private val HOST_PATTERN = Regex("(\\*\\.)?[a-z0-9]([a-z0-9._-]*[a-z0-9])?\\.?|[0-9a-f:.]+")

        /**
         * @param apps Package names separated by commas.
         * @param blockHosts Hosts separated by commas.
         * @throws InvalidOptionException for a value that is not what its option takes. Nothing is
         * dropped silently: a caller that mistypes a host must not get a capture without the block.
         */
        fun parse(tag: String?, apps: String?, blockHosts: String?, mitm: Boolean?, quicPolicy: String?): CaptureSessionOptions {
            val cleanTag = tag?.trim()?.takeIf { it.isNotEmpty() }
            if (cleanTag != null && (cleanTag.length > MAX_TAG_LENGTH || !TAG_PATTERN.matches(cleanTag))) {
                throw InvalidOptionException("invalid_tag")
            }
            val packages = split(apps)
            if (packages.any { !PACKAGE_PATTERN.matches(it) }) {
                throw InvalidOptionException("invalid_apps")
            }
            val hosts = split(blockHosts).map { it.lowercase() }
            if (hosts.any { !HOST_PATTERN.matches(it) }) {
                throw InvalidOptionException("invalid_block_hosts")
            }
            val policy = quicPolicy?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
            if (policy != null && policy != QuicPolicyResolver.OVERRIDE_BLOCK && policy != QuicPolicyResolver.OVERRIDE_PASSTHROUGH) {
                throw InvalidOptionException("invalid_quic_policy")
            }
            return CaptureSessionOptions(cleanTag, packages, hosts, mitm, policy)
        }

        private fun split(list: String?): List<String> =
            list?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }?.distinct() ?: emptyList()
    }
}
