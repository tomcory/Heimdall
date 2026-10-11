package de.tomcory.heimdall.core.vpn.connection.transportLayer

import org.junit.Assert.assertTrue
import org.junit.Test

class InitialSequenceNumberTest {

    @Test
    fun `initial sequence numbers use the full 32-bit range`() {
        val samples = List(2000) { TcpConnection.newInitialSequenceNumber() }

        assertTrue("every value is an unsigned 32-bit number", samples.all { it in 0L..0xFFFFFFFFL })
        // the old generator never went above 0x0FFFFFFF; a quarter or more of uniform samples land
        // above 0xC0000000
        assertTrue("values above 28 bits must occur", samples.any { it > 0x0FFFFFFFL })
        assertTrue("the upper quarter of the range must occur", samples.count { it >= 0xC0000000L } > 300)
        assertTrue("values must not repeat in a small sample", samples.toSet().size > 1990)
    }
}
