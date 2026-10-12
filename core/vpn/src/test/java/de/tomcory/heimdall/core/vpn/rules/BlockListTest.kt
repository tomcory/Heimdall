package de.tomcory.heimdall.core.vpn.rules

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BlockListTest {

    @Test
    fun `an empty list blocks nothing`() {
        assertTrue(BlockList.NONE.isEmpty)
        assertFalse(BlockList.NONE.blocks("example.com", "93.184.216.34"))
        assertTrue(BlockList(listOf(" ", "")).isEmpty)
    }

    @Test
    fun `entries match as domain suffixes, not as substrings`() {
        val list = BlockList(listOf("tracker.net", "*.Ads.Example.com."))
        assertTrue(list.blocks("tracker.net", null))
        assertTrue(list.blocks("cdn.eu.tracker.net", null))
        assertTrue(list.blocks("ADS.example.com.", null))
        assertTrue(list.blocks("x.ads.example.com", null))
        assertFalse(list.blocks("nottracker.net", null))
        assertFalse(list.blocks("tracker.net.evil.org", null))
        assertFalse("a more specific entry must not match its parent", list.blocks("example.com", null))
    }

    @Test
    fun `an address entry matches that address, whatever the connection is called`() {
        val list = BlockList(listOf("10.1.2.3", "2001:DB8::1"))
        assertTrue(list.blocks(null, "10.1.2.3"))
        assertTrue(list.blocks("some.name", "10.1.2.3"))
        assertTrue(list.blocks(null, "2001:db8::1"))
        assertFalse(list.blocks(null, "10.1.2.30"))
        assertFalse(list.blocks(null, "110.1.2.3"))
    }

    @Test
    fun `a connection without a name is only blocked by its address`() {
        val list = BlockList(listOf("example.com"))
        assertFalse(list.blocks(null, "93.184.216.34"))
        assertFalse(list.blocks("", "93.184.216.34"))
        assertTrue(list.blocks("example.com", "93.184.216.34"))
    }

    @Test
    fun `the matcher is the one the MitM scope uses`() {
        val matcher = HostMatcher(listOf("example.com"))
        assertTrue(matcher.matches("api.example.com"))
        assertFalse(matcher.matches("badexample.com"))
        assertFalse(matcher.matches(""))
        assertFalse(HostMatcher(emptyList()).matches("example.com"))
    }
}
