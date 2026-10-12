package de.tomcory.heimdall.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The stored block list, a session's own hosts, and the text they are typed as. */
class BlockListResolverTest {

    @Test
    fun `stored and session hosts add up`() {
        val list = BlockListResolver.resolve(stored = listOf("tracker.net"), session = listOf("ads.example.com"))
        assertTrue(list.blocks("cdn.tracker.net", null))
        assertTrue(list.blocks("ads.example.com", null))
        assertFalse(list.blocks("example.com", null))
        assertEquals(listOf("tracker.net", "ads.example.com"), BlockListResolver.hosts(listOf("Tracker.net ", ""), listOf("ads.example.com", "tracker.net")))
    }

    @Test
    fun `without hosts nothing is blocked`() {
        assertTrue(BlockListResolver.resolve(emptyList(), emptyList()).isEmpty)
    }

    @Test
    fun `typed lists are split, lower-cased and deduplicated`() {
        assertEquals(listOf("ads.example.com", "*.tracker.net", "10.0.0.1", "2001:db8::1"), BlockListResolver.parse("Ads.Example.com, *.tracker.net ,10.0.0.1,2001:DB8::1,ads.example.com"))
        assertEquals(emptyList<String>(), BlockListResolver.parse(" , "))
        assertEquals(emptyList<String>(), BlockListResolver.parse(null))
    }

    @Test
    fun `a list with an entry that is no host is refused as a whole`() {
        assertNull(BlockListResolver.parse("example.com, http://example.org/"))
        assertNull(BlockListResolver.parse("exa mple.com"))
        assertNull(BlockListResolver.parse("example.com;other.com"))
    }
}
