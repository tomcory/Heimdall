package de.tomcory.heimdall.core.export.util

import org.junit.Assert.assertEquals
import org.junit.Test

class BodyTest {

    @Test
    fun `stored headers become pairs in their order`() {
        assertEquals(
            listOf("Host" to "example.com", "X-Time" to "12:30:00", "Empty" to "", "NoColon" to ""),
            headerPairs("Host: example.com\nX-Time: 12:30:00\n\nEmpty:\nNoColon")
        )
        assertEquals(emptyList<Pair<String, String>>(), headerPairs(""))
    }
}
