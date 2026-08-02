package net.portswigger.mcp

import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class Utf8SizeTest {
    @Test
    fun `allocation-free limit check matches JDK UTF-8 encoding`() {
        val unpairedHigh = charArrayOf(0xD800.toChar()).concatToString()
        val unpairedLow = charArrayOf(0xDC00.toChar()).concatToString()
        val samples = listOf(
            "ascii",
            "café",
            "߿ࠀ€",
            "emoji-🚀",
            "unpaired-high-$unpairedHigh",
            "unpaired-low-$unpairedLow",
            "mixed-${unpairedHigh}x$unpairedLow",
        )

        for (sample in samples) {
            val encodedBytes = sample.toByteArray(StandardCharsets.UTF_8).size.toLong()
            assertFalse(sample.exceedsUtf8ByteLimit(encodedBytes), sample)
            assertTrue(sample.exceedsUtf8ByteLimit(encodedBytes - 1), sample)
        }
    }

    @Test
    fun `limit check stops at the exact byte boundary`() {
        val limit = 512 * 1024L
        assertFalse("a".repeat(limit.toInt()).exceedsUtf8ByteLimit(limit))
        assertTrue(("a".repeat(limit.toInt()) + "b").exceedsUtf8ByteLimit(limit))
        assertEquals(4, "🚀".toByteArray(StandardCharsets.UTF_8).size)
        assertFalse("🚀".exceedsUtf8ByteLimit(4))
        assertTrue("🚀".exceedsUtf8ByteLimit(3))
        assertFailsWith<IllegalArgumentException> { "x".exceedsUtf8ByteLimit(-1) }
    }
}
