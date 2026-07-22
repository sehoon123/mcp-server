package net.portswigger.mcp.tools

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LegacyToolBoundsTest {
    @Test
    fun `safe regex accepts one bounded wildcard and rejects backtracking constructs`() {
        assertEquals("host.*path", validateSafeRegex("host.*path").pattern())
        assertThrows<IllegalArgumentException> { validateSafeRegex("(a+)+$") }
        assertThrows<IllegalArgumentException> { validateSafeRegex("a.*b.*c") }
        assertThrows<IllegalArgumentException> { validateSafeRegex("(a)\\1") }
        assertThrows<IllegalArgumentException> { validateSafeRegex("(?=secret)") }
    }

    @Test
    fun `legacy page output keeps complete records and emits explicit truncation metadata`() {
        val oversized = "x".repeat(MAX_LEGACY_PAGE_CHARS)
        val output = boundedLegacyPage(listOf<CharSequence>("first", oversized, "third").iterator())

        assertTrue(output.startsWith("first\n\n{"))
        assertTrue(output.contains("\"pageTruncated\":true"))
        assertTrue(output.contains("\"omittedItems\":2"))
        assertFalse(output.contains(oversized))
    }
}
