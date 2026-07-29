package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class StandardToolResultsTest {
    @Test
    fun `standard errors are single line and bounded after adding a prefix`() {
        val result = standardToolException(
            "Burp operation failed",
            IllegalStateException("first\nsecond\t" + "x".repeat(1000)),
        )

        assertTrue(result.length <= MAX_STANDARD_TOOL_ERROR_CHARS)
        assertFalse(result.any(Char::isISOControl))
        assertEquals("Burp operation failed: IllegalStateException", result)
    }

    @Test
    fun `standard exception errors never expose arbitrary exception messages`() {
        val token = "A".repeat(43)
        val result = standardToolException(
            "Burp operation failed",
            IllegalStateException("Authorization: Bearer $token at /home/user/private.json"),
        )

        assertFalse(result.contains(token))
        assertFalse(result.contains("/home/user/private.json"))
        assertEquals("Burp operation failed: IllegalStateException", result)
    }

    @Test
    fun `known messages are normalized without changing their meaning`() {
        assertEquals(
            "change may have occurred; do not retry automatically",
            boundedStandardToolError(" change may have occurred;\r\n do not retry automatically "),
        )
    }
}
