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
        assertTrue(result.startsWith("Burp operation failed: IllegalStateException: first second"))
    }

    @Test
    fun `standard exception errors retain safe logging redaction`() {
        val token = "A".repeat(43)
        val result = standardToolException(
            "Burp operation failed",
            IllegalStateException("Authorization: Bearer $token at /home/user/private.json"),
        )

        assertFalse(result.contains(token))
        assertFalse(result.contains("/home/user/private.json"))
        assertTrue(result.startsWith("Burp operation failed: IllegalStateException:"))
    }

    @Test
    fun `known messages are normalized without changing their meaning`() {
        assertEquals(
            "change may have occurred; do not retry automatically",
            boundedStandardToolError(" change may have occurred;\r\n do not retry automatically "),
        )
    }
}
