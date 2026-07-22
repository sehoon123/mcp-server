package net.portswigger.mcp.security

import org.junit.jupiter.api.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SafeLoggingTest {
    @Test
    fun `exception summaries are bounded single-line and redact credentials and paths`() {
        val secret = "abcdefghijklmnopqrstuvwxyz0123456789"
        val result = safeExceptionSummary(
            IllegalStateException(
                "Authorization: Bearer $secret token=$secret at /home/alice/private/config.json\r\nfor C:\\Users\\alice\\secret.txt"
            )
        )

        assertTrue(result.startsWith("IllegalStateException:"))
        assertTrue(result.contains("<redacted>"))
        assertTrue(result.contains("<path>"))
        assertFalse(result.contains(secret))
        assertFalse(result.contains('\n'))
        assertFalse(result.contains('\r'))
        assertTrue(result.length <= 384)
    }
}
