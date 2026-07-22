package net.portswigger.mcp.config

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test

class ConfigUiTest {
    @Test
    fun `version label is conspicuous and bounded`() {
        assertEquals("Extension version: 4.0.1", formatMcpVersionLabel("4.0.1"))
        val sanitized = formatMcpVersionLabel("4.0.1\nBearer secret-value /home/user/file")
        assertFalse(sanitized.contains('\n'))
        assertFalse(sanitized.contains("secret-value"))
        assertFalse(sanitized.contains("/home/"))
        assertEquals("Extension version: unknown", formatMcpVersionLabel(""))
    }
}
