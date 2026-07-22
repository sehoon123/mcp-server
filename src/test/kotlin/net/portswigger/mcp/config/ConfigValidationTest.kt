package net.portswigger.mcp.config

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class ConfigValidationTest {
    @Test
    fun `accepts only canonical numeric loopback bind addresses`() {
        assertEquals("127.0.0.1", ConfigValidation.normalizeLoopbackHost(" 127.0.0.1 "))
        assertEquals("::1", ConfigValidation.normalizeLoopbackHost("::1"))
        assertEquals("::1", ConfigValidation.normalizeLoopbackHost("[::1]"))

        listOf("localhost", "0.0.0.0", "::", "127.0.0.2", "example.com", "").forEach {
            assertNull(ConfigValidation.normalizeLoopbackHost(it), it)
        }
    }

    @Test
    fun `server validation rejects non-loopback hosts and privileged ports`() {
        assertNull(ConfigValidation.validateServerConfig("127.0.0.1", "9876"))
        assertNotNull(ConfigValidation.validateServerConfig("0.0.0.0", "9876"))
        assertNotNull(ConfigValidation.validateServerConfig("127.0.0.1", "443"))
    }
}
