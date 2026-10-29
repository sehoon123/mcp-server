package net.portswigger.mcp.config

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import net.portswigger.mcp.testPreferences
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HttpRateLimitConfigTest {
    @Test
    fun `rate limit defaults off and survives replacement project and config instances`() {
        val preferences = testPreferences()
        fun config() = McpConfig(mockk<PersistedObject>(relaxed = true), mockk<Logging>(relaxed = true), preferences)
        val original = config()
        assertFalse(original.httpRateLimitEnabled)
        assertEquals(10, original.httpRequestsPerSecond)
        original.httpRequestsPerSecond = 37
        original.httpRateLimitEnabled = true

        val reloaded = config()
        assertTrue(reloaded.httpRateLimitEnabled)
        assertEquals(37, reloaded.httpRequestsPerSecond)
        reloaded.resetPersistentApprovals()
        assertTrue(reloaded.httpRateLimitEnabled, "Approval reset must not disable traffic pacing")
    }

    @Test
    fun `invalid limits and failed writes do not publish changes or notify the runtime`() {
        val preferences = testPreferences()
        val config = McpConfig(mockk(relaxed = true), mockk(relaxed = true), preferences)
        var changes = 0
        val listener: () -> Unit = { changes++ }
        val handle = config.addHttpRateLimitChangeListener(listener)
        listOf(Int.MIN_VALUE, -1, 0, MAX_HTTP_REQUESTS_PER_SECOND + 1, Int.MAX_VALUE).forEach { value ->
            assertFailsWith<IllegalArgumentException> { config.httpRequestsPerSecond = value }
        }
        every { preferences.setBoolean(any(), any()) } throws IllegalStateException("unavailable")
        every { preferences.setInteger(any(), any()) } throws IllegalStateException("unavailable")
        assertFailsWith<IllegalStateException> { config.httpRateLimitEnabled = true }
        assertFailsWith<IllegalStateException> { config.httpRequestsPerSecond = 20 }
        assertFalse(config.httpRateLimitEnabled)
        assertEquals(10, config.httpRequestsPerSecond)
        assertEquals(0, changes)
        handle.remove()
    }

    @Test
    fun `rate changes notify and listener handles and config cleanup detach listeners`() {
        val config = McpConfig(mockk(relaxed = true), mockk(relaxed = true), testPreferences())
        var changes = 0
        val listener: () -> Unit = { changes++ }
        val handle = config.addHttpRateLimitChangeListener(listener)
        config.httpRateLimitEnabled = true
        config.httpRequestsPerSecond = 1
        config.httpRequestsPerSecond = MAX_HTTP_REQUESTS_PER_SECOND
        assertEquals(3, changes)
        handle.remove()
        config.httpRateLimitEnabled = false
        assertEquals(3, changes)
        config.addHttpRateLimitChangeListener(listener)
        config.cleanup()
        config.httpRateLimitEnabled = true
        assertEquals(3, changes)
    }

    @Test
    fun `out of range saved rates are bounded instead of causing division by zero`() {
        val preferences = testPreferences()
        every { preferences.getInteger("independentMcpBridge.httpRequestsPerSecond.v1") } returns 0
        assertEquals(1, McpConfig(mockk(relaxed = true), mockk(relaxed = true), preferences).httpRequestsPerSecond)
        every { preferences.getInteger("independentMcpBridge.httpRequestsPerSecond.v1") } returns Int.MAX_VALUE
        assertEquals(MAX_HTTP_REQUESTS_PER_SECOND,
            McpConfig(mockk(relaxed = true), mockk(relaxed = true), preferences).httpRequestsPerSecond)
    }
}
