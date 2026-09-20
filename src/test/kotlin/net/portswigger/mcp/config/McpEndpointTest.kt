package net.portswigger.mcp.config

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class McpEndpointTest {
    @Test
    fun `endpoint normalizes numeric loopback and formats one canonical URL`() {
        val hosts = mapOf("127.0.0.1" to "127.0.0.1", "::1" to "[::1]", "[::1]" to "[::1]")
        hosts.forEach { (host, authority) ->
            listOf(1024, 9876, 65535).forEach { port ->
                val endpoint = McpEndpoint.from(" $host ", port)
                assertNull(ConfigValidation.validateServerConfig(host, port.toString()))
                assertEquals(authority.removeSurrounding("[", "]"), endpoint.host)
                assertEquals(port, endpoint.port)
                assertEquals("http://$authority:$port/mcp", endpoint.url)
            }
        }
    }

    @Test
    fun `runtime and UI reject the same out of policy ports`() {
        listOf(Int.MIN_VALUE, -1, 0, 1, 1023, 65536, Int.MAX_VALUE).forEach { port ->
            val uiError = ConfigValidation.validateServerConfig("127.0.0.1", port.toString())
            assertNotNull(uiError)
            val error = assertThrows<IllegalArgumentException> { McpEndpoint.from("127.0.0.1", port) }
            assertEquals(uiError, error.message)
        }
    }

    @Test
    fun `runtime and UI reject nonnumeric or nonloopback hosts without resolving them`() {
        listOf("", "localhost", "0.0.0.0", "::", "127.0.0.2", "example.invalid").forEach { host ->
            val uiError = ConfigValidation.validateServerConfig(host, "9876")
            assertNotNull(uiError)
            val error = assertThrows<IllegalArgumentException> { McpEndpoint.from(host, 9876) }
            assertEquals(uiError, error.message)
        }
    }
}
