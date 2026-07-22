package net.portswigger.mcp

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import io.modelcontextprotocol.kotlin.sdk.server.StreamableHttpServerTransport
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class BoundedMcpSessionRegistryTest {
    @Test
    fun `capacity is reclaimed and shutdown closes active and pending transports exactly once`() = runBlocking {
        val firstTransport = transport()
        val secondTransport = transport()
        val thirdTransport = transport()
        val registry = BoundedMcpSessionRegistry(maxSessions = 2, idleMillis = 60_000)
        val first = assertNotNull(registry.reserve(firstTransport))
        val pending = assertNotNull(registry.reserve(secondTransport))
        assertNull(registry.reserve(thirdTransport))
        registry.activate(first, "session-one")

        registry.closeAll()
        registry.closeAll()

        coVerify(exactly = 1) { firstTransport.close() }
        coVerify(exactly = 1) { secondTransport.close() }
        coVerify(exactly = 0) { thirdTransport.close() }
        assertNull(registry.reserve(thirdTransport))
        // The pending entry remains safe to abandon after concurrent shutdown.
        registry.abandon(pending)
    }

    @Test
    fun `idle eviction removes an inactive session and returns its slot`() = runBlocking {
        val staleTransport = transport()
        val replacementTransport = transport()
        val registry = BoundedMcpSessionRegistry(maxSessions = 1, idleMillis = 0)
        val stale = assertNotNull(registry.reserve(staleTransport))
        registry.activate(stale, "stale-session")

        registry.evictIdle()

        coVerify(exactly = 1) { staleTransport.close() }
        assertNotNull(registry.reserve(replacementTransport))
        registry.closeAll()
        coVerify(exactly = 1) { replacementTransport.close() }
    }

    private fun transport(): StreamableHttpServerTransport =
        mockk<StreamableHttpServerTransport>().also { coEvery { it.close() } returns Unit }
}
