package net.portswigger.mcp

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import io.modelcontextprotocol.kotlin.sdk.server.StreamableHttpServerTransport
import kotlinx.coroutines.Job
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

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
    fun `registry updates pending active initialized and eviction diagnostics`() = runBlocking {
        val metrics = McpRuntimeMetrics("test", maxHttpCalls = 64, maxSessions = 1)
        val registry = BoundedMcpSessionRegistry(maxSessions = 1, idleMillis = 0, runtimeMetrics = metrics)
        val pending = assertNotNull(registry.reserve(transport()))
        assertEquals(1, metrics.snapshot().pendingSessions)

        registry.activate(pending, "diagnostic-session")
        assertEquals(0, metrics.snapshot().pendingSessions)
        assertEquals(1, metrics.snapshot().activeSessions)
        assertEquals(1, metrics.snapshot().initializedSessions)

        registry.evictIdle()
        assertEquals(0, metrics.snapshot().activeSessions)
        assertEquals(1, metrics.snapshot().idleEvictions)
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

    @Test
    fun `session removal cancels registered SSE handlers and rejects late registration`() {
        val registry = BoundedMcpSessionRegistry(maxSessions = 1, idleMillis = 60_000)
        val entry = assertNotNull(registry.reserve(transport()))
        registry.activate(entry, "stream-session")
        val streamJob = Job()

        assertTrue(entry.registerStream(streamJob))
        registry.remove(entry)

        assertTrue(streamJob.isCancelled)
        assertFalse(entry.registerStream(Job()))
    }

    private fun transport(): StreamableHttpServerTransport =
        mockk<StreamableHttpServerTransport>().also { coEvery { it.close() } returns Unit }
}
