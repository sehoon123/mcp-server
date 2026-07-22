package net.portswigger.mcp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class McpDiagnosticsTest {
    private val clock = Clock.fixed(Instant.parse("2026-07-22T00:00:00Z"), ZoneOffset.UTC)

    @Test
    fun `runtime metrics expose bounded secret-free counters`() {
        val metrics = McpRuntimeMetrics("2.1.1", 64, 32, clock)
        metrics.markStarting("http://127.0.0.1:9876/mcp")
        metrics.markRunning()
        repeat(3) { metrics.onRequest() }
        repeat(2) { metrics.onCallStarted() }
        metrics.onCallFinished()
        metrics.updateSessions(pending = 2, active = 3)
        repeat(3) { metrics.onSessionInitialized() }
        metrics.onIdleEvicted(2)
        metrics.onHostOriginRejected()
        metrics.onMetadataRejected()
        metrics.onAuthenticationRejected()
        metrics.onOverloadRejected()
        metrics.onSessionCapacityRejected()

        val snapshot = metrics.snapshot()
        assertEquals("running", snapshot.state)
        assertEquals("2.1.1", snapshot.serverVersion)
        assertEquals(PRODUCTION_MCP_PROTOCOL_VERSION, snapshot.protocolVersion)
        assertEquals("http://127.0.0.1:9876/mcp", snapshot.endpoint)
        assertEquals(clock.millis(), snapshot.startedAtEpochMillis)
        assertEquals(clock.millis(), snapshot.lastActivityEpochMillis)
        assertEquals(1, snapshot.activeHttpCalls)
        assertEquals(2, snapshot.peakHttpCalls)
        assertEquals(2, snapshot.pendingSessions)
        assertEquals(3, snapshot.activeSessions)
        assertEquals(3, snapshot.totalRequests)
        assertEquals(3, snapshot.initializedSessions)
        assertEquals(2, snapshot.idleEvictions)
        assertEquals(1, snapshot.hostOriginRejections)
        assertEquals(1, snapshot.metadataRejections)
        assertEquals(1, snapshot.authenticationRejections)
        assertEquals(1, snapshot.overloadRejections)
        assertEquals(1, snapshot.sessionCapacityRejections)
        assertNull(snapshot.lastError)
    }

    @Test
    fun `stop and failure clear live counts without erasing totals`() {
        val metrics = McpRuntimeMetrics("dev", 64, 32, clock)
        metrics.markStarting(null)
        metrics.markRunning()
        metrics.onRequest()
        metrics.onCallStarted()
        metrics.updateSessions(1, 1)
        metrics.markFailed("IllegalStateException: safe failure")

        val failed = metrics.snapshot()
        assertEquals("failed", failed.state)
        assertEquals(0, failed.activeHttpCalls)
        assertEquals(0, failed.pendingSessions)
        assertEquals(0, failed.activeSessions)
        assertEquals(1, failed.totalRequests)
        assertEquals("IllegalStateException: safe failure", failed.lastError)

        metrics.markStopped()
        assertEquals("stopped", metrics.snapshot().state)
    }
}
