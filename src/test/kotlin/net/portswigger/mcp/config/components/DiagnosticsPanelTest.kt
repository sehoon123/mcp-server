package net.portswigger.mcp.config.components

import net.portswigger.mcp.EdtWatchdogSnapshot
import net.portswigger.mcp.McpDiagnosticsSnapshot
import net.portswigger.mcp.providers.ProxyProvenance
import net.portswigger.mcp.tools.HISTORY_PERFORMANCE_BUCKET_COUNT
import net.portswigger.mcp.tools.HistoryPerformanceMetric
import net.portswigger.mcp.tools.HistoryPerformanceMetricSnapshot
import net.portswigger.mcp.tools.HistoryPerformanceSnapshot
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DiagnosticsPanelTest {
    @Test
    fun `diagnostics export contains provenance and counters but no credentials`() {
        val text = formatMcpDiagnostics(
            diagnostics = McpDiagnosticsSnapshot(
                state = "running",
                serverVersion = "2.1.1",
                protocolVersion = "2025-11-25",
                loadedArtifactSha256 = "a".repeat(64),
                endpoint = "http://127.0.0.1:9876/mcp",
                startedAtEpochMillis = 1_784_678_400_000,
                lastActivityEpochMillis = 1_784_678_401_000,
                activeHttpCalls = 1,
                peakHttpCalls = 4,
                pendingSessions = 2,
                activeSessions = 3,
                totalRequests = 10,
                initializedSessions = 3,
                idleEvictions = 1,
                hostOriginRejections = 2,
                metadataRejections = 3,
                authenticationRejections = 4,
                overloadRejections = 5,
                sessionCapacityRejections = 6,
                lastError = "Bearer secret-token at /home/user/error.log",
                maxHttpCalls = 64,
                maxSessions = 32,
                activeEventStreams = 1,
                openedEventStreams = 7,
                closedEventStreams = 6,
                reopenedEventStreams = 3,
                livenessPingsSent = 20,
                livenessResponses = 18,
                livenessTimeouts = 1,
                livenessErrors = 1,
                heartbeatFailures = 2,
                sessionDeleteRequests = 8,
                pressureEvictions = 9,
                sessionsWithApprovals = 2,
                sessionApprovalGrants = 5,
                webSocketSearchActive = 1,
                webSocketSearchCompleted = 11,
                webSocketSearchCancelled = 2,
                projectBoundaryResets = 2,
                initializedWithProtocol20250326 = 1,
                initializedWithProtocol20250618 = 2,
                initializedWithProtocol20251125 = 3,
                initializedWithOtherProtocol = 4,
                initializedWithoutProtocolHeader = 5,
                historyPerformance = HistoryPerformanceSnapshot(
                    HistoryPerformanceMetric.entries.mapIndexed { index, metric ->
                        HistoryPerformanceMetricSnapshot(
                            metric = metric,
                            active = index % 2,
                            attempts = (index + 1).toLong(),
                            completed = index.toLong(),
                            failed = 1,
                            cancelled = 0,
                            latencyBuckets = List(HISTORY_PERFORMANCE_BUCKET_COUNT) { bucket ->
                                (index + bucket).toLong()
                            },
                            totalNanos = 2_000_000L + index,
                            maxNanos = 1_000_000L + index,
                        )
                    },
                ),
            ),
            readOnlyMode = true,
            yoloMode = true,
            auditEnabled = true,
            auditEntries = 12,
            auditRetention = 250,
            proxyProvenance = ProxyProvenance(
                version = "2.1.0",
                commit = "f46c402adc54ee45aff9a0ffea371708d2b6b004",
                sha256 = "ef27202e253d8bc23b98aa2cd64bf3860dafb80d02e85468a8ff1ba7e8d47a82",
            ),
            proxyVerified = true,
            edtWatchdog = EdtWatchdogSnapshot(
                samples = 100,
                coalescedProbes = 3,
                delaysAtLeast100Millis = 7,
                delaysAtLeast250Millis = 2,
                delaysAtLeast1Second = 1,
                maxDelayMillis = 1_250,
            ),
        )

        assertTrue(text.contains("State: running"))
        assertTrue(text.contains("Loaded artifact SHA-256: ${"a".repeat(64)}"))
        assertTrue(text.contains("WebSocket search outcomes: active=1, completed=11, cancelled=2"))
        assertTrue(text.contains("HTTP calls: 1/64 active, peak 4"))
        assertEquals(HistoryPerformanceMetric.entries.size, text.lineSequence().count { it.startsWith("History ") })
        assertTrue(text.contains("History index Proxy acquisition: active=0, attempts=1"))
        assertTrue(text.contains("History WebSocket search processing: active=1, attempts=12"))
        assertTrue(text.contains("History related correlation Montoya acquisition:"))
        assertTrue(text.contains("History related correlation extension processing:"))
        assertTrue(text.contains("History Scanner delta Montoya acquisition:"))
        assertTrue(text.contains("History Scanner delta extension processing:"))
        assertTrue(text.contains("total=2000000ns, max=1000000ns"))
        assertTrue(text.contains("<1ms=0,<5ms=1"))
        assertTrue(text.contains(">=5000ms=10"))
        assertTrue(text.contains("Sessions: 3 active + 2 pending / 32"))
        assertTrue(text.contains("Session approvals: 5 grants across 2 active sessions"))
        assertTrue(text.contains("Project changes observed: 2"))
        assertTrue(
            text.contains(
                "Initialized session protocol requests: 2025-03-26=1, 2025-06-18=2, " +
                    "2025-11-25=3, other=4, not-reported=5"
            )
        )
        assertTrue(
            text.contains("Swing EDT delay: samples=100, coalesced=3, >=100ms=7, >=250ms=2, >=1s=1, max=1250ms, errors=0")
        )
        assertTrue(text.contains("Event streams: 1 active, 7 opened, 6 closed, 3 reopened"))
        assertTrue(text.contains("Liveness: pings=20, responses=18, timeouts=1, errors=1, heartbeat-failures=2"))
        assertTrue(text.contains("Session cleanup: DELETE=8, pressure-evictions=9, idle-evictions=1"))
        assertTrue(text.contains("auth=4"))
        assertTrue(text.contains("Emergency read-only: enabled"))
        assertTrue(text.contains("YOLO approval bypass: enabled"))
        assertTrue(text.contains("12/250 retained"))
        assertTrue(text.contains("f46c402adc54ee45aff9a0ffea371708d2b6b004"))
        assertFalse(text.contains("secret-token"))
        assertFalse(text.contains("token="))
        assertFalse(text.contains("C:\\"))
        assertFalse(text.contains("/home/"))
    }
}
