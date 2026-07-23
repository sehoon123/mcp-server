package net.portswigger.mcp.config.components

import net.portswigger.mcp.McpDiagnosticsSnapshot
import net.portswigger.mcp.providers.ProxyProvenance
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
            ),
            readOnlyMode = true,
            auditEnabled = true,
            auditEntries = 12,
            auditRetention = 250,
            proxyProvenance = ProxyProvenance(
                version = "2.1.0",
                commit = "f46c402adc54ee45aff9a0ffea371708d2b6b004",
                sha256 = "ef27202e253d8bc23b98aa2cd64bf3860dafb80d02e85468a8ff1ba7e8d47a82",
            ),
            proxyVerified = true,
        )

        assertTrue(text.contains("State: running"))
        assertTrue(text.contains("HTTP calls: 1/64 active, peak 4"))
        assertTrue(text.contains("Sessions: 3 active + 2 pending / 32"))
        assertTrue(text.contains("Session approvals: 5 grants across 2 active sessions"))
        assertTrue(text.contains("Event streams: 1 active, 7 opened, 6 closed, 3 reopened"))
        assertTrue(text.contains("Liveness: pings=20, responses=18, timeouts=1, errors=1, heartbeat-failures=2"))
        assertTrue(text.contains("Session cleanup: DELETE=8, pressure-evictions=9, idle-evictions=1"))
        assertTrue(text.contains("auth=4"))
        assertTrue(text.contains("Emergency read-only: enabled"))
        assertTrue(text.contains("12/250 retained"))
        assertTrue(text.contains("f46c402adc54ee45aff9a0ffea371708d2b6b004"))
        assertFalse(text.contains("secret-token"))
        assertFalse(text.contains("token="))
        assertFalse(text.contains("C:\\"))
        assertFalse(text.contains("/home/"))
    }
}
