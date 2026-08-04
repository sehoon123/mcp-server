package net.portswigger.mcp.tools

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class McpErrorPolicyTest {
    @Test
    fun `retained tool statuses preserve exact MCP error outcomes`() {
        assertPolicy(
            HttpMessageActionStatus.entries,
            10,
            setOf(
                HttpMessageActionStatus.OK,
                HttpMessageActionStatus.ACCESS_DENIED,
                HttpMessageActionStatus.ACTION_DENIED,
                HttpMessageActionStatus.REQUEST_UNAVAILABLE,
            ),
            { it.isMcpError() },
        )
        assertPolicy(
            HttpMessageReadStatus.entries,
            9,
            setOf(
                HttpMessageReadStatus.OK,
                HttpMessageReadStatus.ACCESS_DENIED,
                HttpMessageReadStatus.REQUEST_UNAVAILABLE,
                HttpMessageReadStatus.PART_UNAVAILABLE,
            ),
            { it.isMcpError() },
        )
        assertPolicy(
            HttpComparisonStatus.entries,
            9,
            setOf(
                HttpComparisonStatus.OK,
                HttpComparisonStatus.ACCESS_DENIED,
                HttpComparisonStatus.REQUEST_UNAVAILABLE,
                HttpComparisonStatus.PART_UNAVAILABLE,
            ),
            { it.isMcpError() },
        )
        assertPolicy(
            ScopeToolStatus.entries,
            10,
            setOf(
                ScopeToolStatus.OK,
                ScopeToolStatus.ACCESS_DENIED,
                ScopeToolStatus.ACTION_DENIED,
                ScopeToolStatus.REQUEST_UNAVAILABLE,
            ),
            { it.isMcpError() },
        )
        assertPolicy(
            ScannerAuditToolStatus.entries,
            12,
            setOf(
                ScannerAuditToolStatus.OK,
                ScannerAuditToolStatus.ACCESS_DENIED,
                ScannerAuditToolStatus.ACTION_DENIED,
                ScannerAuditToolStatus.REQUEST_UNAVAILABLE,
                ScannerAuditToolStatus.OUT_OF_SCOPE,
                ScannerAuditToolStatus.CAPACITY_EXCEEDED,
            ),
            { it.isMcpError() },
        )
        assertPolicy(
            HistoryReadStatus.entries,
            9,
            setOf(
                HistoryReadStatus.OK,
                HistoryReadStatus.ACCESS_DENIED,
                HistoryReadStatus.SCAN_LIMIT_REACHED,
                HistoryReadStatus.PART_UNAVAILABLE,
                HistoryReadStatus.FIELD_UNAVAILABLE,
            ),
            { it.isMcpError() },
        )
        assertPolicy(
            CollaboratorToolStatus.entries,
            6,
            setOf(
                CollaboratorToolStatus.OK,
                CollaboratorToolStatus.ACCESS_DENIED,
            ),
            { it.isMcpError() },
        )
        assertPolicy(
            HttpMessageSearchStatus.entries,
            7,
            setOf(
                HttpMessageSearchStatus.OK,
                HttpMessageSearchStatus.ACCESS_DENIED,
            ),
            { it.isMcpError() },
        )
        assertPolicy(
            WebSocketSearchStatus.entries,
            7,
            setOf(
                WebSocketSearchStatus.OK,
                WebSocketSearchStatus.ACCESS_DENIED,
            ),
            { it.isMcpError() },
        )
        assertPolicy(
            HttpAttackSurfaceStatus.entries,
            5,
            setOf(
                HttpAttackSurfaceStatus.OK,
                HttpAttackSurfaceStatus.ACCESS_DENIED,
            ),
            { it.isMcpError() },
        )
        assertPolicy(
            HttpActivityCorrelationStatus.entries,
            8,
            setOf(
                HttpActivityCorrelationStatus.OK,
                HttpActivityCorrelationStatus.ACCESS_DENIED,
                HttpActivityCorrelationStatus.REQUEST_UNAVAILABLE,
            ),
            { it.isMcpError() },
        )
        assertPolicy(
            HttpSessionAnalysisStatus.entries,
            8,
            setOf(
                HttpSessionAnalysisStatus.OK,
                HttpSessionAnalysisStatus.ACCESS_DENIED,
                HttpSessionAnalysisStatus.REQUEST_UNAVAILABLE,
            ),
            { it.isMcpError() },
        )
        assertPolicy(
            ScannerIssuePageStatus.entries,
            7,
            setOf(
                ScannerIssuePageStatus.OK,
                ScannerIssuePageStatus.ACCESS_DENIED,
            ),
            { it.isMcpError() },
        )
    }

    private fun <T : Enum<T>> assertPolicy(
        statuses: List<T>,
        expectedStatusCount: Int,
        ordinaryOutcomes: Set<T>,
        isMcpError: (T) -> Boolean,
    ) {
        val statusType = statuses.first().declaringJavaClass.simpleName
        assertEquals(
            expectedStatusCount,
            statuses.size,
            "$statusType changed; review every MCP error outcome explicitly",
        )
        statuses.forEach { status ->
            assertEquals(
                status !in ordinaryOutcomes,
                isMcpError(status),
                "$statusType.${status.name}",
            )
        }
    }
}
