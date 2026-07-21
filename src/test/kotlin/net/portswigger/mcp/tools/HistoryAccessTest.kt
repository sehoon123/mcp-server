package net.portswigger.mcp.tools

import burp.api.montoya.http.HttpService
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class HistoryAccessTest {
    @Test
    fun `scanner issue IDs are deterministic and scoped to identity fields`() {
        val first = issue(detail = "first detail")
        val equivalent = issue(detail = "first detail")
        val changed = issue(detail = "changed detail")

        val firstId = first.stableHistoryId()
        assertEquals(firstId, equivalent.stableHistoryId())
        assertNotEquals(firstId, changed.stableHistoryId())
        assertTrue(firstId.matches(Regex("issue_[0-9a-f]{32}")))
        assertEquals(firstId, first.toHistorySummary().id)
    }

    @Test
    fun `history slice arguments are bounded`() {
        assertEquals(0, normalizeHistoryOffset(null))
        assertEquals(DEFAULT_HISTORY_SLICE_BYTES, normalizeHistoryLimit(null))
        assertEquals("metadata", normalizeHttpPart(null))
        assertEquals("response_body", normalizeHttpPart("response-body"))
        assertEquals("base64", normalizeHistoryEncoding("BASE64"))

        assertFailsWith<IllegalArgumentException> { normalizeHistoryOffset(-1) }
        assertFailsWith<IllegalArgumentException> { normalizeHistoryLimit(0) }
        assertFailsWith<IllegalArgumentException> { normalizeHistoryLimit(MAX_HISTORY_SLICE_BYTES + 1) }
        assertFailsWith<IllegalArgumentException> { normalizeHttpPart("everything") }
        assertFailsWith<IllegalArgumentException> { normalizeHistoryEncoding("hex") }
    }

    private fun issue(detail: String): AuditIssue {
        val issue = mockk<AuditIssue>()
        val service = mockk<HttpService>()
        val definition = mockk<AuditIssueDefinition>()
        every { issue.definition() } returns definition
        every { definition.typeIndex() } returns 0x1234
        every { issue.name() } returns "Example issue"
        every { issue.baseUrl() } returns "https://example.test/path"
        every { issue.httpService() } returns service
        every { service.host() } returns "example.test"
        every { service.port() } returns 443
        every { service.secure() } returns true
        every { issue.severity() } returns AuditIssueSeverity.HIGH
        every { issue.confidence() } returns AuditIssueConfidence.CERTAIN
        every { issue.detail() } returns detail
        every { issue.requestResponses() } returns emptyList()
        return issue
    }
}
