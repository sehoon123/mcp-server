package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.sitemap.SiteMap
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ScannerIssueReadTest {
    private val api = mockk<MontoyaApi>()
    private val project = mockk<Project>()
    private val siteMap = mockk<SiteMap>()
    private val logging = mockk<Logging>(relaxed = true)
    private lateinit var service: ScannerIssueReadService

    @BeforeEach
    fun setUp() {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns false
        every { storage.getString(any()) } returns ""
        every { api.project() } returns project
        every { project.id() } returns "project-123"
        every { api.siteMap() } returns siteMap
        every { api.logging() } returns logging
        service = ScannerIssueReadService(api, McpConfig(storage, logging))
    }

    @Test
    fun `metadata read reuses resolved Scanner identity`() = runBlocking {
        val issue = issue(7, "Identity", "detail-7")
        every { siteMap.issues() } returns listOf(issue)
        val id = issue.stableHistoryId(0)

        val result = service.read(
            GetScannerIssueById(
                projectId = "project-123",
                id = id,
                field = "metadata",
            )
        )

        assertEquals(HistoryReadStatus.OK, result.status)
        assertEquals(id, result.summary?.id)
        verify(exactly = 0) { issue.detail() }
        verify(exactly = 0) { issue.remediation() }
        verify(exactly = 0) { issue.requestResponses() }
    }

    @Test
    fun `evidence field without evidenceIndex fails with documented requirement`() = runBlocking {
        val issue = issue(12, "Evidence", "detail")
        every { siteMap.issues() } returns listOf(issue)
        val error = assertFailsWith<IllegalArgumentException> {
            service.read(
                GetScannerIssueById(
                    projectId = "project-123",
                    id = issue.stableHistoryId(0),
                    field = "evidence_request",
                ),
            )
        }

        assertTrue(error.message.orEmpty().contains("evidenceIndex is required"))
        verify(exactly = 0) { issue.requestResponses() }
    }

    @Test
    fun `oversized Scanner text field streams only the requested UTF-8 slice`() = runBlocking {
        val detail = "x".repeat(600 * 1024)
        val issue = issue(8, "Oversized", detail)
        every { siteMap.issues() } returns listOf(issue)
        val id = issue.stableHistoryId(0)

        val result = service.read(
            GetScannerIssueById(
                projectId = "project-123",
                id = id,
                field = "detail",
                limit = MAX_HISTORY_SLICE_BYTES,
            )
        )

        assertEquals(HistoryReadStatus.OK, result.status)
        assertEquals(MAX_HISTORY_SLICE_BYTES, result.content?.returnedBytes)
        assertEquals(600 * 1024, result.content?.totalBytes)
        assertEquals(true, result.content?.hasMore)
        assertEquals(MAX_HISTORY_SLICE_BYTES, result.content?.data?.length)
        assertTrue(result.error == null)
        verify(exactly = 1) { issue.detail() }
    }

    @Test
    fun `project transition after approval prevents Scanner source access`() = runBlocking {
        every { project.id() } returnsMany listOf("project-123", "project-after")
        val issue = issue(9, "Transition", "secret detail")
        val id = issue.stableHistoryId(0)

        val result = service.read(
            GetScannerIssueById(id = id, projectId = "project-123", field = "metadata")
        )

        assertEquals(HistoryReadStatus.PROJECT_MISMATCH, result.status)
        assertEquals("project-after", result.projectId)
        verify(exactly = 0) { siteMap.issues() }
        verify(exactly = 0) { issue.detail() }
    }

    @Test
    fun `unlocated Scanner ID rejects ambiguous bounded metadata`() = runBlocking {
        val first = issue(11, "Duplicate", "first detail")
        val second = issue(11, "Duplicate", "second detail")
        val id = first.stableHistoryId()
        every { siteMap.issues() } returns listOf(first, second)

        val result = service.read(
            GetScannerIssueById(id = id, projectId = "project-123", field = "detail")
        )

        assertEquals(HistoryReadStatus.NOT_FOUND, result.status)
        assertTrue(result.error.orEmpty().contains("ambiguous"))
        verify(exactly = 0) { first.detail() }
        verify(exactly = 0) { second.detail() }
    }

    @Test
    fun `indexed Scanner ID beyond scan bound resolves directly`() = runBlocking {
        val issue = issue(10, "Direct", "detail")
        val id = issue.stableHistoryId(MAX_SCANNER_ISSUE_SCAN)
        val issues = mockk<List<AuditIssue>>()
        every { issues.size } returns MAX_SCANNER_ISSUE_SCAN + 1
        every { issues[MAX_SCANNER_ISSUE_SCAN] } returns issue
        every { siteMap.issues() } returns issues

        val result = service.read(
            GetScannerIssueById(id = id, projectId = "project-123", field = "metadata")
        )

        assertEquals(HistoryReadStatus.OK, result.status)
        assertEquals(id, result.summary?.id)
        verify(exactly = 1) { issues[MAX_SCANNER_ISSUE_SCAN] }
        verify(exactly = 0) { issue.detail() }
    }

    private fun issue(typeIndex: Int, name: String, detail: String): AuditIssue {
        val issue = mockk<AuditIssue>()
        val definition = mockk<AuditIssueDefinition>()
        val httpService = mockk<HttpService>()
        every { issue.definition() } returns definition
        every { definition.typeIndex() } returns typeIndex
        every { issue.name() } returns name
        every { issue.baseUrl() } returns "https://example.test/$typeIndex"
        every { issue.httpService() } returns httpService
        every { httpService.host() } returns "example.test"
        every { httpService.port() } returns 443
        every { httpService.secure() } returns true
        every { issue.severity() } returns AuditIssueSeverity.HIGH
        every { issue.confidence() } returns AuditIssueConfidence.CERTAIN
        every { issue.detail() } returns detail
        every { issue.requestResponses() } returns emptyList()
        return issue
    }
}
