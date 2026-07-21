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
import io.mockk.*
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.util.HexFormat
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ScannerIssueSearchTest {
    private val api = mockk<MontoyaApi>()
    private val project = mockk<Project>()
    private val siteMap = mockk<SiteMap>()
    private val logging = mockk<Logging>(relaxed = true)
    private lateinit var service: ScannerIssueSearchService
    private lateinit var config: McpConfig
    private lateinit var originalDataHandler: DataAccessApprovalHandler

    @BeforeEach
    fun setUp() {
        originalDataHandler = DataAccessSecurity.approvalHandler
        every { api.project() } returns project
        every { project.id() } returns "project-123"
        every { api.siteMap() } returns siteMap
        config = config(false)
        service = ScannerIssueSearchService(api, config, ByteArray(32) { it.toByte() })
    }

    @AfterEach
    fun tearDown() {
        DataAccessSecurity.approvalHandler = originalDataHandler
    }

    @Test
    fun `streamed Scanner issue identity preserves the established stable ID format`() {
        val issue = issue(7, "Identity", "example.test", AuditIssueSeverity.HIGH)
        val canonical = listOf(
            "7",
            "Identity",
            "https://example.test/7",
            "example.test",
            "443",
            "true",
            "HIGH",
            "CERTAIN",
            "detail-7",
        ).joinToString("\u0000")
        val digest = MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray())
        val expected = "issue_" + HexFormat.of().formatHex(digest, 0, 16)

        assertEquals(expected, issue.stableHistoryId())
    }

    @Test
    fun `legacy offset mode serializes only selected Scanner issues`() = runBlocking {
        val skipped = issue(1, "Skipped", "one.example", AuditIssueSeverity.LOW)
        val selected = issue(2, "Selected", "two.example", AuditIssueSeverity.HIGH)
        every { siteMap.issues() } returns listOf(skipped, selected)

        val result = service.get(GetScannerIssues(count = 1, offset = 1, summariesOnly = true))

        assertEquals(ScannerIssuePageStatus.OK, result.output.status)
        assertTrue(result.output.legacyMode)
        assertEquals(listOf("Selected"), result.output.items.map { it.name })
        assertTrue(result.text.orEmpty().contains("Selected"))
        verify(exactly = 0) { skipped.name() }
    }

    @Test
    fun `cursor mode filters severity host and name before returning compact summaries`() = runBlocking {
        val issues = listOf(
            issue(1, "Old API finding", "api.example", AuditIssueSeverity.HIGH),
            issue(2, "Low API finding", "api.example", AuditIssueSeverity.LOW),
            issue(3, "New API finding", "api.example", AuditIssueSeverity.HIGH),
            issue(4, "Other", "other.example", AuditIssueSeverity.HIGH),
        )
        every { siteMap.issues() } returns issues

        val result = service.get(
            GetScannerIssues(
                count = 10,
                severities = listOf(ScannerIssueSeverityFilter.HIGH),
                host = "API.EXAMPLE.",
                nameContains = "api",
            )
        )

        assertEquals(ScannerIssuePageStatus.OK, result.output.status)
        assertEquals(listOf("New API finding", "Old API finding"), result.output.items.map { it.name })
        assertTrue(result.output.items.all { it.evidenceCount == 0 })
        assertTrue(!result.output.legacyMode)
    }

    @Test
    fun `signed cursor continues an append-only snapshot without exposing appended issues`() = runBlocking {
        val first = issue(1, "One", "example.test", AuditIssueSeverity.LOW)
        val second = issue(2, "Two", "example.test", AuditIssueSeverity.LOW)
        val third = issue(3, "Three", "example.test", AuditIssueSeverity.LOW)
        val appended = issue(4, "Appended", "example.test", AuditIssueSeverity.LOW)
        val current = mutableListOf(first, second, third)
        every { siteMap.issues() } answers { current.toList() }

        val page1 = service.get(
            GetScannerIssues(count = 1, cursorMode = true, newestFirst = false)
        ).output
        assertEquals(listOf("One"), page1.items.map { it.name })
        assertNotNull(page1.nextCursor)

        current += appended
        val page2 = service.get(GetScannerIssues(count = 1, cursor = page1.nextCursor)).output
        assertEquals(ScannerIssuePageStatus.OK, page2.status)
        assertEquals(listOf("Two"), page2.items.map { it.name })
        assertEquals(3, page2.snapshotSize)

        clearMocks(siteMap, answers = false, recordedCalls = true)
        val tampered = (if (page1.nextCursor!!.first() == 'A') "B" else "A") + page1.nextCursor!!.drop(1)
        val invalid = service.get(GetScannerIssues(cursor = tampered)).output
        assertEquals(ScannerIssuePageStatus.INVALID_CURSOR, invalid.status)
        val restarted = ScannerIssueSearchService(api, config, ByteArray(32) { 99 })
            .get(GetScannerIssues(cursor = page1.nextCursor)).output
        assertEquals(ScannerIssuePageStatus.INVALID_CURSOR, restarted.status)
        verify(exactly = 0) { siteMap.issues() }
    }

    @Test
    fun `cursor fails closed when original issue ordering changes`() = runBlocking {
        val first = issue(1, "One", "example.test", AuditIssueSeverity.LOW)
        val second = issue(2, "Two", "example.test", AuditIssueSeverity.LOW)
        val third = issue(3, "Three", "example.test", AuditIssueSeverity.LOW)
        var current = listOf(first, second, third)
        every { siteMap.issues() } answers { current }

        val page1 = service.get(GetScannerIssues(count = 1, cursorMode = true, newestFirst = false)).output
        current = listOf(second, first, third)
        val page2 = service.get(GetScannerIssues(count = 1, cursor = page1.nextCursor)).output

        assertEquals(ScannerIssuePageStatus.STALE_CURSOR, page2.status)
    }

    @Test
    fun `cursor rejects conflicting explicit filters`() = runBlocking {
        every { siteMap.issues() } returns listOf(
            issue(1, "One", "example.test", AuditIssueSeverity.HIGH),
            issue(2, "Two", "example.test", AuditIssueSeverity.HIGH),
        )
        val page1 = service.get(
            GetScannerIssues(
                count = 1,
                severities = listOf(ScannerIssueSeverityFilter.HIGH),
            )
        ).output

        val page2 = service.get(
            GetScannerIssues(
                count = 1,
                cursor = page1.nextCursor,
                severities = listOf(ScannerIssueSeverityFilter.LOW),
            )
        ).output

        assertEquals(ScannerIssuePageStatus.INVALID_CURSOR, page2.status)
    }

    @Test
    fun `Scanner issue access denial returns no project data`() = runBlocking {
        config = config(true)
        service = ScannerIssueSearchService(api, config, ByteArray(32) { 7 })
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean = false
        }

        val result = service.get(GetScannerIssues()).output

        assertEquals(ScannerIssuePageStatus.ACCESS_DENIED, result.status)
        assertTrue(result.items.isEmpty())
        verify(exactly = 0) { siteMap.issues() }
        verify(exactly = 0) { project.id() }
    }

    @Test
    fun `legacy full issue text is capped and advertises truncation`() = runBlocking {
        val issue = issue(1, "Large", "example.test", AuditIssueSeverity.HIGH)
        every { issue.detail() } returns "x".repeat(600 * 1024)
        every { siteMap.issues() } returns listOf(issue)

        val result = service.get(GetScannerIssues(count = 1, summariesOnly = false))

        assertEquals(ScannerIssuePageStatus.OK, result.output.status)
        assertTrue(result.output.legacyTextTruncated)
        assertTrue(result.text.orEmpty().length <= 512 * 1024)
        assertTrue(result.text.orEmpty().contains("output truncated"))
    }

    @Test
    fun `Scanner issue count is bounded`() = runBlocking {
        val result = service.get(GetScannerIssues(count = 51)).output
        assertEquals(ScannerIssuePageStatus.INVALID_ARGUMENT, result.status)
        verify(exactly = 0) { siteMap.issues() }
    }

    private fun issue(
        typeIndex: Int,
        name: String,
        host: String,
        severity: AuditIssueSeverity,
        confidence: AuditIssueConfidence = AuditIssueConfidence.CERTAIN,
    ): AuditIssue {
        val issue = mockk<AuditIssue>()
        val definition = mockk<AuditIssueDefinition>()
        val service = mockk<HttpService>()
        every { issue.definition() } returns definition
        every { definition.typeIndex() } returns typeIndex
        every { definition.name() } returns "definition-$typeIndex"
        every { definition.background() } returns null
        every { definition.remediation() } returns null
        every { issue.name() } returns name
        every { issue.baseUrl() } returns "https://$host/$typeIndex"
        every { issue.httpService() } returns service
        every { service.host() } returns host
        every { service.port() } returns 443
        every { service.secure() } returns true
        every { issue.severity() } returns severity
        every { issue.confidence() } returns confidence
        every { issue.detail() } returns "detail-$typeIndex"
        every { issue.remediation() } returns null
        every { issue.requestResponses() } returns emptyList()
        every { issue.collaboratorInteractions() } returns emptyList()
        return issue
    }

    private fun config(requireDataApproval: Boolean): McpConfig {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers {
            firstArg<String>() == "requireDataAccessApproval" && requireDataApproval
        }
        every { storage.getString(any()) } returns ""
        return McpConfig(storage, logging)
    }
}
