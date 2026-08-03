package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.sitemap.SiteMap
import io.mockk.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// Changes require reviewed compatibility/version handling and independent regeneration, not copied runtime output.
private const val GOLDEN_SCANNER_PAGE_CURSOR =
    "eyJ2ZXJzaW9uIjoxLCJraW5kIjoicGFnZSIsInByb2plY3RJZCI6InByb2plY3QtMTIzIiwicXVlcnkiOnsic2V2ZXJpdGllcyI6bnVsbCwiY29uZmlkZW5jZXMiOm51bGwsImhvc3QiOm51bGwsIm5hbWVDb250YWlucyI6bnVsbCwiY2FzZVNlbnNpdGl2ZSI6ZmFsc2UsIm5ld2VzdEZpcnN0IjpmYWxzZX0sInNuYXBzaG90Ijp7InNpemUiOjMsImZpcnN0QW5jaG9yIjoiaXNzdWVfdjJfMF85ODE3MzczNzdiMmExODAxMDE4YmEwNjRjZTcxNTg3MSIsImxhc3RBbmNob3IiOiJpc3N1ZV92Ml8yX2FlYWQxNDcyYmNhZGU4YzQ0OGIzNjhkZmYwYTE3NTYxIn0sIm5leHRJbmRleCI6MX0.QA9lgYfqkbbXMFpEJFhgPVMea_ruS9YbI0RE6MPgl3E"
private const val GOLDEN_SCANNER_SNAPSHOT_CURSOR =
    "eyJ2ZXJzaW9uIjoxLCJraW5kIjoic25hcHNob3QiLCJwcm9qZWN0SWQiOiJwcm9qZWN0LTEyMyIsInF1ZXJ5Ijp7InNldmVyaXRpZXMiOm51bGwsImNvbmZpZGVuY2VzIjpudWxsLCJob3N0IjpudWxsLCJuYW1lQ29udGFpbnMiOm51bGwsImNhc2VTZW5zaXRpdmUiOmZhbHNlLCJuZXdlc3RGaXJzdCI6ZmFsc2V9LCJzbmFwc2hvdCI6eyJzaXplIjozLCJmaXJzdEFuY2hvciI6Imlzc3VlX3YyXzBfOTgxNzM3Mzc3YjJhMTgwMTAxOGJhMDY0Y2U3MTU4NzEiLCJsYXN0QW5jaG9yIjoiaXNzdWVfdjJfMl9hZWFkMTQ3MmJjYWRlOGM0NDhiMzY4ZGZmMGExNzU2MSJ9fQ.wEepHLs4Van9NHogmVjZFAt5s8VhEZbRjAaYHbbD5ZY"
private const val GOLDEN_SCANNER_DELTA_CURSOR =
    "eyJ2ZXJzaW9uIjoxLCJraW5kIjoiZGVsdGEiLCJwcm9qZWN0SWQiOiJwcm9qZWN0LTEyMyIsInF1ZXJ5Ijp7InNldmVyaXRpZXMiOm51bGwsImNvbmZpZGVuY2VzIjpudWxsLCJob3N0IjpudWxsLCJuYW1lQ29udGFpbnMiOm51bGwsImNhc2VTZW5zaXRpdmUiOmZhbHNlLCJuZXdlc3RGaXJzdCI6dHJ1ZX0sImJhc2VsaW5lIjp7InNpemUiOjIsImZpcnN0QW5jaG9yIjoiaXNzdWVfdjJfMF83ZDI3ZDc1YTgzNzYxNGFlOTY5ZjgyNTdkNjVhY2VkZiIsImxhc3RBbmNob3IiOiJpc3N1ZV92Ml8xXzIxYTRlZTE0NGMyZTJjOTQyOGMwMjcwYWMyNGRhNmUzIn0sImN1cnJlbnQiOnsic2l6ZSI6NSwiZmlyc3RBbmNob3IiOiJpc3N1ZV92Ml8wXzdkMjdkNzVhODM3NjE0YWU5NjlmODI1N2Q2NWFjZWRmIiwibGFzdEFuY2hvciI6Imlzc3VlX3YyXzRfY2U1NjhlNDg3ZGE3YjBmZjcwZmUxMjBhODVlNzZiNjEifSwibmV4dEluZGV4IjoyfQ.egwKwlp9KwRMaHa_eI0mf7TnXSB2kf30aXsdvVgshqw"

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
    fun `versioned Scanner identity uses bounded metadata without content getters`() {
        val issue = issue(7, "Identity", "example.test", AuditIssueSeverity.HIGH)

        val id = issue.stableHistoryId(123)

        assertTrue(id.matches(Regex("issue_v2_3f_[0-9a-f]{32}")))
        verify(exactly = 0) { issue.detail() }
        verify(exactly = 0) { issue.remediation() }
        verify(exactly = 0) { issue.requestResponses() }
        verify(exactly = 0) { issue.collaboratorInteractions() }
    }

    @Test
    fun `Scanner identity bounds long metadata and keeps locator separate`() {
        val prefix = "a".repeat(512)
        val first = issue(8, prefix + "one", "example.test", AuditIssueSeverity.HIGH)
        val second = issue(8, prefix + "two", "example.test", AuditIssueSeverity.HIGH)

        val firstId = first.stableHistoryId(0)
        val secondId = second.stableHistoryId(1)

        assertEquals(firstId.substringAfterLast('_'), secondId.substringAfterLast('_'))
        assertTrue(firstId.startsWith("issue_v2_0_"))
        assertTrue(secondId.startsWith("issue_v2_1_"))
    }

    @Test
    fun `cursor call fingerprints one boundary object once across both anchors and result ID`() = runBlocking {
        val issue = issue(1, "Only", "example.test", AuditIssueSeverity.HIGH)
        val definition = issue.definition()
        val service = issue.httpService()
        clearMocks(issue, definition, service, answers = false, recordedCalls = true)
        every { siteMap.issues() } returns listOf(issue)

        val result = this@ScannerIssueSearchTest.service.get(
            GetScannerIssues(count = 1, cursorMode = true, newestFirst = false),
        ).output

        assertEquals(ScannerIssuePageStatus.OK, result.status)
        assertEquals(listOf("Only"), result.items.map { it.name })
        verify(exactly = 2) { issue.definition() }
        verify(exactly = 2) { definition.typeIndex() }
        verify(exactly = 2) { issue.name() }
        verify(exactly = 2) { issue.baseUrl() }
        verify(exactly = 2) { issue.httpService() }
        verify(exactly = 2) { service.host() }
        verify(exactly = 2) { service.port() }
        verify(exactly = 2) { service.secure() }
        verify(exactly = 2) { issue.severity() }
        verify(exactly = 2) { issue.confidence() }
        verify(exactly = 0) { issue.detail() }
        verify(exactly = 0) { issue.remediation() }
        verify(exactly = 0) { issue.requestResponses() }
        verify(exactly = 0) { issue.collaboratorInteractions() }
    }

    @Test
    fun `cursor cache keys value-equal colliding issues by object identity`() = runBlocking {
        val first = issue(1, "First", "example.test", AuditIssueSeverity.HIGH)
        val second = issue(2, "Second", "example.test", AuditIssueSeverity.HIGH)
        every { first.hashCode() } returns 17
        every { second.hashCode() } returns 17
        every { first == second } returns true
        every { second == first } returns true
        assertEquals(first.hashCode(), second.hashCode())
        assertTrue(first == second)
        assertTrue(second == first)
        clearMocks(first, second, answers = false, recordedCalls = true)
        every { siteMap.issues() } returns listOf(first, second)

        val result = service.get(
            GetScannerIssues(count = 2, cursorMode = true, newestFirst = false),
        ).output

        assertEquals(ScannerIssuePageStatus.OK, result.status)
        assertEquals(2, result.items.size)
        assertTrue(result.items[0].id.startsWith("issue_v2_0_"))
        assertTrue(result.items[1].id.startsWith("issue_v2_1_"))
        assertNotEquals(
            result.items[0].id.substringAfterLast('_'),
            result.items[1].id.substringAfterLast('_'),
        )
        verify(exactly = 2) { first.name() }
        verify(exactly = 2) { second.name() }
        verify(exactly = 0) { first.hashCode() }
        verify(exactly = 0) { second.hashCode() }
        verify(exactly = 0) { first == second }
        verify(exactly = 0) { second == first }
    }

    @Test
    fun `cursor composes base36 locator outside cache for one object at two indices`() = runBlocking {
        val repeated = issue(1, "Repeated", "example.test", AuditIssueSeverity.HIGH)
        val filler = issue(2, "Filler", "example.test", AuditIssueSeverity.LOW)
        val issues = MutableList(36) { filler }.also {
            it[0] = repeated
            it[35] = repeated
        }
        every { siteMap.issues() } returns issues

        val result = service.get(
            GetScannerIssues(count = 1, cursorMode = true, newestFirst = true),
        ).output

        assertEquals(ScannerIssuePageStatus.OK, result.status)
        assertEquals(1, result.items.size)
        assertEquals(repeated.stableHistoryId(35), result.items.single().id)
        assertTrue(result.items.single().id.startsWith("issue_v2_z_"))
        verify(exactly = 0) { filler.name() }
    }

    @Test
    fun `cursor result-only misses are computed without retention`() = runBlocking {
        val first = issue(1, "First boundary", "example.test", AuditIssueSeverity.HIGH)
        val repeated = issue(2, "Repeated result", "example.test", AuditIssueSeverity.MEDIUM)
        val last = issue(3, "Last boundary", "example.test", AuditIssueSeverity.LOW)
        val definition = repeated.definition()
        val httpService = repeated.httpService()
        clearMocks(repeated, definition, httpService, answers = false, recordedCalls = true)
        every { siteMap.issues() } returns listOf(first, repeated, repeated, last)

        val result = service.get(
            GetScannerIssues(count = 4, cursorMode = true, newestFirst = false),
        ).output

        assertEquals(ScannerIssuePageStatus.OK, result.status)
        assertEquals(
            listOf("First boundary", "Repeated result", "Repeated result", "Last boundary"),
            result.items.map { it.name },
        )
        assertTrue(result.items[1].id.startsWith("issue_v2_1_"))
        assertTrue(result.items[2].id.startsWith("issue_v2_2_"))
        assertEquals(
            result.items[1].id.substringAfterLast('_'),
            result.items[2].id.substringAfterLast('_'),
        )
        verify(exactly = 4) { repeated.definition() }
        verify(exactly = 4) { definition.typeIndex() }
        verify(exactly = 4) { repeated.name() }
        verify(exactly = 4) { repeated.baseUrl() }
        verify(exactly = 4) { repeated.httpService() }
        verify(exactly = 4) { httpService.host() }
        verify(exactly = 4) { httpService.port() }
        verify(exactly = 4) { httpService.secure() }
        verify(exactly = 4) { repeated.severity() }
        verify(exactly = 4) { repeated.confidence() }
        verify(exactly = 0) { repeated.detail() }
        verify(exactly = 0) { repeated.remediation() }
        verify(exactly = 0) { repeated.requestResponses() }
        verify(exactly = 0) { repeated.collaboratorInteractions() }
    }

    @Test
    fun `cursor fingerprint cache is fresh for every service call`() = runBlocking {
        val issue = issue(1, "Original", "example.test", AuditIssueSeverity.HIGH)
        var currentName = "Original"
        every { issue.name() } answers { currentName }
        every { siteMap.issues() } returns listOf(issue)
        val baseline = assertNotNull(
            service.get(GetScannerIssues(cursorMode = true, newestFirst = false)).output.snapshotCursor,
        )

        currentName = "Changed"
        val delta = service.get(GetScannerIssues(sinceSnapshotCursor = baseline)).output

        assertEquals(ScannerIssuePageStatus.STALE_CURSOR, delta.status)
        assertTrue(delta.items.isEmpty())
    }

    @Test
    fun `cursor fingerprint cancellation propagates and a later call recomputes`() = runBlocking {
        val issue = issue(1, "Retry", "example.test", AuditIssueSeverity.HIGH)
        val definition = issue.definition()
        clearMocks(issue, definition, answers = false, recordedCalls = true)
        val cancellation = CancellationException("cancel fingerprint")
        var cancelNext = true
        every { issue.definition() } answers {
            if (cancelNext) {
                cancelNext = false
                throw cancellation
            }
            definition
        }
        every { siteMap.issues() } returns listOf(issue)

        val observed = assertFailsWith<CancellationException> {
            service.get(GetScannerIssues(count = 1, cursorMode = true))
        }
        assertTrue(observed === cancellation)

        val retry = service.get(GetScannerIssues(count = 1, cursorMode = true)).output
        assertEquals(ScannerIssuePageStatus.OK, retry.status)
        assertEquals(listOf("Retry"), retry.items.map { it.name })
        verify(exactly = 3) { issue.definition() }
        verify(exactly = 2) { definition.typeIndex() }
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
        assertTrue(result.output.items.all { it.evidenceCount == null })
        assertTrue(!result.output.legacyMode)
        issues.forEach { issue -> verify(exactly = 0) { issue.requestResponses() } }
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
        assertEquals(GOLDEN_SCANNER_PAGE_CURSOR, page1.nextCursor)
        assertEquals(GOLDEN_SCANNER_SNAPSHOT_CURSOR, page1.snapshotCursor)

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
    fun `snapshot delta returns only matching issues in the append-stable visible range`() = runBlocking {
        val baseline = mutableListOf(
            issue(1, "Baseline one", "example.test", AuditIssueSeverity.HIGH),
            issue(2, "Baseline two", "example.test", AuditIssueSeverity.HIGH),
        )
        every { siteMap.issues() } answers { baseline.toList() }
        val snapshotPage = service.get(
            GetScannerIssues(
                count = 50,
                cursorMode = true,
                severities = listOf(ScannerIssueSeverityFilter.HIGH),
                newestFirst = false,
            ),
        ).output
        val snapshotCursor = assertNotNull(snapshotPage.snapshotCursor)
        assertFalse(snapshotPage.deltaMode)
        assertNull(snapshotPage.delta)

        val low = issue(3, "New low", "example.test", AuditIssueSeverity.LOW)
        val high = issue(4, "New high", "example.test", AuditIssueSeverity.HIGH)
        baseline += listOf(low, high)
        val deltaPage = service.get(
            GetScannerIssues(
                count = 50,
                sinceSnapshotCursor = snapshotCursor,
            ),
        ).output

        assertEquals(ScannerIssuePageStatus.OK, deltaPage.status)
        assertTrue(deltaPage.deltaMode)
        assertFalse(deltaPage.legacyMode)
        assertEquals(listOf("New high"), deltaPage.items.map { it.name })
        assertEquals(2, deltaPage.scanned)
        assertEquals(4, deltaPage.snapshotSize)
        assertFalse(deltaPage.hasMore)
        assertNull(deltaPage.nextCursor)
        assertNull(deltaPage.nextDeltaCursor)
        assertNotNull(deltaPage.snapshotCursor)
        val evidence = assertNotNull(deltaPage.delta)
        assertEquals("append_stable_currently_visible_range", evidence.basis)
        assertEquals(2, evidence.baselineSnapshotSize)
        assertEquals(4, evidence.currentSnapshotSize)
        assertEquals(2, evidence.appendedRangeSize)
        assertFalse(evidence.regressionEstablished)
        assertFalse(evidence.removedOrChangedEstablished)
        assertFalse(evidence.completeHistoryEstablished)
        verify(exactly = 0) { low.detail() }
        verify(exactly = 0) { low.requestResponses() }
        verify(exactly = 0) { high.detail() }
        verify(exactly = 0) { high.requestResponses() }
    }

    @Test
    fun `delta reuses baseline and appended boundary fingerprints within one call`() = runBlocking {
        val baseline = issue(1, "Baseline", "example.test", AuditIssueSeverity.HIGH)
        val appended = issue(2, "Appended", "example.test", AuditIssueSeverity.HIGH)
        val current = mutableListOf(baseline)
        every { siteMap.issues() } answers { current.toList() }
        val snapshotCursor = assertNotNull(
            service.get(GetScannerIssues(cursorMode = true, newestFirst = false)).output.snapshotCursor,
        )
        val baselineDefinition = baseline.definition()
        val baselineService = baseline.httpService()
        val appendedDefinition = appended.definition()
        val appendedService = appended.httpService()
        clearMocks(
            baseline,
            baselineDefinition,
            baselineService,
            appended,
            appendedDefinition,
            appendedService,
            answers = false,
            recordedCalls = true,
        )
        current += appended

        val result = service.get(GetScannerIssues(sinceSnapshotCursor = snapshotCursor)).output

        assertEquals(ScannerIssuePageStatus.OK, result.status)
        assertEquals(listOf("Appended"), result.items.map { it.name })
        verify(exactly = 1) { baseline.definition() }
        verify(exactly = 1) { baselineDefinition.typeIndex() }
        verify(exactly = 1) { baseline.name() }
        verify(exactly = 1) { baseline.baseUrl() }
        verify(exactly = 1) { baseline.httpService() }
        verify(exactly = 1) { baselineService.host() }
        verify(exactly = 1) { baselineService.port() }
        verify(exactly = 1) { baselineService.secure() }
        verify(exactly = 1) { baseline.severity() }
        verify(exactly = 1) { baseline.confidence() }
        verify(exactly = 2) { appended.definition() }
        verify(exactly = 2) { appendedDefinition.typeIndex() }
        verify(exactly = 2) { appended.name() }
        verify(exactly = 2) { appended.baseUrl() }
        verify(exactly = 2) { appended.httpService() }
        verify(exactly = 2) { appendedService.host() }
        verify(exactly = 2) { appendedService.port() }
        verify(exactly = 2) { appendedService.secure() }
        verify(exactly = 2) { appended.severity() }
        verify(exactly = 2) { appended.confidence() }
        listOf(baseline, appended).forEach { issue ->
            verify(exactly = 0) { issue.detail() }
            verify(exactly = 0) { issue.remediation() }
            verify(exactly = 0) { issue.requestResponses() }
            verify(exactly = 0) { issue.collaboratorInteractions() }
        }
    }

    @Test
    fun `only Scanner delta records fixed acquisition and processing phase metrics`() = runBlocking {
        var tick = 0L
        val diagnostics = HistoryPerformanceDiagnostics { tick++ }
        service = ScannerIssueSearchService(
            api,
            config,
            ByteArray(32) { it.toByte() },
            diagnostics,
        )
        val current = mutableListOf(issue(1, "Baseline", "example.test", AuditIssueSeverity.HIGH))
        every { siteMap.issues() } answers { current.toList() }

        val snapshotCursor = assertNotNull(
            service.get(GetScannerIssues(cursorMode = true, newestFirst = false)).output.snapshotCursor,
        )
        HistoryPerformanceMetric.entries.filter { it.name.startsWith("SCANNER_DELTA_") }.forEach { metric ->
            assertEquals(0, diagnostics.snapshot().metrics.single { it.metric == metric }.attempts)
        }

        current += issue(2, "Appended", "example.test", AuditIssueSeverity.HIGH)
        val result = service.get(GetScannerIssues(sinceSnapshotCursor = snapshotCursor)).output

        assertEquals(ScannerIssuePageStatus.OK, result.status)
        val acquisition = diagnostics.snapshot().metrics.single {
            it.metric == HistoryPerformanceMetric.SCANNER_DELTA_MONTOYA_ACQUISITION
        }
        val processing = diagnostics.snapshot().metrics.single {
            it.metric == HistoryPerformanceMetric.SCANNER_DELTA_EXTENSION_PROCESSING
        }
        assertEquals(1, acquisition.attempts)
        assertEquals(1, acquisition.completed)
        assertEquals(1, acquisition.totalNanos)
        assertEquals(1, processing.attempts)
        assertEquals(1, processing.completed)
        assertEquals(1, processing.totalNanos)
    }

    @Test
    fun `default newest-first delta returns the appended range in reverse order across continuations`() = runBlocking {
        val current = mutableListOf(
            issue(1, "Baseline one", "example.test", AuditIssueSeverity.HIGH),
            issue(2, "Baseline two", "example.test", AuditIssueSeverity.HIGH),
        )
        every { siteMap.issues() } answers { current.toList() }
        val baselineCursor = assertNotNull(
            service.get(GetScannerIssues(cursorMode = true)).output.snapshotCursor,
        )
        current += listOf(
            issue(3, "New three", "example.test", AuditIssueSeverity.HIGH),
            issue(4, "New four", "example.test", AuditIssueSeverity.HIGH),
            issue(5, "New five", "example.test", AuditIssueSeverity.HIGH),
        )

        val first = service.get(
            GetScannerIssues(count = 2, sinceSnapshotCursor = baselineCursor),
        ).output
        assertEquals(listOf("New five", "New four"), first.items.map { it.name })
        assertTrue(first.hasMore)
        assertNull(first.snapshotCursor)
        assertEquals(GOLDEN_SCANNER_DELTA_CURSOR, first.nextDeltaCursor)

        val second = service.get(
            GetScannerIssues(count = 2, sinceSnapshotCursor = assertNotNull(first.nextDeltaCursor)),
        ).output
        assertEquals(listOf("New three"), second.items.map { it.name })
        assertFalse(second.hasMore)
        assertNull(second.nextDeltaCursor)
        assertNotNull(second.snapshotCursor)
        Unit
    }

    @Test
    fun `delta continuation freezes its comparison snapshot and chains through sinceSnapshotCursor`() = runBlocking {
        val current = mutableListOf(issue(1, "Baseline", "example.test", AuditIssueSeverity.HIGH))
        every { siteMap.issues() } answers { current.toList() }
        val baselineCursor = assertNotNull(
            service.get(GetScannerIssues(cursorMode = true, newestFirst = false)).output.snapshotCursor,
        )
        current += listOf(
            issue(2, "New two", "example.test", AuditIssueSeverity.HIGH),
            issue(3, "New three", "example.test", AuditIssueSeverity.HIGH),
            issue(4, "New four", "example.test", AuditIssueSeverity.HIGH),
        )

        val first = service.get(
            GetScannerIssues(count = 1, sinceSnapshotCursor = baselineCursor),
        ).output
        assertEquals(listOf("New two"), first.items.map { it.name })
        val continuation = assertNotNull(first.nextDeltaCursor)
        assertTrue(first.hasMore)
        assertNull(first.nextCursor)
        assertNull(first.snapshotCursor)

        current += issue(5, "Late append", "example.test", AuditIssueSeverity.HIGH)
        val second = service.get(
            GetScannerIssues(count = 10, sinceSnapshotCursor = continuation),
        ).output
        assertEquals(listOf("New three", "New four"), second.items.map { it.name })
        assertEquals(4, second.snapshotSize)
        assertFalse(second.hasMore)
        assertNull(second.nextDeltaCursor)

        val nextBaseline = assertNotNull(second.snapshotCursor)
        val late = service.get(GetScannerIssues(sinceSnapshotCursor = nextBaseline)).output
        assertEquals(listOf("Late append"), late.items.map { it.name })
        assertEquals(1, late.delta?.appendedRangeSize)
    }

    @Test
    fun `delta rejects tampering restart query mismatch and mixed cursor inputs before issue acquisition`() = runBlocking {
        every { siteMap.issues() } returns listOf(
            issue(1, "Baseline", "example.test", AuditIssueSeverity.HIGH),
            issue(2, "Second", "example.test", AuditIssueSeverity.HIGH),
        )
        val baselinePage = service.get(
            GetScannerIssues(
                count = 1,
                severities = listOf(ScannerIssueSeverityFilter.HIGH),
            ),
        ).output
        val snapshotCursor = assertNotNull(baselinePage.snapshotCursor)
        val ordinaryCursor = assertNotNull(baselinePage.nextCursor)
        clearMocks(siteMap, answers = false, recordedCalls = true)

        val tampered = (if (snapshotCursor.first() == 'A') "B" else "A") + snapshotCursor.drop(1)
        assertEquals(
            ScannerIssuePageStatus.INVALID_CURSOR,
            service.get(GetScannerIssues(sinceSnapshotCursor = tampered)).output.status,
        )
        assertEquals(
            ScannerIssuePageStatus.INVALID_CURSOR,
            ScannerIssueSearchService(api, config, ByteArray(32) { 99 })
                .get(GetScannerIssues(sinceSnapshotCursor = snapshotCursor)).output.status,
        )
        assertEquals(
            ScannerIssuePageStatus.INVALID_CURSOR,
            service.get(
                GetScannerIssues(
                    sinceSnapshotCursor = snapshotCursor,
                    severities = listOf(ScannerIssueSeverityFilter.LOW),
                ),
            ).output.status,
        )
        assertEquals(
            ScannerIssuePageStatus.INVALID_CURSOR,
            service.get(GetScannerIssues(sinceSnapshotCursor = ordinaryCursor)).output.status,
        )
        assertEquals(
            ScannerIssuePageStatus.INVALID_CURSOR,
            service.get(GetScannerIssues(cursor = snapshotCursor)).output.status,
        )
        assertEquals(
            ScannerIssuePageStatus.INVALID_ARGUMENT,
            service.get(
                GetScannerIssues(cursor = ordinaryCursor, sinceSnapshotCursor = snapshotCursor),
            ).output.status,
        )
        assertEquals(
            ScannerIssuePageStatus.INVALID_ARGUMENT,
            service.get(GetScannerIssues(offset = 1, sinceSnapshotCursor = snapshotCursor)).output.status,
        )
        assertEquals(
            ScannerIssuePageStatus.INVALID_ARGUMENT,
            service.get(
                GetScannerIssues(summariesOnly = false, sinceSnapshotCursor = snapshotCursor),
            ).output.status,
        )
        verify(exactly = 0) { siteMap.issues() }
    }

    @Test
    fun `delta project binding is rejected before approval or issue acquisition`() = runBlocking {
        every { siteMap.issues() } returns listOf(issue(1, "Baseline", "example.test", AuditIssueSeverity.HIGH))
        val snapshotCursor = assertNotNull(
            service.get(GetScannerIssues(cursorMode = true)).output.snapshotCursor,
        )
        every { project.id() } returns "other-project"
        config = config(true)
        service = ScannerIssueSearchService(api, config, ByteArray(32) { it.toByte() })
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                error("project-mismatched snapshot must not request approval")
            }
        }
        clearMocks(siteMap, answers = false, recordedCalls = true)

        val result = service.get(GetScannerIssues(sinceSnapshotCursor = snapshotCursor)).output

        assertEquals(ScannerIssuePageStatus.PROJECT_MISMATCH, result.status)
        assertEquals("other-project", result.projectId)
        verify(exactly = 0) { siteMap.issues() }
    }

    @Test
    fun `delta continuation rejects a changed frozen comparison snapshot`() = runBlocking {
        val current = mutableListOf(issue(1, "Baseline", "example.test", AuditIssueSeverity.HIGH))
        every { siteMap.issues() } answers { current.toList() }
        val snapshotCursor = assertNotNull(
            service.get(GetScannerIssues(cursorMode = true, newestFirst = false)).output.snapshotCursor,
        )
        current += listOf(
            issue(2, "New two", "example.test", AuditIssueSeverity.HIGH),
            issue(3, "New three", "example.test", AuditIssueSeverity.HIGH),
        )
        val continuation = assertNotNull(
            service.get(GetScannerIssues(count = 1, sinceSnapshotCursor = snapshotCursor)).output.nextDeltaCursor,
        )
        current.removeLast()

        val result = service.get(GetScannerIssues(sinceSnapshotCursor = continuation)).output

        assertEquals(ScannerIssuePageStatus.STALE_CURSOR, result.status)
        assertTrue(result.items.isEmpty())
        assertNull(result.nextDeltaCursor)
        assertNull(result.snapshotCursor)
    }

    @Test
    fun `delta rejects shrink and boundary reorder as stale`() = runBlocking {
        val first = issue(1, "First", "example.test", AuditIssueSeverity.HIGH)
        val second = issue(2, "Second", "example.test", AuditIssueSeverity.HIGH)
        var current = listOf(first, second)
        every { siteMap.issues() } answers { current }
        val snapshotCursor = assertNotNull(
            service.get(GetScannerIssues(cursorMode = true, newestFirst = false)).output.snapshotCursor,
        )

        current = listOf(first)
        assertEquals(
            ScannerIssuePageStatus.STALE_CURSOR,
            service.get(GetScannerIssues(sinceSnapshotCursor = snapshotCursor)).output.status,
        )
        current = listOf(second, first, issue(3, "Appended", "example.test", AuditIssueSeverity.HIGH))
        assertEquals(
            ScannerIssuePageStatus.STALE_CURSOR,
            service.get(GetScannerIssues(sinceSnapshotCursor = snapshotCursor)).output.status,
        )
    }

    @Test
    fun `same-size middle replacement cannot be promoted to a complete regression claim`() = runBlocking {
        val first = issue(1, "First", "example.test", AuditIssueSeverity.HIGH)
        val middle = issue(2, "Middle", "example.test", AuditIssueSeverity.HIGH)
        val last = issue(3, "Last", "example.test", AuditIssueSeverity.HIGH)
        var current = listOf(first, middle, last)
        every { siteMap.issues() } answers { current }
        val snapshotCursor = assertNotNull(
            service.get(GetScannerIssues(cursorMode = true)).output.snapshotCursor,
        )

        current = listOf(first, issue(9, "Replacement", "example.test", AuditIssueSeverity.HIGH), last)
        val delta = service.get(GetScannerIssues(sinceSnapshotCursor = snapshotCursor)).output

        assertEquals(ScannerIssuePageStatus.OK, delta.status)
        assertTrue(delta.items.isEmpty())
        assertEquals(0, delta.delta?.appendedRangeSize)
        assertFalse(requireNotNull(delta.delta).regressionEstablished)
        assertFalse(requireNotNull(delta.delta).removedOrChangedEstablished)
        assertFalse(requireNotNull(delta.delta).completeHistoryEstablished)
    }

    @Test
    fun `delta scan limit returns a resumable continuation without reading issue content`() = runBlocking {
        var current: List<AuditIssue> = emptyList()
        every { siteMap.issues() } answers { current }
        val snapshotCursor = assertNotNull(
            service.get(
                GetScannerIssues(
                    cursorMode = true,
                    severities = listOf(ScannerIssueSeverityFilter.HIGH),
                    newestFirst = false,
                ),
            ).output.snapshotCursor,
        )
        val low = issue(1, "Low", "example.test", AuditIssueSeverity.LOW)
        current = List(MAX_SCANNER_ISSUE_SCAN + 1) { low }

        val delta = service.get(GetScannerIssues(count = 1, sinceSnapshotCursor = snapshotCursor)).output

        assertEquals(ScannerIssuePageStatus.OK, delta.status)
        assertEquals(MAX_SCANNER_ISSUE_SCAN, delta.scanned)
        assertTrue(delta.scanLimitReached)
        assertTrue(delta.hasMore)
        assertNotNull(delta.nextDeltaCursor)
        assertTrue(delta.items.isEmpty())
        verify(exactly = 0) { low.detail() }
        verify(exactly = 0) { low.requestResponses() }
    }

    @Test
    fun `delta scanning propagates cancellation without partial output`() = runBlocking {
        val diagnostics = HistoryPerformanceDiagnostics()
        service = ScannerIssueSearchService(
            api,
            config,
            ByteArray(32) { it.toByte() },
            diagnostics,
        )
        var current: List<AuditIssue> = emptyList()
        every { siteMap.issues() } answers { current }
        val snapshotCursor = assertNotNull(
            service.get(
                GetScannerIssues(
                    cursorMode = true,
                    severities = listOf(ScannerIssueSeverityFilter.HIGH),
                    newestFirst = false,
                ),
            ).output.snapshotCursor,
        )
        val cancelling = issue(1, "Cancel", "example.test", AuditIssueSeverity.LOW)
        var severityReads = 0
        every { cancelling.severity() } answers {
            severityReads++
            if (severityReads == 67) throw CancellationException("client cancelled")
            AuditIssueSeverity.LOW
        }
        current = List(100) { cancelling }

        assertFailsWith<CancellationException> {
            service.get(GetScannerIssues(sinceSnapshotCursor = snapshotCursor))
        }
        val acquisition = diagnostics.snapshot().metrics.single {
            it.metric == HistoryPerformanceMetric.SCANNER_DELTA_MONTOYA_ACQUISITION
        }
        val processing = diagnostics.snapshot().metrics.single {
            it.metric == HistoryPerformanceMetric.SCANNER_DELTA_EXTENSION_PROCESSING
        }
        assertEquals(1, acquisition.completed)
        assertEquals(1, processing.cancelled)
        assertEquals(0, processing.completed)
        Unit
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
    fun `Scanner issue access denial returns only the rechecked project binding`() = runBlocking {
        config = config(true)
        service = ScannerIssueSearchService(api, config, ByteArray(32) { 7 })
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean = false
        }

        val result = service.get(GetScannerIssues()).output

        assertEquals(ScannerIssuePageStatus.ACCESS_DENIED, result.status)
        assertTrue(result.items.isEmpty())
        assertEquals("project-123", result.projectId)
        verify(exactly = 0) { siteMap.issues() }
        verify(exactly = 2) { project.id() }
    }

    @Test
    fun `Scanner approval failure preserves the safely captured project binding`() = runBlocking {
        config = config(true)
        service = ScannerIssueSearchService(api, config, ByteArray(32) { 7 })
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                throw IllegalStateException("synthetic approval failure")
            }
        }

        val result = service.get(GetScannerIssues()).output

        assertEquals(ScannerIssuePageStatus.BURP_ERROR, result.status)
        assertEquals("project-123", result.projectId)
        verify(exactly = 0) { siteMap.issues() }
    }

    @Test
    fun `Scanner approval recheck failure preserves the safely captured project binding`() = runBlocking {
        var projectReads = 0
        every { project.id() } answers {
            projectReads++
            if (projectReads == 1) "project-123" else throw IllegalStateException("synthetic recheck failure")
        }
        config = config(true)
        service = ScannerIssueSearchService(api, config, ByteArray(32) { 7 })
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean = true
        }

        val result = service.get(GetScannerIssues()).output

        assertEquals(ScannerIssuePageStatus.BURP_ERROR, result.status)
        assertEquals("project-123", result.projectId)
        verify(exactly = 0) { siteMap.issues() }
    }

    @Test
    fun `Scanner denial after a project transition returns mismatch instead of stale binding`() = runBlocking {
        var observedProjectId = "project-123"
        every { project.id() } answers { observedProjectId }
        config = config(true)
        service = ScannerIssueSearchService(api, config, ByteArray(32) { 7 })
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                observedProjectId = "project-after-denial"
                return false
            }
        }

        val response = service.get(GetScannerIssues())

        assertEquals(ScannerIssuePageStatus.PROJECT_MISMATCH, response.output.status)
        assertEquals("project-after-denial", response.output.projectId)
        assertEquals(true, response.isError)
        verify(exactly = 0) { siteMap.issues() }
    }

    @Test
    fun `project transition during Scanner approval prevents source access`() = runBlocking {
        config = config(true)
        service = ScannerIssueSearchService(api, config, ByteArray(32) { 7 })
        var currentProjectId = "project-123"
        every { project.id() } answers { currentProjectId }
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                currentProjectId = "other-project"
                return true
            }
        }

        val result = service.get(GetScannerIssues()).output

        assertEquals(ScannerIssuePageStatus.PROJECT_MISMATCH, result.status)
        assertEquals("other-project", result.projectId)
        assertTrue(result.items.isEmpty())
        verify(exactly = 0) { siteMap.issues() }
    }

    @Test
    fun `project transition during Scanner materialization discards output`() = runBlocking {
        val issue = issue(9, "Transition", "example.test", AuditIssueSeverity.HIGH)
        var currentProjectId = "project-123"
        every { project.id() } answers { currentProjectId }
        every { issue.name() } answers {
            currentProjectId = "other-project"
            "Transition"
        }
        every { siteMap.issues() } returns listOf(issue)

        val result = service.get(GetScannerIssues(count = 1, summariesOnly = true)).output

        assertEquals(ScannerIssuePageStatus.PROJECT_MISMATCH, result.status)
        assertEquals("other-project", result.projectId)
        assertTrue(result.items.isEmpty())
    }

    @Test
    fun `legacy full issue text keeps complete JSON and stops after bounded truncation`() = runBlocking {
        val issue = issue(1, "Large", "example.test", AuditIssueSeverity.HIGH)
        val unvisited = issue(2, "Unvisited", "later.example", AuditIssueSeverity.LOW)
        every { issue.detail() } returns "x".repeat(600 * 1024)
        every { siteMap.issues() } returns listOf(issue, unvisited)

        val result = service.get(GetScannerIssues(count = 2, summariesOnly = false))

        assertEquals(ScannerIssuePageStatus.OK, result.output.status)
        assertTrue(result.output.legacyTextTruncated)
        assertEquals(1, result.output.returned)
        assertEquals(1, result.output.scanned)
        assertTrue(result.output.hasMore)
        assertTrue(result.text.orEmpty().length <= 512 * 1024)
        assertTrue(result.text.orEmpty().contains("output truncated"))
        Json.parseToJsonElement(result.text.orEmpty().substringBefore("\n\n<Scanner issue output truncated"))
        verify(exactly = 0) { unvisited.name() }
        verify(exactly = 0) { unvisited.detail() }
    }

    @Test
    fun `legacy evidence slices Montoya bytes before bounded text conversion`() = runBlocking {
        val issue = issue(3, "Evidence", "example.test", AuditIssueSeverity.HIGH)
        val evidence = mockk<HttpRequestResponse>()
        val request = mockk<HttpRequest>()
        val annotations = mockk<Annotations>()
        val bytes = mockk<MontoyaByteArray>()
        val selected = mockk<MontoyaByteArray>()
        every { issue.requestResponses() } returns listOf(evidence)
        every { evidence.request() } returns request
        every { evidence.response() } returns null
        every { evidence.annotations() } returns annotations
        every { annotations.notes() } returns null
        every { request.toByteArray() } returns bytes
        every { bytes.length() } returns 128 * 1024
        every { bytes.subArray(0, 16 * 1024) } returns selected
        every { selected.toString() } returns "r".repeat(16 * 1024)
        every { siteMap.issues() } returns listOf(issue)

        val result = service.get(GetScannerIssues(count = 1, summariesOnly = false))

        assertEquals(ScannerIssuePageStatus.OK, result.output.status)
        assertTrue(result.output.legacyTextTruncated)
        assertEquals(1, result.output.returned)
        Json.parseToJsonElement(result.text.orEmpty().substringBefore("\n\n<Scanner issue output truncated"))
        verify(exactly = 1) { bytes.subArray(0, 16 * 1024) }
        verify(exactly = 0) { request.toString() }
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
        return McpConfig(storage, logging, net.portswigger.mcp.testPreferences())
    }
}
