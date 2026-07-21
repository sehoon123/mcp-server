package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.core.Range
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.Scanner
import burp.api.montoya.scanner.audit.Audit
import burp.api.montoya.scope.Scope
import io.mockk.*
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.SensitiveActionApprovalHandler
import net.portswigger.mcp.security.SensitiveActionSecurity
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ScannerAuditToolsTest {
    private val api = mockk<MontoyaApi>()
    private val project = mockk<Project>()
    private val proxy = mockk<Proxy>()
    private val scope = mockk<Scope>()
    private val scanner = mockk<Scanner>()
    private val logging = mockk<Logging>(relaxed = true)
    private val configuration = mockk<AuditConfiguration>()
    private lateinit var service: ScannerAuditService
    private lateinit var config: McpConfig
    private lateinit var originalSensitiveHandler: SensitiveActionApprovalHandler
    private lateinit var originalDataHandler: DataAccessApprovalHandler
    private val createdRanges = mutableListOf<Pair<Int, Int>>()

    @BeforeEach
    fun setUp() {
        mockkStatic(AuditConfiguration::class)
        mockkStatic(HttpRequestResponse::class)
        mockkStatic(Range::class)
        originalSensitiveHandler = SensitiveActionSecurity.approvalHandler
        originalDataHandler = DataAccessSecurity.approvalHandler
        every { api.project() } returns project
        every { project.id() } returns "project-123"
        every { api.proxy() } returns proxy
        every { api.scope() } returns scope
        every { api.scanner() } returns scanner
        every { api.logging() } returns logging
        every { AuditConfiguration.auditConfiguration(any<BuiltInAuditConfiguration>()) } returns configuration
        every { HttpRequestResponse.httpRequestResponse(any(), any()) } answers { mockk() }
        createdRanges.clear()
        every { Range.range(any(), any()) } answers {
            createdRanges += firstArg<Int>() to secondArg<Int>()
            mockk(relaxed = true)
        }
        config = config(requireDataApproval = false)
        service = ScannerAuditService(api)
        SensitiveActionSecurity.approvalHandler = approvalHandler(true)
    }

    @AfterEach
    fun tearDown() {
        SensitiveActionSecurity.approvalHandler = originalSensitiveHandler
        DataAccessSecurity.approvalHandler = originalDataHandler
        unmockkStatic(AuditConfiguration::class)
        unmockkStatic(HttpRequestResponse::class)
        unmockkStatic(Range::class)
    }

    @Test
    fun `out of scope target is rejected before approval or Scanner start`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns false
        val approval = mockk<SensitiveActionApprovalHandler>()
        SensitiveActionSecurity.approvalHandler = approval

        val result = service.start(passiveInput(1), config)

        assertEquals(ScannerAuditToolStatus.OUT_OF_SCOPE, result.status)
        assertEquals(ScannerAuditActionState.NOT_STARTED, result.actionState)
        assertEquals(0, result.errorTargetIndex)
        coVerify(exactly = 0) { approval.requestApproval(any(), any(), any(), any(), any()) }
        verify(exactly = 0) { scanner.startAudit(any()) }
    }

    @Test
    fun `passive audit start get and cancellation retain an extension owned task`() = runBlocking {
        val item = proxyItem(7, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "Running audit"
        every { audit.insertionPointCount() } returns 0
        every { audit.requestCount() } returns 1
        every { audit.errorCount() } returns 0
        every { audit.issues() } returns emptyList()
        every { audit.delete() } just runs

        val started = service.start(passiveInput(7), config)
        assertEquals(ScannerAuditToolStatus.OK, started.status)
        assertEquals(ScannerAuditActionState.COMPLETED, started.actionState)
        assertEquals(ScannerAuditTaskState.RUNNING, started.taskState)
        assertNotNull(started.taskId)
        assertTrue(started.taskId!!.matches(Regex("scanner_audit_[0-9a-f]{32}")))
        assertEquals(1, started.targetCount)
        verify(exactly = 1) {
            AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS)
            audit.addRequestResponse(any())
        }

        val current = service.get(GetScannerAudit("project-123", started.taskId!!), config)
        assertEquals(ScannerAuditToolStatus.OK, current.status)
        assertEquals(ScannerAuditTaskState.RUNNING, current.taskState)
        assertEquals("Running audit", current.statusMessage)
        assertEquals(0, current.auditedInsertionPointCount)
        assertEquals(1, current.requestCount)
        assertEquals(0, current.errorCount)
        assertEquals(0, current.discoveredIssueCount)

        val cancelled = service.cancel(CancelScannerAudit("project-123", started.taskId!!))
        assertEquals(ScannerAuditToolStatus.OK, cancelled.status)
        assertEquals(ScannerAuditTaskState.CANCELLED, cancelled.taskState)
        assertNotNull(cancelled.cancelledAt)
        verify(exactly = 1) { audit.delete() }

        val afterCancel = service.get(GetScannerAudit("project-123", started.taskId!!), config)
        assertEquals(ScannerAuditTaskState.CANCELLED, afterCancel.taskState)
    }

    @Test
    fun `approval denial starts no audit`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        SensitiveActionSecurity.approvalHandler = approvalHandler(false)

        val result = service.start(passiveInput(1), config)

        assertEquals(ScannerAuditToolStatus.ACTION_DENIED, result.status)
        assertEquals(ScannerAuditActionState.NOT_STARTED, result.actionState)
        assertEquals(1, result.targetCount)
        verify(exactly = 0) { scanner.startAudit(any()) }
    }

    @Test
    fun `Scanner start exception is conservatively execution uncertain without a task ID`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } throws IllegalStateException("transport failed")

        val result = service.start(passiveInput(1), config)

        assertEquals(ScannerAuditToolStatus.EXECUTION_UNCERTAIN, result.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, result.actionState)
        assertNull(result.taskId)
        assertTrue(result.error.orEmpty().contains("must not", ignoreCase = true).not())
    }

    @Test
    fun `partial target submission returns an owned task ID that can be cancelled`() = runBlocking {
        val first = proxyItem(1, response = mockk())
        val second = proxyItem(2, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returnsMany listOf(listOf(first), listOf(second))
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        var submissions = 0
        every { audit.addRequestResponse(any()) } answers {
            submissions++
            if (submissions == 2) throw IllegalStateException("queue failed")
        }
        every { audit.delete() } just runs

        val result = service.start(
            StartScannerAuditFromIds(
                "project-123",
                ScannerAuditMode.PASSIVE,
                listOf(target(1), target(2)),
            ),
            config,
        )

        assertEquals(ScannerAuditToolStatus.EXECUTION_UNCERTAIN, result.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, result.actionState)
        assertNotNull(result.taskId)
        assertEquals(ScannerAuditTaskState.UNKNOWN, result.taskState)

        val cancelled = service.cancel(CancelScannerAudit("project-123", result.taskId!!))
        assertEquals(ScannerAuditToolStatus.OK, cancelled.status)
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `active audit requires explicit semantic insertion points`() = runBlocking {
        val item = proxyItem(1, response = null)
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true

        val result = service.start(
            StartScannerAuditFromIds(
                "project-123",
                ScannerAuditMode.ACTIVE,
                listOf(ScannerAuditTarget(target(1).ref)),
            ),
            config,
        )

        assertEquals(ScannerAuditToolStatus.INVALID_ARGUMENT, result.status)
        assertTrue(result.error.orEmpty().contains("insertion point"))
        verify(exactly = 0) { scanner.startAudit(any()) }
    }

    @Test
    fun `active audit submits only resolved body insertion range`() = runBlocking {
        val raw = "POST / HTTP/1.1\r\nHost: example.test\r\n\r\nsecret".toByteArray()
        val bodyOffset = raw.toString(Charsets.ISO_8859_1).indexOf("secret")
        val request = request(3, raw, bodyOffset)
        val item = proxyItem(3, response = null, request = request)
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequest(request, any<List<Range>>()) } just runs

        val result = service.start(
            StartScannerAuditFromIds(
                "project-123",
                ScannerAuditMode.ACTIVE,
                listOf(
                    ScannerAuditTarget(
                        target(3).ref,
                        listOf(HttpInsertionPointSelector(HttpInsertionPointKind.BODY)),
                    )
                ),
            ),
            config,
        )

        assertEquals(ScannerAuditToolStatus.OK, result.status)
        assertEquals(1, result.insertionPointCount)
        assertEquals(listOf(bodyOffset to raw.size), createdRanges)
        verify(exactly = 1) {
            AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS)
            audit.addRequest(request, match { ranges -> ranges.size == 1 })
        }
    }

    @Test
    fun `get and cancel reject task IDs not owned by this extension instance`() = runBlocking {
        val unknown = "scanner_audit_${"0".repeat(32)}"

        val get = service.get(GetScannerAudit("project-123", unknown), config)
        val cancel = service.cancel(CancelScannerAudit("project-123", unknown))

        assertEquals(ScannerAuditToolStatus.NOT_FOUND, get.status)
        assertEquals(ScannerAuditToolStatus.NOT_FOUND, cancel.status)
        verify(exactly = 0) { scanner.startAudit(any()) }
    }

    @Test
    fun `unsupported live task issues are a nonfatal bounded warning`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "scanning"
        every { audit.insertionPointCount() } returns 1
        every { audit.requestCount() } returns 10
        every { audit.errorCount() } returns 0
        every { audit.issues() } throws UnsupportedOperationException("Currently unsupported")

        val started = service.start(passiveInput(1), config)
        val result = service.get(GetScannerAudit("project-123", started.taskId!!), config)

        assertEquals(ScannerAuditToolStatus.OK, result.status)
        assertTrue(result.issuesUnavailable)
        assertTrue(result.error.orEmpty().contains("unsupported", ignoreCase = true))
        assertEquals(10, result.requestCount)
    }

    @Test
    fun `task issue permission denial retains status but returns no issues`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "Running"
        every { audit.insertionPointCount() } returns 0
        every { audit.requestCount() } returns 1
        every { audit.errorCount() } returns 0
        config = config(requireDataApproval = true)
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean =
                accessType != DataAccessType.SCANNER_ISSUES
        }

        val started = service.start(passiveInput(1), config)
        val result = service.get(GetScannerAudit("project-123", started.taskId!!), config)

        assertEquals(ScannerAuditToolStatus.OK, result.status)
        assertTrue(result.issuesAccessDenied)
        assertTrue(result.issues.isEmpty())
        verify(exactly = 0) { audit.issues() }
    }

    private fun passiveInput(id: Int) = StartScannerAuditFromIds(
        "project-123",
        ScannerAuditMode.PASSIVE,
        listOf(target(id)),
    )

    private fun target(id: Int) = ScannerAuditTarget(
        HttpMessageReference(HttpMessageSource.PROXY, id.toString())
    )

    private fun proxyItem(
        id: Int,
        response: HttpResponse?,
        request: HttpRequest = request(id),
    ): ProxyHttpRequestResponse = mockk<ProxyHttpRequestResponse>().also {
        every { it.id() } returns id
        every { it.request() } returns request
        every { it.response() } returns response
    }

    private fun request(
        id: Int,
        raw: ByteArray = "GET /$id HTTP/1.1\r\nHost: example.test\r\n\r\n".toByteArray(),
        bodyOffset: Int = raw.size,
    ): HttpRequest = mockk<HttpRequest>().also { request ->
        val body = montoyaBytes(raw.copyOfRange(bodyOffset, raw.size))
        val bytes = montoyaBytes(raw)
        every { request.url() } returns "https://example.test/$id"
        every { request.method() } returns if (bodyOffset == raw.size) "GET" else "POST"
        every { request.bodyOffset() } returns bodyOffset
        every { request.body() } returns body
        every { request.toByteArray() } returns bytes
        every { request.toString() } returns raw.toString(Charsets.ISO_8859_1)
    }

    private fun montoyaBytes(raw: ByteArray): MontoyaByteArray = mockk<MontoyaByteArray>().also { bytes ->
        every { bytes.length() } returns raw.size
        every { bytes.getBytes() } returns raw
        every { bytes.subArray(any(), any()) } answers {
            montoyaBytes(raw.copyOfRange(firstArg(), secondArg()))
        }
    }

    private fun config(requireDataApproval: Boolean): McpConfig {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers {
            firstArg<String>() == "requireDataAccessApproval" && requireDataApproval
        }
        every { storage.getString(any()) } returns ""
        return McpConfig(storage, logging)
    }

    private fun approvalHandler(approved: Boolean) = object : SensitiveActionApprovalHandler {
        override suspend fun requestApproval(
            action: String,
            summary: String,
            reviewContent: String?,
            renderContentAsHttp: Boolean,
            api: MontoyaApi,
        ): Boolean = approved
    }
}
