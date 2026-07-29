package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.core.Range
import burp.api.montoya.http.HttpService
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
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.scope.Scope
import io.mockk.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withTimeout
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.SensitiveActionApprovalHandler
import net.portswigger.mcp.security.SensitiveActionSecurity
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
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
    private var currentInstant = Instant.parse("2026-01-01T00:00:00Z")
    private var currentTick = 0L

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
        currentInstant = Instant.parse("2026-01-01T00:00:00Z")
        currentTick = 0L
        service = ScannerAuditService(
            api,
            clock = { currentInstant },
            ticker = { currentTick },
            cleanupExecutor = null,
        )
        SensitiveActionSecurity.approvalHandler = approvalHandler(true)
    }

    @AfterEach
    fun tearDown() {
        service.close()
        SensitiveActionSecurity.approvalHandler = originalSensitiveHandler
        DataAccessSecurity.approvalHandler = originalDataHandler
        unmockkStatic(AuditConfiguration::class)
        unmockkStatic(HttpRequestResponse::class)
        unmockkStatic(Range::class)
    }

    @Test
    fun `pre-capture Scanner validation does not echo the caller project`() = runBlocking {
        val result = service.start(
            StartScannerAuditFromIds(
                projectId = "caller-forged",
                mode = ScannerAuditMode.ACTIVE,
                targets = emptyList(),
            ),
            config,
        )

        assertEquals(ScannerAuditToolStatus.INVALID_ARGUMENT, result.status)
        assertEquals(ScannerAuditActionState.NOT_STARTED, result.actionState)
        assertNull(result.projectId)
        verify(exactly = 0) { api.project() }
        verify(exactly = 0) { scanner.startAudit(any()) }
    }

    @Test
    fun `pre-capture Scanner task validation does not echo the caller project`() = runBlocking {
        val result = service.get(GetScannerAudit("caller-forged", "not-a-task-id"), config)

        assertEquals(ScannerAuditToolStatus.INVALID_ID, result.status)
        assertEquals(ScannerAuditActionState.NOT_STARTED, result.actionState)
        assertNull(result.projectId)
        verify(exactly = 0) { api.project() }
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
    fun `Scanner request accessor IllegalArgumentException is a sanitized Burp failure`() = runBlocking {
        val request = request(1)
        every { request.bodyOffset() } throws IllegalArgumentException("PRIVATE_SENTINEL")
        every { proxy.history(any()) } returns listOf(proxyItem(1, response = mockk(), request = request))
        val approval = mockk<SensitiveActionApprovalHandler>()
        SensitiveActionSecurity.approvalHandler = approval

        val result = service.start(passiveInput(1), config)

        assertEquals(ScannerAuditToolStatus.BURP_ERROR, result.status)
        assertEquals(ScannerAuditActionState.NOT_STARTED, result.actionState)
        assertFalse(result.error.orEmpty().contains("PRIVATE_SENTINEL"))
        coVerify(exactly = 0) { approval.requestApproval(any(), any(), any(), any(), any()) }
        verify(exactly = 0) { scanner.startAudit(any()) }
    }

    @Test
    fun `Scanner insertion point accessor IllegalArgumentException is not caller-invalid`() = runBlocking {
        val request = request(2)
        every { request.parameters(any()) } throws IllegalArgumentException("PRIVATE_SENTINEL")
        every { proxy.history(any()) } returns listOf(proxyItem(2, response = mockk(), request = request))
        every { scope.isInScope(any()) } returns true
        val approval = mockk<SensitiveActionApprovalHandler>()
        SensitiveActionSecurity.approvalHandler = approval
        val active = StartScannerAuditFromIds(
            "project-123",
            ScannerAuditMode.ACTIVE,
            listOf(
                ScannerAuditTarget(
                    HttpMessageReference(HttpMessageSource.PROXY, "2"),
                    listOf(
                        HttpInsertionPointSelector(
                            kind = HttpInsertionPointKind.PARAMETER,
                            name = "q",
                            parameterType = HttpActionParameterType.URL,
                        )
                    ),
                )
            ),
        )

        val result = service.start(active, config)

        assertEquals(ScannerAuditToolStatus.BURP_ERROR, result.status)
        assertEquals(ScannerAuditActionState.NOT_STARTED, result.actionState)
        assertFalse(result.error.orEmpty().contains("PRIVATE_SENTINEL"))
        coVerify(exactly = 0) { approval.requestApproval(any(), any(), any(), any(), any()) }
        verify(exactly = 0) { scanner.startAudit(any()) }
    }

    @Test
    fun `Scanner summary accessor failure stays inside the structured Burp taxonomy`() = runBlocking {
        val request = request(3)
        every { request.method() } throws IllegalStateException("PRIVATE_SENTINEL")
        every { proxy.history(any()) } returns listOf(proxyItem(3, response = mockk(), request = request))
        every { scope.isInScope(any()) } returns true
        val approval = mockk<SensitiveActionApprovalHandler>()
        SensitiveActionSecurity.approvalHandler = approval

        val result = service.start(passiveInput(3), config)

        assertEquals(ScannerAuditToolStatus.BURP_ERROR, result.status)
        assertEquals(ScannerAuditActionState.NOT_STARTED, result.actionState)
        assertTrue(result.targets.isEmpty())
        assertFalse(result.error.orEmpty().contains("PRIVATE_SENTINEL"))
        coVerify(exactly = 0) { approval.requestApproval(any(), any(), any(), any(), any()) }
        verify(exactly = 0) { scanner.startAudit(any()) }
    }

    @Test
    fun `active out of scope target is rejected before approval or Scanner start`() = runBlocking {
        val item = proxyItem(2, response = mockk())
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns false
        val approval = mockk<SensitiveActionApprovalHandler>()
        SensitiveActionSecurity.approvalHandler = approval
        val active = StartScannerAuditFromIds(
            "project-123",
            ScannerAuditMode.ACTIVE,
            listOf(
                ScannerAuditTarget(
                    HttpMessageReference(HttpMessageSource.PROXY, "2"),
                    listOf(HttpInsertionPointSelector(HttpInsertionPointKind.BODY)),
                ),
            ),
        )

        val result = service.start(active, config)

        assertEquals(ScannerAuditToolStatus.OUT_OF_SCOPE, result.status)
        assertEquals(ScannerAuditActionState.NOT_STARTED, result.actionState)
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

        val cancelled = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
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
    fun `project transition with denied Scanner approval returns mismatch before denial`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        var currentProjectId = "project-123"
        every { project.id() } answers { currentProjectId }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean {
                currentProjectId = "replacement-project"
                return false
            }
        }

        val result = service.start(passiveInput(1), config)

        assertEquals(ScannerAuditToolStatus.PROJECT_MISMATCH, result.status)
        assertEquals(ScannerAuditActionState.NOT_STARTED, result.actionState)
        verify(exactly = 0) { scanner.startAudit(any()) }
    }

    @Test
    fun `YOLO Scanner start still rejects a project transition after scope validation`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        var scopeCompleted = false
        var projectReadsAfterScope = 0
        every { project.id() } answers {
            if (!scopeCompleted || projectReadsAfterScope++ == 0) "project-123" else "replacement-project"
        }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } answers {
            scopeCompleted = true
            true
        }
        config.approvalYoloMode = true
        val approval = mockk<SensitiveActionApprovalHandler>()
        SensitiveActionSecurity.approvalHandler = approval

        val result = service.start(passiveInput(1), config)

        assertEquals(ScannerAuditToolStatus.PROJECT_MISMATCH, result.status)
        assertEquals(ScannerAuditActionState.NOT_STARTED, result.actionState)
        coVerify(exactly = 0) { approval.requestApproval(any(), any(), any(), any(), any()) }
        verify(exactly = 0) { scanner.startAudit(any()) }
    }

    @Test
    fun `project transition during initial scope inspection returns mismatch`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        var currentProjectId = "project-123"
        every { project.id() } answers { currentProjectId }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } answers {
            currentProjectId = "replacement-project"
            true
        }

        val result = service.start(passiveInput(1), config)

        assertEquals(ScannerAuditToolStatus.PROJECT_MISMATCH, result.status)
        assertEquals(ScannerAuditActionState.NOT_STARTED, result.actionState)
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
        assertEquals("project-123", result.projectId)
        assertEquals(ScannerAuditMode.PASSIVE, result.mode)
        assertNull(result.taskId)
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
    }

    @Test
    fun `Scanner start cancellation after invocation is execution uncertain`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } throws CancellationException("cancelled")

        val result = service.start(passiveInput(1), config)

        assertEquals(ScannerAuditToolStatus.EXECUTION_UNCERTAIN, result.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, result.actionState)
        assertEquals("project-123", result.projectId)
        assertEquals(ScannerAuditMode.PASSIVE, result.mode)
        assertNull(result.taskId)
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        verify(exactly = 1) { scanner.startAudit(configuration) }
    }

    @Test
    fun `Scanner start exception during a project transition returns only scrubbed uncertainty`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        var currentProjectId = "project-123"
        every { project.id() } answers { currentProjectId }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } answers {
            currentProjectId = "replacement-project"
            throw IllegalStateException("PRIVATE_START_SENTINEL")
        }

        val result = service.start(passiveInput(1), config)

        assertEquals(ScannerAuditToolStatus.PROJECT_MISMATCH, result.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, result.actionState)
        assertEquals("replacement-project", result.projectId)
        assertTaskDataScrubbed(result)
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        assertFalse(result.error.orEmpty().contains("PRIVATE_START_SENTINEL"))
    }

    @Test
    fun `Scanner start cancellation during a project transition returns only scrubbed uncertainty`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        var currentProjectId = "project-123"
        every { project.id() } answers { currentProjectId }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } answers {
            currentProjectId = "replacement-project"
            throw CancellationException("PRIVATE_START_SENTINEL")
        }

        val result = service.start(passiveInput(1), config)

        assertEquals(ScannerAuditToolStatus.PROJECT_MISMATCH, result.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, result.actionState)
        assertEquals("replacement-project", result.projectId)
        assertTaskDataScrubbed(result)
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        assertFalse(result.error.orEmpty().contains("PRIVATE_START_SENTINEL"))
    }

    @Test
    fun `Scanner start exception plus project accessor failure returns only scrubbed uncertainty`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        var startAttempted = false
        every { project.id() } answers {
            if (startAttempted) throw IllegalStateException("PRIVATE_PROJECT_SENTINEL")
            "project-123"
        }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } answers {
            startAttempted = true
            throw IllegalStateException("PRIVATE_START_SENTINEL")
        }

        val result = service.start(passiveInput(1), config)

        assertEquals(ScannerAuditToolStatus.EXECUTION_UNCERTAIN, result.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, result.actionState)
        assertNull(result.projectId)
        assertTaskDataScrubbed(result)
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        assertFalse(result.error.orEmpty().contains("PRIVATE_"))
    }

    @Test
    fun `caller cancellation during target submission cleans the unreturned task and propagates`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        lateinit var invocationJob: Job
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } answers {
            invocationJob.cancel(CancellationException("caller cancelled"))
            throw CancellationException("caller cancelled")
        }
        every { audit.delete() } just runs

        supervisorScope {
            val invocation = async {
                invocationJob = currentCoroutineContext()[Job]!!
                service.start(passiveInput(1), config)
            }
            assertFailsWith<CancellationException> { invocation.await() }
        }

        verify(exactly = 1) { audit.addRequestResponse(any()) }
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `caller cancellation during post-start project recheck cleans the unreturned task and propagates`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        var targetSubmitted = false
        lateinit var invocationJob: Job
        every { project.id() } answers {
            if (targetSubmitted) {
                invocationJob.cancel(CancellationException("caller cancelled"))
                throw CancellationException("caller cancelled")
            }
            "project-123"
        }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } answers { targetSubmitted = true }
        every { audit.delete() } just runs

        supervisorScope {
            val invocation = async {
                invocationJob = currentCoroutineContext()[Job]!!
                service.start(passiveInput(1), config)
            }
            assertFailsWith<CancellationException> { invocation.await() }
        }

        verify(exactly = 1) { audit.addRequestResponse(any()) }
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `post-start project accessor failure returns only scrubbed uncertainty`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        var targetSubmitted = false
        every { project.id() } answers {
            if (targetSubmitted) throw IllegalStateException("PRIVATE_SENTINEL")
            "project-123"
        }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } answers { targetSubmitted = true }
        every { audit.delete() } just runs

        val result = service.start(passiveInput(1), config)

        assertEquals(ScannerAuditToolStatus.EXECUTION_UNCERTAIN, result.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, result.actionState)
        assertEquals(ScannerAuditTaskState.UNKNOWN, result.taskState)
        assertNull(result.projectId)
        assertNull(result.taskId)
        assertNull(result.mode)
        assertTrue(result.targets.isEmpty())
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        assertFalse(result.error.orEmpty().contains("PRIVATE_SENTINEL"))
        service.close()
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `target submission failure plus project accessor failure returns only scrubbed uncertainty`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        var submissionFailed = false
        every { project.id() } answers {
            if (submissionFailed) throw IllegalStateException("PRIVATE_PROJECT_SENTINEL")
            "project-123"
        }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } answers {
            submissionFailed = true
            throw IllegalStateException("PRIVATE_SUBMISSION_SENTINEL")
        }
        every { audit.delete() } just runs

        val result = service.start(passiveInput(1), config)

        assertEquals(ScannerAuditToolStatus.EXECUTION_UNCERTAIN, result.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, result.actionState)
        assertEquals(ScannerAuditTaskState.UNKNOWN, result.taskState)
        assertNull(result.projectId)
        assertNull(result.taskId)
        assertNull(result.mode)
        assertTrue(result.targets.isEmpty())
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        assertFalse(result.error.orEmpty().contains("PRIVATE_"))
        service.close()
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `target submission cancellation returns an owned uncertain task`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } throws CancellationException("cancelled")
        every { audit.delete() } just runs

        val result = service.start(passiveInput(1), config)

        assertEquals(ScannerAuditToolStatus.EXECUTION_UNCERTAIN, result.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, result.actionState)
        assertEquals(ScannerAuditTaskState.UNKNOWN, result.taskState)
        assertNotNull(result.taskId)
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        val cancelled = service.cancel(CancelScannerAudit("project-123", result.taskId!!), config)
        assertEquals(ScannerAuditToolStatus.OK, cancelled.status)
        verify(exactly = 1) { audit.addRequestResponse(any()) }
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `project transition during target submission returns only scrubbed uncertainty and schedules cleanup`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } answers {
            every { project.id() } returns "replacement-project"
        }
        every { audit.delete() } just runs

        val result = service.start(passiveInput(1), config)

        assertEquals(ScannerAuditToolStatus.PROJECT_MISMATCH, result.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, result.actionState)
        assertEquals(ScannerAuditTaskState.UNKNOWN, result.taskState)
        assertEquals("replacement-project", result.projectId)
        assertNull(result.taskId)
        assertNull(result.mode)
        assertTrue(result.targets.isEmpty())
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        service.close()
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `partial target submission returns an owned task ID that can be cancelled`() = runBlocking {
        val first = proxyItem(1, response = mockk())
        val second = proxyItem(2, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } answers {
            val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
            listOf(first, second).filter(filter::matches)
        }
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
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))

        val cancelled = service.cancel(CancelScannerAudit("project-123", result.taskId!!), config)
        assertEquals(ScannerAuditToolStatus.OK, cancelled.status)
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `observing a project switch cancels and forgets active extension-owned audits`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } just runs

        val started = service.start(passiveInput(1), config)
        every { project.id() } returns "second-project"
        val result = service.get(GetScannerAudit("second-project", started.taskId!!), config)

        assertEquals(ScannerAuditToolStatus.NOT_FOUND, result.status)
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `stale project observation cannot roll back the boundary or detach the current task`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val firstAudit = mockk<Audit>()
        val currentAudit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returnsMany listOf(firstAudit, currentAudit)
        every { firstAudit.addRequestResponse(any()) } just runs
        every { currentAudit.addRequestResponse(any()) } just runs
        every { firstAudit.delete() } just runs
        every { currentAudit.delete() } just runs
        every { currentAudit.statusMessage() } returns "running"
        every { currentAudit.insertionPointCount() } returns 0
        every { currentAudit.requestCount() } returns 0
        every { currentAudit.errorCount() } returns 0
        val first = service.start(passiveInput(1), config)

        val blockNextProjectRead = AtomicInteger(1)
        val staleReadEntered = CountDownLatch(1)
        val releaseStaleRead = CountDownLatch(1)
        var currentProjectId = "project-123"
        every { project.id() } answers {
            if (blockNextProjectRead.compareAndSet(1, 0)) {
                staleReadEntered.countDown()
                check(releaseStaleRead.await(5, TimeUnit.SECONDS))
                "project-123"
            } else {
                currentProjectId
            }
        }
        val staleRead = async(Dispatchers.Default) {
            service.get(GetScannerAudit("project-123", first.taskId!!, issueLimit = 0), config)
        }
        assertTrue(staleReadEntered.await(5, TimeUnit.SECONDS))

        currentProjectId = "replacement-project"
        val current = service.start(
            StartScannerAuditFromIds(
                "replacement-project",
                ScannerAuditMode.PASSIVE,
                listOf(target(1)),
            ),
            config,
        )
        assertEquals(ScannerAuditToolStatus.OK, current.status)
        releaseStaleRead.countDown()
        val stale = staleRead.await()

        assertEquals(ScannerAuditToolStatus.BURP_ERROR, stale.status)
        assertNull(stale.projectId)
        assertTaskDataScrubbed(stale)
        val retained = service.get(GetScannerAudit("replacement-project", current.taskId!!, issueLimit = 0), config)
        assertEquals(ScannerAuditToolStatus.OK, retained.status)
        assertEquals(ScannerAuditTaskState.RUNNING, retained.taskState)
        verify(exactly = 1) { firstAudit.delete() }
        verify(exactly = 0) { currentAudit.delete() }
    }

    @Test
    fun `newer failed project observation supersedes an older blocked read`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "running"
        every { audit.insertionPointCount() } returns 0
        every { audit.requestCount() } returns 0
        every { audit.errorCount() } returns 0
        every { audit.delete() } just runs
        val started = service.start(passiveInput(1), config)

        val readSequence = AtomicInteger()
        val staleReadEntered = CountDownLatch(1)
        val releaseStaleRead = CountDownLatch(1)
        every { project.id() } answers {
            when (readSequence.getAndIncrement()) {
                0 -> {
                    staleReadEntered.countDown()
                    check(releaseStaleRead.await(5, TimeUnit.SECONDS))
                    "project-123"
                }
                1 -> throw IllegalStateException("PRIVATE_PROJECT_SENTINEL")
                else -> "project-123"
            }
        }
        val staleRead = async(Dispatchers.Default) {
            service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        }
        assertTrue(staleReadEntered.await(5, TimeUnit.SECONDS))

        val newerFailure = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        assertEquals(ScannerAuditToolStatus.BURP_ERROR, newerFailure.status)
        assertTaskDataScrubbed(newerFailure)
        assertFalse(newerFailure.error.orEmpty().contains("PRIVATE_PROJECT_SENTINEL"))

        releaseStaleRead.countDown()
        val stale = staleRead.await()
        assertEquals(ScannerAuditToolStatus.BURP_ERROR, stale.status)
        assertTaskDataScrubbed(stale)
        assertTrue(stale.error.orEmpty().contains("superseded"))

        val retained = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        assertEquals(ScannerAuditToolStatus.OK, retained.status)
        assertEquals(ScannerAuditTaskState.RUNNING, retained.taskState)
        verify(exactly = 0) { audit.delete() }
    }

    @Test
    fun `boundary reset prevents an older in-flight start from attaching after the tombstone`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val staleAudit = mockk<Audit>()
        val currentAudit = mockk<Audit>()
        val startEntered = CountDownLatch(1)
        val releaseStart = CountDownLatch(1)
        val starts = AtomicInteger()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } answers {
            if (starts.getAndIncrement() == 0) {
                startEntered.countDown()
                check(releaseStart.await(5, TimeUnit.SECONDS))
                staleAudit
            } else {
                currentAudit
            }
        }
        every { staleAudit.addRequestResponse(any()) } just runs
        every { currentAudit.addRequestResponse(any()) } just runs
        every { staleAudit.delete() } just runs
        every { currentAudit.delete() } just runs
        every { currentAudit.statusMessage() } returns "running"
        every { currentAudit.insertionPointCount() } returns 0
        every { currentAudit.requestCount() } returns 0
        every { currentAudit.errorCount() } returns 0

        val staleStart = async(Dispatchers.Default) { service.start(passiveInput(1), config) }
        assertTrue(startEntered.await(5, TimeUnit.SECONDS))
        service.resetForProjectBoundary()
        releaseStart.countDown()
        val stale = staleStart.await()

        assertEquals(ScannerAuditToolStatus.EXECUTION_UNCERTAIN, stale.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, stale.actionState)
        assertTaskDataScrubbed(stale)
        assertTrue(stale.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        verify(exactly = 1) { staleAudit.delete() }

        val current = service.start(passiveInput(1), config)
        assertEquals(ScannerAuditToolStatus.OK, current.status)
        val retained = service.get(GetScannerAudit("project-123", current.taskId!!, issueLimit = 0), config)
        assertEquals(ScannerAuditToolStatus.OK, retained.status)
        assertEquals(ScannerAuditTaskState.RUNNING, retained.taskState)
        verify(exactly = 0) { currentAudit.delete() }
    }

    @Test
    fun `inactive published task expires and is deleted once`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } just runs

        val started = service.start(passiveInput(1), config)
        advance(Duration.ofHours(6).plusNanos(1))

        assertEquals(1, service.cleanupExpired())
        val expired = service.get(GetScannerAudit("project-123", started.taskId!!), config)
        assertEquals(ScannerAuditToolStatus.NOT_FOUND, expired.status)
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `status observation renews idle retention but not maximum lifetime`() = runBlocking {
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
        every { audit.delete() } just runs

        val started = service.start(passiveInput(1), config)
        repeat(4) {
            advance(Duration.ofHours(5))
            val current = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
            assertEquals(ScannerAuditTaskState.RUNNING, current.taskState)
            assertEquals(0, service.cleanupExpired())
        }

        advance(Duration.ofHours(4).plusNanos(1))
        assertEquals(1, service.cleanupExpired())
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `terminal task record expires without deleting the completed Burp audit`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "Finished"
        every { audit.insertionPointCount() } returns 0
        every { audit.requestCount() } returns 1
        every { audit.errorCount() } returns 0

        val started = service.start(passiveInput(1), config)
        val finished = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        assertEquals(ScannerAuditTaskState.FINISHED, finished.taskState)

        advance(Duration.ofHours(1).plusNanos(1))
        assertEquals(1, service.cleanupExpired())
        val expired = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        assertEquals(ScannerAuditToolStatus.NOT_FOUND, expired.status)
        verify(exactly = 0) { audit.delete() }
    }

    @Test
    fun `returned uncertain cancellation record expires without retrying ambiguous cleanup`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } throws CancellationException("cancelled")
        every { audit.delete() } throws IllegalStateException("delete outcome unknown")

        val result = service.start(passiveInput(1), config)
        assertEquals(ScannerAuditToolStatus.EXECUTION_UNCERTAIN, result.status)
        assertNotNull(result.taskId)
        advance(Duration.ofHours(6).plusNanos(1))

        assertEquals(1, service.cleanupExpired())
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `unresolved cleanup reservations continue to enforce the active task cap`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audits = List(8) {
            mockk<Audit>().also { audit ->
                every { audit.addRequestResponse(any()) } just runs
                every { audit.delete() } throws IllegalStateException("delete outcome unknown")
            }
        }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returnsMany audits

        repeat(8) {
            val started = service.start(passiveInput(1), config)
            assertEquals(ScannerAuditToolStatus.OK, started.status)
        }
        service.resetForProjectBoundary()

        val blocked = service.start(passiveInput(1), config)
        assertEquals(ScannerAuditToolStatus.CAPACITY_EXCEEDED, blocked.status)
        audits.forEach { audit -> verify(exactly = 1) { audit.delete() } }
        verify(exactly = 8) { scanner.startAudit(configuration) }
    }

    @Test
    fun `terminal sample committing after failed boundary cleanup releases reserved capacity`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val finishingAudit = mockk<Audit>()
        val replacementAudits = List(8) { mockk<Audit>() }
        val terminalSampled = CountDownLatch(1)
        val releaseTerminalSample = CountDownLatch(1)
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returnsMany (listOf(finishingAudit) + replacementAudits)
        every { finishingAudit.addRequestResponse(any()) } just runs
        every { finishingAudit.statusMessage() } returns "finished"
        every { finishingAudit.insertionPointCount() } answers {
            terminalSampled.countDown()
            check(releaseTerminalSample.await(5, TimeUnit.SECONDS))
            1
        }
        every { finishingAudit.requestCount() } returns 1
        every { finishingAudit.errorCount() } returns 0
        every { finishingAudit.delete() } throws IllegalStateException("delete outcome unknown")
        replacementAudits.forEach { audit ->
            every { audit.addRequestResponse(any()) } just runs
            every { audit.statusMessage() } returns "running"
            every { audit.delete() } just runs
        }
        val started = service.start(passiveInput(1), config)

        val terminalRead = async(Dispatchers.Default) {
            service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        }
        assertTrue(terminalSampled.await(5, TimeUnit.SECONDS))
        service.resetForProjectBoundary()
        releaseTerminalSample.countDown()
        val finished = terminalRead.await()
        assertEquals(ScannerAuditToolStatus.PROJECT_MISMATCH, finished.status)
        assertTaskDataScrubbed(finished)

        repeat(8) {
            val replacement = service.start(passiveInput(1), config)
            assertEquals(ScannerAuditToolStatus.OK, replacement.status)
        }
        verify(exactly = 1) { finishingAudit.delete() }
    }

    @Test
    fun `successful claimed cancellation racing reset does not leak cleanup capacity`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val cancellingAudit = mockk<Audit>()
        val replacementAudits = List(8) { mockk<Audit>() }
        val deleteEntered = CountDownLatch(1)
        val releaseDelete = CountDownLatch(1)
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returnsMany (listOf(cancellingAudit) + replacementAudits)
        every { cancellingAudit.addRequestResponse(any()) } just runs
        every { cancellingAudit.delete() } answers {
            deleteEntered.countDown()
            check(releaseDelete.await(5, TimeUnit.SECONDS))
        }
        replacementAudits.forEach { audit ->
            every { audit.addRequestResponse(any()) } just runs
            every { audit.delete() } just runs
        }
        val started = service.start(passiveInput(1), config)

        val cancellation = async(Dispatchers.Default) {
            service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        }
        assertTrue(deleteEntered.await(5, TimeUnit.SECONDS))
        val resetStarted = CountDownLatch(1)
        val reset = async(Dispatchers.Default) {
            resetStarted.countDown()
            service.resetForProjectBoundary()
        }
        assertTrue(resetStarted.await(5, TimeUnit.SECONDS))
        releaseDelete.countDown()
        val cancelled = cancellation.await()
        reset.await()
        assertTrue(
            cancelled.status == ScannerAuditToolStatus.OK ||
                cancelled.status == ScannerAuditToolStatus.PROJECT_MISMATCH ||
                cancelled.status == ScannerAuditToolStatus.BURP_ERROR,
        )
        assertEquals(ScannerAuditActionState.COMPLETED, cancelled.actionState)
        assertEquals(ScannerAuditTaskState.CANCELLED, cancelled.taskState)
        if (cancelled.status != ScannerAuditToolStatus.OK) assertTaskDataScrubbed(cancelled)

        repeat(8) {
            val replacement = service.start(passiveInput(1), config)
            assertEquals(ScannerAuditToolStatus.OK, replacement.status)
        }
        verify(exactly = 1) { cancellingAudit.delete() }
    }

    @Test
    fun `authenticated project boundary detaches Scanner tasks before cleanup`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } just runs

        val started = service.start(passiveInput(1), config)
        service.resetForProjectBoundary()

        val detached = service.get(GetScannerAudit("project-123", started.taskId!!), config)
        assertEquals(ScannerAuditToolStatus.NOT_FOUND, detached.status)
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
        val cancel = service.cancel(CancelScannerAudit("project-123", unknown), config)

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
    fun `task status probing preserves cancellation`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } throws CancellationException("cancelled")

        val started = service.start(passiveInput(1), config)

        assertFailsWith<CancellationException> {
            service.get(GetScannerAudit("project-123", started.taskId!!), config)
        }
        verify(exactly = 1) { audit.statusMessage() }
    }

    @Test
    fun `cancelled status preserves an independent accessor failure`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "cancelled"
        every { audit.insertionPointCount() } returns 0
        every { audit.requestCount() } throws IllegalStateException("PRIVATE_SENTINEL")
        every { audit.errorCount() } returns 0

        val started = service.start(passiveInput(1), config)
        val result = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)

        assertEquals(ScannerAuditToolStatus.BURP_ERROR, result.status)
        assertEquals(ScannerAuditActionState.COMPLETED, result.actionState)
        assertEquals(ScannerAuditTaskState.CANCELLED, result.taskState)
        assertTrue(result.error.orEmpty().contains("request count unavailable"))
        assertFalse(result.error.orEmpty().contains("PRIVATE_SENTINEL"))
    }

    @Test
    fun `older live status sample cannot demote a newer finished observation`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val staleCountEntered = CountDownLatch(1)
        val releaseStaleCount = CountDownLatch(1)
        val statusReads = AtomicInteger()
        val insertionReads = AtomicInteger()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } answers {
            if (statusReads.getAndIncrement() == 0) "running" else "finished"
        }
        every { audit.insertionPointCount() } answers {
            if (insertionReads.getAndIncrement() == 0) {
                staleCountEntered.countDown()
                check(releaseStaleCount.await(5, TimeUnit.SECONDS))
                9
            } else {
                2
            }
        }
        every { audit.requestCount() } returns 4
        every { audit.errorCount() } returns 0
        every { audit.delete() } just runs
        val started = service.start(passiveInput(1), config)

        val staleRead = async(Dispatchers.Default) {
            service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        }
        assertTrue(staleCountEntered.await(5, TimeUnit.SECONDS))
        val finished = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        assertEquals(ScannerAuditTaskState.FINISHED, finished.taskState)
        assertEquals("finished", finished.statusMessage)
        assertEquals(2, finished.auditedInsertionPointCount)

        releaseStaleCount.countDown()
        val stale = staleRead.await()
        val final = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        listOf(stale, final).forEach { result ->
            assertEquals(ScannerAuditTaskState.FINISHED, result.taskState)
            assertEquals("finished", result.statusMessage)
            assertEquals(2, result.auditedInsertionPointCount)
        }
        verify(exactly = 0) { audit.delete() }
    }

    @Test
    fun `older issue materialization cannot overwrite a newer retained issue count`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val issue = scannerIssue()
        val staleIssuesEntered = CountDownLatch(1)
        val releaseStaleIssues = CountDownLatch(1)
        val issueReads = AtomicInteger()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "running"
        every { audit.insertionPointCount() } returns 0
        every { audit.requestCount() } returns 0
        every { audit.errorCount() } returns 0
        every { audit.issues() } answers {
            if (issueReads.getAndIncrement() == 0) {
                staleIssuesEntered.countDown()
                check(releaseStaleIssues.await(5, TimeUnit.SECONDS))
                List(2) { issue }
            } else {
                List(10) { issue }
            }
        }
        every { audit.delete() } just runs
        val started = service.start(passiveInput(1), config)

        val staleRead = async(Dispatchers.Default) {
            service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 1), config)
        }
        assertTrue(staleIssuesEntered.await(5, TimeUnit.SECONDS))
        val newer = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 1), config)
        assertEquals(10, newer.discoveredIssueCount)

        releaseStaleIssues.countDown()
        val stale = staleRead.await()
        val retained = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        assertEquals(10, stale.discoveredIssueCount)
        assertTrue(stale.issues.isEmpty())
        assertFalse(stale.issuesTruncated)
        assertTrue(stale.issuesUnavailable)
        assertEquals(10, retained.discoveredIssueCount)
        verify(exactly = 2) { audit.issues() }
    }

    @Test
    fun `older committed issue payload cannot publish after a newer observation`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val issue = scannerIssue()
        val publicationChecked = CountDownLatch(1)
        val releasePublication = CountDownLatch(1)
        val armPublication = AtomicBoolean(false)
        val issueReads = AtomicInteger()
        service.close()
        service = ScannerAuditService(
            api,
            clock = { currentInstant },
            ticker = { currentTick },
            cleanupExecutor = null,
            retainedResultPublicationHook = {
                if (armPublication.compareAndSet(true, false)) {
                    publicationChecked.countDown()
                    check(releasePublication.await(5, TimeUnit.SECONDS))
                }
            },
        )
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "running"
        every { audit.insertionPointCount() } returns 0
        every { audit.requestCount() } returns 0
        every { audit.errorCount() } returns 0
        every { audit.issues() } answers {
            if (issueReads.getAndIncrement() == 0) List(2) { issue } else List(10) { issue }
        }
        every { audit.delete() } just runs
        val started = service.start(passiveInput(1), config)

        armPublication.set(true)
        val olderRead = async(Dispatchers.Default) {
            service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 1), config)
        }
        assertTrue(publicationChecked.await(5, TimeUnit.SECONDS))
        val newer = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 1), config)
        assertEquals(10, newer.discoveredIssueCount)

        releasePublication.countDown()
        val older = olderRead.await()
        assertEquals(10, older.discoveredIssueCount)
        assertTrue(older.issues.isEmpty())
        assertFalse(older.issuesTruncated)
        assertTrue(older.issuesUnavailable)
        assertTrue(older.error.orEmpty().contains("superseded"))
        verify(exactly = 2) { audit.issues() }
    }

    @Test
    fun `rejected older issue observation publishes the later retained count`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val issue = scannerIssue()
        val olderIssuesEntered = CountDownLatch(1)
        val newerIssuesEntered = CountDownLatch(1)
        val releaseOlderIssues = CountDownLatch(1)
        val releaseNewerIssues = CountDownLatch(1)
        val olderPublicationChecked = CountDownLatch(1)
        val releaseOlderPublication = CountDownLatch(1)
        val armPublication = AtomicBoolean(false)
        val issueReads = AtomicInteger()
        service.close()
        service = ScannerAuditService(
            api,
            clock = { currentInstant },
            ticker = { currentTick },
            cleanupExecutor = null,
            retainedResultPublicationHook = {
                if (armPublication.compareAndSet(true, false)) {
                    olderPublicationChecked.countDown()
                    check(releaseOlderPublication.await(5, TimeUnit.SECONDS))
                }
            },
        )
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "running"
        every { audit.insertionPointCount() } returns 0
        every { audit.requestCount() } returns 0
        every { audit.errorCount() } returns 0
        every { audit.issues() } answers {
            when (issueReads.getAndIncrement()) {
                0 -> List(2) { issue }
                1 -> {
                    olderIssuesEntered.countDown()
                    check(releaseOlderIssues.await(5, TimeUnit.SECONDS))
                    List(2) { issue }
                }
                else -> {
                    newerIssuesEntered.countDown()
                    check(releaseNewerIssues.await(5, TimeUnit.SECONDS))
                    List(10) { issue }
                }
            }
        }
        every { audit.delete() } just runs
        val started = service.start(passiveInput(1), config)
        val seeded = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 1), config)
        assertEquals(2, seeded.discoveredIssueCount)

        armPublication.set(true)
        val olderRead = async(Dispatchers.Default) {
            service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 1), config)
        }
        assertTrue(olderIssuesEntered.await(5, TimeUnit.SECONDS))
        val newerRead = async(Dispatchers.Default) {
            service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 1), config)
        }
        assertTrue(newerIssuesEntered.await(5, TimeUnit.SECONDS))
        releaseOlderIssues.countDown()
        assertTrue(olderPublicationChecked.await(5, TimeUnit.SECONDS))
        releaseNewerIssues.countDown()
        val newer = newerRead.await()
        assertEquals(10, newer.discoveredIssueCount)
        releaseOlderPublication.countDown()
        val older = olderRead.await()

        assertEquals(10, older.discoveredIssueCount)
        assertTrue(older.issues.isEmpty())
        assertFalse(older.issuesTruncated)
        assertTrue(older.issuesUnavailable)
        assertTrue(older.error.orEmpty().contains("superseded"))
        verify(exactly = 3) { audit.issues() }
    }

    @Test
    fun `same-count newer issue sequence invalidates an older payload snapshot`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val olderIssue = scannerIssue("Older issue")
        val newerIssue = scannerIssue("Newer issue")
        val olderCounterEntered = CountDownLatch(1)
        val newerCounterEntered = CountDownLatch(1)
        val releaseOlderCounter = CountDownLatch(1)
        val releaseNewerCounter = CountDownLatch(1)
        val olderPublicationChecked = CountDownLatch(1)
        val releaseOlderPublication = CountDownLatch(1)
        val armPublication = AtomicBoolean(false)
        val statusReads = AtomicInteger()
        val counterReads = AtomicInteger()
        val issueReads = AtomicInteger()
        service.close()
        service = ScannerAuditService(
            api,
            clock = { currentInstant },
            ticker = { currentTick },
            cleanupExecutor = null,
            retainedResultPublicationHook = {
                if (armPublication.compareAndSet(true, false)) {
                    olderPublicationChecked.countDown()
                    check(releaseOlderPublication.await(5, TimeUnit.SECONDS))
                }
            },
        )
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } answers {
            if (statusReads.getAndIncrement() == 0) "finished" else "running"
        }
        every { audit.insertionPointCount() } answers {
            if (counterReads.getAndIncrement() == 0) {
                olderCounterEntered.countDown()
                check(releaseOlderCounter.await(5, TimeUnit.SECONDS))
            } else {
                newerCounterEntered.countDown()
                check(releaseNewerCounter.await(5, TimeUnit.SECONDS))
            }
            0
        }
        every { audit.requestCount() } returns 0
        every { audit.errorCount() } returns 0
        every { audit.issues() } answers {
            if (issueReads.getAndIncrement() == 0) listOf(olderIssue) else listOf(newerIssue)
        }
        every { audit.delete() } just runs
        val started = service.start(passiveInput(1), config)

        armPublication.set(true)
        val olderRead = async(Dispatchers.Default) {
            service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 1), config)
        }
        assertTrue(olderCounterEntered.await(5, TimeUnit.SECONDS))
        val newerRead = async(Dispatchers.Default) {
            service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 1), config)
        }
        assertTrue(newerCounterEntered.await(5, TimeUnit.SECONDS))
        releaseOlderCounter.countDown()
        assertTrue(olderPublicationChecked.await(5, TimeUnit.SECONDS))
        releaseNewerCounter.countDown()
        val newer = newerRead.await()
        assertEquals(ScannerAuditTaskState.FINISHED, newer.taskState)
        assertEquals("Newer issue", newer.issues.single().name)
        releaseOlderPublication.countDown()
        val older = olderRead.await()

        assertEquals(ScannerAuditTaskState.FINISHED, older.taskState)
        assertEquals(1, older.discoveredIssueCount)
        assertTrue(older.issues.isEmpty())
        assertFalse(older.issuesTruncated)
        assertTrue(older.issuesUnavailable)
        verify(exactly = 2) { audit.issues() }
    }

    @Test
    fun `successful delete and cancellation publication exclude a concurrent status read`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val deleteEntered = CountDownLatch(1)
        val releaseDelete = CountDownLatch(1)
        val readCaptureEntered = CountDownLatch(1)
        every { project.id() } answers {
            if (deleteEntered.count == 0L) readCaptureEntered.countDown()
            "project-123"
        }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } answers {
            deleteEntered.countDown()
            check(releaseDelete.await(5, TimeUnit.SECONDS))
        }
        val started = service.start(passiveInput(1), config)

        val cancellation = async(Dispatchers.Default) {
            service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        }
        assertTrue(deleteEntered.await(5, TimeUnit.SECONDS))
        val read = async(Dispatchers.Default) {
            service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 1), config)
        }
        assertTrue(readCaptureEntered.await(5, TimeUnit.SECONDS))
        releaseDelete.countDown()

        val cancelled = cancellation.await()
        val result = read.await()
        listOf(cancelled, result).forEach { value ->
            assertEquals(ScannerAuditToolStatus.OK, value.status)
            assertEquals(ScannerAuditActionState.COMPLETED, value.actionState)
            assertEquals(ScannerAuditTaskState.CANCELLED, value.taskState)
            assertNotNull(value.cancelledAt)
            assertNull(value.statusMessage)
        }
        assertTrue(result.issuesUnavailable)
        assertTrue(result.issues.isEmpty())
        assertNull(result.discoveredIssueCount)
        verify(exactly = 0) { audit.statusMessage() }
        verify(exactly = 0) { audit.issues() }
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `candidate snapshotted before completed cancellation is canonicalized before publication`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val snapshotCaptured = CountDownLatch(1)
        val releaseSnapshot = CountDownLatch(1)
        val armSnapshot = AtomicBoolean(false)
        service.close()
        service = ScannerAuditService(
            api,
            clock = { currentInstant },
            ticker = { currentTick },
            cleanupExecutor = null,
            retainedResultPublicationHook = {
                if (armSnapshot.compareAndSet(true, false)) {
                    snapshotCaptured.countDown()
                    check(releaseSnapshot.await(5, TimeUnit.SECONDS))
                }
            },
        )
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "running"
        every { audit.insertionPointCount() } returns 7
        every { audit.requestCount() } returns 11
        every { audit.errorCount() } returns 2
        every { audit.delete() } just runs
        val started = service.start(passiveInput(1), config)

        armSnapshot.set(true)
        val statusRead = async(Dispatchers.Default) {
            service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        }
        assertTrue(snapshotCaptured.await(5, TimeUnit.SECONDS))
        val cancelled = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        assertEquals(ScannerAuditTaskState.CANCELLED, cancelled.taskState)
        releaseSnapshot.countDown()
        val result = statusRead.await()

        assertEquals(ScannerAuditToolStatus.OK, result.status)
        assertEquals(ScannerAuditActionState.COMPLETED, result.actionState)
        assertEquals(ScannerAuditTaskState.CANCELLED, result.taskState)
        assertNotNull(result.cancelledAt)
        assertNull(result.statusMessage)
        assertNull(result.auditedInsertionPointCount)
        assertNull(result.requestCount)
        assertNull(result.errorCount)
        assertNull(result.discoveredIssueCount)
        assertTrue(result.issues.isEmpty())
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `boundary reset after a successful publication check still scrubs the candidate`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val publicationChecked = CountDownLatch(1)
        val releasePublication = CountDownLatch(1)
        val armPublication = AtomicBoolean(false)
        service.close()
        service = ScannerAuditService(
            api,
            clock = { currentInstant },
            ticker = { currentTick },
            cleanupExecutor = null,
            retainedResultPublicationHook = {
                if (armPublication.compareAndSet(true, false)) {
                    publicationChecked.countDown()
                    check(releasePublication.await(5, TimeUnit.SECONDS))
                }
            },
        )
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "running"
        every { audit.insertionPointCount() } returns 7
        every { audit.requestCount() } returns 11
        every { audit.errorCount() } returns 2
        every { audit.delete() } just runs
        val started = service.start(passiveInput(1), config)

        armPublication.set(true)
        val statusRead = async(Dispatchers.Default) {
            service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        }
        assertTrue(publicationChecked.await(5, TimeUnit.SECONDS))
        service.resetForProjectBoundary()
        releasePublication.countDown()
        val result = statusRead.await()

        assertEquals(ScannerAuditToolStatus.PROJECT_MISMATCH, result.status)
        assertTaskDataScrubbed(result)
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `stale live status telemetry cannot overwrite definitive cancellation`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val statusSampled = CountDownLatch(1)
        val releaseStatusRead = CountDownLatch(1)
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "running"
        every { audit.insertionPointCount() } answers {
            statusSampled.countDown()
            check(releaseStatusRead.await(5, TimeUnit.SECONDS))
            7
        }
        every { audit.requestCount() } returns 11
        every { audit.errorCount() } returns 2
        every { audit.delete() } just runs
        val started = service.start(passiveInput(1), config)

        val staleRead = async(Dispatchers.Default) {
            service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        }
        assertTrue(statusSampled.await(5, TimeUnit.SECONDS))
        val cancelled = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        releaseStatusRead.countDown()
        val staleResult = staleRead.await()
        val final = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)

        listOf(cancelled, staleResult, final).forEach { result ->
            assertEquals(ScannerAuditToolStatus.OK, result.status)
            assertEquals(ScannerAuditActionState.COMPLETED, result.actionState)
            assertEquals(ScannerAuditTaskState.CANCELLED, result.taskState)
            assertNotNull(result.cancelledAt)
            assertNull(result.statusMessage)
        }
        assertNull(staleResult.auditedInsertionPointCount)
        assertNull(staleResult.requestCount)
        assertNull(staleResult.errorCount)
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `issue materialization racing cancellation emits no stale issue telemetry`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val issuesEntered = CountDownLatch(1)
        val releaseIssues = CountDownLatch(1)
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "running"
        every { audit.insertionPointCount() } returns 0
        every { audit.requestCount() } returns 0
        every { audit.errorCount() } returns 0
        every { audit.issues() } answers {
            issuesEntered.countDown()
            check(releaseIssues.await(5, TimeUnit.SECONDS))
            emptyList()
        }
        every { audit.delete() } just runs
        val started = service.start(passiveInput(1), config)

        val read = async(Dispatchers.Default) {
            service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 1), config)
        }
        assertTrue(issuesEntered.await(5, TimeUnit.SECONDS))
        val cancelled = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        assertEquals(ScannerAuditTaskState.CANCELLED, cancelled.taskState)
        releaseIssues.countDown()
        val result = read.await()

        assertEquals(ScannerAuditToolStatus.OK, result.status)
        assertEquals(ScannerAuditActionState.COMPLETED, result.actionState)
        assertEquals(ScannerAuditTaskState.CANCELLED, result.taskState)
        assertTrue(result.issues.isEmpty())
        assertNull(result.discoveredIssueCount)
        assertFalse(result.issuesTruncated)
        assertFalse(result.issuesAccessDenied)
        assertTrue(result.issuesUnavailable)
        verify(exactly = 1) { audit.issues() }
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `newly observed cancelled task skips requested issue access as unavailable`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val dataApproval = mockk<DataAccessApprovalHandler>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "cancelled"
        every { audit.insertionPointCount() } returns 0
        every { audit.requestCount() } returns 0
        every { audit.errorCount() } returns 0
        val started = service.start(passiveInput(1), config)
        config = config(requireDataApproval = true)
        DataAccessSecurity.approvalHandler = dataApproval

        val result = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 1), config)

        assertEquals(ScannerAuditToolStatus.OK, result.status)
        assertEquals(ScannerAuditTaskState.CANCELLED, result.taskState)
        assertNull(result.statusMessage)
        assertNull(result.auditedInsertionPointCount)
        assertNull(result.requestCount)
        assertNull(result.errorCount)
        assertTrue(result.issuesUnavailable)
        assertFalse(result.issuesAccessDenied)
        assertTrue(result.issues.isEmpty())
        coVerify(exactly = 0) { dataApproval.requestDataAccess(any(), any()) }
        verify(exactly = 0) { audit.issues() }
    }

    @Test
    fun `already cancelled task marks requested issues unavailable without claiming denial`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } just runs

        val started = service.start(passiveInput(1), config)
        val cancelled = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        assertEquals(ScannerAuditTaskState.CANCELLED, cancelled.taskState)
        val result = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 1), config)

        assertEquals(ScannerAuditToolStatus.OK, result.status)
        assertEquals(ScannerAuditActionState.COMPLETED, result.actionState)
        assertEquals(ScannerAuditTaskState.CANCELLED, result.taskState)
        assertTrue(result.issuesUnavailable)
        assertFalse(result.issuesAccessDenied)
        assertTrue(result.issues.isEmpty())
        verify(exactly = 0) { audit.issues() }
    }

    @Test
    fun `project transition with denied Scanner cancellation returns mismatch before denial`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        var currentProjectId = "project-123"
        every { project.id() } answers { currentProjectId }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } just runs
        val started = service.start(passiveInput(1), config)
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean {
                currentProjectId = "replacement-project"
                return false
            }
        }

        val result = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)

        assertEquals(ScannerAuditToolStatus.PROJECT_MISMATCH, result.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, result.actionState)
        assertNull(result.taskId)
        assertNull(result.mode)
        assertTrue(result.targets.isEmpty())
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `cancellation approval exception after project transition scrubs task data and reports uncertainty`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        var currentProjectId = "project-123"
        every { project.id() } answers { currentProjectId }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } just runs
        val started = service.start(passiveInput(1), config)
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean {
                currentProjectId = "replacement-project"
                throw IllegalStateException("PRIVATE_SENTINEL")
            }
        }

        val result = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)

        assertEquals(ScannerAuditToolStatus.PROJECT_MISMATCH, result.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, result.actionState)
        assertNull(result.taskId)
        assertNull(result.mode)
        assertTrue(result.targets.isEmpty())
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        assertFalse(result.error.orEmpty().contains("PRIVATE_SENTINEL"))
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `failed post-approval project recheck scrubs retained Scanner task data`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        var failNextProjectRead = false
        every { project.id() } answers {
            if (failNextProjectRead) {
                failNextProjectRead = false
                throw IllegalStateException("PRIVATE_SENTINEL")
            }
            "project-123"
        }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } just runs
        val started = service.start(passiveInput(1), config)
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean {
                failNextProjectRead = true
                return true
            }
        }

        val result = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)

        assertEquals(ScannerAuditToolStatus.BURP_ERROR, result.status)
        assertEquals(ScannerAuditActionState.NOT_STARTED, result.actionState)
        assertNull(result.projectId)
        assertNull(result.taskId)
        assertNull(result.mode)
        assertTrue(result.targets.isEmpty())
        assertFalse(result.error.orEmpty().contains("PRIVATE_SENTINEL"))
        verify(exactly = 0) { audit.delete() }
    }

    @Test
    fun `duplicate cancellation project accessor failure preserves definitive scrubbed state`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } just runs
        val started = service.start(passiveInput(1), config)
        val cancelled = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        assertEquals(ScannerAuditTaskState.CANCELLED, cancelled.taskState)
        every { project.id() } throws IllegalStateException("PRIVATE_SENTINEL")

        val result = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)

        assertEquals(ScannerAuditToolStatus.BURP_ERROR, result.status)
        assertEquals(ScannerAuditActionState.COMPLETED, result.actionState)
        assertEquals(ScannerAuditTaskState.CANCELLED, result.taskState)
        assertTaskDataScrubbed(result)
        assertNull(result.projectId)
        assertNull(result.taskId)
        assertNull(result.mode)
        assertTrue(result.targets.isEmpty())
        assertTrue(result.error.orEmpty().contains("cancellation completed"))
        assertFalse(result.error.orEmpty().contains("PRIVATE_SENTINEL"))
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `duplicate cancellation project mismatch preserves definitive scrubbed state`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        var currentProjectId = "project-123"
        every { project.id() } answers { currentProjectId }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } just runs
        val started = service.start(passiveInput(1), config)
        val cancelled = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        assertEquals(ScannerAuditTaskState.CANCELLED, cancelled.taskState)
        currentProjectId = "replacement-project"

        val result = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)

        assertEquals(ScannerAuditToolStatus.PROJECT_MISMATCH, result.status)
        assertEquals(ScannerAuditActionState.COMPLETED, result.actionState)
        assertEquals(ScannerAuditTaskState.CANCELLED, result.taskState)
        assertEquals("replacement-project", result.projectId)
        assertTaskDataScrubbed(result)
        assertTrue(result.error.orEmpty().contains("cancellation completed"))
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `initial project accessor failure preserves retained cancellation uncertainty`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } throws IllegalStateException("PRIVATE_DELETE_SENTINEL")
        val started = service.start(passiveInput(1), config)
        val uncertain = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        assertEquals(ScannerAuditToolStatus.EXECUTION_UNCERTAIN, uncertain.status)
        every { project.id() } throws IllegalStateException("PRIVATE_PROJECT_SENTINEL")

        val result = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)

        assertEquals(ScannerAuditToolStatus.BURP_ERROR, result.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, result.actionState)
        assertEquals(ScannerAuditTaskState.UNKNOWN, result.taskState)
        assertNull(result.projectId)
        assertTaskDataScrubbed(result)
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        assertFalse(result.error.orEmpty().contains("PRIVATE_"))
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `concurrent boundary reset scrubs a status read even when the project ID is unchanged`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val statusSampled = CountDownLatch(1)
        val releaseStatusRead = CountDownLatch(1)
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "running"
        every { audit.insertionPointCount() } answers {
            statusSampled.countDown()
            check(releaseStatusRead.await(5, TimeUnit.SECONDS))
            3
        }
        every { audit.requestCount() } returns 4
        every { audit.errorCount() } returns 1
        every { audit.delete() } just runs
        val started = service.start(passiveInput(1), config)

        val read = async(Dispatchers.Default) {
            service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        }
        assertTrue(statusSampled.await(5, TimeUnit.SECONDS))
        service.resetForProjectBoundary()
        releaseStatusRead.countDown()
        val result = read.await()

        assertEquals(ScannerAuditToolStatus.PROJECT_MISMATCH, result.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, result.actionState)
        assertTaskDataScrubbed(result)
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `concurrent status read project transition preserves definitive scrubbed cancellation`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val issuesEntered = CountDownLatch(1)
        val releaseIssues = CountDownLatch(1)
        var currentProjectId = "project-123"
        every { project.id() } answers { currentProjectId }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "running"
        every { audit.insertionPointCount() } returns 0
        every { audit.requestCount() } returns 0
        every { audit.errorCount() } returns 0
        every { audit.issues() } answers {
            issuesEntered.countDown()
            check(releaseIssues.await(5, TimeUnit.SECONDS))
            emptyList()
        }
        every { audit.delete() } just runs
        val started = service.start(passiveInput(1), config)

        val read = async(Dispatchers.Default) {
            service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 1), config)
        }
        assertTrue(issuesEntered.await(5, TimeUnit.SECONDS))
        val cancelled = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        assertEquals(ScannerAuditTaskState.CANCELLED, cancelled.taskState)
        currentProjectId = "replacement-project"
        releaseIssues.countDown()
        val result = read.await()

        assertEquals(ScannerAuditToolStatus.PROJECT_MISMATCH, result.status)
        assertEquals(ScannerAuditActionState.COMPLETED, result.actionState)
        assertEquals(ScannerAuditTaskState.CANCELLED, result.taskState)
        assertEquals("replacement-project", result.projectId)
        assertTaskDataScrubbed(result)
        assertTrue(result.error.orEmpty().contains("cancellation completed"))
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `post-delete project transition preserves definitive scrubbed cancellation provenance`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        var currentProjectId = "project-123"
        every { project.id() } answers { currentProjectId }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } answers { currentProjectId = "replacement-project" }
        val started = service.start(passiveInput(1), config)

        val result = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)

        assertEquals(ScannerAuditToolStatus.PROJECT_MISMATCH, result.status)
        assertEquals(ScannerAuditActionState.COMPLETED, result.actionState)
        assertEquals(ScannerAuditTaskState.CANCELLED, result.taskState)
        assertEquals("replacement-project", result.projectId)
        assertTaskDataScrubbed(result)
        assertTrue(result.error.orEmpty().contains("cancellation completed"))
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `post-delete project accessor failure preserves cancellation and a scrubbed Burp error`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        var deleted = false
        every { project.id() } answers {
            if (deleted) throw IllegalStateException("PRIVATE_PROJECT_SENTINEL")
            "project-123"
        }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } answers { deleted = true }
        val started = service.start(passiveInput(1), config)

        val result = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)

        assertEquals(ScannerAuditToolStatus.BURP_ERROR, result.status)
        assertEquals(ScannerAuditActionState.COMPLETED, result.actionState)
        assertEquals(ScannerAuditTaskState.CANCELLED, result.taskState)
        assertNull(result.projectId)
        assertTaskDataScrubbed(result)
        assertTrue(result.error.orEmpty().contains("cancellation completed"))
        assertFalse(result.error.orEmpty().contains("PRIVATE_PROJECT_SENTINEL"))
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `failed cleanup during a project transition returns only scrubbed uncertainty`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        var currentProjectId = "project-123"
        every { project.id() } answers { currentProjectId }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } answers {
            currentProjectId = "replacement-project"
            throw IllegalStateException("PRIVATE_DELETE_SENTINEL")
        }
        val started = service.start(passiveInput(1), config)

        val result = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)

        assertEquals(ScannerAuditToolStatus.PROJECT_MISMATCH, result.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, result.actionState)
        assertEquals(ScannerAuditTaskState.UNKNOWN, result.taskState)
        assertEquals("replacement-project", result.projectId)
        assertNull(result.taskId)
        assertNull(result.mode)
        assertTrue(result.targets.isEmpty())
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        assertFalse(result.error.orEmpty().contains("PRIVATE_DELETE_SENTINEL"))
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `failed cleanup plus project accessor failure returns only scrubbed uncertainty`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        var cleanupFailed = false
        every { project.id() } answers {
            if (cleanupFailed) throw IllegalStateException("PRIVATE_PROJECT_SENTINEL")
            "project-123"
        }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } answers {
            cleanupFailed = true
            throw IllegalStateException("PRIVATE_DELETE_SENTINEL")
        }
        val started = service.start(passiveInput(1), config)

        val result = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)

        assertEquals(ScannerAuditToolStatus.EXECUTION_UNCERTAIN, result.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, result.actionState)
        assertEquals(ScannerAuditTaskState.UNKNOWN, result.taskState)
        assertNull(result.projectId)
        assertNull(result.taskId)
        assertNull(result.mode)
        assertTrue(result.targets.isEmpty())
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        assertFalse(result.error.orEmpty().contains("PRIVATE_"))
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `YOLO Scanner cancellation still rejects a project transition before deletion`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        var cancelling = false
        var cancellationProjectReads = 0
        every { project.id() } answers {
            if (cancelling && cancellationProjectReads++ > 0) "replacement-project" else "project-123"
        }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } just runs
        config.approvalYoloMode = true
        val approval = mockk<SensitiveActionApprovalHandler>()
        SensitiveActionSecurity.approvalHandler = approval
        val started = service.start(passiveInput(1), config)
        assertEquals(ScannerAuditToolStatus.OK, started.status)

        cancelling = true
        val result = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)

        assertEquals(ScannerAuditToolStatus.PROJECT_MISMATCH, result.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, result.actionState)
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        coVerify(exactly = 0) { approval.requestApproval(any(), any(), any(), any(), any()) }
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `Scanner cancellation uncertainty survives reads and resolves during a later start refresh`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val laterAudit = mockk<Audit>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returnsMany listOf(audit, laterAudit)
        every { audit.addRequestResponse(any()) } just runs
        every { laterAudit.addRequestResponse(any()) } just runs
        var auditStatus = "unknown"
        every { audit.delete() } throws CancellationException("cancelled")
        every { audit.statusMessage() } answers { auditStatus }
        every { audit.insertionPointCount() } returns 0
        every { audit.requestCount() } returns 0
        every { audit.errorCount() } returns 0

        val started = service.start(passiveInput(1), config)

        val cancelled = service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        assertEquals(ScannerAuditToolStatus.EXECUTION_UNCERTAIN, cancelled.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, cancelled.actionState)
        assertTrue(cancelled.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        val current = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)

        assertEquals(ScannerAuditToolStatus.EXECUTION_UNCERTAIN, current.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, current.actionState)
        assertEquals(ScannerAuditTaskState.UNKNOWN, current.taskState)
        assertTrue(current.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))

        auditStatus = "cancelled"
        val laterStarted = service.start(passiveInput(1), config)
        assertEquals(ScannerAuditToolStatus.OK, laterStarted.status)
        val resolved = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        assertEquals(ScannerAuditToolStatus.OK, resolved.status)
        assertEquals(ScannerAuditActionState.COMPLETED, resolved.actionState)
        assertEquals(ScannerAuditTaskState.CANCELLED, resolved.taskState)
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `caller cancellation after Scanner cleanup invocation retains uncertainty until definitive reconciliation`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        lateinit var invocationJob: Job
        var auditStatus = "running"
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } answers {
            invocationJob.cancel(CancellationException("caller cancelled"))
            throw CancellationException("caller cancelled")
        }
        every { audit.statusMessage() } answers { auditStatus }
        every { audit.insertionPointCount() } returns 0
        every { audit.requestCount() } returns 0
        every { audit.errorCount() } returns 0
        val started = service.start(passiveInput(1), config)

        supervisorScope {
            val invocation = async {
                invocationJob = currentCoroutineContext()[Job]!!
                service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
            }
            assertFailsWith<CancellationException> { invocation.await() }
        }

        val unresolved = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        assertEquals(ScannerAuditToolStatus.EXECUTION_UNCERTAIN, unresolved.status)
        assertEquals(ScannerAuditActionState.UNCERTAIN, unresolved.actionState)
        assertEquals(ScannerAuditTaskState.RUNNING, unresolved.taskState)
        assertTrue(unresolved.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))

        auditStatus = "cancelled"
        val resolved = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        assertEquals(ScannerAuditToolStatus.OK, resolved.status)
        assertEquals(ScannerAuditActionState.COMPLETED, resolved.actionState)
        assertEquals(ScannerAuditTaskState.CANCELLED, resolved.taskState)
        assertNull(resolved.error)
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `definitive cancellation remains monotonic when a stale concurrent cancel resumes`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val firstApprovalEntered = CompletableDeferred<Unit>()
        val staleApprovalEntered = CompletableDeferred<Unit>()
        val releaseFirstApproval = CompletableDeferred<Unit>()
        val releaseStaleApproval = CompletableDeferred<Unit>()
        val cancellationCommitted = CompletableDeferred<Unit>()
        val approvalSequence = AtomicInteger()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } just runs
        every { audit.statusMessage() } returns "unknown"
        every { audit.insertionPointCount() } returns 0
        every { audit.requestCount() } returns 0
        every { audit.errorCount() } returns 0
        every {
            logging.logToOutput(match { it.contains("outcome=cancelled") })
        } answers {
            cancellationCommitted.complete(Unit)
        }
        val started = service.start(passiveInput(1), config)
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean {
                val sequence = approvalSequence.incrementAndGet()
                val release = if (sequence == 1) {
                    firstApprovalEntered.complete(Unit)
                    releaseFirstApproval
                } else {
                    staleApprovalEntered.complete(Unit)
                    releaseStaleApproval
                }
                release.await()
                return true
            }
        }

        val firstCancellation = async(Dispatchers.Default) {
            service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        }
        withTimeout(10_000) { firstApprovalEntered.await() }
        val staleCancellation = async(Dispatchers.Default) {
            service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        }
        withTimeout(10_000) { staleApprovalEntered.await() }
        releaseFirstApproval.complete(Unit)
        withTimeout(10_000) { cancellationCommitted.await() }
        releaseStaleApproval.complete(Unit)
        val results = listOf(firstCancellation, staleCancellation).map { it.await() }
        val final = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)

        (results + final).forEach { result ->
            assertEquals(ScannerAuditToolStatus.OK, result.status)
            assertEquals(ScannerAuditActionState.COMPLETED, result.actionState)
            assertEquals(ScannerAuditTaskState.CANCELLED, result.taskState)
            assertNull(result.error)
        }
        assertEquals(2, approvalSequence.get())
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `stale concurrent cancellation denial preserves definitive completed action state`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val firstApprovalEntered = CompletableDeferred<Unit>()
        val staleApprovalEntered = CompletableDeferred<Unit>()
        val releaseFirstApproval = CompletableDeferred<Unit>()
        val releaseStaleApproval = CompletableDeferred<Unit>()
        val cancellationCommitted = CompletableDeferred<Unit>()
        val approvalSequence = AtomicInteger()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } just runs
        every {
            logging.logToOutput(match { it.contains("outcome=cancelled") })
        } answers {
            cancellationCommitted.complete(Unit)
        }
        val started = service.start(passiveInput(1), config)
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean {
                val sequence = approvalSequence.incrementAndGet()
                val release = if (sequence == 1) {
                    firstApprovalEntered.complete(Unit)
                    releaseFirstApproval
                } else {
                    staleApprovalEntered.complete(Unit)
                    releaseStaleApproval
                }
                release.await()
                return sequence == 1
            }
        }

        val firstCancellation = async(Dispatchers.Default) {
            service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        }
        withTimeout(10_000) { firstApprovalEntered.await() }
        val staleCancellation = async(Dispatchers.Default) {
            service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        }
        withTimeout(10_000) { staleApprovalEntered.await() }
        releaseFirstApproval.complete(Unit)
        withTimeout(10_000) { cancellationCommitted.await() }
        releaseStaleApproval.complete(Unit)
        val results = listOf(firstCancellation, staleCancellation).map { it.await() }
        val final = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)

        (results + final).forEach { result ->
            assertEquals(ScannerAuditToolStatus.OK, result.status)
            assertEquals(ScannerAuditActionState.COMPLETED, result.actionState)
            assertEquals(ScannerAuditTaskState.CANCELLED, result.taskState)
            assertNull(result.error)
        }
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `stale concurrent cancellation approval failure preserves definitive completed action state`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val firstApprovalEntered = CompletableDeferred<Unit>()
        val staleApprovalEntered = CompletableDeferred<Unit>()
        val releaseFirstApproval = CompletableDeferred<Unit>()
        val releaseStaleApproval = CompletableDeferred<Unit>()
        val cancellationCommitted = CompletableDeferred<Unit>()
        val approvalSequence = AtomicInteger()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } just runs
        every {
            logging.logToOutput(match { it.contains("outcome=cancelled") })
        } answers {
            cancellationCommitted.complete(Unit)
        }
        val started = service.start(passiveInput(1), config)
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean {
                val sequence = approvalSequence.incrementAndGet()
                val release = if (sequence == 1) {
                    firstApprovalEntered.complete(Unit)
                    releaseFirstApproval
                } else {
                    staleApprovalEntered.complete(Unit)
                    releaseStaleApproval
                }
                release.await()
                if (sequence != 1) throw IllegalStateException("PRIVATE_SENTINEL")
                return true
            }
        }

        val firstCancellation = async(Dispatchers.Default) {
            service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        }
        withTimeout(10_000) { firstApprovalEntered.await() }
        val staleCancellation = async(Dispatchers.Default) {
            service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        }
        withTimeout(10_000) { staleApprovalEntered.await() }
        releaseFirstApproval.complete(Unit)
        withTimeout(10_000) { cancellationCommitted.await() }
        releaseStaleApproval.complete(Unit)
        val results = listOf(firstCancellation, staleCancellation).map { it.await() }
        val final = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)

        (results + final).forEach { result ->
            assertEquals(ScannerAuditToolStatus.OK, result.status)
            assertEquals(ScannerAuditActionState.COMPLETED, result.actionState)
            assertEquals(ScannerAuditTaskState.CANCELLED, result.taskState)
            assertNull(result.error)
        }
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `stale project transition scrubs data while preserving definitive completed cancellation`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val firstApprovalEntered = CompletableDeferred<Unit>()
        val staleApprovalEntered = CompletableDeferred<Unit>()
        val releaseFirstApproval = CompletableDeferred<Unit>()
        val releaseStaleApproval = CompletableDeferred<Unit>()
        val cancellationCommitted = CompletableDeferred<Unit>()
        val approvalSequence = AtomicInteger()
        val deleteReturned = AtomicInteger()
        var currentProjectId = "project-123"
        every { project.id() } answers {
            if (deleteReturned.get() == 1 && currentProjectId == "project-123") {
                cancellationCommitted.complete(Unit)
            }
            currentProjectId
        }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } answers { deleteReturned.set(1) }
        val started = service.start(passiveInput(1), config)
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean {
                val sequence = approvalSequence.incrementAndGet()
                val release = if (sequence == 1) {
                    firstApprovalEntered.complete(Unit)
                    releaseFirstApproval
                } else {
                    staleApprovalEntered.complete(Unit)
                    releaseStaleApproval
                }
                release.await()
                if (sequence != 1) currentProjectId = "replacement-project"
                return true
            }
        }

        val cancellations = List(2) {
            async(Dispatchers.Default) {
                service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
            }
        }
        withTimeout(5_000) {
            firstApprovalEntered.await()
            staleApprovalEntered.await()
        }
        releaseFirstApproval.complete(Unit)
        withTimeout(10_000) { cancellationCommitted.await() }
        releaseStaleApproval.complete(Unit)
        val results = cancellations.map { it.await() }
        assertTrue(results.any { it.status == ScannerAuditToolStatus.PROJECT_MISMATCH })
        results.forEach { result ->
            assertTrue(
                result.status == ScannerAuditToolStatus.OK ||
                    result.status == ScannerAuditToolStatus.PROJECT_MISMATCH ||
                    result.status == ScannerAuditToolStatus.BURP_ERROR,
            )
            assertEquals(ScannerAuditActionState.COMPLETED, result.actionState)
            assertEquals(ScannerAuditTaskState.CANCELLED, result.taskState)
            if (result.status != ScannerAuditToolStatus.OK) {
                if (result.status == ScannerAuditToolStatus.PROJECT_MISMATCH) {
                    assertEquals("replacement-project", result.projectId)
                }
                assertTaskDataScrubbed(result)
                assertTrue(result.error.orEmpty().contains("cancellation completed"))
                assertFalse(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
            }
        }
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `definitive cancelled refresh wins over a stale concurrent uncertainty publisher`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val publisherPaused = CountDownLatch(1)
        val resumePublisher = CountDownLatch(1)
        var auditStatus = "unknown"
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.delete() } throws IllegalStateException("PRIVATE_SENTINEL")
        every { audit.statusMessage() } answers { auditStatus }
        every { audit.insertionPointCount() } returns 0
        every { audit.requestCount() } returns 0
        every { audit.errorCount() } returns 0
        every {
            logging.logToOutput(match { it.contains("outcome=cancellation uncertain") })
        } answers {
            publisherPaused.countDown()
            check(resumePublisher.await(5, TimeUnit.SECONDS))
        }
        val started = service.start(passiveInput(1), config)

        val cancellation = async(Dispatchers.Default) {
            service.cancel(CancelScannerAudit("project-123", started.taskId!!), config)
        }
        assertTrue(publisherPaused.await(5, TimeUnit.SECONDS))
        auditStatus = "cancelled"
        val observed = try {
            service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)
        } finally {
            resumePublisher.countDown()
        }
        val stalePublisherResult = cancellation.await()
        val final = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)

        listOf(observed, stalePublisherResult, final).forEach { result ->
            assertEquals(ScannerAuditToolStatus.OK, result.status)
            assertEquals(ScannerAuditActionState.COMPLETED, result.actionState)
            assertEquals(ScannerAuditTaskState.CANCELLED, result.taskState)
            assertNull(result.error)
        }
        verify(exactly = 1) { audit.delete() }
    }

    @Test
    fun `pre-issue project accessor failure marks a requested issue read unavailable`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        var readingStatus = false
        var statusProjectReads = 0
        every { project.id() } answers {
            if (readingStatus && statusProjectReads++ == 1) {
                throw IllegalStateException("PRIVATE_PROJECT_SENTINEL")
            }
            "project-123"
        }
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "Running"
        every { audit.insertionPointCount() } returns 0
        every { audit.requestCount() } returns 1
        every { audit.errorCount() } returns 0
        val started = service.start(passiveInput(1), config)
        readingStatus = true

        val result = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 1), config)

        assertEquals(ScannerAuditToolStatus.BURP_ERROR, result.status)
        assertEquals("project-123", result.projectId)
        assertFalse(result.issuesAccessDenied)
        assertTrue(result.issuesUnavailable)
        assertTrue(result.issues.isEmpty())
        assertTrue(result.error.orEmpty().contains("project recheck failed"))
        assertFalse(result.error.orEmpty().contains("PRIVATE_PROJECT_SENTINEL"))
        verify(exactly = 0) { audit.issues() }
    }

    @Test
    fun `task issue permission failure is unavailable rather than denied`() = runBlocking {
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
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                if (accessType == DataAccessType.SCANNER_ISSUES) {
                    throw IllegalStateException("PRIVATE_SENTINEL")
                }
                return true
            }
        }

        val started = service.start(passiveInput(1), config)
        val result = service.get(GetScannerAudit("project-123", started.taskId!!), config)

        assertEquals(ScannerAuditToolStatus.BURP_ERROR, result.status)
        assertFalse(result.issuesAccessDenied)
        assertTrue(result.issuesUnavailable)
        assertTrue(result.issues.isEmpty())
        assertTrue(result.error.orEmpty().contains("issue access check failed"))
        assertFalse(result.error.orEmpty().contains("PRIVATE_SENTINEL"))
        verify(exactly = 0) { audit.issues() }
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
        assertFalse(result.issuesUnavailable)
        assertTrue(result.issues.isEmpty())
        verify(exactly = 0) { audit.issues() }
    }

    @Test
    fun `issue limit zero returns task status without prompting for issue access`() = runBlocking {
        val item = proxyItem(1, response = mockk())
        val audit = mockk<Audit>()
        val dataApproval = mockk<DataAccessApprovalHandler>()
        every { proxy.history(any()) } returns listOf(item)
        every { scope.isInScope(any()) } returns true
        every { scanner.startAudit(configuration) } returns audit
        every { audit.addRequestResponse(any()) } just runs
        every { audit.statusMessage() } returns "Running"
        every { audit.insertionPointCount() } returns 0
        every { audit.requestCount() } returns 1
        every { audit.errorCount() } returns 0
        config = config(requireDataApproval = false)
        DataAccessSecurity.approvalHandler = dataApproval

        val started = service.start(passiveInput(1), config)
        val result = service.get(GetScannerAudit("project-123", started.taskId!!, issueLimit = 0), config)

        assertEquals(ScannerAuditToolStatus.OK, result.status)
        assertTrue(result.issues.isEmpty())
        assertFalse(result.issuesAccessDenied)
        assertFalse(result.issuesUnavailable)
        coVerify(exactly = 0) { dataApproval.requestDataAccess(any(), any()) }
        verify(exactly = 0) { audit.issues() }
    }

    private fun assertTaskDataScrubbed(result: ScannerAuditResult) {
        assertNull(result.taskId)
        assertNull(result.mode)
        assertNull(result.statusMessage)
        assertNull(result.startedAt)
        assertNull(result.cancelledAt)
        assertTrue(result.targets.isEmpty())
        assertEquals(0, result.targetCount)
        assertEquals(0, result.insertionPointCount)
        assertNull(result.auditedInsertionPointCount)
        assertNull(result.requestCount)
        assertNull(result.errorCount)
        assertNull(result.discoveredIssueCount)
    }

    private fun advance(duration: Duration) {
        currentInstant = currentInstant.plus(duration)
        currentTick += duration.toNanos()
    }

    private fun passiveInput(id: Int) = StartScannerAuditFromIds(
        "project-123",
        ScannerAuditMode.PASSIVE,
        listOf(target(id)),
    )

    private fun target(id: Int) = ScannerAuditTarget(
        HttpMessageReference(HttpMessageSource.PROXY, id.toString())
    )

    private fun scannerIssue(name: String = "Example issue"): AuditIssue {
        val issue = mockk<AuditIssue>()
        val service = mockk<HttpService>()
        val definition = mockk<AuditIssueDefinition>()
        every { issue.definition() } returns definition
        every { definition.typeIndex() } returns 0x1234
        every { issue.name() } returns name
        every { issue.baseUrl() } returns "https://example.test/path"
        every { issue.httpService() } returns service
        every { service.host() } returns "example.test"
        every { service.port() } returns 443
        every { service.secure() } returns true
        every { issue.severity() } returns AuditIssueSeverity.HIGH
        every { issue.confidence() } returns AuditIssueConfidence.CERTAIN
        return issue
    }

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
