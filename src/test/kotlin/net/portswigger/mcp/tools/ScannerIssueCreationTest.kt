package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.sitemap.SiteMap
import io.mockk.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.McpAuditRecord
import net.portswigger.mcp.security.McpAuditSink
import net.portswigger.mcp.security.SensitiveActionApprovalHandler
import net.portswigger.mcp.security.SensitiveActionSecurity
import net.portswigger.mcp.security.newToolAuditInvocation
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Base64
import kotlin.test.*

class ScannerIssueCreationTest {
    private lateinit var originalSensitiveHandler: SensitiveActionApprovalHandler
    private lateinit var originalDataHandler: DataAccessApprovalHandler

    @BeforeEach
    fun setUp() {
        originalSensitiveHandler = SensitiveActionSecurity.approvalHandler
        originalDataHandler = DataAccessSecurity.approvalHandler
    }

    @AfterEach
    fun tearDown() {
        SensitiveActionSecurity.approvalHandler = originalSensitiveHandler
        DataAccessSecurity.approvalHandler = originalDataHandler
    }

    @Test
    fun `invalid attestation and canonical duplicate refs fail before source access`() = runBlocking {
        val fixture = fixture()
        val duplicate = fixture.input.copy(
            refs = listOf(
                HttpMessageReference(HttpMessageSource.PROXY, "1"),
                HttpMessageReference(HttpMessageSource.PROXY, "01"),
            )
        )

        assertEquals(NativeToolStatus.INVALID_ARGUMENT, fixture.service.create(duplicate).status)
        assertEquals(
            NativeToolStatus.INVALID_ARGUMENT,
            fixture.service.create(fixture.input.copy(humanReviewed = false)).status,
        )
        verify(exactly = 0) { fixture.api.project() }
        verify(exactly = 0) { fixture.proxy.history(any()) }
    }

    @Test
    fun `approval preview contains every exact field service ref and base64 evidence`() = runBlocking {
        val request = "GET /evidence HTTP/1.1\r\nHost: example.test\r\n\r\n".toByteArray()
        val response = "HTTP/1.1 200 OK\r\n\r\nsecret".toByteArray()
        val fixture = fixture(request, response)
        var preview: String? = null
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean {
                preview = reviewContent
                return false
            }
        }

        val result = fixture.service.create(
            fixture.input.copy(name = "Caller <name>", detail = "detail & exact", remediation = "fix\nline")
        )

        assertEquals(NativeToolStatus.ACCESS_DENIED, result.status)
        assertEquals(StandardExecutionState.NOT_STARTED, result.executionState)
        assertEquals(0, result.evidenceCount)
        val content = preview.orEmpty()
        listOf(
            "\"projectId\":\"project-a\"",
            "Caller <name>",
            "detail & exact",
            "fix\\nline",
            "https://example.test/evidence",
            "example.test",
            "proxy",
            Base64.getEncoder().encodeToString(request),
            Base64.getEncoder().encodeToString(response),
            "\"requestEncoding\":\"base64\"",
            "\"responseEncoding\":\"base64\"",
        ).forEach { assertTrue(content.contains(it), it) }
        verify(exactly = 0) { fixture.siteMap.add(any<AuditIssue>()) }
    }

    @Test
    fun `issue approval audit records metadata and never field or traffic values`() = runBlocking {
        val fixture = fixture(
            requestBytes = "GET /PRIVATE_TRAFFIC HTTP/1.1\r\nHost: example.test\r\n\r\n".toByteArray()
        )
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ) = false
        }
        val sink = RecordingAuditSink()
        val invocation = newToolAuditInvocation(
            sink,
            "session-private",
            "create_scanner_issue",
            readOnly = false,
            argumentKeys = listOf("projectId", "refs", "name", "detail", "severity", "confidence", "humanReviewed"),
        )

        withContext(invocation) {
            fixture.service.create(fixture.input.copy(detail = "PRIVATE_FIELD_VALUE"))
        }
        invocation.complete("completed")

        val record = sink.records.single()
        assertEquals("create_scanner_issue", record.tool)
        assertEquals(
            listOf("data_access:http_history", "sensitive_action:scanner_issue_create"),
            record.approvals.map { it.kind },
        )
        assertFalse(record.toString().contains("PRIVATE_FIELD_VALUE"))
        assertFalse(record.toString().contains("PRIVATE_TRAFFIC"))
        assertFalse(record.toString().contains("session-private"))
    }

    @Test
    fun `approved submission HTML escapes caller text and reports metadata only`() = runBlocking {
        val fixture = fixture()
        SensitiveActionSecurity.approvalHandler = allowApproval()
        val native = mockNativeIssueFactories(fixture.requestBytes, fixture.responseBytes!!)
        try {
            val result = fixture.service.create(
                fixture.input.copy(
                    name = "A&B <issue> \"quoted\" 'single'",
                    detail = "first<&>\nsecond \"q\" 's'",
                    remediation = "fix & verify",
                )
            )

            assertEquals(NativeToolStatus.OK, result.status)
            assertEquals(ToolRetryGuidance.NOT_APPLICABLE, result.retry)
            assertEquals(StandardExecutionState.COMPLETED, result.executionState)
            assertEquals("project-a", result.projectId)
            assertEquals(1, result.evidenceCount)
            assertNull(result.error)
            verify(exactly = 1) {
                AuditIssue.auditIssue(
                    "A&amp;B &lt;issue&gt; &quot;quoted&quot; &#39;single&#39;",
                    "first&lt;&amp;&gt;<br>second &quot;q&quot; &#39;s&#39;",
                    "fix &amp; verify",
                    "https://example.test/evidence",
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.FIRM,
                    match { it.contains("Caller-authored") && it.contains("did not automatically verify") },
                    match { it.contains("did not automatically verify") },
                    AuditIssueSeverity.HIGH,
                    any<List<HttpRequestResponse>>(),
                )
            }
            verify(exactly = 1) { fixture.siteMap.add(native.issue) }
        } finally {
            native.close()
        }
    }

    @Test
    fun `changed complete evidence after approval fails stale before native mutation`() = runBlocking {
        val fixture = fixture(
            requestBytes = "GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n".toByteArray(),
            responseBytes = "HTTP/1.1 200 OK\r\n\r\none".toByteArray(),
            refreshedRequestBytes = "GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n".toByteArray(),
        )
        SensitiveActionSecurity.approvalHandler = allowApproval()

        val result = fixture.service.create(fixture.input)

        assertEquals(NativeToolStatus.STALE_STATE, result.status)
        assertEquals(StandardExecutionState.NOT_STARTED, result.executionState)
        assertEquals(0, result.evidenceCount)
        verify(exactly = 0) { fixture.siteMap.add(any<AuditIssue>()) }
    }

    @Test
    fun `disappeared evidence or invalid changed URL is stale after approval`() = runBlocking {
        for (disappear in listOf(true, false)) {
            var available = true
            val fixture = fixture(
                available = { available },
                refreshedUrl = if (disappear) "https://example.test/evidence" else "invalid\nurl",
            )
            SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
                override suspend fun requestApproval(
                    action: String, summary: String, reviewContent: String?, renderContentAsHttp: Boolean, api: MontoyaApi,
                ): Boolean {
                    if (disappear) available = false
                    return true
                }
            }
            val result = fixture.service.create(fixture.input)
            assertEquals(NativeToolStatus.STALE_STATE, result.status)
            assertEquals(StandardExecutionState.NOT_STARTED, result.executionState)
            verify(exactly = 0) { fixture.siteMap.add(any<AuditIssue>()) }
        }
    }

    @Test
    fun `evidence limit rejects complete snapshot without reading a prefix or prompting`() = runBlocking {
        val fixture = fixture(requestLengthOverride = 256 * 1024 + 1)
        var prompted = false
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean {
                prompted = true
                return true
            }
        }

        val result = fixture.service.create(fixture.input)

        assertEquals(NativeToolStatus.LIMIT_EXCEEDED, result.status)
        assertFalse(prompted)
        verify(exactly = 0) { fixture.requestRaw.getBytes() }
        verify(exactly = 0) { fixture.siteMap.add(any<AuditIssue>()) }
    }

    @Test
    fun `emergency transition after approval prevents submission`() = runBlocking {
        var emergency = false
        val fixture = fixture(emergency = { emergency })
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean {
                emergency = true
                return true
            }
        }

        val result = fixture.service.create(fixture.input)

        assertEquals(NativeToolStatus.DISABLED, result.status)
        assertEquals(StandardExecutionState.NOT_STARTED, result.executionState)
        verify(exactly = 0) { fixture.siteMap.add(any<AuditIssue>()) }
    }

    @Test
    fun `project transition after native add suppresses stale project output and is uncertain`() = runBlocking {
        var projectId = "project-a"
        val fixture = fixture(projectId = { projectId })
        SensitiveActionSecurity.approvalHandler = allowApproval()
        val native = mockNativeIssueFactories(fixture.requestBytes, fixture.responseBytes!!)
        every { fixture.siteMap.add(native.issue) } answers { projectId = "project-b" }
        try {
            val result = fixture.service.create(fixture.input)

            assertEquals(NativeToolStatus.EXECUTION_UNCERTAIN, result.status)
            assertEquals(ToolRetryGuidance.DO_NOT_RETRY, result.retry)
            assertEquals(StandardExecutionState.UNCERTAIN, result.executionState)
            assertNull(result.projectId)
            assertEquals(0, result.evidenceCount)
            verify(exactly = 1) { fixture.siteMap.add(native.issue) }
        } finally {
            native.close()
        }
    }

    @Test
    fun `project transition when the mutation barrier returns suppresses completed output`() = runBlocking {
        var projectId = "project-a"
        val fixture = fixture(
            projectId = { projectId },
            withMutation = { _, block -> block(); projectId = "project-b" },
        )
        SensitiveActionSecurity.approvalHandler = allowApproval()
        val native = mockNativeIssueFactories(fixture.requestBytes, fixture.responseBytes!!)
        try {
            val result = fixture.service.create(fixture.input)
            assertEquals(NativeToolStatus.EXECUTION_UNCERTAIN, result.status)
            assertEquals(ToolRetryGuidance.DO_NOT_RETRY, result.retry)
            assertNull(result.projectId)
            assertEquals(0, result.evidenceCount)
            verify(exactly = 1) { fixture.siteMap.add(native.issue) }
        } finally {
            native.close()
        }
    }

    @Test
    fun `source denial prevents evidence capture and issue approval`() = runBlocking {
        val fixture = fixture(requireDataApproval = true)
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(
                accessType: net.portswigger.mcp.security.DataAccessType,
                config: McpConfig,
            ) = false
        }
        val result = fixture.service.create(fixture.input)
        assertEquals(NativeToolStatus.ACCESS_DENIED, result.status)
        verify(exactly = 0) { fixture.proxy.history(any()) }
        verify(exactly = 0) { fixture.siteMap.add(any<AuditIssue>()) }
    }

    @Test
    fun `native add failure is uncertain and must not be retried`() = runBlocking {
        val fixture = fixture()
        SensitiveActionSecurity.approvalHandler = allowApproval()
        val native = mockNativeIssueFactories(fixture.requestBytes, fixture.responseBytes!!)
        every { fixture.siteMap.add(native.issue) } throws IllegalStateException("PRIVATE_NATIVE_FAILURE")
        try {
            val result = fixture.service.create(fixture.input)

            assertEquals(NativeToolStatus.EXECUTION_UNCERTAIN, result.status)
            assertEquals(ToolRetryGuidance.DO_NOT_RETRY, result.retry)
            assertEquals(StandardExecutionState.UNCERTAIN, result.executionState)
            assertFalse(result.error.orEmpty().contains("PRIVATE_NATIVE_FAILURE"))
            assertNull(result.projectId)
            assertEquals(0, result.evidenceCount)
            verify(exactly = 1) { fixture.siteMap.add(native.issue) }
        } finally {
            native.close()
        }
    }

    @Test
    fun `caller cancellation while waiting for mutation barrier propagates without submission`() = runBlocking {
        val fixture = fixture(withMutation = { _, _ -> throw CancellationException("barrier cancelled") })
        SensitiveActionSecurity.approvalHandler = allowApproval()

        assertFailsWith<CancellationException> { fixture.service.create(fixture.input) }
        verify(exactly = 0) { fixture.siteMap.add(any<AuditIssue>()) }
    }

    private fun allowApproval() = object : SensitiveActionApprovalHandler {
        override suspend fun requestApproval(
            action: String,
            summary: String,
            reviewContent: String?,
            renderContentAsHttp: Boolean,
            api: MontoyaApi,
        ) = true
    }

    private fun fixture(
        requestBytes: ByteArray = "GET /evidence HTTP/1.1\r\nHost: example.test\r\n\r\nbody".toByteArray(),
        responseBytes: ByteArray? = "HTTP/1.1 200 OK\r\n\r\nresponse".toByteArray(),
        refreshedRequestBytes: ByteArray = requestBytes,
        requestLengthOverride: Int? = null,
        requireDataApproval: Boolean = false,
        available: () -> Boolean = { true },
        refreshedUrl: String = "https://example.test/evidence",
        emergency: () -> Boolean = { false },
        projectId: () -> String = { "project-a" },
        withMutation: suspend (String, suspend () -> Unit) -> Unit = { _, block -> block() },
    ): Fixture {
        val api = mockk<MontoyaApi>(relaxed = true)
        val project = mockk<Project>()
        val proxy = mockk<Proxy>()
        val item = mockk<ProxyHttpRequestResponse>()
        val request = mockk<HttpRequest>()
        val response = responseBytes?.let { mockk<HttpResponse>() }
        val service = mockk<HttpService>()
        val siteMap = mockk<SiteMap>(relaxed = true)
        val logging = mockk<Logging>(relaxed = true)
        val storage = mockk<PersistedObject>()
        val initialRaw = montoyaBytes(requestBytes, requestLengthOverride)
        val refreshedRaw = montoyaBytes(refreshedRequestBytes)
        val responseRaw = responseBytes?.let(::montoyaBytes)
        var requestReads = 0

        every { storage.getBoolean(any()) } answers {
            when (firstArg<String>()) {
                "emergencyReadOnlyMode" -> emergency()
                "requireDataAccessApproval" -> requireDataApproval
                else -> false
            }
        }
        every { storage.getString(any()) } returns ""
        val config = McpConfig(storage, logging, net.portswigger.mcp.testPreferences())
        every { api.project() } returns project
        every { project.id() } answers { projectId() }
        every { api.proxy() } returns proxy
        every { api.siteMap() } returns siteMap
        every { api.logging() } returns logging
        every { proxy.history(any()) } answers {
            val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
            if (available()) listOf(item).filter(filter::matches) else emptyList()
        }
        every { item.id() } returns 1
        every { item.request() } returns request
        every { item.response() } returns response
        every { request.bodyOffset() } returns 0
        every { request.body() } answers { if (requestReads == 0) initialRaw else refreshedRaw }
        every { request.toByteArray() } answers {
            if (requestReads++ == 0) initialRaw else refreshedRaw
        }
        every { request.httpService() } returns service
        every { request.url() } answers { if (requestReads > 1) refreshedUrl else "https://example.test/evidence" }
        every { service.host() } returns "example.test"
        every { service.port() } returns 443
        every { service.secure() } returns true
        if (response != null && responseRaw != null) {
            every { response.bodyOffset() } returns 0
            every { response.body() } returns responseRaw
            every { response.toByteArray() } returns responseRaw
        }

        val input = CreateScannerIssue(
            projectId = "project-a",
            refs = listOf(HttpMessageReference(HttpMessageSource.PROXY, "1")),
            name = "Example issue",
            detail = "Human reviewed detail",
            severity = ScannerIssueSeverity.HIGH,
            confidence = ScannerIssueConfidence.FIRM,
            humanReviewed = true,
        )
        return Fixture(
            api,
            proxy,
            siteMap,
            requestRaw = initialRaw,
            requestBytes,
            responseBytes,
            input,
            ScannerIssueCreationService(api, config, withMutation),
        )
    }

    private fun montoyaBytes(raw: ByteArray, lengthOverride: Int? = null): MontoyaByteArray =
        mockk<MontoyaByteArray>().also {
            every { it.length() } returns (lengthOverride ?: raw.size)
            every { it.getBytes() } returns raw
        }

    private fun mockNativeIssueFactories(requestBytes: ByteArray, responseBytes: ByteArray): NativeFactories {
        mockkStatic(HttpService::class)
        mockkStatic(MontoyaByteArray::class)
        mockkStatic(HttpRequest::class)
        mockkStatic(HttpResponse::class)
        mockkStatic(HttpRequestResponse::class)
        mockkStatic(AuditIssue::class)
        val service = mockk<HttpService>()
        val requestRaw = mockk<MontoyaByteArray>()
        val responseRaw = mockk<MontoyaByteArray>()
        val request = mockk<HttpRequest>()
        val response = mockk<HttpResponse>()
        val evidence = mockk<HttpRequestResponse>()
        val issue = mockk<AuditIssue>()
        every { HttpService.httpService("example.test", 443, true) } returns service
        every { MontoyaByteArray.byteArray(*requestBytes) } returns requestRaw
        every { MontoyaByteArray.byteArray(*responseBytes) } returns responseRaw
        every { HttpRequest.httpRequest(service, requestRaw) } returns request
        every { HttpResponse.httpResponse(responseRaw) } returns response
        every { HttpRequestResponse.httpRequestResponse(request, response) } returns evidence
        every {
            AuditIssue.auditIssue(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any<List<HttpRequestResponse>>()
            )
        } returns issue
        return NativeFactories(issue)
    }

    private data class Fixture(
        val api: MontoyaApi,
        val proxy: Proxy,
        val siteMap: SiteMap,
        val requestRaw: MontoyaByteArray,
        val requestBytes: ByteArray,
        val responseBytes: ByteArray?,
        val input: CreateScannerIssue,
        val service: ScannerIssueCreationService,
    )

    private class RecordingAuditSink : McpAuditSink {
        val records = mutableListOf<McpAuditRecord>()
        override fun append(record: McpAuditRecord) { records += record }
        override fun recordLocalEvent(tool: String, outcome: String) = Unit
        override fun snapshot(limit: Int) = records.takeLast(limit)
        override fun size() = records.size
        override fun clear() = records.clear()
        override fun trimToConfiguredRetention() = Unit
        override fun flush() = Unit
        override fun exportJsonLines(limit: Int) = ""
        override fun close() = Unit
    }

    private data class NativeFactories(val issue: AuditIssue) : AutoCloseable {
        override fun close() {
            unmockkStatic(AuditIssue::class)
            unmockkStatic(HttpRequestResponse::class)
            unmockkStatic(HttpResponse::class)
            unmockkStatic(HttpRequest::class)
            unmockkStatic(MontoyaByteArray::class)
            unmockkStatic(HttpService::class)
        }
    }
}
