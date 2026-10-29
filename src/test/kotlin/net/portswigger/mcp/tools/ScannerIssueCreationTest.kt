package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.core.Marker
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

        val result = fixture.service.create(fixture.input.copy(markers = listOf(
            ScannerEvidenceMarker(0, ScannerEvidencePart.REQUEST, 0, 1),
        )))

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

    @Test
    fun `marker shape index counts duplicates and overlaps fail before source access`() = runBlocking {
        val fixture = fixture()
        val range = ScannerEvidenceMarker(0, ScannerEvidencePart.REQUEST, 0, 2)
        val invalid = listOf(
            listOf(range.copy(evidenceIndex = -1)), listOf(range.copy(evidenceIndex = 1)),
            listOf(range.copy(start = -1)), listOf(range.copy(end = 0)),
            listOf(range.copy(start = 2)), listOf(range.copy(end = 262145)),
            listOf(range, range), listOf(range, range.copy(start = 1, end = 3)),
            List(65) { range.copy(start = it * 2, end = it * 2 + 1) },
        )
        for (markers in invalid) {
            val result = fixture.service.create(fixture.input.copy(markers = markers))
            assertEquals(NativeToolStatus.INVALID_ARGUMENT, result.status)
            assertEquals(StandardExecutionState.NOT_STARTED, result.executionState)
        }
        verify(exactly = 0) { fixture.api.project() }
        verify(exactly = 0) { fixture.proxy.history(any()) }
        verify(exactly = 0) { fixture.siteMap.add(any<AuditIssue>()) }
    }

    @Test
    fun `missing response and actual byte overflow fail before issue approval`() = runBlocking {
        var prompts = 0
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String, summary: String, reviewContent: String?, renderContentAsHttp: Boolean, api: MontoyaApi,
            ): Boolean { prompts++; return true }
        }
        for (part in ScannerEvidencePart.entries) {
            val fixture = fixture(responseBytes = null)
            val end = if (part == ScannerEvidencePart.REQUEST) fixture.requestBytes.size + 1 else 1
            val result = fixture.service.create(fixture.input.copy(markers = listOf(ScannerEvidenceMarker(0, part, 0, end))))
            assertEquals(NativeToolStatus.INVALID_ARGUMENT, result.status)
            assertEquals(StandardExecutionState.NOT_STARTED, result.executionState)
            verify(exactly = 0) { fixture.siteMap.add(any<AuditIssue>()) }
        }
        assertEquals(0, prompts)
    }

    @Test
    fun `marker limits accept 64 adjacent ranges and exact maximum byte boundary`() = runBlocking {
        val fixture = fixture(requestBytes = ByteArray(262144) { 'a'.code.toByte() })
        var preview: String? = null
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String, summary: String, reviewContent: String?, renderContentAsHttp: Boolean, api: MontoyaApi,
            ): Boolean { preview = reviewContent; return false }
        }
        val markers = List(63) { ScannerEvidenceMarker(0, ScannerEvidencePart.REQUEST, it, it + 1) } +
            ScannerEvidenceMarker(0, ScannerEvidencePart.REQUEST, 63, 262144)
        val result = fixture.service.create(fixture.input.copy(markers = markers))
        assertEquals(NativeToolStatus.ACCESS_DENIED, result.status)
        assertTrue(preview.orEmpty().contains("\"end\":262144"))
        verify(exactly = 0) { fixture.siteMap.add(any<AuditIssue>()) }
    }

    @Test
    fun `frozen refs and markers apply raw multibyte ranges only to new evidence copies`() = runBlocking {
        val raw = "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n한글".toByteArray()
        val fixture = fixture(requestBytes = raw)
        val refs = fixture.input.refs.toMutableList()
        val markers = mutableListOf(
            ScannerEvidenceMarker(0, ScannerEvidencePart.REQUEST, raw.size - 3, raw.size),
            ScannerEvidenceMarker(0, ScannerEvidencePart.REQUEST, raw.size - 6, raw.size - 3),
            ScannerEvidenceMarker(0, ScannerEvidencePart.RESPONSE, 0, 2),
        )
        var preview: String? = null
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String, summary: String, reviewContent: String?, renderContentAsHttp: Boolean, api: MontoyaApi,
            ): Boolean {
                preview = reviewContent
                refs.clear()
                markers.clear()
                return true
            }
        }
        val native = mockNativeIssueFactories(raw, fixture.responseBytes!!)
        val first = mockk<Marker>()
        val second = mockk<Marker>()
        val response = mockk<Marker>()
        val requestMarked = mockk<HttpRequestResponse>()
        val bothMarked = mockk<HttpRequestResponse>()
        every { Marker.marker(raw.size - 6, raw.size - 3) } returns first
        every { Marker.marker(raw.size - 3, raw.size) } returns second
        every { Marker.marker(0, 2) } returns response
        every { native.evidence.withRequestMarkers(listOf(first, second)) } returns requestMarked
        every { requestMarked.withResponseMarkers(listOf(response)) } returns bothMarked
        try {
            val result = fixture.service.create(fixture.input.copy(refs = refs, markers = markers))
            assertEquals(NativeToolStatus.OK, result.status)
            assertEquals(1, result.evidenceCount)
            assertTrue(preview.orEmpty().contains("\"evidenceIndex\":0"))
            assertTrue(preview.orEmpty().contains("\"part\":\"request\""))
            assertTrue(preview.orEmpty().contains("\"end\":${raw.size}"))
            assertTrue(raw.size > raw.toString(Charsets.UTF_8).length)
            verify(exactly = 1) { native.evidence.withRequestMarkers(listOf(first, second)) }
            verify(exactly = 1) { requestMarked.withResponseMarkers(listOf(response)) }
            verify(exactly = 1) {
                AuditIssue.auditIssue(any(), any(), any(), any(), any(), any(), any(), any(), any(), listOf(bothMarked))
            }
            verify(exactly = 0) { fixture.sourceRequest.withMarkers(any<List<Marker>>()) }
            verify(exactly = 0) { fixture.sourceResponse!!.withMarkers(any<List<Marker>>()) }
            verify(exactly = 1) { fixture.siteMap.add(native.issue) }
        } finally { native.close() }
    }

    @Test
    fun `markers are attached to the selected evidence index only`() = runBlocking {
        val fixture = fixture(evidenceCount = 2)
        SensitiveActionSecurity.approvalHandler = allowApproval()
        val native = mockNativeIssueFactories(fixture.requestBytes, fixture.responseBytes!!)
        val second = mockk<HttpRequestResponse>()
        val marked = mockk<HttpRequestResponse>()
        every { HttpRequestResponse.httpRequestResponse(any(), any()) } returnsMany listOf(native.evidence, second)
        every { second.withResponseMarkers(any<List<Marker>>()) } returns marked
        try {
            val result = fixture.service.create(fixture.input.copy(markers = listOf(
                ScannerEvidenceMarker(1, ScannerEvidencePart.RESPONSE, 0, 1),
            )))
            assertEquals(NativeToolStatus.OK, result.status)
            verify(exactly = 0) { native.evidence.withResponseMarkers(any<List<Marker>>()) }
            verify(exactly = 1) {
                AuditIssue.auditIssue(any(), any(), any(), any(), any(), any(), any(), any(), any(), listOf(native.evidence, marked))
            }
        } finally { native.close() }
    }

    @Test
    fun `null and empty markers retain unmarked submission and marker failures do not submit`() = runBlocking {
        val fixture = fixture()
        SensitiveActionSecurity.approvalHandler = allowApproval()
        val native = mockNativeIssueFactories(fixture.requestBytes, fixture.responseBytes!!)
        try {
            for (markers in listOf(null, emptyList<ScannerEvidenceMarker>())) {
                assertEquals(NativeToolStatus.OK, fixture.service.create(fixture.input.copy(markers = markers)).status)
            }
            verify(exactly = 0) { Marker.marker(any<Int>(), any<Int>()) }
            verify(exactly = 0) { native.evidence.withRequestMarkers(any<List<Marker>>()) }
            every { native.evidence.withRequestMarkers(any<List<Marker>>()) } throws IllegalStateException("private marker failure")
            val failed = fixture.service.create(fixture.input.copy(markers = listOf(
                ScannerEvidenceMarker(0, ScannerEvidencePart.REQUEST, 0, 1),
            )))
            assertEquals(NativeToolStatus.BURP_ERROR, failed.status)
            assertEquals(StandardExecutionState.NOT_STARTED, failed.executionState)
            assertFalse(failed.error.orEmpty().contains("private marker failure"))
            verify(exactly = 2) { fixture.siteMap.add(native.issue) }
        } finally { native.close() }
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
        evidenceCount: Int = 1,
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
        val items = listOf(item) + (2..evidenceCount).map { id ->
            mockk<ProxyHttpRequestResponse>().also {
                every { it.id() } returns id
                every { it.request() } returns request
                every { it.response() } returns response
            }
        }
        every { proxy.history(any()) } answers {
            val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
            if (available()) items.filter(filter::matches) else emptyList()
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
            refs = (1..evidenceCount).map { HttpMessageReference(HttpMessageSource.PROXY, it.toString()) },
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
            sourceRequest = request,
            sourceResponse = response,
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
        mockkStatic(Marker::class)
        every { Marker.marker(any<Int>(), any<Int>()) } answers { mockk<Marker>() }
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
        every { evidence.withRequestMarkers(any<List<Marker>>()) } returns evidence
        every { evidence.withResponseMarkers(any<List<Marker>>()) } returns evidence
        every {
            AuditIssue.auditIssue(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any<List<HttpRequestResponse>>()
            )
        } returns issue
        return NativeFactories(issue, evidence)
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
        val sourceRequest: HttpRequest,
        val sourceResponse: HttpResponse?,
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

    private data class NativeFactories(val issue: AuditIssue, val evidence: HttpRequestResponse) : AutoCloseable {
        override fun close() {
            unmockkStatic(Marker::class)
            unmockkStatic(AuditIssue::class)
            unmockkStatic(HttpRequestResponse::class)
            unmockkStatic(HttpResponse::class)
            unmockkStatic(HttpRequest::class)
            unmockkStatic(MontoyaByteArray::class)
            unmockkStatic(HttpService::class)
        }
    }
}
