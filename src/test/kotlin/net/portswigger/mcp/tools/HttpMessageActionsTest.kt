package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.core.Range
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.RedirectionMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.intruder.HttpRequestTemplate
import burp.api.montoya.intruder.Intruder
import burp.api.montoya.logging.Logging
import burp.api.montoya.organizer.Organizer
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHistoryFilter
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.repeater.Repeater
import burp.api.montoya.sitemap.SiteMap
import io.mockk.*
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.RequestActionApprovalHandler
import net.portswigger.mcp.security.RequestActionSecurity
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class HttpMessageActionsTest {
    private val api = mockk<MontoyaApi>()
    private val project = mockk<Project>()
    private val proxy = mockk<Proxy>()
    private val logging = mockk<Logging>(relaxed = true)
    private lateinit var config: McpConfig
    private lateinit var service: HttpMessageActionService
    private lateinit var originalApprovalHandler: RequestActionApprovalHandler

    @BeforeEach
    fun setUp() {
        originalApprovalHandler = RequestActionSecurity.approvalHandler
        val storedBooleans = mutableMapOf<String, Boolean>()
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers { storedBooleans[firstArg()] ?: false }
        every { storage.setBoolean(any(), any()) } answers {
            storedBooleans[firstArg()] = secondArg()
        }
        every { storage.getString(any()) } returns ""
        every { api.project() } returns project
        every { project.id() } returns "project-123"
        every { api.proxy() } returns proxy
        every { api.logging() } returns logging
        config = McpConfig(storage, logging)
        service = HttpMessageActionService(api, config)
    }

    @AfterEach
    fun tearDown() {
        RequestActionSecurity.approvalHandler = originalApprovalHandler
    }

    @Test
    fun `Repeater action resolves with a filtered lookup and routes the exact request`() = runBlocking {
        val fixture = proxyFixture(42)
        filteredHistory(fixture.item)
        val repeater = mockk<Repeater>(relaxed = true)
        every { api.repeater() } returns repeater

        val result = service.createRepeaterTab(
            CreateRepeaterTabFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "42"),
                tabName = "derived",
            )
        )

        assertEquals(HttpMessageActionStatus.OK, result.status)
        assertEquals(HttpMessageExecutionState.COMPLETED, result.executionState)
        assertFalse(result.patchApplied)
        assertEquals(64, result.requestBytes)
        verify(exactly = 1) { proxy.history(any()) }
        verify(exactly = 0) { proxy.history() }
        verify(exactly = 0) { fixture.request.toByteArray() }
        verify(exactly = 1) { fixture.request.bodyOffset() }
        verify(exactly = 0) { fixture.request.toString() }
        verify(exactly = 1) { repeater.sendToRepeater(fixture.request, "derived") }
    }

    @Test
    fun `project mismatch is rejected before history access`() = runBlocking {
        val result = service.sendToIntruder(
            SendToIntruderFromId(
                projectId = "other-project",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "42"),
            )
        )

        assertEquals(HttpMessageActionStatus.PROJECT_MISMATCH, result.status)
        assertEquals(HttpMessageExecutionState.NOT_STARTED, result.executionState)
        verify(exactly = 0) { proxy.history(any()) }
    }

    @Test
    fun `structured patch applies method header and body without rebuilding raw HTTP`() = runBlocking {
        val item = mockk<ProxyHttpRequestResponse>()
        val original = request(method = "GET", path = "/old", text = "GET /old HTTP/1.1\r\n\r\n")
        val withMethod = request(method = "POST", path = "/old", text = "POST /old HTTP/1.1\r\n\r\n")
        val withHeader = request(method = "POST", path = "/old", text = "POST /old HTTP/1.1\r\nX-Test: yes\r\n\r\n")
        val finalRequest = request(
            method = "POST",
            path = "/old",
            text = "POST /old HTTP/1.1\r\nX-Test: yes\r\nContent-Length: 5\r\n\r\nhello",
            bytes = 67,
        )
        every { original.withMethod("POST") } returns withMethod
        every { withMethod.withRemovedHeader("X-Test") } returns withMethod
        every { withMethod.withAddedHeader("X-Test", "yes") } returns withHeader
        every { withHeader.withBody("hello") } returns finalRequest
        every { item.id() } returns 7
        every { item.request() } returns original
        every { item.response() } returns null
        every { item.httpService() } returns original.httpService()
        filteredHistory(item)
        val intruder = mockk<Intruder>(relaxed = true)
        every { api.intruder() } returns intruder

        val result = service.sendToIntruder(
            SendToIntruderFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "7"),
                patch = HttpRequestPatch(
                    method = "POST",
                    setHeaders = listOf(HttpHeaderMutation("X-Test", "yes")),
                    body = HttpBodyPatch(HttpBodyPatchEncoding.TEXT, "hello"),
                ),
                tabName = "patched",
            )
        )

        assertEquals(HttpMessageActionStatus.OK, result.status)
        assertTrue(result.patchApplied)
        assertTrue(result.changes.orEmpty().contains("method GET -> POST"))
        assertTrue(result.changes.orEmpty().contains("set header x-test"))
        assertTrue(result.changes.orEmpty().contains("replace body (5 bytes"))
        verify(exactly = 1) { intruder.sendToIntruder(finalRequest, "patched") }
    }

    @Test
    fun `structured patch fails closed if Burp reports a changed destination service`() = runBlocking {
        val item = mockk<ProxyHttpRequestResponse>()
        val original = request(method = "GET")
        val changed = request(method = "POST")
        val changedService = mockk<HttpService>()
        every { changed.httpService() } returns changedService
        every { changedService.host() } returns "attacker.test"
        every { changedService.port() } returns 443
        every { changedService.secure() } returns true
        every { original.withMethod("POST") } returns changed
        every { item.id() } returns 18
        every { item.request() } returns original
        every { item.response() } returns null
        filteredHistory(item)
        val intruder = mockk<Intruder>(relaxed = true)
        every { api.intruder() } returns intruder

        val result = service.sendToIntruder(
            SendToIntruderFromId(
                "project-123",
                HttpMessageReference(HttpMessageSource.PROXY, "18"),
                patch = HttpRequestPatch(method = "POST"),
            )
        )

        assertEquals(HttpMessageActionStatus.INVALID_ARGUMENT, result.status)
        assertTrue(result.error.orEmpty().contains("destination service"))
        verify(exactly = 0) { intruder.sendToIntruder(any<HttpRequest>()) }
    }

    @Test
    fun `completed action audit omits request bodies and header values`() = runBlocking {
        val item = mockk<ProxyHttpRequestResponse>()
        val original = request(method = "POST", path = "/audit", text = "POST /audit HTTP/1.1\r\n\r\n")
        val withHeader = request(
            method = "POST",
            path = "/audit",
            text = "POST /audit HTTP/1.1\r\nAuthorization: Bearer audit-header-secret\r\n\r\n",
        )
        val finalRequest = request(
            method = "POST",
            path = "/audit",
            text = "POST /audit HTTP/1.1\r\nAuthorization: Bearer audit-header-secret\r\n\r\naudit-body-secret",
        )
        every { original.withAddedHeader("Authorization", "Bearer audit-header-secret") } returns withHeader
        every { withHeader.withBody("audit-body-secret") } returns finalRequest
        every { item.id() } returns 17
        every { item.request() } returns original
        every { item.response() } returns null
        filteredHistory(item)
        val repeater = mockk<Repeater>(relaxed = true)
        every { api.repeater() } returns repeater
        val auditMessages = mutableListOf<String>()
        every { logging.logToOutput(capture(auditMessages)) } just Runs

        val result = service.createRepeaterTab(
            CreateRepeaterTabFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "17"),
                patch = HttpRequestPatch(
                    addHeaders = listOf(HttpHeaderMutation("Authorization", "Bearer audit-header-secret")),
                    body = HttpBodyPatch(HttpBodyPatchEncoding.TEXT, "audit-body-secret"),
                ),
            )
        )

        assertEquals(HttpMessageActionStatus.OK, result.status)
        val audit = auditMessages.joinToString("\n")
        assertTrue(audit.contains("destination=repeater"))
        assertTrue(audit.contains("patchApplied=true"))
        assertFalse(audit.contains("audit-header-secret"))
        assertFalse(audit.contains("audit-body-secret"))
    }

    @Test
    fun `header injection is rejected before any destination action`() = runBlocking {
        val fixture = proxyFixture(8)
        filteredHistory(fixture.item)
        val repeater = mockk<Repeater>(relaxed = true)
        every { api.repeater() } returns repeater

        val result = service.createRepeaterTab(
            CreateRepeaterTabFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "8"),
                patch = HttpRequestPatch(
                    addHeaders = listOf(HttpHeaderMutation("X-Test", "ok\r\nInjected: yes")),
                ),
            )
        )

        assertEquals(HttpMessageActionStatus.INVALID_ARGUMENT, result.status)
        assertEquals(HttpMessageExecutionState.NOT_STARTED, result.executionState)
        verify(exactly = 0) { repeater.sendToRepeater(any<HttpRequest>()) }
    }

    @Test
    fun `oversized source request is rejected before routing`() = runBlocking {
        val item = mockk<ProxyHttpRequestResponse>()
        val oversized = request(bytes = MAX_ACTION_REQUEST_BYTES + 1)
        every { item.id() } returns 12
        every { item.request() } returns oversized
        every { item.response() } returns null
        every { item.httpService() } returns oversized.httpService()
        filteredHistory(item)
        val repeater = mockk<Repeater>(relaxed = true)
        every { api.repeater() } returns repeater

        val result = service.createRepeaterTab(
            CreateRepeaterTabFromId(
                "project-123",
                HttpMessageReference(HttpMessageSource.PROXY, "12"),
            )
        )

        assertEquals(HttpMessageActionStatus.INVALID_ARGUMENT, result.status)
        assertTrue(result.error.orEmpty().contains("action limit"))
        verify(exactly = 0) { repeater.sendToRepeater(any<HttpRequest>()) }
    }

    @Test
    fun `body replacement rejects conflicting body parameter mutations`() = runBlocking {
        val fixture = proxyFixture(13)
        filteredHistory(fixture.item)
        val intruder = mockk<Intruder>(relaxed = true)
        every { api.intruder() } returns intruder

        val result = service.sendToIntruder(
            SendToIntruderFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "13"),
                patch = HttpRequestPatch(
                    addParameters = listOf(
                        HttpParameterMutation(HttpActionParameterType.JSON, "name", "value")
                    ),
                    body = HttpBodyPatch(HttpBodyPatchEncoding.TEXT, "{}"),
                ),
            )
        )

        assertEquals(HttpMessageActionStatus.INVALID_ARGUMENT, result.status)
        assertTrue(result.error.orEmpty().contains("body replacement"))
        verify(exactly = 0) { intruder.sendToIntruder(any<HttpRequest>()) }
    }

    @Test
    fun `Site Map action validates the opaque project scoped ID`() = runBlocking {
        val siteMap = mockk<SiteMap>()
        val item = mockk<HttpRequestResponse>()
        val sourceRequest = request()
        every { api.siteMap() } returns siteMap
        every { siteMap.requestResponses() } returns listOf(item)
        every { item.request() } returns sourceRequest
        every { item.response() } returns null
        every { item.httpService() } returns sourceRequest.httpService()
        val id = stableSiteMapId("project-123", 0, item)
        val repeater = mockk<Repeater>(relaxed = true)
        every { api.repeater() } returns repeater

        val result = service.createRepeaterTab(
            CreateRepeaterTabFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.SITE_MAP, id),
            )
        )

        assertEquals(HttpMessageActionStatus.OK, result.status)
        verify(exactly = 1) { repeater.sendToRepeater(sourceRequest) }
    }

    @Test
    fun `Organizer action preserves an unmodified source response`() = runBlocking {
        val organizer = mockk<Organizer>()
        val item = mockk<OrganizerItem>()
        val sourceRequest = request()
        val sourceResponse = mockk<HttpResponse>()
        every { api.organizer() } returns organizer
        every { organizer.items(any()) } answers {
            val filter = firstArg<burp.api.montoya.organizer.OrganizerItemFilter>()
            listOf(item).filter(filter::matches)
        }
        every { item.id() } returns 14
        every { item.request() } returns sourceRequest
        every { item.response() } returns sourceResponse
        every { item.httpService() } returns sourceRequest.httpService()
        every { organizer.sendToOrganizer(item) } just Runs

        val result = service.sendToOrganizer(
            SendToOrganizerFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.ORGANIZER, "14"),
            )
        )

        assertEquals(HttpMessageActionStatus.OK, result.status)
        assertEquals(true, result.preservedResponseInOrganizer)
        verify(exactly = 1) { organizer.sendToOrganizer(item) }
        verify(exactly = 0) { organizer.sendToOrganizer(any<HttpRequest>()) }
    }

    @Test
    fun `action denial exposes the normalized diff and does not mutate Burp`() = runBlocking {
        config.requireRequestActionApproval = true
        val fixture = proxyFixture(9)
        filteredHistory(fixture.item)
        val repeater = mockk<Repeater>(relaxed = true)
        every { api.repeater() } returns repeater
        var approvedChanges: String? = null
        RequestActionSecurity.approvalHandler = object : RequestActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                source: String,
                target: String,
                changes: String,
                requestContent: String,
                config: McpConfig,
                api: MontoyaApi,
            ): Boolean {
                approvedChanges = changes
                return false
            }
        }

        val result = service.createRepeaterTab(
            CreateRepeaterTabFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "9"),
            )
        )

        assertEquals(HttpMessageActionStatus.ACTION_DENIED, result.status)
        assertEquals("none (exact source request)", approvedChanges)
        verify(exactly = 0) { fixture.request.toByteArray() }
        verify(exactly = 1) { fixture.request.bodyOffset() }
        verify(exactly = 1) { fixture.request.toString() }
        verify(exactly = 0) { repeater.sendToRepeater(any<HttpRequest>()) }
    }

    @Test
    fun `parameter patches parse each parameter type once and apply batched mutations`() = runBlocking {
        mockkStatic(HttpParameter::class)
        try {
            val item = mockk<ProxyHttpRequestResponse>()
            val original = request()
            val removed = request()
            val finalRequest = request(path = "/test?a=one&b=two")
            val oldA = mockk<ParsedHttpParameter>()
            val oldB = mockk<ParsedHttpParameter>()
            val newA = mockk<HttpParameter>()
            val newB = mockk<HttpParameter>()
            every { oldA.name() } returns "a"
            every { oldB.name() } returns "b"
            every { original.parameters(HttpParameterType.URL) } returns listOf(oldA, oldB)
            every { original.withRemovedParameters(listOf(oldA, oldB)) } returns removed
            every { HttpParameter.parameter("a", "one", HttpParameterType.URL) } returns newA
            every { HttpParameter.parameter("b", "two", HttpParameterType.URL) } returns newB
            every { removed.withAddedParameters(listOf(newA, newB)) } returns finalRequest
            every { item.id() } returns 15
            every { item.request() } returns original
            every { item.response() } returns null
            every { item.httpService() } returns original.httpService()
            filteredHistory(item)
            val intruder = mockk<Intruder>(relaxed = true)
            every { api.intruder() } returns intruder

            val result = service.sendToIntruder(
                SendToIntruderFromId(
                    projectId = "project-123",
                    ref = HttpMessageReference(HttpMessageSource.PROXY, "15"),
                    patch = HttpRequestPatch(
                        setParameters = listOf(
                            HttpParameterMutation(HttpActionParameterType.URL, "a", "one"),
                            HttpParameterMutation(HttpActionParameterType.URL, "b", "two"),
                        ),
                    ),
                )
            )

            assertEquals(HttpMessageActionStatus.OK, result.status)
            verify(exactly = 1) { original.parameters(HttpParameterType.URL) }
            verify(exactly = 1) { original.withRemovedParameters(listOf(oldA, oldB)) }
            verify(exactly = 1) { removed.withAddedParameters(listOf(newA, newB)) }
            verify(exactly = 1) { intruder.sendToIntruder(finalRequest) }
        } finally {
            unmockkStatic(HttpParameter::class)
        }
    }

    @Test
    fun `Intruder semantic insertion points become a bounded request template`() = runBlocking {
        mockkStatic(Range::class)
        mockkStatic(HttpRequestTemplate::class)
        try {
            val rawText = "POST /submit HTTP/1.1\r\nHost: example.test\r\n\r\nsecret"
            val rawBytes = rawText.toByteArray()
            val bodyOffset = rawText.indexOf("secret")
            val request = request(method = "POST", path = "/submit", text = rawText, bytes = bodyOffset)
            val body = mockk<MontoyaByteArray>()
            every { request.body() } returns body
            every { body.length() } returns rawBytes.size - bodyOffset
            val range = mockk<Range>()
            every { Range.range(bodyOffset, rawBytes.size) } returns range
            val template = mockk<HttpRequestTemplate>()
            every { HttpRequestTemplate.httpRequestTemplate(request, listOf(range)) } returns template
            val item = mockk<ProxyHttpRequestResponse>()
            every { item.id() } returns 19
            every { item.request() } returns request
            every { item.response() } returns null
            filteredHistory(item)
            val intruder = mockk<Intruder>(relaxed = true)
            every { api.intruder() } returns intruder

            val result = service.sendToIntruder(
                SendToIntruderFromId(
                    projectId = "project-123",
                    ref = HttpMessageReference(HttpMessageSource.PROXY, "19"),
                    tabName = "focused",
                    insertionPoints = listOf(HttpInsertionPointSelector(HttpInsertionPointKind.BODY)),
                )
            )

            assertEquals(HttpMessageActionStatus.OK, result.status)
            assertEquals(1, result.insertionPointCount)
            assertTrue(result.changes.orEmpty().contains("entire request body"))
            verify(exactly = 1) { Range.range(bodyOffset, rawBytes.size) }
            verify(exactly = 1) { intruder.sendToIntruder(any<HttpService>(), template, "focused") }
            verify(exactly = 0) { intruder.sendToIntruder(request, any<String>()) }
        } finally {
            unmockkStatic(HttpRequestTemplate::class)
            unmockkStatic(Range::class)
        }
    }

    @Test
    fun `HTTP replay uses bounded request options and returns a bounded response preview`() = runBlocking {
        mockkStatic(RequestOptions::class)
        try {
            val fixture = proxyFixture(10)
            filteredHistory(fixture.item)
            val options = mockk<RequestOptions>()
            every { RequestOptions.requestOptions() } returns options
            every { options.withHttpMode(HttpMode.HTTP_1) } returns options
            every { options.withRedirectionMode(RedirectionMode.SAME_HOST) } returns options
            every { options.withResponseTimeout(2500) } returns options

            val http = mockk<Http>()
            val envelope = mockk<HttpRequestResponse>()
            val response = mockk<HttpResponse>()
            val responseBody = montoyaBytes("response-body")
            every { api.http() } returns http
            every { http.sendRequest(fixture.request, options) } returns envelope
            every { envelope.request() } returns fixture.request
            every { envelope.response() } returns response
            every { response.statusCode() } returns 201
            every { response.mimeType() } returns MimeType.JSON
            every { response.httpVersion() } returns "HTTP/1.1"
            every { response.headers() } returns emptyList()
            every { response.body() } returns responseBody
            val siteMap = mockk<SiteMap>(relaxed = true)
            every { api.siteMap() } returns siteMap
            every { siteMap.requestResponses() } returns listOf(envelope)

            val result = service.send(
                SendHttpRequestFromId(
                    projectId = "project-123",
                    ref = HttpMessageReference(HttpMessageSource.PROXY, "10"),
                    redirection = HttpRedirectionPolicy.SAME_HOST,
                    responseTimeoutMs = 2500,
                    responseBodyLimit = 8,
                )
            )

            assertEquals(HttpMessageActionStatus.OK, result.status)
            assertEquals(201, result.response?.statusCode)
            assertEquals("response", result.response?.body?.data)
            assertEquals(8, result.response?.body?.returnedBytes)
            assertEquals(8, result.response?.body?.nextOffsetBytes)
            assertEquals(true, result.recordedInSiteMap)
            assertEquals(HttpMessageSource.SITE_MAP, result.recordedRef?.source)
            assertTrue(result.recordedRef?.id.orEmpty().startsWith("sitemap_0_"))
            verify(exactly = 1) { http.sendRequest(fixture.request, options) }
            verify(exactly = 1) { siteMap.add(envelope) }
        } finally {
            unmockkStatic(RequestOptions::class)
        }
    }

    @Test
    fun `response preview failure cannot turn a completed HTTP request into an uncertain retry`() = runBlocking {
        mockkStatic(RequestOptions::class)
        try {
            val fixture = proxyFixture(16)
            filteredHistory(fixture.item)
            val options = mockk<RequestOptions>()
            every { RequestOptions.requestOptions() } returns options
            every { options.withHttpMode(HttpMode.HTTP_1) } returns options
            every { options.withRedirectionMode(RedirectionMode.NEVER) } returns options
            every { options.withResponseTimeout(30_000) } returns options
            val http = mockk<Http>()
            val envelope = mockk<HttpRequestResponse>()
            val response = mockk<HttpResponse>()
            val brokenBody = mockk<MontoyaByteArray>()
            every { api.http() } returns http
            every { http.sendRequest(fixture.request, options) } returns envelope
            every { envelope.response() } returns response
            every { response.statusCode() } returns 200
            every { response.mimeType() } returns MimeType.JSON
            every { response.httpVersion() } returns "HTTP/1.1"
            every { response.body() } returns brokenBody
            every { brokenBody.length() } throws IllegalStateException("preview unavailable")
            val siteMap = mockk<SiteMap>(relaxed = true)
            every { api.siteMap() } returns siteMap

            val result = service.send(
                SendHttpRequestFromId(
                    projectId = "project-123",
                    ref = HttpMessageReference(HttpMessageSource.PROXY, "16"),
                )
            )

            assertEquals(HttpMessageActionStatus.OK, result.status)
            assertEquals(HttpMessageExecutionState.COMPLETED, result.executionState)
            assertTrue(result.error.orEmpty().contains("preview unavailable"))
            assertEquals(null, result.response)
            verify(exactly = 1) { http.sendRequest(fixture.request, options) }
        } finally {
            unmockkStatic(RequestOptions::class)
        }
    }

    @Test
    fun `project change after resolution prevents the destination side effect`() = runBlocking {
        val fixture = proxyFixture(21)
        filteredHistory(fixture.item)
        every { project.id() } returnsMany listOf("project-123", "other-project")
        val intruder = mockk<Intruder>(relaxed = true)
        every { api.intruder() } returns intruder

        val result = service.sendToIntruder(
            SendToIntruderFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "21"),
            )
        )

        assertEquals(HttpMessageActionStatus.PROJECT_MISMATCH, result.status)
        assertEquals(HttpMessageExecutionState.NOT_STARTED, result.executionState)
        verify(exactly = 0) { intruder.sendToIntruder(any<HttpRequest>()) }
    }

    @Test
    fun `post-approval destination exception is reported as execution uncertain`() = runBlocking {
        val fixture = proxyFixture(11)
        filteredHistory(fixture.item)
        val intruder = mockk<Intruder>()
        every { api.intruder() } returns intruder
        every { intruder.sendToIntruder(fixture.request) } throws IllegalStateException("UI unavailable")

        val result = service.sendToIntruder(
            SendToIntruderFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "11"),
            )
        )

        assertEquals(HttpMessageActionStatus.EXECUTION_UNCERTAIN, result.status)
        assertEquals(HttpMessageExecutionState.UNCERTAIN, result.executionState)
        assertTrue(result.error.orEmpty().contains("UI unavailable"))
        verify(exactly = 1) { intruder.sendToIntruder(fixture.request) }
    }

    private fun filteredHistory(vararg items: ProxyHttpRequestResponse) {
        every { proxy.history(any()) } answers {
            val filter = firstArg<ProxyHistoryFilter>()
            items.filter(filter::matches)
        }
    }

    private fun proxyFixture(id: Int): ProxyFixture {
        val item = mockk<ProxyHttpRequestResponse>()
        val request = request()
        every { item.id() } returns id
        every { item.request() } returns request
        every { item.response() } returns null
        every { item.httpService() } returns request.httpService()
        return ProxyFixture(item, request)
    }

    private fun request(
        method: String = "GET",
        path: String = "/test",
        text: String = "GET /test HTTP/1.1\r\nHost: example.test\r\n\r\n",
        bytes: Int = 64,
    ): HttpRequest {
        val request = mockk<HttpRequest>()
        val service = mockk<HttpService>()
        val raw = mockk<MontoyaByteArray>()
        val body = mockk<MontoyaByteArray>()
        every { service.host() } returns "example.test"
        every { service.port() } returns 443
        every { service.secure() } returns true
        every { request.httpService() } returns service
        every { request.method() } returns method
        every { request.path() } returns path
        every { request.url() } returns "https://example.test$path"
        every { request.httpVersion() } returns "HTTP/1.1"
        every { request.headers() } returns emptyList()
        every { request.body() } returns body
        every { body.length() } returns 0
        every { request.bodyOffset() } returns bytes
        every { request.toByteArray() } returns raw
        every { raw.length() } returns bytes
        every { request.toString() } returns text
        every { request.parameters(any()) } returns emptyList()
        return request
    }

    private fun montoyaBytes(text: String): MontoyaByteArray {
        val bytes = mockk<MontoyaByteArray>()
        val raw = text.toByteArray()
        every { bytes.length() } returns raw.size
        every { bytes.getByte(any()) } answers { raw[firstArg<Int>()] }
        every { bytes.subArray(any(), any()) } answers {
            val start = firstArg<Int>()
            val end = secondArg<Int>()
            val selectedRaw = raw.copyOfRange(start, end)
            val selected = mockk<MontoyaByteArray>()
            every { selected.toString() } returns selectedRaw.toString(Charsets.UTF_8)
            every { selected.getBytes() } returns selectedRaw
            every { selected.length() } returns selectedRaw.size
            selected
        }
        return bytes
    }

    private data class ProxyFixture(val item: ProxyHttpRequestResponse, val request: HttpRequest)
}
