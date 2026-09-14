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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withContext
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.McpSessionApproval
import net.portswigger.mcp.security.McpSessionApprovalContext
import net.portswigger.mcp.security.McpSessionApprovalState
import net.portswigger.mcp.security.RequestActionApprovalHandler
import net.portswigger.mcp.security.RequestActionSecurity
import net.portswigger.mcp.security.UserApprovalHandler
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HttpMessageActionsTest {
    private val api = mockk<MontoyaApi>()
    private val project = mockk<Project>()
    private val proxy = mockk<Proxy>()
    private val logging = mockk<Logging>(relaxed = true)
    private lateinit var config: McpConfig
    private lateinit var service: HttpMessageActionService
    private lateinit var originalRequestActionApprovalHandler: RequestActionApprovalHandler
    private lateinit var originalHttpRequestApprovalHandler: UserApprovalHandler

    @BeforeEach
    fun setUp() {
        originalRequestActionApprovalHandler = RequestActionSecurity.approvalHandler
        originalHttpRequestApprovalHandler = HttpRequestSecurity.approvalHandler
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
        config = McpConfig(storage, logging, net.portswigger.mcp.testPreferences())
        service = HttpMessageActionService(api, config) { _, block -> block() }
    }

    @AfterEach
    fun tearDown() {
        RequestActionSecurity.approvalHandler = originalRequestActionApprovalHandler
        HttpRequestSecurity.approvalHandler = originalHttpRequestApprovalHandler
    }

    @Test
    fun `Repeater action resolves with a filtered lookup and routes the exact request`() = runBlocking {
        val fixture = proxyFixture(42)
        filteredHistory(fixture.item)
        val repeater = mockk<Repeater>(relaxed = true)
        every { api.repeater() } returns repeater

        val result = service.route(
            RouteHttpMessageFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "42"),
                destination = HttpMessageRouteDestination.REPEATER,
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
        verify(exactly = 0) { api.http() }
    }

    @Test
    fun `unified routing rejects destination specific fields before source access`() = runBlocking {
        val repeater = service.route(
            RouteHttpMessageFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "42"),
                destination = HttpMessageRouteDestination.REPEATER,
                insertionPoints = listOf(HttpInsertionPointSelector(HttpInsertionPointKind.BODY)),
            )
        )
        val organizer = service.route(
            RouteHttpMessageFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "42"),
                destination = HttpMessageRouteDestination.ORGANIZER,
                tabName = "unsupported",
            )
        )

        assertEquals(HttpMessageActionStatus.INVALID_ARGUMENT, repeater.status)
        assertEquals(HttpMessageExecutionState.NOT_STARTED, repeater.executionState)
        assertNull(repeater.projectId)
        assertEquals(HttpMessageActionStatus.INVALID_ARGUMENT, organizer.status)
        assertNull(organizer.projectId)
        verify(exactly = 0) { proxy.history(any()) }
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
    fun `successive sparse patches restart from the stored source request`() = runBlocking {
        val item = mockk<ProxyHttpRequestResponse>()
        val original = request(method = "GET")
        val firstDerived = request(method = "POST")
        val secondDerived = request(method = "GET")
        every { original.withMethod("POST") } returns firstDerived
        every { original.withAddedHeader("X-Second", "yes") } returns secondDerived
        every { item.id() } returns 19
        every { item.request() } returns original
        every { item.response() } returns null
        every { item.httpService() } returns original.httpService()
        filteredHistory(item)
        val intruder = mockk<Intruder>(relaxed = true)
        every { api.intruder() } returns intruder
        val ref = HttpMessageReference(HttpMessageSource.PROXY, "19")

        val first = service.sendToIntruder(
            SendToIntruderFromId(
                projectId = "project-123",
                ref = ref,
                patch = HttpRequestPatch(method = "POST"),
            )
        )
        val second = service.sendToIntruder(
            SendToIntruderFromId(
                projectId = "project-123",
                ref = ref,
                patch = HttpRequestPatch(addHeaders = listOf(HttpHeaderMutation("X-Second", "yes"))),
            )
        )

        assertEquals(HttpMessageActionStatus.OK, first.status)
        assertEquals(HttpMessageActionStatus.OK, second.status)
        verify(exactly = 1) { original.withMethod("POST") }
        verify(exactly = 1) { original.withAddedHeader("X-Second", "yes") }
        verify(exactly = 0) { firstDerived.withAddedHeader(any(), any()) }
        verify(exactly = 1) { intruder.sendToIntruder(firstDerived) }
        verify(exactly = 1) { intruder.sendToIntruder(secondDerived) }
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

        assertEquals(HttpMessageActionStatus.BURP_ERROR, result.status)
        assertEquals(HttpMessageExecutionState.NOT_STARTED, result.executionState)
        assertFalse(result.error.orEmpty().contains("destination service"))
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

        assertEquals(HttpMessageActionStatus.BURP_ERROR, result.status)
        assertEquals(HttpMessageExecutionState.NOT_STARTED, result.executionState)
        assertFalse(result.error.orEmpty().contains("action limit"))
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
    fun `Organizer action preserves an unmodified source response inside the mutation barrier`() = runBlocking {
        val events = mutableListOf<String>()
        val measuredService = HttpMessageActionService(api, config) { _, mutation ->
            events += "begin"
            try {
                mutation()
            } finally {
                events += "end"
            }
        }
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
        every { organizer.sendToOrganizer(item) } answers { events += "send" }

        val result = measuredService.sendToOrganizer(
            SendToOrganizerFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.ORGANIZER, "14"),
            )
        )

        assertEquals(HttpMessageActionStatus.OK, result.status)
        assertEquals(true, result.preservedResponseInOrganizer)
        assertEquals(listOf("begin", "send", "end"), events)
        verify(exactly = 1) { organizer.sendToOrganizer(item) }
        verify(exactly = 0) { organizer.sendToOrganizer(any<HttpRequest>()) }
    }

    @Test
    fun `Organizer barrier distinguishes rejection before execution from uncertain execution`() = runBlocking {
        val events = mutableListOf<String>()
        val measuredService = HttpMessageActionService(api, config) { _, mutation ->
            events += "begin"
            try {
                mutation()
            } finally {
                events += "end"
            }
        }
        val unavailableService = HttpMessageActionService(api, config) { _, _ ->
            throw OrganizerMutationNotStartedException(IllegalStateException("closed"))
        }
        var mismatchExpectedProjectId: String? = null
        val projectMismatchService = HttpMessageActionService(api, config) { expectedProjectId, _ ->
            mismatchExpectedProjectId = expectedProjectId
            throw OrganizerProjectMismatchBeforeMutationException("project-new")
        }
        val organizer = mockk<Organizer>()
        val item = mockk<OrganizerItem>()
        val sourceRequest = request()
        every { api.organizer() } returns organizer
        every { organizer.items(any()) } answers {
            val filter = firstArg<burp.api.montoya.organizer.OrganizerItemFilter>()
            listOf(item).filter(filter::matches)
        }
        every { item.id() } returns 15
        every { item.request() } returns sourceRequest
        every { item.response() } returns null
        every { item.httpService() } returns sourceRequest.httpService()
        every { organizer.sendToOrganizer(sourceRequest) } answers {
            events += "send"
            throw IllegalStateException("uncertain")
        }

        val uncertain = measuredService.sendToOrganizer(
            SendToOrganizerFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.ORGANIZER, "15"),
            )
        )
        val invalid = measuredService.sendToOrganizer(
            SendToOrganizerFromId(
                projectId = "",
                ref = HttpMessageReference(HttpMessageSource.ORGANIZER, "15"),
            )
        )
        val unavailable = unavailableService.sendToOrganizer(
            SendToOrganizerFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.ORGANIZER, "15"),
            )
        )
        val projectMismatch = projectMismatchService.sendToOrganizer(
            SendToOrganizerFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.ORGANIZER, "15"),
            )
        )

        assertEquals(HttpMessageActionStatus.EXECUTION_UNCERTAIN, uncertain.status)
        assertEquals(HttpMessageActionStatus.INVALID_ARGUMENT, invalid.status)
        assertEquals(HttpMessageActionStatus.BURP_ERROR, unavailable.status)
        assertEquals(HttpMessageExecutionState.NOT_STARTED, unavailable.executionState)
        assertEquals(HttpMessageActionStatus.PROJECT_MISMATCH, projectMismatch.status)
        assertEquals(HttpMessageExecutionState.NOT_STARTED, projectMismatch.executionState)
        assertEquals("project-new", projectMismatch.projectId)
        assertEquals("project-123", mismatchExpectedProjectId)
        assertEquals(listOf("begin", "send", "end"), events)
        verify(exactly = 1) { organizer.sendToOrganizer(sourceRequest) }
    }

    @Test
    fun `cancellation while waiting to enter the Organizer barrier prevents the side effect`() = runBlocking {
        val barrierEntered = CompletableDeferred<Unit>()
        val blockedService = HttpMessageActionService(api, config) { _, _ ->
            barrierEntered.complete(Unit)
            awaitCancellation()
        }
        val organizer = mockk<Organizer>()
        val item = mockk<OrganizerItem>()
        val sourceRequest = request()
        every { api.organizer() } returns organizer
        every { organizer.items(any()) } answers {
            val filter = firstArg<burp.api.montoya.organizer.OrganizerItemFilter>()
            listOf(item).filter(filter::matches)
        }
        every { item.id() } returns 16
        every { item.request() } returns sourceRequest
        every { item.response() } returns null
        every { item.httpService() } returns sourceRequest.httpService()

        val call = async {
            blockedService.sendToOrganizer(
                SendToOrganizerFromId(
                    projectId = "project-123",
                    ref = HttpMessageReference(HttpMessageSource.ORGANIZER, "16"),
                )
            )
        }
        barrierEntered.await()
        call.cancel()

        assertFailsWith<CancellationException> { call.await() }
        verify(exactly = 0) { organizer.sendToOrganizer(any<HttpRequest>()) }
        verify(exactly = 0) { organizer.sendToOrganizer(any<OrganizerItem>()) }
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
            every { options.withRedirectionMode(RedirectionMode.NEVER) } returns options
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
            val result = service.send(
                SendHttpRequestFromId(
                    projectId = "project-123",
                    ref = HttpMessageReference(HttpMessageSource.PROXY, "10"),
                    redirection = HttpRedirectionPolicy.NEVER,
                    responseTimeoutMs = 2500,
                    responseBodyLimit = 8,
                )
            )

            assertEquals(HttpMessageActionStatus.OK, result.status)
            assertEquals(201, result.response?.statusCode)
            assertEquals("response", result.response?.body?.data)
            assertEquals(8, result.response?.body?.returnedBytes)
            assertEquals(8, result.response?.body?.nextOffsetBytes)
            assertEquals(false, result.recordedInSiteMap)
            assertEquals(null, result.recordedRef)
            assertTrue(result.error.orEmpty().contains("atomic project-bound add"))
            verify(exactly = 1) { http.sendRequest(fixture.request, options) }
            verify(exactly = 0) { api.siteMap() }
        } finally {
            unmockkStatic(RequestOptions::class)
        }
    }

    @Test
    fun `routing session grant cannot bypass outbound HTTP approval`() = runBlocking {
        withMockedRequestOptions { options ->
            config.requireRequestActionApproval = true
            config.requireHttpRequestApproval = true
            val fixture = proxyFixture(22)
            filteredHistory(fixture.item)
            val http = mockk<Http>(relaxed = true)
            every { api.http() } returns http
            RequestActionSecurity.approvalHandler = object : RequestActionApprovalHandler {
                override suspend fun requestApproval(
                    action: String,
                    source: String,
                    target: String,
                    changes: String,
                    requestContent: String,
                    config: McpConfig,
                    api: MontoyaApi,
                ): Boolean = error("routing session approval should bypass only this request-action prompt")
            }
            var outboundApprovalCount = 0
            HttpRequestSecurity.approvalHandler = object : UserApprovalHandler {
                override suspend fun requestApproval(
                    hostname: String,
                    port: Int,
                    config: McpConfig,
                    requestContent: String?,
                    api: MontoyaApi?,
                ): Boolean {
                    outboundApprovalCount++
                    assertEquals("example.test", hostname)
                    assertEquals(443, port)
                    assertEquals("GET /test HTTP/1.1\r\nHost: example.test\r\n\r\n", requestContent)
                    verify(exactly = 0) { http.sendRequest(any<HttpRequest>(), any<RequestOptions>()) }
                    return false
                }
            }
            val state = McpSessionApprovalState(onGrantAdded = {}, onGrantsCleared = {})
            val context = McpSessionApprovalContext.create(state)
            assertTrue(context.grant(McpSessionApproval.REQUEST_ROUTING))

            val result = withContext(context) {
                service.send(
                    SendHttpRequestFromId(
                        projectId = "project-123",
                        ref = HttpMessageReference(HttpMessageSource.PROXY, "22"),
                    )
                )
            }

            assertEquals(HttpMessageActionStatus.ACTION_DENIED, result.status)
            assertEquals(HttpMessageExecutionState.NOT_STARTED, result.executionState)
            assertEquals(1, outboundApprovalCount)
            verify(exactly = 0) { http.sendRequest(fixture.request, options) }
        }
    }

    @Test
    fun `outbound session grant cannot bypass exact request denial`() = runBlocking {
        withMockedRequestOptions { options ->
            config.requireRequestActionApproval = true
            config.requireHttpRequestApproval = true
            val fixture = proxyFixture(25)
            filteredHistory(fixture.item)
            val http = mockk<Http>(relaxed = true)
            every { api.http() } returns http
            RequestActionSecurity.approvalHandler = object : RequestActionApprovalHandler {
                override suspend fun requestApproval(
                    action: String,
                    source: String,
                    target: String,
                    changes: String,
                    requestContent: String,
                    config: McpConfig,
                    api: MontoyaApi,
                ): Boolean = false
            }
            HttpRequestSecurity.approvalHandler = object : UserApprovalHandler {
                override suspend fun requestApproval(
                    hostname: String,
                    port: Int,
                    config: McpConfig,
                    requestContent: String?,
                    api: MontoyaApi?,
                ): Boolean = error("exact request denial must stop before outbound approval")
            }

            val result = withContext(sessionContext(McpSessionApproval.OUTBOUND_HTTP)) {
                service.send(
                    SendHttpRequestFromId(
                        projectId = "project-123",
                        ref = HttpMessageReference(HttpMessageSource.PROXY, "25"),
                    )
                )
            }

            assertEquals(HttpMessageActionStatus.ACTION_DENIED, result.status)
            assertEquals(HttpMessageExecutionState.NOT_STARTED, result.executionState)
            verify(exactly = 0) { http.sendRequest(fixture.request, options) }
        }
    }

    @Test
    fun `both session grants authorize exactly one HTTP replay`() = runBlocking {
        withMockedRequestOptions { options ->
            config.requireRequestActionApproval = true
            config.requireHttpRequestApproval = true
            val fixture = proxyFixture(26)
            filteredHistory(fixture.item)
            val http = mockk<Http>()
            every { api.http() } returns http
            every { http.sendRequest(fixture.request, options) } returns null
            RequestActionSecurity.approvalHandler = object : RequestActionApprovalHandler {
                override suspend fun requestApproval(
                    action: String,
                    source: String,
                    target: String,
                    changes: String,
                    requestContent: String,
                    config: McpConfig,
                    api: MontoyaApi,
                ): Boolean = error("request-action handler must not run for its session grant")
            }
            HttpRequestSecurity.approvalHandler = object : UserApprovalHandler {
                override suspend fun requestApproval(
                    hostname: String,
                    port: Int,
                    config: McpConfig,
                    requestContent: String?,
                    api: MontoyaApi?,
                ): Boolean = error("outbound handler must not run for its session grant")
            }

            val result = withContext(
                sessionContext(McpSessionApproval.REQUEST_ROUTING, McpSessionApproval.OUTBOUND_HTTP)
            ) {
                service.send(
                    SendHttpRequestFromId(
                        projectId = "project-123",
                        ref = HttpMessageReference(HttpMessageSource.PROXY, "26"),
                    )
                )
            }

            assertEquals(HttpMessageActionStatus.OK, result.status)
            assertEquals(HttpMessageExecutionState.COMPLETED, result.executionState)
            verify(exactly = 1) { http.sendRequest(fixture.request, options) }
        }
    }

    @Test
    fun `project transition during exact request approval stops before outbound approval`() = runBlocking {
        withMockedRequestOptions { options ->
            config.requireRequestActionApproval = true
            config.requireHttpRequestApproval = true
            val fixture = proxyFixture(27)
            filteredHistory(fixture.item)
            val http = mockk<Http>(relaxed = true)
            every { api.http() } returns http
            var currentProjectId = "project-123"
            every { project.id() } answers { currentProjectId }
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
                    currentProjectId = "other-project"
                    return true
                }
            }
            HttpRequestSecurity.approvalHandler = object : UserApprovalHandler {
                override suspend fun requestApproval(
                    hostname: String,
                    port: Int,
                    config: McpConfig,
                    requestContent: String?,
                    api: MontoyaApi?,
                ): Boolean = error("project mismatch must stop before outbound approval")
            }

            val result = service.send(
                SendHttpRequestFromId(
                    projectId = "project-123",
                    ref = HttpMessageReference(HttpMessageSource.PROXY, "27"),
                )
            )

            assertEquals(HttpMessageActionStatus.PROJECT_MISMATCH, result.status)
            assertEquals(HttpMessageExecutionState.NOT_STARTED, result.executionState)
            verify(exactly = 0) { http.sendRequest(fixture.request, options) }
        }
    }

    @Test
    fun `project transition with denied exact request approval returns mismatch`() = runBlocking {
        withMockedRequestOptions { options ->
            config.requireRequestActionApproval = true
            config.requireHttpRequestApproval = true
            val fixture = proxyFixture(28)
            filteredHistory(fixture.item)
            val http = mockk<Http>(relaxed = true)
            every { api.http() } returns http
            var currentProjectId = "project-123"
            every { project.id() } answers { currentProjectId }
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
                    currentProjectId = "other-project"
                    return false
                }
            }
            HttpRequestSecurity.approvalHandler = object : UserApprovalHandler {
                override suspend fun requestApproval(
                    hostname: String,
                    port: Int,
                    config: McpConfig,
                    requestContent: String?,
                    api: MontoyaApi?,
                ): Boolean = error("project mismatch must stop before outbound approval")
            }

            val result = service.send(
                SendHttpRequestFromId(
                    projectId = "project-123",
                    ref = HttpMessageReference(HttpMessageSource.PROXY, "28"),
                )
            )

            assertEquals(HttpMessageActionStatus.PROJECT_MISMATCH, result.status)
            assertEquals(HttpMessageExecutionState.NOT_STARTED, result.executionState)
            assertEquals("other-project", result.projectId)
            verify(exactly = 0) { http.sendRequest(fixture.request, options) }
        }
    }

    @Test
    fun `HTTP replay requires exact request and outbound approvals in order`() = runBlocking {
        withMockedRequestOptions { options ->
            config.requireRequestActionApproval = true
            config.requireHttpRequestApproval = true
            val fixture = proxyFixture(23)
            filteredHistory(fixture.item)
            val http = mockk<Http>()
            every { api.http() } returns http
            val order = mutableListOf<String>()
            every { http.sendRequest(fixture.request, options) } answers {
                order += "send"
                null
            }
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
                    assertEquals(emptyList(), order)
                    assertEquals("GET /test HTTP/1.1\r\nHost: example.test\r\n\r\n", requestContent)
                    verify(exactly = 0) { http.sendRequest(any<HttpRequest>(), any<RequestOptions>()) }
                    order += "request_action"
                    return true
                }
            }
            HttpRequestSecurity.approvalHandler = object : UserApprovalHandler {
                override suspend fun requestApproval(
                    hostname: String,
                    port: Int,
                    config: McpConfig,
                    requestContent: String?,
                    api: MontoyaApi?,
                ): Boolean {
                    assertEquals(listOf("request_action"), order)
                    assertEquals("GET /test HTTP/1.1\r\nHost: example.test\r\n\r\n", requestContent)
                    verify(exactly = 0) { http.sendRequest(any<HttpRequest>(), any<RequestOptions>()) }
                    order += "outbound"
                    return true
                }
            }

            val result = service.send(
                SendHttpRequestFromId(
                    projectId = "project-123",
                    ref = HttpMessageReference(HttpMessageSource.PROXY, "23"),
                )
            )

            assertEquals(HttpMessageActionStatus.OK, result.status)
            assertEquals(HttpMessageExecutionState.COMPLETED, result.executionState)
            assertEquals(listOf("request_action", "outbound", "send"), order)
            verify(exactly = 1) { http.sendRequest(fixture.request, options) }
        }
    }

    @Test
    fun `project transition during outbound approval prevents HTTP replay`() = runBlocking {
        withMockedRequestOptions { options ->
            config.requireRequestActionApproval = false
            config.requireHttpRequestApproval = true
            val fixture = proxyFixture(24)
            filteredHistory(fixture.item)
            val http = mockk<Http>(relaxed = true)
            every { api.http() } returns http
            var currentProjectId = "project-123"
            every { project.id() } answers { currentProjectId }
            HttpRequestSecurity.approvalHandler = object : UserApprovalHandler {
                override suspend fun requestApproval(
                    hostname: String,
                    port: Int,
                    config: McpConfig,
                    requestContent: String?,
                    api: MontoyaApi?,
                ): Boolean {
                    currentProjectId = "other-project"
                    return true
                }
            }

            val result = service.send(
                SendHttpRequestFromId(
                    projectId = "project-123",
                    ref = HttpMessageReference(HttpMessageSource.PROXY, "24"),
                )
            )

            assertEquals(HttpMessageActionStatus.PROJECT_MISMATCH, result.status)
            assertEquals(HttpMessageExecutionState.NOT_STARTED, result.executionState)
            assertEquals("other-project", result.projectId)
            verify(exactly = 0) { http.sendRequest(fixture.request, options) }
        }
    }

    @Test
    fun `cancellation after HTTP transmission begins is execution uncertain`() = runBlocking {
        withMockedRequestOptions { options ->
            val fixture = proxyFixture(29)
            filteredHistory(fixture.item)
            val http = mockk<Http>()
            every { api.http() } returns http
            every { http.sendRequest(fixture.request, options) } throws CancellationException("cancelled")

            val result = service.send(
                SendHttpRequestFromId(
                    projectId = "project-123",
                    ref = HttpMessageReference(HttpMessageSource.PROXY, "29"),
                )
            )

            assertEquals(HttpMessageActionStatus.EXECUTION_UNCERTAIN, result.status)
            assertEquals(HttpMessageExecutionState.UNCERTAIN, result.executionState)
            assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
            verify(exactly = 1) { http.sendRequest(fixture.request, options) }
        }
    }

    @Test
    fun `caller cancellation during stable ID HTTP replay propagates`() = runBlocking {
        withMockedRequestOptions { options ->
            val fixture = proxyFixture(30)
            filteredHistory(fixture.item)
            val http = mockk<Http>()
            lateinit var invocationJob: Job
            every { api.http() } returns http
            every { http.sendRequest(fixture.request, options) } answers {
                invocationJob.cancel(CancellationException("caller cancelled"))
                throw CancellationException("caller cancelled")
            }

            supervisorScope {
                val invocation = async {
                    invocationJob = currentCoroutineContext()[Job]!!
                    service.send(
                        SendHttpRequestFromId(
                            projectId = "project-123",
                            ref = HttpMessageReference(HttpMessageSource.PROXY, "30"),
                        )
                    )
                }
                assertFailsWith<CancellationException> { invocation.await() }
            }

            verify(exactly = 1) { http.sendRequest(fixture.request, options) }
        }
    }

    @Test
    fun `HTTP replay rejects automatic redirects before resolution or network access`() = runBlocking {
        val http = mockk<Http>(relaxed = true)
        every { api.http() } returns http

        val result = service.send(
            SendHttpRequestFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "10"),
                redirection = HttpRedirectionPolicy.ALWAYS,
            )
        )

        assertEquals(HttpMessageActionStatus.INVALID_ARGUMENT, result.status)
        assertEquals(HttpMessageExecutionState.NOT_STARTED, result.executionState)
        assertNull(result.projectId)
        assertTrue(result.error.orEmpty().contains("redirected destinations"))
        verify(exactly = 0) { http.sendRequest(any<HttpRequest>(), any<RequestOptions>()) }
        verify(exactly = 0) { proxy.history(any()) }
    }

    @Test
    fun `stored request accessor IllegalArgumentException is a sanitized Burp error for send and route`() = runBlocking {
        val sendFixture = proxyFixture(14)
        val routeFixture = proxyFixture(15)
        filteredHistory(sendFixture.item, routeFixture.item)
        every { sendFixture.request.httpService() } throws IllegalArgumentException("SEND_PRIVATE_SENTINEL")
        every { routeFixture.request.httpService() } throws IllegalArgumentException("ROUTE_PRIVATE_SENTINEL")

        val sent = service.send(
            SendHttpRequestFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "14"),
            )
        )
        val routed = service.route(
            RouteHttpMessageFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "15"),
                destination = HttpMessageRouteDestination.REPEATER,
            )
        )

        listOf(sent, routed).forEach { result ->
            assertEquals(HttpMessageActionStatus.BURP_ERROR, result.status)
            assertEquals(HttpMessageExecutionState.NOT_STARTED, result.executionState)
            assertFalse(result.error.orEmpty().contains("PRIVATE_SENTINEL"))
        }
        verify(exactly = 0) { api.http() }
        verify(exactly = 0) { api.repeater() }
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
            assertTrue(result.error.orEmpty().contains("response preview could not be created"))
            assertFalse(result.error.orEmpty().contains("preview unavailable"))
            assertEquals(null, result.response)
            verify(exactly = 1) { http.sendRequest(fixture.request, options) }
        } finally {
            unmockkStatic(RequestOptions::class)
        }
    }

    @Test
    fun `response preview cancellation propagates after the HTTP send`() = runBlocking {
        withMockedRequestOptions { options ->
            val fixture = proxyFixture(17)
            filteredHistory(fixture.item)
            val http = mockk<Http>()
            val envelope = mockk<HttpRequestResponse>()
            every { api.http() } returns http
            every { http.sendRequest(fixture.request, options) } returns envelope
            every { envelope.response() } throws CancellationException("preview cancelled")

            assertFailsWith<CancellationException> {
                service.send(
                    SendHttpRequestFromId(
                        projectId = "project-123",
                        ref = HttpMessageReference(HttpMessageSource.PROXY, "17"),
                    )
                )
            }

            verify(exactly = 1) { http.sendRequest(fixture.request, options) }
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
    fun `project transition during successful stable ID routing is execution uncertain`() = runBlocking {
        val fixture = proxyFixture(31)
        filteredHistory(fixture.item)
        var currentProjectId = "project-123"
        every { project.id() } answers { currentProjectId }
        val intruder = mockk<Intruder>()
        every { api.intruder() } returns intruder
        every { intruder.sendToIntruder(fixture.request) } answers { currentProjectId = "replacement-project" }

        val result = service.sendToIntruder(
            SendToIntruderFromId(
                projectId = "project-123",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "31"),
            )
        )

        assertEquals(HttpMessageActionStatus.EXECUTION_UNCERTAIN, result.status)
        assertEquals(HttpMessageExecutionState.UNCERTAIN, result.executionState)
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
    }

    @Test
    fun `project transition during successful stable ID HTTP send suppresses response as uncertain`() = runBlocking {
        withMockedRequestOptions { options ->
            val fixture = proxyFixture(32)
            filteredHistory(fixture.item)
            var currentProjectId = "project-123"
            every { project.id() } answers { currentProjectId }
            val http = mockk<Http>()
            every { api.http() } returns http
            every { http.sendRequest(fixture.request, options) } answers {
                currentProjectId = "replacement-project"
                mockk<HttpRequestResponse>(relaxed = true)
            }

            val result = service.send(
                SendHttpRequestFromId(
                    projectId = "project-123",
                    ref = HttpMessageReference(HttpMessageSource.PROXY, "32"),
                )
            )

            assertEquals(HttpMessageActionStatus.EXECUTION_UNCERTAIN, result.status)
            assertEquals(HttpMessageExecutionState.UNCERTAIN, result.executionState)
            assertEquals(null, result.response)
        }
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
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
        assertFalse(result.error.orEmpty().contains("UI unavailable"))
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

    private fun sessionContext(vararg approvals: McpSessionApproval): McpSessionApprovalContext {
        val state = McpSessionApprovalState(onGrantAdded = {}, onGrantsCleared = {})
        return McpSessionApprovalContext.create(state).also { context ->
            approvals.forEach { assertTrue(context.grant(it)) }
        }
    }

    private suspend fun <T> withMockedRequestOptions(block: suspend (RequestOptions) -> T): T {
        mockkStatic(RequestOptions::class)
        return try {
            val options = mockk<RequestOptions>()
            every { RequestOptions.requestOptions() } returns options
            every { options.withHttpMode(HttpMode.HTTP_1) } returns options
            every { options.withRedirectionMode(RedirectionMode.NEVER) } returns options
            every { options.withResponseTimeout(30_000) } returns options
            block(options)
        } finally {
            unmockkStatic(RequestOptions::class)
        }
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
