package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.execution.*
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import io.mockk.*
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.SensitiveActionApprovalHandler
import net.portswigger.mcp.security.SensitiveActionSecurity
import net.portswigger.mcp.testPreferences
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class RequestExecutionToolsTest {
    private val api = mockk<MontoyaApi>()
    private val project = mockk<Project>()
    private val proxy = mockk<Proxy>()
    private val http = mockk<Http>()
    private val logging = mockk<Logging>(relaxed = true)
    private val engine = mockk<RequestExecutionEngine>()
    private val execution = mockk<RequestExecution>()
    private val lifetime = mockk<RequestExecutionLifetime>()
    private val stats = mockk<ExecutionStats>()
    private lateinit var originalSensitiveHandler: SensitiveActionApprovalHandler

    @BeforeEach
    fun setUp() {
        originalSensitiveHandler = SensitiveActionSecurity.approvalHandler
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean = true
        }
        every { api.project() } returns project
        every { project.id() } returns "project-1"
        every { api.proxy() } returns proxy
        every { api.http() } returns http
        every { api.logging() } returns logging
        every { http.createRequestEngine() } returns engine
        every { execution.lifetime() } returns lifetime
        every { execution.stats() } returns stats
        every { stats.requested() } returns 1
        every { stats.completed() } returns 0
        every { stats.failed() } returns 0
        every { stats.inFlight() } returns 1
        every { stats.pending() } returns 0
        every { stats.elapsed() } returns java.time.Duration.ofMillis(5)
        every { lifetime.cancel() } returns Unit
    }

    @AfterEach
    fun tearDown() {
        SensitiveActionSecurity.approvalHandler = originalSensitiveHandler
    }

    @Test
    fun `engine starts queues captures bounded metadata and supports lifecycle controls`() = runBlocking {
        val request = request(120)
        val item = proxyItem(7, request)
        stubHistory(item)
        val handler = slot<ResponseHandler>()
        every { engine.queue(request, "first") } returns Unit
        every { engine.sendAll(capture(handler), any<java.time.Duration>()) } returns execution
        every { lifetime.finished() } returns false
        every { execution.queue(request, "second") } returns Unit
        every { lifetime.pause() } returns Unit
        val service = HttpRequestExecutionService(api, config())

        val started = service.start(
            StartHttpRequestExecution(
                projectId = "project-1",
                requests = listOf(
                    HttpRequestExecutionItem(
                        stored = StoredRequestExecutionSource(ref(7)),
                        label = "first",
                    )
                ),
            )
        )

        assertEquals(NativeToolStatus.OK, started.status)
        val executionId = assertNotNull(started.executionId)
        assertTrue(executionId.startsWith("reqexec-"))
        verify(exactly = 1) { engine.queue(request, "first") }

        val response = response(240)
        val exchange = mockk<HttpRequestResponse>()
        every { exchange.request() } returns request
        every { exchange.response() } returns response
        val requestResult = mockk<RequestResult>()
        every { requestResult.requestResponse() } returns exchange
        every { requestResult.label() } returns "first"
        every { requestResult.status() } returns RequestStatus.RESPONDED
        assertEquals(
            burp.api.montoya.http.execution.Retention.DROP,
            handler.captured.onResponse(requestResult, execution),
        )

        val completion = mockk<RequestExecutionResult>()
        every { completion.cancelled() } returns false
        every { lifetime.finished() } returns true
        every { lifetime.awaitCompletion() } returns completion
        every { stats.completed() } returns 1
        every { stats.inFlight() } returns 0
        val status = service.get(GetHttpRequestExecution("project-1", executionId))
        assertEquals(NativeToolStatus.OK, status.status)
        assertEquals(true, status.finished)
        assertEquals(1, status.results.size)
        assertEquals(120, status.results.single().requestBytes)
        assertEquals(240, status.results.single().responseBytes)
        assertEquals(200, status.results.single().responseStatusCode)

        every { lifetime.finished() } returns false
        val queued = service.queue(
            QueueHttpRequestExecution(
                "project-1",
                executionId,
                listOf(HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)), label = "second")),
            )
        )
        assertEquals(NativeToolStatus.OK, queued.status)
        assertEquals(1, queued.queued)
        verify(exactly = 1) { execution.queue(request, "second") }

        val paused = service.control(
            ControlHttpRequestExecution("project-1", executionId, HttpRequestExecutionControl.PAUSE)
        )
        assertEquals(NativeToolStatus.OK, paused.status)
        verify(exactly = 1) { lifetime.pause() }

        service.resetForProjectBoundary()
        verify(atLeast = 1) { lifetime.cancel() }
        val missing = service.get(GetHttpRequestExecution("project-1", executionId))
        assertEquals(NativeToolStatus.NOT_FOUND, missing.status)
    }

    @Test
    fun `execution byte budget is cumulative across queue calls`() = runBlocking {
        val request = request(MAX_ACTION_REQUEST_BYTES)
        stubHistory(proxyItem(7, request))
        every { engine.queue(request) } returns Unit
        every { engine.sendAll(any<ResponseHandler>(), any<java.time.Duration>()) } returns execution
        every { lifetime.finished() } returns false
        every { execution.queue(request) } returns Unit
        val service = HttpRequestExecutionService(api, config())
        val started = service.start(
            StartHttpRequestExecution(
                "project-1",
                listOf(HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)))),
            )
        )
        val executionId = assertNotNull(started.executionId)

        val fill = service.queue(
            QueueHttpRequestExecution(
                "project-1",
                executionId,
                List(7) { HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7))) },
            )
        )
        val exceeded = service.queue(
            QueueHttpRequestExecution(
                "project-1",
                executionId,
                listOf(HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)))),
            )
        )

        assertEquals(NativeToolStatus.OK, fill.status)
        assertEquals(NativeToolStatus.LIMIT_EXCEEDED, exceeded.status)
        verify(exactly = 7) { execution.queue(request) }
    }

    @Test
    fun `invalid engine source shape fails before project source or network access`() = runBlocking {
        val service = HttpRequestExecutionService(api, config())
        val result = service.start(
            StartHttpRequestExecution(
                projectId = "project-1",
                requests = listOf(HttpRequestExecutionItem()),
            )
        )

        assertEquals(NativeToolStatus.INVALID_ARGUMENT, result.status)
        assertEquals(StandardExecutionState.NOT_STARTED, result.executionState)
        verify(exactly = 0) { api.project() }
        verify(exactly = 0) { api.proxy() }
        verify(exactly = 0) { api.http() }
    }

    @Test
    fun `cancelled start waiting for lifecycle admission releases its capacity reservation`() = runBlocking {
        val request = request(120)
        stubHistory(proxyItem(7, request))
        val approvalReached = CompletableDeferred<Unit>()
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean {
                approvalReached.complete(Unit)
                return true
            }
        }
        val service = HttpRequestExecutionService(api, config())
        val lifecycle = HttpRequestExecutionService::class.java.getDeclaredField("lifecycleMutation").run {
            isAccessible = true
            get(service) as kotlinx.coroutines.sync.Mutex
        }
        lifecycle.lock()
        // The runBlocking event loop resumes this test only after start suspends on lifecycle admission.
        val start = async {
            service.start(
                StartHttpRequestExecution(
                    "project-1",
                    listOf(HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)))),
                )
            )
        }
        approvalReached.await()
        val blockerAcquired = CompletableDeferred<Unit>()
        val releaseBlocker = CompletableDeferred<Unit>()
        // Queue behind cleanup admission before unlocking, then hold the lock for cancellation.
        val blocker = launch(start = CoroutineStart.UNDISPATCHED) {
            lifecycle.lock()
            try {
                blockerAcquired.complete(Unit)
                releaseBlocker.await()
            } finally {
                lifecycle.unlock()
            }
        }
        lifecycle.unlock()
        blockerAcquired.await()
        val observedInFlight = HttpRequestExecutionService::class.java.getDeclaredField("startsInFlight").run {
            isAccessible = true
            getInt(service)
        }
        assertEquals(1, observedInFlight)

        start.cancelAndJoin()
        val remaining = HttpRequestExecutionService::class.java.getDeclaredField("startsInFlight").run {
            isAccessible = true
            getInt(service)
        }
        releaseBlocker.complete(Unit)
        blocker.join()

        assertEquals(0, remaining)
    }

    @Test
    fun `updated config replaces the retained resolver data policy`() = runBlocking {
        val original = DataAccessSecurity.approvalHandler
        try {
            DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
                override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean = false
            }
            val service = HttpRequestExecutionService(api, config(requireDataApproval = false))
            service.updateConfig(config(requireDataApproval = true))

            val result = service.start(
                StartHttpRequestExecution(
                    "project-1",
                    listOf(HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)))),
                )
            )

            assertEquals(NativeToolStatus.ACCESS_DENIED, result.status)
            verify(exactly = 0) { proxy.history(any()) }
        } finally {
            DataAccessSecurity.approvalHandler = original
        }
    }

    @Test
    fun `raw HTTP source is constructed once and queued without stored-history access`() = runBlocking {
        mockkStatic(HttpService::class)
        mockkStatic(HttpRequest::class)
        try {
            val nativeService = mockk<HttpService>()
            val request = request(120)
            every { HttpService.httpService("example.test", 443, true) } returns nativeService
            every { HttpRequest.httpRequest(nativeService, any<String>()) } returns request
            every { engine.queue(request, "raw") } returns Unit
            every { engine.sendAll(any<ResponseHandler>(), any<java.time.Duration>()) } returns execution
            every { lifetime.finished() } returns false
            val service = HttpRequestExecutionService(api, config())

            val result = service.start(
                StartHttpRequestExecution(
                    "project-1",
                    listOf(
                        HttpRequestExecutionItem(
                            raw = RawRequestExecutionSource(
                                protocol = RawHttpProtocol.HTTP_1,
                                http1 = RawHttp1Input("GET / HTTP/1.1\nHost: example.test\n\n"),
                                targetHostname = "example.test",
                                targetPort = 443,
                                usesHttps = true,
                            ),
                            label = "raw",
                        )
                    ),
                )
            )

            assertEquals(NativeToolStatus.OK, result.status)
            verify(exactly = 1) { HttpRequest.httpRequest(nativeService, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n") }
            verify(exactly = 0) { api.proxy() }
        } finally {
            unmockkStatic(HttpRequest::class)
            unmockkStatic(HttpService::class)
        }
    }

    @Test
    fun `batch approval denial starts no native engine`() = runBlocking {
        val request = request(120)
        stubHistory(proxyItem(7, request))
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean = false
        }

        val result = HttpRequestExecutionService(api, config()).start(
            StartHttpRequestExecution(
                "project-1",
                listOf(HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)))),
            )
        )

        assertEquals(NativeToolStatus.ACCESS_DENIED, result.status)
        assertEquals(StandardExecutionState.NOT_STARTED, result.executionState)
        verify(exactly = 0) { http.createRequestEngine() }
    }

    @Test
    fun `delete retains cleanup reservation when post-cancel status fails`() = runBlocking {
        val request = request(120)
        stubHistory(proxyItem(7, request))
        every { engine.queue(request) } returns Unit
        every { engine.sendAll(any<ResponseHandler>(), any<java.time.Duration>()) } returns execution
        var finishedCalls = 0
        every { lifetime.finished() } answers {
            finishedCalls++
            if (finishedCalls == 1) false else throw IllegalStateException("status failed")
        }
        val service = HttpRequestExecutionService(api, config())
        val started = service.start(
            StartHttpRequestExecution(
                "project-1",
                listOf(HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)))),
            )
        )
        val id = assertNotNull(started.executionId)

        val deleted = service.control(
            ControlHttpRequestExecution("project-1", id, HttpRequestExecutionControl.DELETE)
        )

        assertEquals(NativeToolStatus.EXECUTION_UNCERTAIN, deleted.status)
        assertEquals(null, deleted.executionId)
        assertTrue(deleted.error.orEmpty().contains("handle was deleted"))
        val reservations = HttpRequestExecutionService::class.java.getDeclaredField("cleanupReservations").run {
            isAccessible = true
            get(service) as List<*>
        }
        assertEquals(1, reservations.size)
    }

    @Test
    fun `unconfirmed project cleanup keeps execution capacity reserved`() = runBlocking {
        val request = request(120)
        stubHistory(proxyItem(7, request))
        val engines = List(4) { mockk<RequestExecutionEngine>() }
        val executions = List(4) { mockk<RequestExecution>() }
        val lifetimes = List(4) { mockk<RequestExecutionLifetime>() }
        every { http.createRequestEngine() } returnsMany engines
        engines.forEachIndexed { index, nativeEngine ->
            every { nativeEngine.queue(request) } returns Unit
            every { nativeEngine.sendAll(any<ResponseHandler>(), any<java.time.Duration>()) } returns executions[index]
            every { executions[index].lifetime() } returns lifetimes[index]
            every { executions[index].stats() } returns stats
            every { lifetimes[index].finished() } returns false
            every { lifetimes[index].cancel() } returns Unit
        }
        every { lifetimes.first().cancel() } throws IllegalStateException("cleanup pending")
        val service = HttpRequestExecutionService(api, config())
        fun input() = StartHttpRequestExecution(
            "project-1",
            listOf(HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)))),
        )

        assertEquals(NativeToolStatus.OK, service.start(input()).status)
        service.resetForProjectBoundary()
        repeat(3) { assertEquals(NativeToolStatus.OK, service.start(input()).status) }
        val blocked = service.start(input())

        assertEquals(NativeToolStatus.LIMIT_EXCEEDED, blocked.status)
        assertTrue(blocked.error.orEmpty().contains("cleanup"))
        verify(exactly = 4) { http.createRequestEngine() }
    }

    @Test
    fun `project change during initial queue prevents sendAll`() = runBlocking {
        var currentProject = "project-1"
        every { project.id() } answers { currentProject }
        val request = request(120)
        stubHistory(proxyItem(7, request))
        every { engine.queue(request) } answers { currentProject = "project-2" }
        val service = HttpRequestExecutionService(api, config())

        val result = service.start(
            StartHttpRequestExecution(
                "project-1",
                listOf(HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)))),
            )
        )

        assertEquals(NativeToolStatus.PROJECT_MISMATCH, result.status)
        assertEquals(StandardExecutionState.NOT_STARTED, result.executionState)
        verify(exactly = 0) { engine.sendAll(any<ResponseHandler>(), any<java.time.Duration>()) }
    }

    @Test
    fun `sendAll failure is uncertain and does not publish a handle`() = runBlocking {
        val request = request(120)
        stubHistory(proxyItem(7, request))
        every { engine.queue(request) } returns Unit
        every { engine.sendAll(any<ResponseHandler>(), any<java.time.Duration>()) } throws IllegalStateException("private")
        val service = HttpRequestExecutionService(api, config())

        val result = service.start(
            StartHttpRequestExecution(
                "project-1",
                listOf(HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)))),
            )
        )

        assertEquals(NativeToolStatus.EXECUTION_UNCERTAIN, result.status)
        assertEquals(ToolRetryGuidance.DO_NOT_RETRY, result.retry)
        assertEquals(null, result.executionId)
        assertTrue(!result.error.orEmpty().contains("private"))
    }

    private fun config(requireDataApproval: Boolean = false): McpConfig {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers {
            when (firstArg<String>()) {
                "approvalYoloMode" -> false
                "requireDataAccessApproval" -> requireDataApproval
                "requireRequestActionApproval" -> false
                "requireHttpRequestApproval" -> false
                else -> false
            }
        }
        every { storage.getString(any()) } returns ""
        return McpConfig(storage, logging, testPreferences())
    }

    private fun ref(id: Int) = HttpMessageReference(HttpMessageSource.PROXY, id.toString())

    private fun stubHistory(vararg items: ProxyHttpRequestResponse) {
        every { proxy.history(any()) } answers {
            val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
            items.filter(filter::matches)
        }
    }

    private fun proxyItem(id: Int, request: HttpRequest) = mockk<ProxyHttpRequestResponse>().also {
        every { it.id() } returns id
        every { it.request() } returns request
        every { it.response() } returns null
    }

    private fun request(size: Int): HttpRequest {
        val body = bytes(size / 2)
        val service = mockk<HttpService>()
        every { service.host() } returns "example.test"
        every { service.port() } returns 443
        every { service.secure() } returns true
        return mockk<HttpRequest>().also {
            every { it.bodyOffset() } returns size - body.length()
            every { it.body() } returns body
            every { it.httpService() } returns service
        }
    }

    private fun response(size: Int): HttpResponse {
        val body = bytes(size / 2)
        return mockk<HttpResponse>().also {
            every { it.bodyOffset() } returns size - body.length()
            every { it.body() } returns body
            every { it.statusCode() } returns 200
        }
    }

    private fun bytes(size: Int) = mockk<MontoyaByteArray>().also {
        every { it.length() } returns size
    }
}
