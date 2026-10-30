package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.execution.*
import burp.api.montoya.http.execution.Retention
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
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
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
    fun `raw HTTP2 conflicts are rejected for both engine start and queue`() = runBlocking {
        val invalidItems = listOf(HttpRequestExecutionItem(raw = RawRequestExecutionSource(
            protocol = RawHttpProtocol.HTTP_2,
            http2 = RawHttp2Input(mapOf("method" to "GET", ":method" to "POST"), emptyMap(), ""),
            targetHostname = "example.test", targetPort = 443, usesHttps = true,
        )))
        val service = HttpRequestExecutionService(api, config())
        val rejected = service.start(StartHttpRequestExecution("project-1", invalidItems))
        assertEquals(NativeToolStatus.INVALID_ARGUMENT, rejected.status)
        assertEquals(StandardExecutionState.NOT_STARTED, rejected.executionState)
        verify(exactly = 0) { http.createRequestEngine() }

        val request = request(120)
        stubHistory(proxyItem(7, request))
        every { engine.queue(request, any()) } returns Unit
        every { engine.sendAll(any<ResponseHandler>(), any<java.time.Duration>()) } returns execution
        every { lifetime.finished() } returns false
        val started = service.start(StartHttpRequestExecution(
            "project-1", listOf(HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)))),
        ))
        assertEquals(NativeToolStatus.OK, started.status, started.error)
        val queued = service.queue(QueueHttpRequestExecution("project-1", assertNotNull(started.executionId), invalidItems))
        assertEquals(NativeToolStatus.INVALID_ARGUMENT, queued.status)
        assertEquals(StandardExecutionState.NOT_STARTED, queued.executionState)
        verify(exactly = 0) { execution.queue(any<HttpRequest>()) }
        verify(exactly = 0) { execution.queue(any(), any()) }
        service.close()
    }

    @Test
    fun `engine starts queues captures bounded metadata and supports lifecycle controls`() = runBlocking {
        val request = request(120)
        val item = proxyItem(7, request)
        stubHistory(item)
        val handler = slot<ResponseHandler>()
        every { engine.queue(request, "mcp-request-0") } returns Unit
        every { engine.sendAll(capture(handler), any<java.time.Duration>()) } returns execution
        every { lifetime.finished() } returns false
        every { execution.queue(request, "mcp-request-1") } returns Unit
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
        verify(exactly = 1) { engine.queue(request, "mcp-request-0") }
        assertEquals(0, started.firstRequestId)

        val response = response(240)
        val exchange = mockk<HttpRequestResponse>()
        every { exchange.request() } returns request
        every { exchange.response() } returns response
        val requestResult = mockk<RequestResult>()
        every { requestResult.requestResponse() } returns exchange
        every { requestResult.label() } returns "mcp-request-0"
        every { requestResult.status() } returns RequestStatus.RESPONDED
        assertEquals(
            burp.api.montoya.http.execution.Retention.DROP,
            handler.captured.onResponse(requestResult, execution),
        )

        val completion = mockk<RequestExecutionResult>()
        every { completion.cancelled() } returns false
        every { completion.results() } returns emptyList()
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
        assertEquals(0, status.results.single().requestId)
        assertEquals("first", status.results.single().label)
        assertTrue(status.resultsComplete)

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
        verify(exactly = 1) { execution.queue(request, "mcp-request-1") }
        assertEquals(1, queued.firstRequestId)

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
    fun `result accessor failures preserve independently available metadata`() = runBlocking {
        for (failure in listOf("label", "status", "exchange", "requestBytes", "response", "statusCode", "responseBytes")) {
            val request = request(120)
            val response = response(240)
            stubHistory(proxyItem(7, request))
            val nativeLabel = slot<String>()
            val handler = slot<ResponseHandler>()
            every { engine.queue(request, capture(nativeLabel)) } returns Unit
            every { engine.sendAll(capture(handler), any<java.time.Duration>()) } returns execution
            every { lifetime.finished() } returns false
            val service = HttpRequestExecutionService(api, config())
            val started = service.start(StartHttpRequestExecution(
                "project-1",
                listOf(HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)), label = "item")),
            ))
            val exchange = mockk<HttpRequestResponse>()
            every { exchange.request() } returns request
            every { exchange.response() } returns response
            val result = mockk<RequestResult>()
            every { result.label() } answers { nativeLabel.captured }
            every { result.status() } returns RequestStatus.RESPONDED
            every { result.requestResponse() } returns exchange
            val error = IllegalStateException("private getter failure")
            when (failure) {
                "label" -> every { result.label() } throws error
                "status" -> every { result.status() } throws error
                "exchange" -> every { result.requestResponse() } throws error
                "requestBytes" -> every { request.body() } throws error
                "response" -> every { exchange.response() } throws error
                "statusCode" -> every { response.statusCode() } throws error
                "responseBytes" -> every { response.body() } throws error
            }

            assertEquals(Retention.DROP, handler.captured.onResponse(result, execution), failure)
            val observed = service.get(GetHttpRequestExecution("project-1", assertNotNull(started.executionId)))
                .results.single()
            assertEquals(if (failure == "label") null else "item", observed.label, failure)
            assertEquals(if (failure == "status") "unavailable" else "responded", observed.status, failure)
            assertEquals(if (failure in listOf("exchange", "requestBytes")) null else 120, observed.requestBytes, failure)
            assertEquals(if (failure in listOf("exchange", "response", "statusCode")) null else 200, observed.responseStatusCode, failure)
            assertEquals(if (failure in listOf("exchange", "response", "responseBytes")) null else 240, observed.responseBytes, failure)
            verify(exactly = 0) { request.toByteArray() }
            verify(exactly = 0) { response.toByteArray() }
            service.close()
        }
    }

    @Test
    fun `execution byte budget is cumulative across queue calls`() = runBlocking {
        val request = request(MAX_ACTION_REQUEST_BYTES)
        stubHistory(proxyItem(7, request))
        every { engine.queue(request, any()) } returns Unit
        every { engine.sendAll(any<ResponseHandler>(), any<java.time.Duration>()) } returns execution
        every { lifetime.finished() } returns false
        every { execution.queue(request, any()) } returns Unit
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
        verify(exactly = 7) { execution.queue(request, any()) }
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
            every { engine.queue(request, "mcp-request-0") } returns Unit
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
        every { engine.queue(request, any()) } returns Unit
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
            every { nativeEngine.queue(request, any()) } returns Unit
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
        every { engine.queue(request, any()) } answers { currentProject = "project-2" }
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
        every { engine.queue(request, any()) } returns Unit
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

    @Test
    fun `internal identities survive missing empty and duplicate user labels and synchronous reverse completion`() = runBlocking {
        val request = request(120)
        stubHistory(proxyItem(7, request))
        val nativeLabels = mutableListOf<String>()
        val userLabels = listOf(null, "", "duplicate", "duplicate")
        every { engine.queue(request, capture(nativeLabels)) } returns Unit
        every { engine.sendAll(any<ResponseHandler>(), any<java.time.Duration>()) } answers {
            val handler = firstArg<ResponseHandler>()
            nativeLabels.asReversed().forEach { label ->
                assertEquals(Retention.DROP, handler.onResponse(nativeResult(label, RequestStatus.RESPONDED, request), execution))
            }
            execution
        }
        every { lifetime.finished() } returns true
        val completion = mockk<RequestExecutionResult>()
        every { completion.cancelled() } returns false
        every { completion.results() } returns emptyList()
        every { lifetime.awaitCompletion() } returns completion
        every { stats.requested() } returns 4
        val service = HttpRequestExecutionService(api, config())
        val started = service.start(StartHttpRequestExecution("project-1", userLabels.map {
            HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)), label = it)
        }))

        assertEquals(0, started.firstRequestId)
        assertEquals(4, nativeLabels.distinct().size)
        val result = service.get(GetHttpRequestExecution("project-1", assertNotNull(started.executionId)))
        assertEquals(listOf(3, 2, 1, 0), result.results.map { it.requestId })
        assertEquals(userLabels.asReversed(), result.results.map { it.label })
        assertTrue(result.resultsComplete)
        assertFalse(result.resultsTruncated)
        service.close()
    }

    @Test
    fun `cancelled never-sent results reconcile without reading exchanges or mutating callback capture`() = runBlocking {
        val request = request(120)
        stubHistory(proxyItem(7, request))
        val labels = mutableListOf<String>()
        val handler = slot<ResponseHandler>()
        every { engine.queue(request, capture(labels)) } returns Unit
        every { engine.sendAll(capture(handler), any<java.time.Duration>()) } returns execution
        val service = HttpRequestExecutionService(api, config())
        val started = service.start(StartHttpRequestExecution("project-1", List(3) {
            HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)), label = "item-$it")
        }))
        handler.captured.onResponse(nativeResult(labels[0], RequestStatus.RESPONDED, request), execution)
        val dropped = labels.drop(1).map { nativeResult(it, RequestStatus.DROPPED) }
        val completion = mockk<RequestExecutionResult>()
        every { lifetime.finished() } returns true
        every { lifetime.awaitCompletion() } returns completion
        every { completion.cancelled() } returns true
        every { completion.results() } returns dropped
        every { stats.requested() } returns 3
        every { stats.completed() } returns 1
        every { stats.failed() } returns 2
        val input = GetHttpRequestExecution("project-1", assertNotNull(started.executionId))
        val first = service.get(input)
        val second = service.get(input)

        assertEquals(first, second)
        assertTrue(first.resultsComplete)
        assertEquals(listOf(0, 1, 2), first.results.map { it.requestId })
        assertEquals(listOf("responded", "dropped", "dropped"), first.results.map { it.status })
        first.results.drop(1).forEach { assertNull(it.requestBytes); assertNull(it.responseBytes) }
        dropped.forEach { verify(exactly = 0) { it.requestResponse() } }
        service.close()
    }

    @Test
    fun `terminal metadata failures preserve callback evidence and never claim complete coverage`() = runBlocking {
        for (failure in listOf("finished", "await", "cancelled", "results", "size", "row", "label", "status")) {
            val request = request(120)
            stubHistory(proxyItem(7, request))
            val labels = mutableListOf<String>()
            val handler = slot<ResponseHandler>()
            every { engine.queue(request, capture(labels)) } returns Unit
            every { engine.sendAll(capture(handler), any<java.time.Duration>()) } returns execution
            val service = HttpRequestExecutionService(api, config())
            val started = service.start(StartHttpRequestExecution("project-1", List(2) {
                HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)), label = "item-$it")
            }))
            handler.captured.onResponse(nativeResult(labels[0], RequestStatus.RESPONDED, request), execution)
            val dropped = nativeResult(labels[1], RequestStatus.DROPPED)
            val completion = mockk<RequestExecutionResult>()
            every { lifetime.finished() } returns true
            every { lifetime.awaitCompletion() } returns completion
            every { completion.cancelled() } returns true
            every { completion.results() } returns listOf(dropped)
            every { stats.requested() } returns 2
            val error = IllegalStateException("PRIVATE_TERMINAL")
            when (failure) {
                "finished" -> every { lifetime.finished() } throws error
                "await" -> every { lifetime.awaitCompletion() } throws error
                "cancelled" -> every { completion.cancelled() } throws error
                "results" -> every { completion.results() } throws error
                "size", "row" -> every { completion.results() } returns object : AbstractList<RequestResult>() {
                    override val size: Int get() = if (failure == "size") throw error else 1
                    override fun get(index: Int): RequestResult = throw error
                }
                "label" -> every { dropped.label() } throws error
                "status" -> every { dropped.status() } throws error
            }
            val result = service.get(GetHttpRequestExecution("project-1", assertNotNull(started.executionId), waitMillis = 30_000))
            assertEquals(NativeToolStatus.OK, result.status, failure)
            assertFalse(result.resultsComplete, failure)
            assertEquals(0, result.results.first().requestId, failure)
            assertEquals("item-0", result.results.first().label, failure)
            assertEquals("responded", result.results.first().status, failure)
            verify(exactly = 0) { dropped.requestResponse() }
            service.close()
        }
    }

    @Test
    fun `terminal getter project and lifecycle changes discard all partial result metadata`() = runBlocking {
        for (change in listOf("project", "lifecycle")) {
            var projectId = "project-1"
            every { project.id() } answers { projectId }
            val request = request(120)
            stubHistory(proxyItem(7, request))
            val label = slot<String>()
            val handler = slot<ResponseHandler>()
            every { engine.queue(request, capture(label)) } returns Unit
            every { engine.sendAll(capture(handler), any<java.time.Duration>()) } returns execution
            val service = HttpRequestExecutionService(api, config())
            val id = assertNotNull(service.start(StartHttpRequestExecution("project-1", listOf(
                HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7))),
            ))).executionId)
            handler.captured.onResponse(nativeResult(label.captured, RequestStatus.RESPONDED, request), execution)
            val completion = mockk<RequestExecutionResult>()
            every { lifetime.finished() } returns true
            every { lifetime.awaitCompletion() } returns completion
            every { completion.cancelled() } returns false
            every { completion.results() } answers {
                if (change == "project") projectId = "project-2" else runBlocking { service.resetForProjectBoundary() }
                throw IllegalStateException("terminal read failed after transition")
            }
            val result = service.get(GetHttpRequestExecution("project-1", id))
            assertEquals(if (change == "project") NativeToolStatus.PROJECT_MISMATCH else NativeToolStatus.STALE_STATE,
                result.status, change)
            assertTrue(result.results.isEmpty(), change)
            assertFalse(result.resultsComplete, change)
            service.close()
        }
    }

    @Test
    fun `uncertain queue reserves the entire input identity range even when no queue call returned`() = runBlocking {
        for (failAt in listOf(0, 1)) {
            val request = request(120)
            stubHistory(proxyItem(7, request))
            val handler = slot<ResponseHandler>()
            every { engine.queue(request, any()) } returns Unit
            every { engine.sendAll(capture(handler), any<java.time.Duration>()) } returns execution
            every { lifetime.finished() } returns false
            val service = HttpRequestExecutionService(api, config())
            val item = HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)), label = "same")
            val started = service.start(StartHttpRequestExecution("project-1", listOf(item)))
            val id = assertNotNull(started.executionId)
            var attempted = 0
            every { execution.queue(request, any()) } answers {
                handler.captured.onResponse(nativeResult(secondArg(), RequestStatus.RESPONDED, request), execution)
                if (attempted++ == failAt) throw IllegalStateException("native queue may have accepted")
            }
            val uncertain = service.queue(QueueHttpRequestExecution("project-1", id, List(3) { item }))
            assertEquals(NativeToolStatus.EXECUTION_UNCERTAIN, uncertain.status)
            assertEquals(ToolRetryGuidance.DO_NOT_RETRY, uncertain.retry)
            assertEquals(failAt, uncertain.queued)
            assertEquals(1, uncertain.firstRequestId)
            every { execution.queue(request, any()) } answers {
                handler.captured.onResponse(nativeResult(secondArg(), RequestStatus.RESPONDED, request), execution)
            }
            val next = service.queue(QueueHttpRequestExecution("project-1", id, listOf(item)))
            assertEquals(NativeToolStatus.OK, next.status)
            assertEquals(4, next.firstRequestId)
            val status = service.get(GetHttpRequestExecution("project-1", id))
            assertEquals((1..failAt + 1).toList() + 4, status.results.map { it.requestId })
            assertFalse(status.resultsComplete)
            service.close()
        }
    }

    @Test
    fun `first queue fence failure allocates no identity and does not consume the next input range`() = runBlocking {
        val request = request(120)
        stubHistory(proxyItem(7, request))
        every { engine.queue(request, any()) } returns Unit
        every { engine.sendAll(any<ResponseHandler>(), any<java.time.Duration>()) } returns execution
        val service = HttpRequestExecutionService(api, config())
        val item = HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)))
        val id = assertNotNull(service.start(StartHttpRequestExecution("project-1", listOf(item))).executionId)
        var projectId = "project-1"
        var checks = 0
        every { project.id() } answers { projectId }
        every { lifetime.finished() } answers {
            if (++checks == 2) projectId = "project-2"
            false
        }
        val rejected = service.queue(QueueHttpRequestExecution("project-1", id, listOf(item)))
        assertEquals(NativeToolStatus.PROJECT_MISMATCH, rejected.status)
        assertEquals(StandardExecutionState.NOT_STARTED, rejected.executionState)
        assertNull(rejected.firstRequestId)
        verify(exactly = 0) { execution.queue(any(), any()) }
        projectId = "project-1"
        every { execution.queue(request, "mcp-request-1") } returns Unit
        val next = service.queue(QueueHttpRequestExecution("project-1", id, listOf(item)))
        assertEquals(NativeToolStatus.OK, next.status)
        assertEquals(1, next.firstRequestId)
        service.close()
    }

    @Test
    fun `unknown duplicate missing and conflicting identities cannot manufacture complete results`() = runBlocking {
        for (case in listOf("unknown", "duplicate", "missing", "conflict", "terminal_duplicate")) {
            val request = request(120)
            stubHistory(proxyItem(7, request))
            val labels = mutableListOf<String>()
            val handler = slot<ResponseHandler>()
            every { engine.queue(request, capture(labels)) } returns Unit
            every { engine.sendAll(capture(handler), any<java.time.Duration>()) } returns execution
            val service = HttpRequestExecutionService(api, config())
            val id = assertNotNull(service.start(StartHttpRequestExecution("project-1", List(2) {
                HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7)))
            })).executionId)
            handler.captured.onResponse(nativeResult(labels[0], RequestStatus.RESPONDED, request), execution)
            if (case == "unknown" || case == "duplicate") {
                val label = if (case == "unknown") labels[1] + "x".repeat(128) else labels[0]
                handler.captured.onResponse(nativeResult(label, RequestStatus.RESPONDED, request), execution)
            }
            val completion = mockk<RequestExecutionResult>()
            every { lifetime.finished() } returns true
            every { lifetime.awaitCompletion() } returns completion
            every { completion.cancelled() } returns false
            every { completion.results() } returns when (case) {
                "conflict" -> listOf(nativeResult(labels[0], RequestStatus.DROPPED))
                "terminal_duplicate" -> List(2) { nativeResult(labels[1], RequestStatus.DROPPED) }
                else -> emptyList()
            }
            every { stats.requested() } returns 2
            val result = service.get(GetHttpRequestExecution("project-1", id))
            assertFalse(result.resultsComplete, case)
            if (case == "unknown") { assertNull(result.results.last().requestId); assertNull(result.results.last().label) }
            service.close()
        }
    }

    @Test
    fun `terminal inspection is bounded and native requested count is never clamped into completeness`() = runBlocking {
        val request = request(120)
        stubHistory(proxyItem(7, request))
        val labels = mutableListOf<String>()
        val handler = slot<ResponseHandler>()
        every { engine.queue(request, capture(labels)) } returns Unit
        every { engine.sendAll(capture(handler), any<java.time.Duration>()) } returns execution
        every { execution.queue(request, capture(labels)) } returns Unit
        every { lifetime.finished() } returns false
        val service = HttpRequestExecutionService(api, config())
        val batch = List(16) { HttpRequestExecutionItem(stored = StoredRequestExecutionSource(ref(7))) }
        val id = assertNotNull(service.start(StartHttpRequestExecution("project-1", batch)).executionId)
        repeat(3) { assertEquals((it + 1) * 16, service.queue(QueueHttpRequestExecution("project-1", id, batch)).firstRequestId) }
        labels.forEach { handler.captured.onResponse(nativeResult(it, RequestStatus.RESPONDED, request), execution) }
        val exceeded = service.queue(QueueHttpRequestExecution("project-1", id, batch.take(1)))
        assertEquals(NativeToolStatus.LIMIT_EXCEEDED, exceeded.status)
        assertNull(exceeded.firstRequestId)
        val completion = mockk<RequestExecutionResult>()
        every { lifetime.finished() } returns true
        every { lifetime.awaitCompletion() } returns completion
        every { completion.cancelled() } returns false
        every { completion.results() } returns emptyList()
        val input = GetHttpRequestExecution("project-1", id)
        for (requested in listOf(64, 65, -1)) {
            every { stats.requested() } returns requested
            val result = service.get(input)
            assertEquals(64, result.results.size)
            assertEquals(requested == 64, result.resultsComplete)
        }
        var inspected = 0
        every { completion.results() } returns object : AbstractList<RequestResult>() {
            override val size = 65
            override fun get(index: Int): RequestResult {
                inspected++
                return nativeResult(labels[index], RequestStatus.DROPPED)
            }
        }
        val truncated = service.get(input)
        assertEquals(64, inspected)
        assertEquals(64, truncated.results.size)
        assertTrue(truncated.resultsTruncated)
        assertFalse(truncated.resultsComplete)
        every { completion.results() } throws kotlinx.coroutines.CancellationException("cancelled read")
        assertFailsWith<kotlinx.coroutines.CancellationException> { service.get(input) }
        service.close()
    }

    private fun nativeResult(label: String, status: RequestStatus, request: HttpRequest? = null): RequestResult =
        mockk<RequestResult>().also { result ->
            every { result.label() } returns label
            every { result.status() } returns status
            if (request == null) {
                every { result.requestResponse() } throws AssertionError("terminal reconciliation must not read an exchange")
            } else {
                val exchange = mockk<HttpRequestResponse>()
                every { exchange.request() } returns request
                every { exchange.response() } returns response(240)
                every { result.requestResponse() } returns exchange
            }
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
