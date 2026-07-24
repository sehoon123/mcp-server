package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.logging.Logging
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.websocket.Direction
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.delay
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.TextResourceContents
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.McpAuditRecord
import net.portswigger.mcp.security.McpAuditSink
import net.portswigger.mcp.security.McpSessionApproval
import net.portswigger.mcp.security.grantCurrentSessionApproval
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.time.Duration
import java.time.ZonedDateTime
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertIs

class McpServerIntegrationTest {
    private val testBearerToken = "0123456789012345678901234567890123456789012"
    private val client = TestStreamableHttpMcpClient(
        mapOf("Authorization" to "Bearer $testBearerToken")
    )
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val auditRecords = CopyOnWriteArrayList<McpAuditRecord>()
    private val auditSink = object : McpAuditSink {
        override fun append(record: McpAuditRecord) {
            auditRecords += record
        }

        override fun recordLocalEvent(tool: String, outcome: String) = Unit
        override fun snapshot(limit: Int): List<McpAuditRecord> = auditRecords.takeLast(limit)
        override fun size(): Int = auditRecords.size
        override fun clear() = auditRecords.clear()
        override fun trimToConfiguredRetention() = Unit
        override fun flush() = Unit
        override fun exportJsonLines(limit: Int): String = ""
        override fun close() = Unit
    }
    private val serverManager = KtorServerManager(api, auditSink)
    private val testPort = findAvailablePort()
    private val persistedObject = mockk<PersistedObject>()
    private var serverStarted = false

    init {
        every { persistedObject.getBoolean(any()) } returns true
        every { persistedObject.getBoolean("emergencyReadOnlyMode") } returns false
        every { persistedObject.getBoolean("_alwaysAllowHttpHistory") } returns false
        every { persistedObject.getBoolean("_alwaysAllowSiteMap") } returns false
        every { persistedObject.getBoolean("_alwaysAllowWebSocketHistory") } returns false
        every { persistedObject.getBoolean("_alwaysAllowOrganizer") } returns false
        every { persistedObject.getBoolean("_alwaysAllowScannerIssues") } returns false
        every { persistedObject.getBoolean("_alwaysAllowCollaboratorInteractions") } returns false
        every { persistedObject.getString(any()) } returns "127.0.0.1"
        every { persistedObject.getString("localBearerToken") } returns testBearerToken
        every { persistedObject.getInteger("port") } returns testPort
        every { persistedObject.setBoolean(any(), any()) } returns Unit
        every { persistedObject.setString(any(), any()) } returns Unit
        every { persistedObject.setInteger(any(), any()) } returns Unit
        every { api.project().id() } returns "integration-project"
        every { api.burpSuite().version().edition() } returns BurpSuiteEdition.COMMUNITY_EDITION
    }

    private val mockLogging = mockk<Logging>().apply {
        every { logToError(any<String>()) } returns Unit
        every { logToOutput(any<String>()) } returns Unit
    }

    private val config = McpConfig(persistedObject, mockLogging)

    @BeforeEach
    fun setup() {
        serverManager.start(config) { state ->
            if (state is ServerState.Running) {
                serverStarted = true
            }
        }
        
        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 10) {
                delay(100)
                attempts++
            }
            
            if (!serverStarted) {
                throw IllegalStateException("Server failed to start after timeout")
            }
        }
    }

    private fun findAvailablePort(): Int {
        return ServerSocket(0).use { it.localPort }
    }

    private fun io.modelcontextprotocol.kotlin.sdk.types.ReadResourceResult.singleTextResourceJson() =
        Json.parseToJsonElement(assertIs<TextResourceContents>(contents.single()).text).jsonObject

    @AfterEach
    fun tearDown() {
        runBlocking {
            if (client.isConnected()) {
                client.close()
            }
        }
        serverManager.shutdown()
    }

    @Test
    fun `server should accept browser-style requests from a loopback origin`() = runBlocking {
        val browserClient = TestStreamableHttpMcpClient(
            mapOf(
                "Origin" to "http://localhost:6274",
                "User-Agent" to "Mozilla/5.0 MCP Inspector",
                "Authorization" to "Bearer $testBearerToken"
            )
        )

        try {
            browserClient.connectToServer("http://127.0.0.1:${testPort}/mcp")
            assertTrue(browserClient.listTools().isNotEmpty())
        } finally {
            browserClient.close()
        }
    }

    @Test
    fun `MCP endpoint rejects missing and incorrect bearer credentials`() {
        val client = java.net.http.HttpClient.newHttpClient()
        fun send(authorization: String?): java.net.http.HttpResponse<String> {
            val builder = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI("http://127.0.0.1:${testPort}/mcp"))
                .header("Content-Type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString("{}"))
            if (authorization != null) builder.header("Authorization", authorization)
            return client.send(builder.build(), java.net.http.HttpResponse.BodyHandlers.ofString())
        }

        assertEquals(401, send(null).statusCode())
        assertEquals(401, send("Bearer incorrect-token").statusCode())
        assertNotEquals(401, send("Bearer $testBearerToken").statusCode())

        // The response body can arrive just before the server's request-admission finally releases the call lease.
        val cleanupDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (serverManager.diagnostics().activeHttpCalls != 0 && System.nanoTime() < cleanupDeadline) {
            Thread.sleep(25)
        }
        val diagnostics = serverManager.diagnostics()
        assertEquals("running", diagnostics.state)
        assertEquals("http://127.0.0.1:${testPort}/mcp", diagnostics.endpoint)
        assertEquals(3, diagnostics.totalRequests)
        assertEquals(2, diagnostics.authenticationRejections)
        assertEquals(0, diagnostics.activeHttpCalls)
    }

    @Test
    fun `MCP endpoint validates Host and Origin even with a valid bearer credential`() {
        val client = java.net.http.HttpClient.newHttpClient()
        fun send(origin: String): java.net.http.HttpResponse<String> {
            val request = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI("http://127.0.0.1:${testPort}/mcp"))
                .header("Authorization", "Bearer $testBearerToken")
                .header("Origin", origin)
                .header("Content-Type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString("{}"))
                .build()
            return client.send(request, java.net.http.HttpResponse.BodyHandlers.ofString())
        }

        assertEquals(403, send("https://attacker.example").statusCode())
        assertEquals(403, send("http://user@localhost:6274").statusCode())
        assertEquals(403, send("http://localhost:6274/").statusCode())
        assertEquals(403, send("http://localhost:6274?token=leak").statusCode())
        assertEquals(403, send("http://localhost:6274#fragment").statusCode())
        assertEquals(403, send("http://localhost:").statusCode())
        assertEquals(403, send("http://localhost:00080").statusCode())
        assertEquals(403, send("http://localhost:0").statusCode())
        assertNotEquals(403, send("http://localhost:6274").statusCode())
        assertNotEquals(403, send("https://[::1]:6274").statusCode())
        assertEquals(10, serverManager.diagnostics().totalRequests)
        assertEquals(8, serverManager.diagnostics().hostOriginRejections)
    }

    @Test
    fun `long lived session SSE stream remains available and closes after session deletion`() {
        val httpClient = java.net.http.HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2))
            .build()
        val endpoint = java.net.URI("http://127.0.0.1:${testPort}/mcp")
        fun requestBuilder() = java.net.http.HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(5))
            .header("Authorization", "Bearer $testBearerToken")
            .header("Mcp-Protocol-Version", "2025-11-25")

        val initializeBody = """
            {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"sse-lifecycle-test","version":"1.0"}}}
        """.trimIndent()
        val initialize = httpClient.send(
            requestBuilder()
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(initializeBody))
                .build(),
            java.net.http.HttpResponse.BodyHandlers.ofString()
        )
        assertEquals(200, initialize.statusCode(), initialize.body())
        val sessionId = initialize.headers().firstValue("Mcp-Session-Id").orElseThrow()

        val initialized = httpClient.send(
            requestBuilder()
                .header("Mcp-Session-Id", sessionId)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(
                    "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"
                ))
                .build(),
            java.net.http.HttpResponse.BodyHandlers.ofString()
        )
        assertTrue(initialized.statusCode() in setOf(200, 202), initialized.body())

        val streamFuture = httpClient.sendAsync(
            requestBuilder()
                .header("Mcp-Session-Id", sessionId)
                .header("Accept", "text/event-stream")
                .GET()
                .build(),
            java.net.http.HttpResponse.BodyHandlers.ofInputStream()
        )
        val stream = streamFuture.get(5, TimeUnit.SECONDS)
        assertEquals(200, stream.statusCode())
        Thread.sleep(1_000)

        val deleted = httpClient.send(
            requestBuilder()
                .header("Mcp-Session-Id", sessionId)
                .header("Accept", "application/json, text/event-stream")
                .DELETE()
                .build(),
            java.net.http.HttpResponse.BodyHandlers.ofString()
        )
        assertTrue(deleted.statusCode() in setOf(200, 202), deleted.body())
        stream.body().close()

        val cleanupDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (serverManager.diagnostics().activeHttpCalls != 0 && System.nanoTime() < cleanupDeadline) {
            Thread.sleep(25)
        }
        val diagnostics = serverManager.diagnostics()
        assertEquals(0, diagnostics.activeHttpCalls)
        assertEquals(0, diagnostics.activeSessions)
    }

    @Test
    fun `bounded HTTP search returns JSON without a stream and fixed progress on an attached stream`() {
        every { persistedObject.getBoolean("_alwaysAllowHttpHistory") } returns true
        every { api.proxy().history() } returns emptyList()

        val httpClient = java.net.http.HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2))
            .build()
        val endpoint = java.net.URI("http://127.0.0.1:${testPort}/mcp")

        fun requestBuilder() = java.net.http.HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(5))
            .header("Authorization", "Bearer $testBearerToken")
            .header("Mcp-Protocol-Version", "2025-11-25")

        fun post(sessionId: String?, body: String): java.net.http.HttpResponse<String> {
            val builder = requestBuilder()
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
            if (sessionId != null) builder.header("Mcp-Session-Id", sessionId)
            return httpClient.send(
                builder.POST(java.net.http.HttpRequest.BodyPublishers.ofString(body)).build(),
                java.net.http.HttpResponse.BodyHandlers.ofString(),
            )
        }

        fun initialize(clientName: String): String {
            val response = post(
                null,
                """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"$clientName","version":"1.0"}}}""",
            )
            assertEquals(200, response.statusCode(), response.body())
            val sessionId = response.headers().firstValue("Mcp-Session-Id").orElseThrow()
            val initialized = post(
                sessionId,
                """{"jsonrpc":"2.0","method":"notifications/initialized"}""",
            )
            assertTrue(initialized.statusCode() in setOf(200, 202), initialized.body())
            return sessionId
        }

        fun delete(sessionId: String) {
            val response = httpClient.send(
                requestBuilder()
                    .header("Mcp-Session-Id", sessionId)
                    .header("Accept", "application/json, text/event-stream")
                    .DELETE()
                    .build(),
                java.net.http.HttpResponse.BodyHandlers.ofString(),
            )
            assertTrue(response.statusCode() in setOf(200, 202), response.body())
        }

        val postOnlySession = initialize("post-only-progress-test")
        val postOnly = post(
            postOnlySession,
            """{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_http_messages","arguments":{},"_meta":{"progressToken":"post-only-progress"}}}""",
        )
        assertEquals(200, postOnly.statusCode(), postOnly.body())
        assertTrue(
            postOnly.headers().firstValue("Content-Type").orElse("").startsWith("application/json"),
            postOnly.headers().map().toString(),
        )
        assertFalse(postOnly.body().contains("notifications/progress"))
        val postOnlyJson = Json.parseToJsonElement(postOnly.body()).jsonObject
        assertEquals(
            "ok",
            postOnlyJson["result"]?.jsonObject
                ?.get("structuredContent")?.jsonObject
                ?.get("status")?.jsonPrimitive?.content,
        )
        delete(postOnlySession)

        val progressSession = initialize("stream-progress-test")
        val stream = httpClient.sendAsync(
            requestBuilder()
                .header("Mcp-Session-Id", progressSession)
                .header("Accept", "text/event-stream")
                .GET()
                .build(),
            java.net.http.HttpResponse.BodyHandlers.ofInputStream(),
        ).get(5, TimeUnit.SECONDS)
        assertEquals(200, stream.statusCode())

        val progressEvents = CopyOnWriteArrayList<Triple<Double, Double?, String?>>()
        val reader = stream.body().bufferedReader()
        val readerFuture = CompletableFuture.runAsync {
            while (progressEvents.size < 6) {
                val line = reader.readLine() ?: break
                if (!line.startsWith("data:")) continue
                val payload = runCatching {
                    Json.parseToJsonElement(line.removePrefix("data:").trim()).jsonObject
                }.getOrNull() ?: continue
                if (payload["method"]?.jsonPrimitive?.content != "notifications/progress") continue
                val params = payload["params"]?.jsonObject ?: continue
                progressEvents += Triple(
                    params["progress"]?.jsonPrimitive?.content?.toDouble() ?: continue,
                    params["total"]?.jsonPrimitive?.content?.toDouble(),
                    params["message"]?.jsonPrimitive?.content,
                )
            }
        }

        val progressCall = post(
            progressSession,
            """{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search_http_messages","arguments":{},"_meta":{"progressToken":"bounded-search-progress"}}}""",
        )
        assertEquals(200, progressCall.statusCode(), progressCall.body())
        assertEquals(
            "ok",
            Json.parseToJsonElement(progressCall.body()).jsonObject["result"]?.jsonObject
                ?.get("structuredContent")?.jsonObject
                ?.get("status")?.jsonPrimitive?.content,
        )

        readerFuture.get(5, TimeUnit.SECONDS)
        assertEquals((0..5).map(Int::toDouble), progressEvents.map { it.first })
        assertTrue(progressEvents.all { it.second == 5.0 })
        assertEquals(
            listOf(
                "Validating HTTP search",
                "Authorizing HTTP history sources",
                "Preparing HTTP search snapshot",
                "Scanning bounded HTTP history",
                "Finalizing HTTP search",
                "HTTP search completed",
            ),
            progressEvents.map { it.third },
        )
        val progressText = progressEvents.joinToString("|") { it.third.orEmpty() }
        assertFalse(progressText.contains("integration-project"))
        assertFalse(progressText.contains(testBearerToken))
        assertFalse(progressText.contains("bounded-search-progress"))

        delete(progressSession)
        stream.body().close()
    }

    @Test
    fun `legacy SSE root endpoint should not be exposed`() {
        val request = java.net.http.HttpRequest.newBuilder()
            .uri(java.net.URI("http://127.0.0.1:${testPort}/"))
            .header("Accept", "text/event-stream")
            .GET()
            .build()
        val response = java.net.http.HttpClient.newHttpClient().send(
            request,
            java.net.http.HttpResponse.BodyHandlers.ofString()
        )

        assertEquals(404, response.statusCode())
    }

    @Test
    fun `streamable HTTP endpoint negotiates every supported production protocol version`() {
        listOf("2025-03-26", "2025-06-18", "2025-11-25").forEach { protocolVersion ->
            val body = """
                {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"$protocolVersion","capabilities":{},"clientInfo":{"name":"protocol-matrix-test","version":"1.0"}}}
            """.trimIndent()
            val request = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI("http://127.0.0.1:${testPort}/mcp"))
                .header("Authorization", "Bearer $testBearerToken")
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .header("Mcp-Protocol-Version", protocolVersion)
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body))
                .build()
            val response = java.net.http.HttpClient.newHttpClient().send(
                request,
                java.net.http.HttpResponse.BodyHandlers.ofString()
            )

            assertEquals(200, response.statusCode(), response.body())
            assertTrue(
                response.body().contains("\"protocolVersion\":\"$protocolVersion\""),
                "Expected negotiated protocol $protocolVersion in ${response.body()}"
            )
        }
    }

    @Test
    fun `project summary fails closed when the Burp project changes during the read`() {
        every { api.project().id() } returnsMany listOf("project-before", "project-after")

        val result = currentProjectSummary(api)

        assertEquals(NativeResourceStatus.PROJECT_MISMATCH, result.status)
        assertEquals("project-after", result.projectId)
        assertFalse(result.toString().contains("integration-project"))
    }

    @Test
    fun `authenticated admission fails closed when the project binding is unavailable`() {
        val projectObservations = AtomicInteger()
        every { api.project().id() } answers {
            projectObservations.incrementAndGet()
            throw IllegalStateException("sensitive-provider-detail")
        }
        val body =
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"unavailable-project-test","version":"1.0"}}}"""
        fun request(authenticated: Boolean): java.net.http.HttpRequest {
            val builder = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI("http://127.0.0.1:${testPort}/mcp"))
                .timeout(Duration.ofSeconds(5))
                .header("Mcp-Protocol-Version", "2025-11-25")
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body))
            if (authenticated) builder.header("Authorization", "Bearer $testBearerToken")
            return builder.build()
        }
        val httpClient = java.net.http.HttpClient.newHttpClient()

        val unauthorized = httpClient.send(
            request(authenticated = false),
            java.net.http.HttpResponse.BodyHandlers.ofString(),
        )
        assertEquals(401, unauthorized.statusCode(), unauthorized.body())
        assertEquals(0, projectObservations.get())

        val response = httpClient.send(
            request(authenticated = true),
            java.net.http.HttpResponse.BodyHandlers.ofString(),
        )
        assertEquals(503, response.statusCode(), response.body())
        assertEquals("1", response.headers().firstValue("Retry-After").orElse(null))
        assertTrue(response.body().contains("Burp project binding is unavailable"))
        assertFalse(response.body().contains("sensitive-provider-detail"))
        assertEquals(1, projectObservations.get())
        assertEquals(0, serverManager.diagnostics().activeSessions)
    }

    @Test
    fun `project transition revokes the old session before a new project can be read`() = runBlocking {
        val currentProject = AtomicReference("integration-project")
        every { api.project().id() } answers { currentProject.get() }
        client.connectToServer("http://127.0.0.1:${testPort}/mcp")
        assertEquals(
            "integration-project",
            client.readResource(PROJECT_SUMMARY_RESOURCE_URI)
                .singleTextResourceJson()["projectId"]?.jsonPrimitive?.content,
        )

        currentProject.set("replacement-project")
        val staleFailure = runCatching {
            client.readResource(PROJECT_SUMMARY_RESOURCE_URI)
        }.exceptionOrNull()

        assertNotNull(staleFailure)
        assertFalse(staleFailure?.message.orEmpty().contains("replacement-project"))
        assertEquals(0, serverManager.diagnostics().activeSessions)
        runCatching { client.close() }

        val replacement = TestStreamableHttpMcpClient(
            mapOf("Authorization" to "Bearer $testBearerToken")
        )
        try {
            replacement.connectToServer("http://127.0.0.1:${testPort}/mcp")
            val project = replacement.readResource(PROJECT_SUMMARY_RESOURCE_URI).singleTextResourceJson()
            assertEquals("ok", project["status"]?.jsonPrimitive?.content)
            assertEquals("replacement-project", project["projectId"]?.jsonPrimitive?.content)
        } finally {
            replacement.close()
        }
    }

    @Test
    fun `HTTP resource templates map every bounded message part`() = runBlocking {
        every { persistedObject.getBoolean("_alwaysAllowHttpHistory") } returns true
        val proxy = api.proxy()
        val item = mockk<ProxyHttpRequestResponse>()
        val request = mockk<HttpRequest>()
        val response = mockk<HttpResponse>()
        val service = mockk<HttpService>()
        val annotations = mockk<Annotations>()
        val requestBytes = montoyaBytes("REQHREQBODY")
        val requestBody = montoyaBytes("REQBODY")
        val responseBytes = montoyaBytes("RESPHRESPBODY")
        val responseBody = montoyaBytes("RESPBODY")

        every { proxy.history(any()) } answers {
            val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
            listOf(item).filter(filter::matches)
        }
        every { item.id() } returns 42
        every { item.request() } returns request
        every { item.response() } returns response
        every { item.annotations() } returns annotations
        every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z")
        every { item.listenerPort() } returns 8080
        every { item.edited() } returns false
        every { annotations.notes() } returns null
        every { request.method() } returns "POST"
        every { request.url() } returns "https://example.test/resource"
        every { request.httpService() } returns service
        every { request.toByteArray() } returns requestBytes
        every { request.bodyOffset() } returns 4
        every { request.body() } returns requestBody
        every { response.statusCode() } returns 200
        every { response.mimeType() } returns MimeType.JSON
        every { response.toByteArray() } returns responseBytes
        every { response.bodyOffset() } returns 5
        every { response.body() } returns responseBody
        every { service.host() } returns "example.test"
        every { service.port() } returns 443
        every { service.secure() } returns true

        client.connectToServer("http://127.0.0.1:${testPort}/mcp")
        val expectedContent = linkedMapOf(
            "metadata" to null,
            "request" to "REQHREQBODY",
            "request_headers" to "REQH",
            "request_body" to "REQBODY",
            "response" to "RESPHRESPBODY",
            "response_headers" to "RESPH",
            "response_body" to "RESPBODY",
        )
        expectedContent.forEach { (part, expected) ->
            val uri = if (part == "metadata") {
                "burp://http/integration-project/proxy/42"
            } else {
                "burp://http/integration-project/proxy/42/$part"
            }
            val result = client.readResource(uri).singleTextResourceJson()
            assertEquals("ok", result["status"]?.jsonPrimitive?.content)
            assertEquals(part, result["part"]?.jsonPrimitive?.content)
            if (expected == null) {
                assertFalse(result.containsKey("content"))
            } else {
                assertEquals(expected, result["content"]?.jsonObject?.get("data")?.jsonPrimitive?.content)
            }
        }
    }

    @Test
    fun `WebSocket resources distinguish original and edited payloads`() = runBlocking {
        every { persistedObject.getBoolean("_alwaysAllowWebSocketHistory") } returns true
        val proxy = api.proxy()
        val item = mockk<ProxyWebSocketMessage>()
        val annotations = mockk<Annotations>()
        every { proxy.webSocketHistory(any()) } answers {
            val filter = firstArg<burp.api.montoya.proxy.ProxyWebSocketHistoryFilter>()
            listOf(item).filter(filter::matches)
        }
        every { item.id() } returns 17
        every { item.webSocketId() } returns 9
        every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z")
        every { item.direction() } returns Direction.SERVER_TO_CLIENT
        every { item.listenerPort() } returns 8080
        every { item.annotations() } returns annotations
        every { annotations.notes() } returns null
        every { item.payload() } returns montoyaBytes("original")
        every { item.editedPayload() } returns montoyaBytes("edited")

        client.connectToServer("http://127.0.0.1:${testPort}/mcp")
        mapOf("original" to "original", "edited" to "edited").forEach { (variant, expected) ->
            val result = client.readResource(
                "burp://websocket/integration-project/17/$variant"
            ).singleTextResourceJson()
            assertEquals("ok", result["status"]?.jsonPrimitive?.content)
            assertEquals(
                variant,
                result["metadata"]?.jsonObject?.get("payloadVariant")?.jsonPrimitive?.content,
            )
            assertEquals(expected, result["content"]?.jsonObject?.get("data")?.jsonPrimitive?.content)
        }
    }

    @Test
    fun `HTTP resources apply source approval on every read`() = runBlocking {
        val previousHandler = DataAccessSecurity.approvalHandler
        val prompts = AtomicInteger()
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                assertEquals(DataAccessType.HTTP_HISTORY, accessType)
                prompts.incrementAndGet()
                return true
            }
        }
        try {
            client.connectToServer("http://127.0.0.1:${testPort}/mcp")
            repeat(2) {
                val result = client.readResource("burp://http/integration-project/proxy/7").singleTextResourceJson()
                assertEquals("not_found", result["status"]?.jsonPrimitive?.content)
            }
            assertEquals(2, prompts.get())
            val resourceAudits = auditRecords.filter { it.tool == "resource:http_message" }
            assertEquals(2, resourceAudits.size)
            assertTrue(resourceAudits.all { it.readOnly })
            assertTrue(resourceAudits.all { it.argumentKeys == listOf("id", "projectId", "source") })
            assertTrue(resourceAudits.all { record -> record.approvals.any { it.kind == "data_access:http_history" } })
            assertTrue(resourceAudits.none { it.toString().contains("integration-project") })
        } finally {
            DataAccessSecurity.approvalHandler = previousHandler
        }
    }

    @Test
    fun `HTTP resources reject noncanonical and cross-project references before source approval`() = runBlocking {
        val previousHandler = DataAccessSecurity.approvalHandler
        val prompts = AtomicInteger()
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                prompts.incrementAndGet()
                return true
            }
        }
        try {
            client.connectToServer("http://127.0.0.1:${testPort}/mcp")
            val noncanonical = client.readResource(
                "burp://http/integration-project/proxy/%37"
            ).singleTextResourceJson()
            assertEquals("invalid_argument", noncanonical["status"]?.jsonPrimitive?.content)

            val wrongProject = client.readResource(
                "burp://http/other-project/proxy/7"
            ).singleTextResourceJson()
            assertEquals("project_mismatch", wrongProject["status"]?.jsonPrimitive?.content)
            val oversizedId = client.readResource(
                "burp://http/integration-project/proxy/${"1".repeat(129)}"
            ).singleTextResourceJson()
            assertEquals("invalid_id", oversizedId["status"]?.jsonPrimitive?.content)
            assertEquals(0, prompts.get())
        } finally {
            DataAccessSecurity.approvalHandler = previousHandler
        }
    }

    @Test
    fun `HTTP resource session approval is reused only through the active MCP session`() = runBlocking {
        val previousHandler = DataAccessSecurity.approvalHandler
        val prompts = AtomicInteger()
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                assertEquals(DataAccessType.HTTP_HISTORY, accessType)
                prompts.incrementAndGet()
                assertTrue(grantCurrentSessionApproval(McpSessionApproval.HTTP_HISTORY))
                return true
            }
        }
        try {
            client.connectToServer("http://127.0.0.1:${testPort}/mcp")
            repeat(2) {
                val result = client.readResource("burp://http/integration-project/proxy/7").singleTextResourceJson()
                assertEquals("not_found", result["status"]?.jsonPrimitive?.content)
            }
            assertEquals(1, prompts.get())
            assertEquals(1, serverManager.clearSessionApprovals())
            val afterReset = client.readResource(
                "burp://http/integration-project/proxy/7"
            ).singleTextResourceJson()
            assertEquals("not_found", afterReset["status"]?.jsonPrimitive?.content)
            assertEquals(2, prompts.get())
            assertEquals(1, serverManager.diagnostics().sessionsWithApprovals)
            assertEquals(1, serverManager.diagnostics().sessionApprovalGrants)
        } finally {
            DataAccessSecurity.approvalHandler = previousHandler
        }
    }

    @Test
    fun `HTTP resource session approval remains isolated by project data source`() = runBlocking {
        val previousHandler = DataAccessSecurity.approvalHandler
        val promptedTypes = CopyOnWriteArrayList<DataAccessType>()
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                promptedTypes += accessType
                if (accessType == DataAccessType.HTTP_HISTORY) {
                    assertTrue(grantCurrentSessionApproval(McpSessionApproval.HTTP_HISTORY))
                }
                return true
            }
        }
        try {
            client.connectToServer("http://127.0.0.1:${testPort}/mcp")
            repeat(2) {
                client.readResource("burp://http/integration-project/proxy/7")
            }
            client.readResource(
                "burp://http/integration-project/site_map/sitemap_0_00000000000000000000000000000000"
            )
            client.readResource("burp://http/integration-project/organizer/7")
            assertEquals(
                listOf(DataAccessType.HTTP_HISTORY, DataAccessType.SITE_MAP, DataAccessType.ORGANIZER),
                promptedTypes,
            )
        } finally {
            DataAccessSecurity.approvalHandler = previousHandler
        }
    }

    @Test
    fun `resource subscription stays unavailable when a client ignores the advertised capability`() {
        val httpClient = java.net.http.HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2))
            .build()
        val endpoint = java.net.URI("http://127.0.0.1:${testPort}/mcp")
        fun post(sessionId: String?, body: String): java.net.http.HttpResponse<String> {
            val builder = java.net.http.HttpRequest.newBuilder(endpoint)
                .timeout(Duration.ofSeconds(5))
                .header("Authorization", "Bearer $testBearerToken")
                .header("Mcp-Protocol-Version", "2025-11-25")
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
            if (sessionId != null) builder.header("Mcp-Session-Id", sessionId)
            return httpClient.send(
                builder.POST(java.net.http.HttpRequest.BodyPublishers.ofString(body)).build(),
                java.net.http.HttpResponse.BodyHandlers.ofString(),
            )
        }

        val initialize = post(
            null,
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"subscription-negative-test","version":"1.0"}}}""",
        )
        assertEquals(200, initialize.statusCode(), initialize.body())
        val sessionId = initialize.headers().firstValue("Mcp-Session-Id").orElseThrow()
        assertTrue(
            post(sessionId, """{"jsonrpc":"2.0","method":"notifications/initialized"}""").statusCode() in
                setOf(200, 202)
        )

        val subscribe = post(
            sessionId,
            """{"jsonrpc":"2.0","id":2,"method":"resources/subscribe","params":{"uri":"burp://unregistered/value"}}""",
        )
        assertEquals(200, subscribe.statusCode(), subscribe.body())
        assertEquals(
            -32601,
            Json.parseToJsonElement(subscribe.body()).jsonObject["error"]?.jsonObject
                ?.get("code")?.jsonPrimitive?.content?.toInt(),
        )

        val deleted = java.net.http.HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(5))
            .header("Authorization", "Bearer $testBearerToken")
            .header("Mcp-Protocol-Version", "2025-11-25")
            .header("Mcp-Session-Id", sessionId)
            .header("Accept", "application/json, text/event-stream")
            .DELETE()
            .build()
            .let { httpClient.send(it, java.net.http.HttpResponse.BodyHandlers.ofString()) }
        assertTrue(deleted.statusCode() in setOf(200, 202), deleted.body())
    }

    @Test
    fun `native resources and prompts are advertised without changing the tool catalog`() = runBlocking {
        client.connectToServer("http://127.0.0.1:${testPort}/mcp")

        val toolsBefore = client.listTools().map { it.name }
        val capabilities = requireNotNull(client.serverCapabilities())
        assertEquals(false, capabilities.tools?.listChanged)
        assertNotNull(capabilities.resources)
        assertEquals(false, capabilities.resources?.listChanged)
        assertEquals(false, capabilities.resources?.subscribe)
        assertNotNull(capabilities.prompts)
        assertEquals(false, capabilities.prompts?.listChanged)

        val resources = client.listResources()
        assertEquals(
            setOf(DIAGNOSTICS_RESOURCE_URI, PROJECT_SUMMARY_RESOURCE_URI, SCOPE_SUMMARY_RESOURCE_URI),
            resources.map { it.uri }.toSet(),
        )
        assertTrue(resources.all { it.mimeType == "application/json" })

        val templates = client.listResourceTemplates().resourceTemplates.associateBy { it.uriTemplate }
        assertEquals(4, templates.size)
        assertTrue(HTTP_RESOURCE_TEMPLATE in templates)
        assertTrue(HTTP_PART_RESOURCE_TEMPLATE in templates)
        assertTrue(WEBSOCKET_RESOURCE_TEMPLATE in templates)
        assertTrue(WEBSOCKET_VARIANT_RESOURCE_TEMPLATE in templates)

        val prompts = client.listPrompts().associateBy { it.name }
        assertEquals(3, prompts.size)
        assertTrue("analyze_http_without_sending" in prompts)
        assertTrue("compare_http_references" in prompts)
        assertTrue("review_auth_session_handling" in prompts)

        val diagnostics = client.readResource(DIAGNOSTICS_RESOURCE_URI).singleTextResourceJson()
        assertEquals("ok", diagnostics["status"]?.jsonPrimitive?.content)
        assertEquals(
            PRODUCTION_MCP_PROTOCOL_VERSION,
            diagnostics["diagnostics"]?.jsonObject?.get("protocolVersion")?.jsonPrimitive?.content,
        )
        assertFalse(diagnostics.toString().contains(testBearerToken))

        val project = client.readResource(PROJECT_SUMMARY_RESOURCE_URI).singleTextResourceJson()
        assertEquals("ok", project["status"]?.jsonPrimitive?.content)
        assertEquals("integration-project", project["projectId"]?.jsonPrimitive?.content)
        assertEquals("false", project["projectNameIncluded"]?.jsonPrimitive?.content)
        assertEquals(
            listOf("http", "websocket"),
            project["referenceKinds"]?.jsonArray?.map { it.jsonPrimitive.content },
        )
        val projectAudit = auditRecords.single { it.tool == "resource:project_summary" }
        assertTrue(projectAudit.readOnly)
        assertTrue(projectAudit.argumentKeys.isEmpty())
        assertFalse(projectAudit.toString().contains("integration-project"))

        val scope = client.readResource(SCOPE_SUMMARY_RESOURCE_URI).singleTextResourceJson()
        assertEquals("ok", scope["status"]?.jsonPrimitive?.content)
        assertEquals("false", scope["scopeRuleEnumerationAvailable"]?.jsonPrimitive?.content)
        assertEquals("check_scope", scope["membershipCheckTool"]?.jsonPrimitive?.content)

        val prompt = client.getPrompt(
            "analyze_http_without_sending",
            mapOf("httpReference" to "burp://http/integration-project/proxy/7"),
        )
        val promptText = assertIs<TextContent>(prompt.messages.single().content).text
        assertTrue(promptText.contains("Do not send traffic"))
        assertTrue(promptText.contains("burp://http/integration-project/proxy/7"))
        verify(exactly = 0) { api.proxy().history(any()) }

        val oversizedPrompt = runCatching {
            client.getPrompt(
                "analyze_http_without_sending",
                mapOf("httpReference" to "burp://http/${"a".repeat(2_049)}"),
            )
        }.exceptionOrNull()
        assertNotNull(oversizedPrompt)
        assertFalse(oversizedPrompt?.message.orEmpty().contains("a".repeat(64)))
        val noncanonicalPrompt = runCatching {
            client.getPrompt(
                "analyze_http_without_sending",
                mapOf("httpReference" to "burp://http/%69ntegration-project/proxy/7"),
            )
        }.exceptionOrNull()
        assertNotNull(noncanonicalPrompt)

        assertEquals(19, toolsBefore.size)
        assertEquals(toolsBefore, client.listTools().map { it.name })
    }

    private fun montoyaBytes(text: String): MontoyaByteArray {
        val raw = text.toByteArray(Charsets.UTF_8)
        return mockk<MontoyaByteArray>().also { value ->
            every { value.length() } returns raw.size
            every { value.getBytes() } returns raw
            every { value.toString() } returns text
            every { value.subArray(any(), any()) } answers {
                val start = firstArg<Int>()
                val end = secondArg<Int>()
                montoyaBytes(raw.copyOfRange(start, end).toString(Charsets.UTF_8))
            }
        }
    }

    @Test
    fun `streamable HTTP endpoint should accept connections and list tools`() = runBlocking {
        try {
            client.connectToServer("http://127.0.0.1:${testPort}/mcp")
            assertTrue(client.isConnected(), "Client should be connected to server")
            
            val tools = client.listTools()
            assertFalse(tools.isEmpty(), "Server should have registered tools")
            
            val toolNames = tools.map { it.name }
            assertTrue(toolNames.contains("get_burp_options"), "Server should have get_burp_options tool")
            assertTrue(toolNames.contains("set_burp_options"), "Server should have set_burp_options tool")
            
            val pingResult = client.ping()
            assertNotNull(pingResult, "Ping should return a result")
        } catch (e: Exception) {
            fail("Connection failed: ${e.message}")
        }
    }
}