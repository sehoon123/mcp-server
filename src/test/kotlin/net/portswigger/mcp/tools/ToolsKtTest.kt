package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine
import burp.api.montoya.collaborator.*
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpProtocol
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.logging.Logging
import burp.api.montoya.organizer.Organizer
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.sitemap.SiteMap
import burp.api.montoya.utilities.Base64Utils
import burp.api.montoya.utilities.RandomUtils
import burp.api.montoya.utilities.URLUtils
import burp.api.montoya.utilities.Utilities
import burp.api.montoya.websocket.Direction
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.mockk.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonPrimitive
import net.portswigger.mcp.KtorServerManager
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.TestStreamableHttpMcpClient
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.RequestActionApprovalHandler
import net.portswigger.mcp.security.RequestActionSecurity
import net.portswigger.mcp.security.SensitiveActionApprovalHandler
import net.portswigger.mcp.security.SensitiveActionSecurity
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.time.ZonedDateTime
import java.util.Optional
import javax.swing.JTextArea

class ToolsKtTest {
    private val testBearerToken = "0123456789012345678901234567890123456789012"
    private val client = TestStreamableHttpMcpClient(
        mapOf("Authorization" to "Bearer $testBearerToken")
    )
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val serverManager = KtorServerManager(api)
    private val testPort = findAvailablePort()
    private var serverStarted = false
    private val config: McpConfig
    private val mockHeaders = mutableListOf<HttpHeader>()
    private val capturedRequest = slot<HttpRequest>()
    private lateinit var originalRequestActionHandler: RequestActionApprovalHandler
    private lateinit var originalSensitiveActionHandler: SensitiveActionApprovalHandler

    init {
        val persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean("enabled") } returns true
            every { getBoolean("emergencyReadOnlyMode") } returns false
            every { getBoolean("configEditingTooling") } returns true
            every { getBoolean("requireHttpRequestApproval") } returns false
            every { getBoolean("requireRequestActionApproval") } returns false
            every { getBoolean("requireDataAccessApproval") } returns false
            every { getBoolean("_alwaysAllowHttpHistory") } returns false
            every { getBoolean("_alwaysAllowSiteMap") } returns false
            every { getBoolean("_alwaysAllowWebSocketHistory") } returns false
            every { getBoolean("_alwaysAllowOrganizer") } returns false
            every { getBoolean("_alwaysAllowScannerIssues") } returns false
            every { getBoolean("_alwaysAllowCollaboratorInteractions") } returns false
            every { getString("host") } returns "127.0.0.1"
            every { getString("localBearerToken") } returns testBearerToken
            every { getString("_autoApproveTargets") } returns ""
            every { getInteger("port") } returns testPort
            every { setBoolean(any(), any()) } returns Unit
            every { setString(any(), any()) } returns Unit
            every { setInteger(any(), any()) } returns Unit
        }
        val mockLogging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
            every { logToOutput(any<String>()) } returns Unit
        }

        config = McpConfig(persistedObject, mockLogging)
        
        mockkStatic(HttpHeader::class)
        mockkStatic(burp.api.montoya.http.HttpService::class)
        mockkStatic(HttpRequest::class)
    }

    private fun CallToolResult?.expectTextContent(
        expected: String? = null,
    ): String {
        assertNotNull(this, "Tool result cannot be null")
        val result = this!!

        val content = result.content
        assertNotNull(content, "Tool result content cannot be null")

        val nonNullContent = content
        assertEquals(1, nonNullContent.size, "Expected exactly one content element")

        val textContent = nonNullContent.firstOrNull() as? TextContent
        assertNotNull(textContent, "Expected content to be TextContent")

        val text = textContent!!.text
        assertNotNull(text, "Text content cannot be null")

        if (expected != null) {
            assertEquals(expected, text, "Text content doesn't match expected value")
        }

        return text!!
    }

    private fun montoyaBytes(raw: ByteArray): MontoyaByteArray = mockk<MontoyaByteArray>().also { bytes ->
        every { bytes.length() } returns raw.size
        every { bytes.toString() } returns raw.toString(Charsets.ISO_8859_1)
        every { bytes.getBytes() } returns raw
        every { bytes.subArray(any(), any()) } answers {
            montoyaBytes(raw.copyOfRange(firstArg(), secondArg()))
        }
    }

    private fun boundedHttpResponse(text: String): HttpResponse = mockk<HttpResponse>().also { response ->
        every { response.toByteArray() } returns montoyaBytes(text.toByteArray(Charsets.ISO_8859_1))
    }

    private fun stubProxyHistorySummary(item: ProxyHttpRequestResponse, index: Int) {
        val request = mockk<HttpRequest>()
        val body = montoyaBytes(byteArrayOf())
        val service = mockk<burp.api.montoya.http.HttpService>()
        val annotations = mockk<Annotations>()
        every { item.id() } returns index
        every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z")
        every { item.request() } returns request
        every { item.response() } returns null
        every { item.httpService() } returns service
        every { item.listenerPort() } returns 8080
        every { item.edited() } returns false
        every { item.annotations() } returns annotations
        every { request.method() } returns "GET"
        every { request.url() } returns "https://example.test/item$index"
        every { request.body() } returns body
        every { service.host() } returns "example.test"
        every { service.port() } returns 443
        every { service.secure() } returns true
        every { annotations.notes() } returns null
    }

    private fun setupHttpHeaderMocks() {
        every { HttpHeader.httpHeader(any<String>(), any<String>()) } answers {
            val name = firstArg<String>()
            val value = secondArg<String>()
            mockk<HttpHeader>().also {
                every { it.name() } returns name
                every { it.value() } returns value
                mockHeaders.add(it)
            }
        }

        every { burp.api.montoya.http.HttpService.httpService(any(), any(), any()) } answers {
            val host = firstArg<String>()
            val port = secondArg<Int>()
            val secure = thirdArg<Boolean>()
            mockk<burp.api.montoya.http.HttpService>().also {
                every { it.host() } returns host
                every { it.port() } returns port
                every { it.secure() } returns secure
            }
        }
    }
    
    @BeforeEach
    fun setup() {
        originalRequestActionHandler = RequestActionSecurity.approvalHandler
        originalSensitiveActionHandler = SensitiveActionSecurity.approvalHandler
        RequestActionSecurity.approvalHandler = object : RequestActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                source: String,
                target: String,
                changes: String,
                requestContent: String,
                config: McpConfig,
                api: MontoyaApi,
            ) = true
        }
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ) = true
        }
        setupHttpHeaderMocks()

        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")

            client.connectToServer("http://127.0.0.1:${testPort}/mcp")
            assertNotNull(client.ping(), "Ping should return a result")
        }
    }

    private fun findAvailablePort() = ServerSocket(0).use { it.localPort }

    @AfterEach
    fun tearDown() {
        RequestActionSecurity.approvalHandler = originalRequestActionHandler
        SensitiveActionSecurity.approvalHandler = originalSensitiveActionHandler
        runBlocking { if (client.isConnected()) client.close() }
        serverManager.shutdown()
    }

    @Nested
    inner class HttpToolsTests {
        @Test
        fun `http1 line endings should be normalized`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val siteMap = mockk<SiteMap>(relaxed = true)
            val contentSlot = slot<String>()

            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                val content = secondArg<String>()
                mockk<HttpRequest>().also {
                    every { it.toString() } returns content
                }
            }
            every { api.http() } returns httpService
            every { api.siteMap() } returns siteMap
            every { httpResponse.response() } returns boundedHttpResponse(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nResponse body"
            )
            every { httpService.sendRequest(capture(capturedRequest)) } returns httpResponse

            runBlocking {
                val result = client.callTool(
                    "send_http1_request", mapOf(
                        "content" to "GET /foo HTTP/1.1\nHost: example.com\n\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertFalse(text.contains("Error"), 
                    "Expected success response but got error: $text")
            }

            verify(exactly = 1) { httpService.sendRequest(any<HttpRequest>()) }
            verify(exactly = 1) { siteMap.add(httpResponse) }
            assertEquals("GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n", capturedRequest.captured.toString(), "Request body should match")
        }

        @Test
        fun `http1 request should handle no response`() {
            val httpService = mockk<Http>()
            val contentSlot = slot<String>()

            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                val content = secondArg<String>()
                mockk<HttpRequest>().also {
                    every { it.toString() } returns content
                }
            }
            every { api.http() } returns httpService
            every { httpService.sendRequest(any()) } returns null

            runBlocking {
                val result = client.callTool(
                    "send_http1_request", mapOf(
                        "content" to "GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    )
                )

                delay(100)
                result.expectTextContent("<no response>")
            }
        }

        @Test
        fun `Site Map recording failure does not make a completed HTTP request retryable`() {
            val http = mockk<Http>()
            val response = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val siteMap = mockk<SiteMap>()
            val apiLogging = mockk<Logging>(relaxed = true)

            every { HttpRequest.httpRequest(any(), any<String>()) } returns mockk()
            every { api.http() } returns http
            every { api.siteMap() } returns siteMap
            every { api.logging() } returns apiLogging
            every { http.sendRequest(any()) } returns response
            every { response.response() } returns boundedHttpResponse("HTTP/1.1 204 No Content")
            every { siteMap.add(response) } throws IllegalStateException("local Site Map failure")

            runBlocking {
                val result = client.callTool(
                    "send_http1_request",
                    mapOf(
                        "content" to "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true,
                    ),
                )

                result.expectTextContent("HTTP/1.1 204 No Content")
            }

            verify(exactly = 1) { http.sendRequest(any()) }
            verify(exactly = 1) { siteMap.add(response) }
            verify(exactly = 1) {
                apiLogging.logToError(match<String> { "could not be added to Site Map" in it })
            }
        }

        @Test
        fun `http2 request should be formatted properly`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequest = mockk<HttpRequest>()
            val requestSlot = slot<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()
            val bodySlot = slot<String>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), capture(bodySlot)) } returns httpRequest
            every { httpResponse.response() } returns boundedHttpResponse(
                "HTTP/2 200 OK\r\nContent-Type: text/plain\r\n\r\nResponse body"
            )
            every { api.http() } returns httpService
            every { httpService.sendRequest(capture(requestSlot), HttpMode.HTTP_2) } returns httpResponse

            val pseudoHeaders = mapOf(
                "authority" to "example.com", "scheme" to "https", "method" to "GET", ":path" to "/test"
            )
            val headers = mapOf(
                "User-Agent" to "Test Agent", "Accept" to "*/*"
            )
            val requestBody = "Test body"

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to requestBody,
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertFalse(text.contains("Error"), 
                    "Expected success response but got error: $text")
            }

            verify(exactly = 1) { HttpRequest.http2Request(any(), any(), any<String>()) }
            
            assertEquals("Test body", bodySlot.captured, "Request body should match")
            
            val pseudoHeaderList = headersSlot.captured.filter { it.name().startsWith(":") }
            val normalHeaderList = headersSlot.captured.filter { !it.name().startsWith(":") }
            
            assertTrue(pseudoHeaderList.any { it.name() == ":scheme" && it.value() == "https" })
            assertTrue(pseudoHeaderList.any { it.name() == ":method" && it.value() == "GET" })
            assertTrue(pseudoHeaderList.any { it.name() == ":path" && it.value() == "/test" })
            assertTrue(pseudoHeaderList.any { it.name() == ":authority" && it.value() == "example.com" })
            
            assertTrue(normalHeaderList.any { it.name() == "user-agent" && it.value() == "Test Agent" })
            assertTrue(normalHeaderList.any { it.name() == "accept" && it.value() == "*/*" })
        }
        
        @Test
        fun `http2 request should handle null response`() {
            val httpService = mockk<Http>()
            val httpRequest = mockk<HttpRequest>()

            every { HttpRequest.http2Request(any(), any(), any<String>()) } returns httpRequest
            every { api.http() } returns httpService
            every { httpService.sendRequest(any(), HttpMode.HTTP_2) } returns null

            val pseudoHeaders = mapOf("method" to "GET", "path" to "/test")
            val headers = mapOf("User-Agent" to "Test Agent")

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to "",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                result.expectTextContent("<no response>")
            }
        }
        
        @Test
        fun `http2 pseudo headers should be ordered correctly`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequest = mockk<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), any<String>()) } returns httpRequest
            every { httpResponse.toString() } returns "HTTP/2 200 OK"
            every { api.http() } returns httpService
            every { httpService.sendRequest(any(), HttpMode.HTTP_2) } returns httpResponse

            val pseudoHeaders = mapOf(
                "path" to "/test",
                ":authority" to "example.com", 
                "method" to "GET",
                "scheme" to "https"
            )

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(emptyMap<String, String>()),
                        "requestBody" to "",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )
                
                delay(100)
                assertNotNull(result)
            }
            
            val pseudoHeaderNames = headersSlot.captured
                .filter { it.name().startsWith(":") }
                .map { it.name() }
            
            val expectedOrder = listOf(":scheme", ":method", ":path", ":authority")
            for (i in 0 until minOf(expectedOrder.size, pseudoHeaderNames.size)) {
                assertEquals(expectedOrder[i], pseudoHeaderNames[i],
                    "Pseudo headers should follow the order: scheme, method, path, authority")
            }
        }

        @Test
        fun `raw routing tools use no-name Montoya overload when tab name is absent`() {
            val repeater = mockk<burp.api.montoya.repeater.Repeater>(relaxed = true)
            val intruder = mockk<burp.api.montoya.intruder.Intruder>(relaxed = true)
            val request = mockk<HttpRequest>()
            every { HttpRequest.httpRequest(any(), any<String>()) } returns request
            every { api.repeater() } returns repeater
            every { api.intruder() } returns intruder
            val arguments: Map<String, Any> = mapOf(
                "content" to "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
                "targetHostname" to "example.test",
                "targetPort" to 443,
                "usesHttps" to true,
            )

            runBlocking {
                assertNotNull(client.callTool("create_repeater_tab", arguments))
                assertNotNull(client.callTool("send_to_intruder", arguments))
            }

            verify(exactly = 1) { repeater.sendToRepeater(request) }
            verify(exactly = 1) { intruder.sendToIntruder(request) }
        }

        @Test
        fun `create repeater tab http2 should build http2 request`() {
            val repeater = mockk<burp.api.montoya.repeater.Repeater>(relaxed = true)
            val httpRequest = mockk<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()
            val bodySlot = slot<String>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), capture(bodySlot)) } returns httpRequest
            every { api.repeater() } returns repeater

            val pseudoHeaders = mapOf(
                "method" to "POST", "path" to "/api/x", "authority" to "example.com", "scheme" to "https"
            )
            val headers = mapOf("Content-Type" to "application/json")
            val requestBody = "{\"k\":\"v\"}"

            runBlocking {
                val result = client.callTool(
                    "create_repeater_tab_http2", mapOf(
                        "tabName" to "h2-tab",
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to requestBody,
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                assertNotNull(result)
            }

            verify(exactly = 1) { repeater.sendToRepeater(httpRequest, "h2-tab") }
            assertEquals("{\"k\":\"v\"}", bodySlot.captured, "Request body should be passed through unchanged")

            val pseudoHeaderNames = headersSlot.captured.filter { it.name().startsWith(":") }.map { it.name() }
            assertEquals(listOf(":scheme", ":method", ":path", ":authority"), pseudoHeaderNames)
            assertTrue(headersSlot.captured.any { it.name() == "content-type" && it.value() == "application/json" })
        }
    }

    @Nested
    inner class UtilityToolsTests {
        @Test
        fun `url encode should work properly`() {
            val urlUtils = mockk<URLUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.urlUtils() } returns urlUtils
            every { urlUtils.encode(any<String>()) } returns "test+string+with+spaces"
            
            runBlocking {
                val result = client.callTool(
                    "url_encode", mapOf(
                        "content" to "test string with spaces"
                    )
                )
                
                delay(100)
                result.expectTextContent("test+string+with+spaces")
            }
            
            verify(exactly = 1) { urlUtils.encode(any<String>()) }
        }
        
        @Test
        fun `url decode should work properly`() {
            val urlUtils = mockk<URLUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.urlUtils() } returns urlUtils
            every { urlUtils.decode(any<String>()) } returns "test string with spaces"
            
            runBlocking {
                val result = client.callTool(
                    "url_decode", mapOf(
                        "content" to "test+string+with+spaces"
                    )
                )
                
                delay(100)
                result.expectTextContent("test string with spaces")
            }
            
            verify(exactly = 1) { urlUtils.decode(any<String>()) }
        }
        
        @Test
        fun `base64 encode should work properly`() {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            every { base64Utils.encodeToString(any<String>()) } returns "dGVzdCBzdHJpbmc="
            
            runBlocking {
                val result = client.callTool(
                    "base64_encode", mapOf(
                        "content" to "test string"
                    )
                )
                
                delay(100)
                result.expectTextContent("dGVzdCBzdHJpbmc=")
            }
            
            verify(exactly = 1) { base64Utils.encodeToString(any<String>()) }
        }
        
        @Test
        fun `base64 decode should work properly`() {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            val burpByteArray = mockk<MontoyaByteArray>()
            
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            every { base64Utils.decode(any<String>()) } returns burpByteArray
            every { burpByteArray.length() } returns 11
            every { burpByteArray.toString() } returns "test string"
            
            runBlocking {
                val result = client.callTool(
                    "base64_decode", mapOf(
                        "content" to "dGVzdCBzdHJpbmc="
                    )
                )
                
                delay(100)
                result.expectTextContent("test string")
            }
            
            verify(exactly = 1) { base64Utils.decode(any<String>()) }
        }
        
        @Test
        fun `generate random string should work properly`() {
            val randomUtils = mockk<RandomUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.randomUtils() } returns randomUtils
            every { randomUtils.randomString(any<Int>(), any<String>()) } returns "1a2b3c1a2b"
            
            runBlocking {
                val result = client.callTool(
                    "generate_random_string", mapOf(
                        "length" to 10,
                        "characterSet" to "abc123"
                    )
                )
                
                delay(100)
                result.expectTextContent("1a2b3c1a2b")
            }
            
            verify(exactly = 1) { randomUtils.randomString(any<Int>(), any<String>()) }
        }
    }
    
    @Nested
    inner class ConfigurationToolsTests {
        @Test
        fun `set task execution engine state should work properly`() {
            val taskExecutionEngine = mockk<TaskExecutionEngine>()
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.taskExecutionEngine() } returns taskExecutionEngine
            every { taskExecutionEngine.state = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_task_execution_engine_state", mapOf(
                        "running" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now running")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.RUNNING }
            
            clearMocks(taskExecutionEngine, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_task_execution_engine_state", mapOf(
                        "running" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now paused")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.PAUSED }
        }
        
        @Test
        fun `set proxy intercept state should work properly`() {
            val proxy = mockk<Proxy>()
            
            every { api.proxy() } returns proxy
            every { proxy.enableIntercept() } just runs
            every { proxy.disableIntercept() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_proxy_intercept_state", mapOf(
                        "intercepting" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been enabled")
            }
            
            verify(exactly = 1) { proxy.enableIntercept() }
            
            clearMocks(proxy, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_proxy_intercept_state", mapOf(
                        "intercepting" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been disabled")
            }
            
            verify(exactly = 1) { proxy.disableIntercept() }
        }
        
        @Test
        fun `config editing tools should respect config settings without logging their contents`() {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            val apiLogging = mockk<Logging>(relaxed = true)
            val sensitiveJson = "{\"api_key\":\"secret-value\"}"

            every { api.burpSuite() } returns burpSuite
            every { api.logging() } returns apiLogging
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { burpSuite.importUserOptionsFromJson(any()) } just runs

            runBlocking {
                val projectResult = client.callTool(
                    "set_project_options", mapOf("json" to sensitiveJson)
                )
                val userResult = client.callTool(
                    "set_user_options", mapOf("json" to sensitiveJson)
                )

                delay(100)
                projectResult.expectTextContent("Project configuration has been applied")
                userResult.expectTextContent("User configuration has been applied")

                val tools = client.listTools()
                val projectDescription = tools.single { it.name == "set_project_options" }.description.orEmpty()
                val userDescription = tools.single { it.name == "set_user_options" }.description.orEmpty()
                assertTrue(projectDescription.contains("top-level 'project_options'"))
                assertFalse(projectDescription.contains("top-level 'user_options'"))
                assertTrue(userDescription.contains("top-level 'user_options'"))
                assertFalse(userDescription.contains("top-level 'project_options'"))
            }

            verify(exactly = 1) { burpSuite.importProjectOptionsFromJson(sensitiveJson) }
            verify(exactly = 1) { burpSuite.importUserOptionsFromJson(sensitiveJson) }
            verify(exactly = 0) { apiLogging.logToOutput(match { "secret-value" in it }) }

            clearMocks(burpSuite, answers = false)

            every { config.configEditingTooling } returns false

            runBlocking {
                val result = client.callTool(
                    "set_project_options", mapOf("json" to sensitiveJson)
                )

                delay(100)
                result.expectTextContent("User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'")
            }

            verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
        }
    }

    @Nested
    inner class EditorTests {
        @Test
        fun `get active editor contents should handle no editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            every { getActiveEditor(api) } returns null
            
            runBlocking {
                val result = client.callTool("get_active_editor_contents", emptyMap())
                
                delay(100)
                result.expectTextContent("<No active editor>")
            }
        }
        
        @Test
        fun `get active editor contents should return text`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.text } returns "Editor content"
            
            runBlocking {
                val result = client.callTool("get_active_editor_contents", emptyMap())
                
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"text\":\"Editor content\""))
                assertTrue(text.contains("\"truncated\":false"))
            }
        }
        
        @Test
        fun `set active editor contents should handle no editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            every { getActiveEditor(api) } returns null
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("<No active editor>")
            }
        }
        
        @Test
        fun `set active editor contents should handle non-editable editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.isEditable } returns false
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("<Current editor is not editable>")
            }
        }
        
        @Test
        fun `set active editor contents should update text`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.isEditable } returns true
            every { textArea.text = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("Editor text has been set")
            }
            
            verify(exactly = 1) { textArea.text = "New content" }
        }
    }
    
    @Nested
    inner class PaginatedToolsTests {
        @Test
        fun `deep pagination serializes only the selected history items`() {
            val proxy = mockk<Proxy>()
            val proxyHistory = List(100) { mockk<ProxyHttpRequestResponse>() }

            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory

            proxyHistory.forEachIndexed { index, item -> stubProxyHistorySummary(item, index) }

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history", mapOf("count" to 1, "offset" to 99)
                )
                assertTrue(result.expectTextContent().contains("/item99"))
            }

            proxyHistory.dropLast(1).forEach { skipped ->
                verify(exactly = 0) { skipped.id() }
            }
            verify(exactly = 1) { proxyHistory.last().id() }
        }

        @Test
        fun `summary mode exposes stable HTTP IDs without serializing full messages`() {
            val proxy = mockk<Proxy>()
            val item = mockk<ProxyHttpRequestResponse>()
            val request = mockk<HttpRequest>()
            val body = mockk<MontoyaByteArray>()
            val service = mockk<burp.api.montoya.http.HttpService>()
            val annotations = mockk<Annotations>()

            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(item)
            every { item.id() } returns 41
            every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z")
            every { item.request() } returns request
            every { item.response() } returns null
            every { item.httpService() } returns service
            every { item.listenerPort() } returns 8080
            every { item.edited() } returns false
            every { item.annotations() } returns annotations
            every { request.method() } returns "GET"
            every { request.url() } returns "https://example.test/path"
            every { request.body() } returns body
            every { body.length() } returns 0
            every { service.host() } returns "example.test"
            every { service.port() } returns 443
            every { service.secure() } returns true
            every { annotations.notes() } returns null

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history",
                    mapOf("count" to 1, "offset" to 0, "summariesOnly" to true),
                )
                val text = result.expectTextContent()
                assertTrue(text.contains("\"id\":41"))
                assertTrue(text.contains("\"url\":\"https://example.test/path\""))
                assertFalse(text.contains("\"request\":"))
            }

            verify(exactly = 0) { request.toByteArray() }
        }

        @Test
        fun `get proxy history should paginate properly`() {
            val proxy = mockk<Proxy>()
            val proxyHistory = listOf(
                mockk<ProxyHttpRequestResponse>(),
                mockk<ProxyHttpRequestResponse>(),
                mockk<ProxyHttpRequestResponse>()
            )
            
            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory
            
            proxyHistory.forEachIndexed { index, item -> stubProxyHistorySummary(item, index + 1) }
            
            runBlocking {
                val result1 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 0
                    )
                )
                
                delay(100)
                val text1 = result1.expectTextContent()
                assertTrue(text1.contains("/item1"))
                assertTrue(text1.contains("/item2"))
                assertFalse(text1.contains("/item3"))
                
                val result2 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 2
                    )
                )
                
                delay(100)
                val text2 = result2.expectTextContent()
                assertTrue(text2.contains("/item3"))
                
                val result3 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 3
                    )
                )
                
                delay(100)
                assertEquals("Reached end of items", result3.expectTextContent())
            }
        }
    }

    @Nested
    inner class HttpMessageSearchToolsTests {
        @Test
        fun `unified HTTP search returns structured compact results and precise schemas`() {
            val project = mockk<burp.api.montoya.project.Project>()
            val proxy = mockk<Proxy>()
            val item = mockk<ProxyHttpRequestResponse>()
            val request = mockk<HttpRequest>()
            val body = mockk<MontoyaByteArray>()
            val service = mockk<burp.api.montoya.http.HttpService>()
            val annotations = mockk<Annotations>()

            every { api.project() } returns project
            every { project.id() } returns "project-integration"
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(item)
            every { item.id() } returns 81
            every { item.request() } returns request
            every { item.response() } returns null
            every { item.httpService() } returns service
            every { item.annotations() } returns annotations
            every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z")
            every { item.listenerPort() } returns 8080
            every { item.edited() } returns false
            every { request.method() } returns "GET"
            every { request.url() } returns "https://example.test/search"
            every { request.path() } returns "/search"
            every { request.isInScope() } returns true
            every { request.body() } returns body
            every { body.length() } returns 0
            every { service.host() } returns "example.test"
            every { service.port() } returns 443
            every { service.secure() } returns true
            every { annotations.notes() } returns null

            runBlocking {
                val result = client.callTool(
                    "search_http_messages",
                    mapOf("host" to "example.test", "pathContains" to "/search"),
                )
                assertEquals(false, result?.isError)
                assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("project-integration", result?.structuredContent?.get("projectId")?.jsonPrimitive?.content)
                assertTrue(result?.structuredContent?.get("items").toString().contains("\"id\":\"81\""))

                val attackSurface = client.callTool(
                    "summarize_http_attack_surface",
                    mapOf("projectId" to "project-integration", "pathDepth" to 1),
                )
                assertEquals(false, attackSurface?.isError)
                assertEquals("ok", attackSurface?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals(1, attackSurface?.structuredContent?.get("matchedRecords")?.jsonPrimitive?.content?.toInt())
                assertTrue(attackSurface?.structuredContent?.get("pathPrefixes").toString().contains("/search"))

                val wrongProject = client.callTool(
                    "get_http_message_by_id",
                    mapOf("id" to 81, "projectId" to "another-project"),
                )
                assertEquals(
                    "project_mismatch",
                    wrongProject?.structuredContent?.get("status")?.jsonPrimitive?.content,
                )

                val searchTool = client.listTools().single { it.name == "search_http_messages" }
                assertEquals(emptyList<String>(), searchTool.inputSchema.required)
                val sourceSchema = searchTool.inputSchema.properties?.get("sources").toString()
                assertTrue(sourceSchema.contains("\"proxy\""))
                assertTrue(sourceSchema.contains("\"site_map\""))
                assertTrue(sourceSchema.contains("\"organizer\""))
                assertNotNull(searchTool.outputSchema?.properties?.get("items"))
                assertEquals(true, searchTool.annotations?.readOnlyHint)
                assertEquals(false, searchTool.annotations?.destructiveHint)

                val detailTool = client.listTools().single { it.name == "get_sitemap_message_by_id" }
                assertEquals(setOf("projectId", "id"), detailTool.inputSchema.required?.toSet())
                assertTrue(detailTool.outputSchema?.properties?.get("status").toString().contains("project_mismatch"))
            }
        }
    }

    @Nested
    inner class HttpMessageActionToolsTests {
        @Test
        fun `ID based Repeater action is structured bounded and correctly annotated`() {
            val project = mockk<burp.api.montoya.project.Project>()
            val proxy = mockk<Proxy>()
            val item = mockk<ProxyHttpRequestResponse>()
            val request = mockk<HttpRequest>()
            val raw = mockk<MontoyaByteArray>()
            val service = mockk<burp.api.montoya.http.HttpService>()
            val repeater = mockk<burp.api.montoya.repeater.Repeater>(relaxed = true)

            every { api.project() } returns project
            every { project.id() } returns "project-actions"
            every { api.proxy() } returns proxy
            every { proxy.history(any()) } answers {
                val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
                listOf(item).filter(filter::matches)
            }
            every { item.id() } returns 91
            every { item.request() } returns request
            every { item.response() } returns null
            every { item.httpService() } returns service
            every { request.toByteArray() } returns raw
            every { request.bodyOffset() } returns 48
            every { request.body() } returns raw
            every { raw.length() } returns 0
            every { request.toString() } returns "GET /action HTTP/1.1\r\nHost: example.test\r\n\r\n"
            every { request.httpService() } returns service
            every { request.method() } returns "GET"
            every { request.path() } returns "/action"
            every { request.httpVersion() } returns "HTTP/1.1"
            every { service.host() } returns "example.test"
            every { service.port() } returns 443
            every { service.secure() } returns true
            every { api.repeater() } returns repeater

            runBlocking {
                val result = client.callTool(
                    "create_repeater_tab_from_id",
                    mapOf(
                        "projectId" to "project-actions",
                        "ref" to mapOf("source" to "proxy", "id" to "91"),
                        "tabName" to "derived",
                    ),
                )

                assertEquals(false, result?.isError)
                assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("completed", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
                verify(exactly = 1) { repeater.sendToRepeater(request, "derived") }

                val tools = client.listTools()
                val repeaterTool = tools.single { it.name == "create_repeater_tab_from_id" }
                assertEquals(setOf("projectId", "ref"), repeaterTool.inputSchema.required?.toSet())
                assertEquals(false, repeaterTool.annotations?.readOnlyHint)
                assertEquals(false, repeaterTool.annotations?.destructiveHint)
                assertEquals(false, repeaterTool.annotations?.idempotentHint)
                assertEquals(false, repeaterTool.annotations?.openWorldHint)
                assertTrue(repeaterTool.outputSchema?.properties?.get("status").toString().contains("execution_uncertain"))

                val sendTool = tools.single { it.name == "send_http_request_from_id" }
                assertEquals(true, sendTool.annotations?.destructiveHint)
                assertEquals(true, sendTool.annotations?.openWorldHint)
                val modeSchema = sendTool.inputSchema.properties?.get("httpMode").toString()
                assertTrue(modeSchema.contains("http_2_ignore_alpn"))

                assertNotNull(tools.singleOrNull { it.name == "send_to_intruder_from_id" })
                assertNotNull(tools.singleOrNull { it.name == "send_to_organizer_from_id" })
            }
        }
    }

    @Nested
    inner class StableHistoryAccessTests {
        @Test
        fun `HTTP message lookup returns bounded structured content and read-only metadata`() {
            val proxy = mockk<Proxy>()
            val item = mockk<ProxyHttpRequestResponse>()
            val request = mockk<HttpRequest>()
            val body = mockk<MontoyaByteArray>()
            val selected = mockk<MontoyaByteArray>()
            val service = mockk<burp.api.montoya.http.HttpService>()
            val annotations = mockk<Annotations>()

            every { api.proxy() } returns proxy
            every { proxy.history(any()) } answers {
                val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
                listOf(item).filter(filter::matches)
            }
            every { item.id() } returns 42
            every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z")
            every { item.request() } returns request
            every { item.response() } returns null
            every { item.httpService() } returns service
            every { item.listenerPort() } returns 8080
            every { item.edited() } returns false
            every { item.annotations() } returns annotations
            every { request.method() } returns "POST"
            every { request.url() } returns "https://example.test/upload"
            every { request.body() } returns body
            every { body.length() } returns 10
            every { body.subArray(2, 6) } returns selected
            every { selected.toString() } returns "cdef"
            every { service.host() } returns "example.test"
            every { service.port() } returns 443
            every { service.secure() } returns true
            every { annotations.notes() } returns "reviewed"

            runBlocking {
                val result = client.callTool(
                    "get_http_message_by_id",
                    mapOf(
                        "id" to 42,
                        "part" to "request_body",
                        "offset" to 2,
                        "limit" to 4,
                        "encoding" to "text",
                    ),
                )
                assertEquals(false, result?.isError)
                assertNotNull(result?.structuredContent)
                val structured = result!!.structuredContent!!
                assertEquals("ok", structured["status"]?.jsonPrimitive?.content)
                assertEquals("42", structured["id"]?.jsonPrimitive?.content)
                val content = structured["content"]
                assertNotNull(content)
                assertTrue(content.toString().contains("\"data\":\"cdef\""))
                assertTrue(content.toString().contains("\"nextOffsetBytes\":6"))

                val tool = client.listTools().single { it.name == "get_http_message_by_id" }
                assertEquals(listOf("id"), tool.inputSchema.required)
                val outputProperties = tool.outputSchema?.properties
                assertNotNull(outputProperties)
                assertTrue(outputProperties!!.containsKey("status"))
                assertTrue(outputProperties["status"].toString().contains("\"not_found\""))
                assertTrue(outputProperties.containsKey("content"))
                assertEquals(true, tool.annotations?.readOnlyHint)
                assertEquals(false, tool.annotations?.destructiveHint)
                assertEquals(true, tool.annotations?.idempotentHint)
                assertEquals(false, tool.annotations?.openWorldHint)
            }

            verify(exactly = 1) { proxy.history(any()) }
            verify(exactly = 0) { proxy.history() }
        }

        @Test
        fun `Organizer lookup returns metadata by stable ID`() {
            val organizer = mockk<Organizer>()
            val item = mockk<OrganizerItem>()
            val request = mockk<HttpRequest>()
            val service = mockk<burp.api.montoya.http.HttpService>()
            val annotations = mockk<Annotations>()

            every { api.organizer() } returns organizer
            every { organizer.items(any()) } answers {
                val filter = firstArg<burp.api.montoya.organizer.OrganizerItemFilter>()
                listOf(item).filter(filter::matches)
            }
            every { item.id() } returns 73
            every { item.request() } returns request
            every { item.response() } returns null
            every { item.httpService() } returns service
            every { item.annotations() } returns annotations
            every { request.method() } returns "GET"
            every { request.url() } returns "https://example.test/organized"
            every { service.host() } returns "example.test"
            every { service.port() } returns 443
            every { service.secure() } returns true
            every { annotations.notes() } returns null

            runBlocking {
                val result = client.callTool("get_organizer_item_by_id", mapOf("id" to 73))
                assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertTrue(result?.structuredContent?.get("metadata").toString().contains("\"source\":\"organizer\""))
            }

            verify(exactly = 1) { organizer.items(any()) }
            verify(exactly = 0) { organizer.items() }
        }

        @Test
        fun `WebSocket lookup supports base64 slices and missing IDs`() {
            val proxy = mockk<Proxy>()
            val item = mockk<ProxyWebSocketMessage>()
            val payload = mockk<MontoyaByteArray>()
            val selected = mockk<MontoyaByteArray>()
            val annotations = mockk<Annotations>()

            every { api.proxy() } returns proxy
            every { proxy.webSocketHistory(any()) } answers {
                val filter = firstArg<burp.api.montoya.proxy.ProxyWebSocketHistoryFilter>()
                listOf(item).filter(filter::matches)
            }
            every { item.id() } returns 17
            every { item.webSocketId() } returns 9
            every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z")
            every { item.direction() } returns Direction.SERVER_TO_CLIENT
            every { item.listenerPort() } returns 8080
            every { item.payload() } returns payload
            every { item.annotations() } returns annotations
            every { annotations.notes() } returns null
            every { payload.length() } returns 5
            every { payload.subArray(1, 4) } returns selected
            every { selected.getBytes() } returns byteArrayOf(2, 3, 4)

            runBlocking {
                val result = client.callTool(
                    "get_websocket_message_by_id",
                    mapOf("id" to 17, "offset" to 1, "limit" to 3, "encoding" to "base64"),
                )
                assertNotNull(result?.structuredContent)
                val structured = result!!.structuredContent!!
                assertEquals("ok", structured["status"]?.jsonPrimitive?.content)
                assertTrue(structured["content"].toString().contains("\"data\":\"AgME\""))

                val missing = client.callTool("get_websocket_message_by_id", mapOf("id" to 999))
                assertEquals("not_found", missing?.structuredContent?.get("status")?.jsonPrimitive?.content)
            }

            verify(exactly = 2) { proxy.webSocketHistory(any()) }
            verify(exactly = 0) { proxy.webSocketHistory() }
        }
    }
    
    @Test
    fun `scope comparison and enhanced action tools expose precise structured schemas`() = runBlocking {
        val tools = client.listTools()
        assertEquals(37, tools.size)
        assertTrue(tools.all { it.annotations?.readOnlyHint != null }, "Every tool needs an explicit read-only classification")

        val attackSurface = tools.single { it.name == "summarize_http_attack_surface" }
        assertEquals(setOf("projectId"), attackSurface.inputSchema.required?.toSet())
        assertTrue(attackSurface.inputSchema.properties?.get("sources").toString().contains("\"maxItems\":3"))
        assertTrue(attackSurface.inputSchema.properties?.get("pathDepth").toString().contains("\"maximum\":4"))
        assertNotNull(attackSurface.outputSchema?.properties?.get("services"))
        assertNotNull(attackSurface.outputSchema?.properties?.get("pathPrefixes"))
        assertNotNull(attackSurface.outputSchema?.properties?.get("extensions"))
        assertNotNull(attackSurface.outputSchema?.properties?.get("availableInScopeRecords"))
        assertEquals(true, attackSurface.annotations?.readOnlyHint)
        assertEquals(false, attackSurface.annotations?.destructiveHint)

        val checkScope = tools.single { it.name == "check_scope" }
        assertEquals(setOf("projectId", "targets"), checkScope.inputSchema.required?.toSet())
        assertNotNull(checkScope.outputSchema?.properties?.get("targets"))
        assertEquals(true, checkScope.annotations?.readOnlyHint)
        assertEquals(true, checkScope.annotations?.idempotentHint)
        assertTrue(checkScope.inputSchema.properties?.get("targets").toString().contains("\"maxItems\":32"))
        assertTrue(checkScope.inputSchema.properties?.get("targets").toString().contains("\"additionalProperties\":false"))

        val updateScope = tools.single { it.name == "update_scope" }
        assertTrue(updateScope.inputSchema.properties?.get("operation").toString().contains("include"))
        assertTrue(updateScope.inputSchema.properties?.get("operation").toString().contains("exclude"))
        assertTrue(updateScope.outputSchema?.properties?.get("executionState").toString().contains("uncertain"))
        assertEquals(true, updateScope.annotations?.destructiveHint)
        assertEquals(true, updateScope.annotations?.idempotentHint)
        assertEquals(false, updateScope.annotations?.openWorldHint)

        val comparison = tools.single { it.name == "compare_http_messages" }
        assertEquals(setOf("projectId", "refs"), comparison.inputSchema.required?.toSet())
        assertTrue(comparison.inputSchema.properties?.get("part").toString().contains("response_body"))
        assertTrue(comparison.inputSchema.properties?.get("excerptEncoding").toString().contains("base64"))
        assertNotNull(comparison.outputSchema?.properties?.get("responseVariations"))
        assertEquals(true, comparison.annotations?.readOnlyHint)

        val intruder = tools.single { it.name == "send_to_intruder_from_id" }
        val insertionSchema = intruder.inputSchema.properties?.get("insertionPoints").toString()
        assertTrue(insertionSchema.contains("parameter"))
        assertTrue(insertionSchema.contains("header"))
        assertTrue(insertionSchema.contains("body"))
        assertNotNull(intruder.outputSchema?.properties?.get("insertionPointCount"))

        val replay = tools.single { it.name == "send_http_request_from_id" }
        assertNotNull(replay.outputSchema?.properties?.get("recordedRef"))
        val redirectSchema = replay.inputSchema.properties?.get("redirection").toString()
        assertTrue(redirectSchema.contains("\"enum\":[\"never\"]"))
        assertTrue(redirectSchema.contains("\"default\":\"never\""))

        val legacyHistory = tools.single { it.name == "get_proxy_http_history" }
        assertEquals(true, legacyHistory.annotations?.readOnlyHint)
        assertTrue(legacyHistory.inputSchema.properties?.get("count").toString().contains("\"maximum\":50"))
        assertNotNull(legacyHistory.inputSchema.properties?.get("part"))

        val project = mockk<burp.api.montoya.project.Project>()
        val scope = mockk<burp.api.montoya.scope.Scope>()
        every { api.project() } returns project
        every { project.id() } returns "project-schema"
        every { api.scope() } returns scope
        every { scope.isInScope("https://example.test/") } returns true
        val scopeResult = client.callTool(
            "check_scope",
            mapOf(
                "projectId" to "project-schema",
                "targets" to listOf(mapOf("url" to "https://EXAMPLE.test:443")),
            ),
        )
        assertEquals("ok", scopeResult?.structuredContent?.get("status")?.jsonPrimitive?.content)
        assertTrue(scopeResult?.structuredContent?.get("targets").toString().contains("https://example.test/"))

        val invalidComparison = client.callTool(
            "compare_http_messages",
            mapOf("projectId" to "project-schema", "refs" to emptyList<Any>()),
        )
        assertEquals(
            "invalid_argument",
            invalidComparison?.structuredContent?.get("status")?.jsonPrimitive?.content,
        )
    }

    @Nested
    inner class CollaboratorToolsTests {
        private val collaborator = mockk<Collaborator>()
        private val collaboratorClient = mockk<CollaboratorClient>()
        private val collaboratorServer = mockk<CollaboratorServer>()
        private val collaboratorProjectId = "project-collaborator"

        @BeforeEach
        fun setupCollaborator() {
            mockkStatic(InteractionFilter::class)

            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            val version = mockk<burp.api.montoya.core.Version>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.version() } returns version
            every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
            every { burpSuite.taskExecutionEngine() } returns mockk(relaxed = true)
            every { burpSuite.exportProjectOptionsAsJson() } returns "{}"
            every { burpSuite.exportUserOptionsAsJson() } returns "{}"
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { burpSuite.importUserOptionsFromJson(any()) } just runs

            val project = mockk<burp.api.montoya.project.Project>()
            every { api.project() } returns project
            every { project.id() } returns collaboratorProjectId
            every { api.collaborator() } returns collaborator
            every { collaborator.createClient() } returns collaboratorClient
            every { collaboratorClient.server() } returns collaboratorServer
            every { collaboratorServer.address() } returns "burpcollaborator.net"

            serverManager.stop {}
            serverStarted = false
            serverManager.start(config) { state ->
                if (state is ServerState.Running) serverStarted = true
            }

            runBlocking {
                var attempts = 0
                while (!serverStarted && attempts < 30) {
                    delay(100)
                    attempts++
                }
                if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")
                client.connectToServer("http://127.0.0.1:${testPort}/mcp")
            }
        }

        @AfterEach
        fun cleanupCollaborator() {
            unmockkStatic(InteractionFilter::class)
        }

        private fun mockInteraction(
            id: String,
            type: InteractionType,
            clientIp: String = "10.0.0.1",
            clientPort: Int = 54321,
            customData: String? = null,
            dnsDetails: DnsDetails? = null,
            httpDetails: HttpDetails? = null,
            smtpDetails: SmtpDetails? = null
        ): Interaction {
            val interactionId = mockk<InteractionId>()
            every { interactionId.toString() } returns id

            return mockk<Interaction>().also {
                every { it.id() } returns interactionId
                every { it.type() } returns type
                every { it.timeStamp() } returns ZonedDateTime.parse("2025-01-01T12:00:00Z")
                every { it.clientIp() } returns InetAddress.getByName(clientIp)
                every { it.clientPort() } returns clientPort
                every { it.customData() } returns Optional.ofNullable(customData)
                every { it.dnsDetails() } returns Optional.ofNullable(dnsDetails)
                every { it.httpDetails() } returns Optional.ofNullable(httpDetails)
                every { it.smtpDetails() } returns Optional.ofNullable(smtpDetails)
            }
        }

        @Test
        fun `Professional Scanner Collaborator and issue search tools expose bounded schemas`() = runBlocking {
            val tools = client.listTools()
            assertEquals(44, tools.size)

            val start = tools.single { it.name == "start_scanner_audit_from_ids" }
            assertEquals(setOf("projectId", "mode", "targets"), start.inputSchema.required?.toSet())
            assertTrue(start.inputSchema.properties?.get("mode").toString().contains("active"))
            assertTrue(start.inputSchema.properties?.get("targets").toString().contains("insertionPoints"))
            assertTrue(start.outputSchema?.properties?.get("actionState").toString().contains("uncertain"))
            assertEquals(false, start.annotations?.readOnlyHint)
            assertEquals(true, start.annotations?.destructiveHint)
            assertEquals(true, start.annotations?.openWorldHint)
            assertEquals(false, start.annotations?.idempotentHint)

            val get = tools.single { it.name == "get_scanner_audit" }
            assertEquals(setOf("projectId", "taskId"), get.inputSchema.required?.toSet())
            assertNotNull(get.outputSchema?.properties?.get("issues"))
            assertEquals(true, get.annotations?.readOnlyHint)

            val cancel = tools.single { it.name == "cancel_scanner_audit" }
            assertEquals(false, cancel.annotations?.readOnlyHint)
            assertEquals(true, cancel.annotations?.destructiveHint)
            assertEquals(true, cancel.annotations?.idempotentHint)
            assertEquals(false, cancel.annotations?.openWorldHint)

            val issues = tools.single { it.name == "get_scanner_issues" }
            assertNotNull(issues.inputSchema.properties?.get("cursor"))
            assertNotNull(issues.inputSchema.properties?.get("severities"))
            assertNotNull(issues.outputSchema?.properties?.get("nextCursor"))

            val generator = tools.single { it.name == "generate_collaborator_payload" }
            assertEquals(false, generator.annotations?.readOnlyHint)

            val interactions = tools.single { it.name == "get_collaborator_interactions" }
            assertNotNull(interactions.inputSchema.properties?.get("waitSeconds"))
            assertTrue(interactions.inputSchema.properties?.get("detailEncoding").toString().contains("base64"))
            assertNotNull(interactions.outputSchema?.properties?.get("detailsTruncated"))
            assertEquals(false, interactions.annotations?.idempotentHint)

            val invalidStart = client.callTool(
                "start_scanner_audit_from_ids",
                mapOf("projectId" to "project", "mode" to "active", "targets" to emptyList<Any>()),
            )
            assertEquals(
                "invalid_argument",
                invalidStart?.structuredContent?.get("status")?.jsonPrimitive?.content,
            )
            assertEquals(
                "not_started",
                invalidStart?.structuredContent?.get("actionState")?.jsonPrimitive?.content,
            )
        }

        @Test
        fun `Scanner issue lookup resolves a stable ID`() {
            val siteMap = mockk<SiteMap>()
            val issue = mockk<AuditIssue>()
            val service = mockk<burp.api.montoya.http.HttpService>()
            val definition = mockk<AuditIssueDefinition>()
            every { api.siteMap() } returns siteMap
            every { siteMap.issues() } returns listOf(issue)
            every { issue.definition() } returns definition
            every { definition.typeIndex() } returns 123
            every { issue.name() } returns "Example issue"
            every { issue.baseUrl() } returns "https://example.test/path"
            every { issue.httpService() } returns service
            every { service.host() } returns "example.test"
            every { service.port() } returns 443
            every { service.secure() } returns true
            every { issue.severity() } returns AuditIssueSeverity.HIGH
            every { issue.confidence() } returns AuditIssueConfidence.CERTAIN
            every { issue.detail() } returns "Issue detail"
            every { issue.requestResponses() } returns emptyList()
            val id = issue.stableHistoryId()

            runBlocking {
                val result = client.callTool("get_scanner_issue_by_id", mapOf("id" to id))
                assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals(id, result?.structuredContent?.get("id")?.jsonPrimitive?.content)
            }
        }

        @Test
        fun `generate payload should return payload and server info`() {
            val payload = mockk<CollaboratorPayload>()
            val payloadId = mockk<InteractionId>()
            every { payload.toString() } returns "abc123.burpcollaborator.net"
            every { payload.id() } returns payloadId
            every { payloadId.toString() } returns "abc123"
            every { collaboratorClient.generatePayload() } returns payload

            runBlocking {
                val result = client.callTool(
                    "generate_collaborator_payload",
                    mapOf("projectId" to collaboratorProjectId),
                )
                delay(100)
                result.expectTextContent(
                    "Payload: abc123.burpcollaborator.net\n" +
                    "Payload ID: abc123\n" +
                    "Collaborator server: burpcollaborator.net"
                )
            }

            verify(exactly = 1) { collaboratorClient.generatePayload() }
        }

        @Test
        fun `generate payload with custom data should pass custom data`() {
            val payload = mockk<CollaboratorPayload>()
            val payloadId = mockk<InteractionId>()
            every { payload.toString() } returns "custom123.burpcollaborator.net"
            every { payload.id() } returns payloadId
            every { payloadId.toString() } returns "custom123"
            every { collaboratorClient.generatePayload(any<String>()) } returns payload

            runBlocking {
                val result = client.callTool(
                    "generate_collaborator_payload", mapOf(
                        "projectId" to collaboratorProjectId,
                        "customData" to "mydata",
                    )
                )
                delay(100)
                result.expectTextContent(
                    "Payload: custom123.burpcollaborator.net\n" +
                    "Payload ID: custom123\n" +
                    "Collaborator server: burpcollaborator.net"
                )
            }

            verify(exactly = 1) { collaboratorClient.generatePayload("mydata") }
        }

        @Test
        fun `get interactions should return dns interaction details`() {
            val dnsDetails = mockk<DnsDetails>().also {
                every { it.queryType() } returns DnsQueryType.A
            }
            val interaction = mockInteraction("int-001", InteractionType.DNS, dnsDetails = dnsDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool(
                    "get_collaborator_interactions",
                    mapOf("projectId" to collaboratorProjectId),
                )
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"id\":\"int-001\""))
                assertTrue(text.contains("\"type\":\"DNS\""))
                assertTrue(text.contains("\"queryType\":\"A\""))
                assertTrue(text.contains("\"clientIp\":\"10.0.0.1\""))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions should return http interaction details`() {
            val mockRequest = mockk<burp.api.montoya.http.message.requests.HttpRequest>()
            every { mockRequest.toString() } returns "GET / HTTP/1.1"
            val mockResponse = mockk<burp.api.montoya.http.message.responses.HttpResponse>()
            every { mockResponse.toString() } returns "HTTP/1.1 200 OK"
            val mockRequestResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            every { mockRequestResponse.request() } returns mockRequest
            every { mockRequestResponse.response() } returns mockResponse

            val httpDetails = mockk<HttpDetails>().also {
                every { it.protocol() } returns HttpProtocol.HTTP
                every { it.requestResponse() } returns mockRequestResponse
            }
            val interaction = mockInteraction("int-002", InteractionType.HTTP, httpDetails = httpDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool(
                    "get_collaborator_interactions",
                    mapOf("projectId" to collaboratorProjectId),
                )
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"type\":\"HTTP\""))
                assertTrue(text.contains("\"protocol\":\"HTTP\""))
                assertTrue(text.contains("GET / HTTP/1.1"))
                assertTrue(text.contains("HTTP/1.1 200 OK"))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions should return smtp interaction details`() {
            val smtpDetails = mockk<SmtpDetails>().also {
                every { it.protocol() } returns SmtpProtocol.SMTP
                every { it.conversation() } returns "EHLO test\r\n250 OK"
            }
            val interaction = mockInteraction("int-003", InteractionType.SMTP, smtpDetails = smtpDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool(
                    "get_collaborator_interactions",
                    mapOf("projectId" to collaboratorProjectId),
                )
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"type\":\"SMTP\""))
                assertTrue(text.contains("\"protocol\":\"SMTP\""))
                assertTrue(text.contains("EHLO test"))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions with payloadId should use filter`() {
            val mockFilter = mockk<InteractionFilter>()
            every { InteractionFilter.interactionIdFilter("abc123") } returns mockFilter
            every { collaboratorClient.getInteractions(mockFilter) } returns emptyList()

            runBlocking {
                val result = client.callTool(
                    "get_collaborator_interactions", mapOf(
                        "projectId" to collaboratorProjectId,
                        "payloadId" to "abc123",
                    )
                )
                delay(100)
                result.expectTextContent("No interactions detected")
            }

            verify(exactly = 1) { collaboratorClient.getInteractions(mockFilter) }
        }

        @Test
        fun `get interactions should return no interactions message when empty`() {
            every { collaboratorClient.getAllInteractions() } returns emptyList()

            runBlocking {
                val result = client.callTool(
                    "get_collaborator_interactions",
                    mapOf("projectId" to collaboratorProjectId),
                )
                delay(100)
                result.expectTextContent("No interactions detected")
            }
        }
    }

    @Test
    fun `tool name conversion should work properly`() {
        assertEquals("send_http1_request", "SendHttp1Request".toLowerSnakeCase())
        assertEquals("test_case_conversion", "TestCaseConversion".toLowerSnakeCase())
        assertEquals("multiple_upper_case_letters", "MultipleUpperCaseLetters".toLowerSnakeCase())
    }
    
    @Test
    fun `edition specific tools should only register in professional edition`() {
        val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
        val version = mockk<burp.api.montoya.core.Version>()
        
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.version() } returns version
        
        every { version.edition() } returns BurpSuiteEdition.COMMUNITY_EDITION
        runBlocking {
            val tools = client.listTools()
            assertTrue(tools.all { it.annotations?.readOnlyHint != null })
            assertFalse(tools.any { it.name == "get_scanner_issues" })
            assertFalse(tools.any { it.name == "generate_collaborator_payload" })
            assertFalse(tools.any { it.name == "get_collaborator_interactions" })
        }

        every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL

        serverManager.stop {}
        serverStarted = false
        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")

            client.connectToServer("http://127.0.0.1:${testPort}/mcp")

            val tools = client.listTools()
            assertTrue(tools.all { it.annotations?.readOnlyHint != null })
            assertTrue(tools.any { it.name == "get_scanner_issues" })
            assertTrue(tools.any { it.name == "generate_collaborator_payload" })
            assertTrue(tools.any { it.name == "get_collaborator_interactions" })
        }
    }
}