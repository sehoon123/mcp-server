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
import burp.api.montoya.http.RedirectionMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
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
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
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
    private lateinit var originalRequestActionHandler: RequestActionApprovalHandler
    private lateinit var originalSensitiveActionHandler: SensitiveActionApprovalHandler

    init {
        val persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean("enabled") } returns true
            every { getBoolean("emergencyReadOnlyMode") } returns false
            every { getBoolean("configEditingTooling") } returns true
            every { getBoolean("filterConfigCredentials") } returns false
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
        mockkStatic(RequestOptions::class)
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
        val defaultProject = mockk<burp.api.montoya.project.Project>()
        every { defaultProject.id() } returns "project-default"
        every { api.project() } returns defaultProject

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
    inner class RawHttpToolsTests {
        @Test
        fun `unified raw HTTP1 send normalizes input and returns structured state`() = runBlocking {
            val http = mockk<Http>()
            val request = mockk<HttpRequest>()
            val body = montoyaBytes(byteArrayOf())
            val options = mockk<RequestOptions>()
            val content = slot<String>()
            every { HttpRequest.httpRequest(any(), capture(content)) } returns request
            every { request.bodyOffset() } returns 48
            every { request.body() } returns body
            every { RequestOptions.requestOptions() } returns options
            every { options.withHttpMode(HttpMode.HTTP_1) } returns options
            every { options.withRedirectionMode(RedirectionMode.NEVER) } returns options
            every { options.withResponseTimeout(30_000) } returns options
            every { api.http() } returns http
            every { http.sendRequest(request, options) } returns null

            val result = client.callTool(
                "send_raw_http_request",
                mapOf(
                    "protocol" to "http_1",
                    "http1" to mapOf("content" to "GET / HTTP/1.1\nHost: example.test\n\n"),
                    "targetHostname" to "example.test",
                    "targetPort" to 443,
                    "usesHttps" to true,
                ),
            )

            assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("completed", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
            assertEquals("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", content.captured)
            verify(exactly = 1) { options.withRedirectionMode(RedirectionMode.NEVER) }
            verify(exactly = 1) { http.sendRequest(request, options) }
        }

        @Test
        fun `unified raw HTTP2 routing creates exactly one approved Repeater tab`() = runBlocking {
            val repeater = mockk<burp.api.montoya.repeater.Repeater>(relaxed = true)
            val request = mockk<HttpRequest>()
            val body = montoyaBytes(byteArrayOf())
            val headers = slot<List<HttpHeader>>()
            every { HttpRequest.http2Request(any(), capture(headers), "payload") } returns request
            every { request.bodyOffset() } returns 64
            every { request.body() } returns body
            every { api.repeater() } returns repeater

            val result = client.callTool(
                "route_raw_http_request",
                mapOf(
                    "destination" to "repeater",
                    "protocol" to "http_2",
                    "http2" to mapOf(
                        "pseudoHeaders" to mapOf("method" to "POST", "path" to "/api"),
                        "headers" to mapOf("Content-Type" to "text/plain"),
                        "requestBody" to "payload",
                    ),
                    "targetHostname" to "example.test",
                    "targetPort" to 443,
                    "usesHttps" to true,
                    "tabName" to "v4",
                ),
            )

            assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("completed", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
            assertEquals(listOf(":method", ":path"), headers.captured.take(2).map { it.name() })
            verify(exactly = 1) { repeater.sendToRepeater(request, "v4") }
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
                    "transform_data", mapOf(
                        "operation" to "url_encode",
                        "content" to "test string with spaces"
                    )
                )
                
                delay(100)
                result.expectTextContent("test+string+with+spaces")
                assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("not_applicable", result?.structuredContent?.get("retry")?.jsonPrimitive?.content)
                assertEquals("test+string+with+spaces", result?.structuredContent?.get("content")?.jsonPrimitive?.content)
                assertEquals(23, result?.structuredContent?.get("contentChars")?.jsonPrimitive?.int)
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
                    "transform_data", mapOf(
                        "operation" to "url_decode",
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
                    "transform_data", mapOf(
                        "operation" to "base64_encode",
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
                    "transform_data", mapOf(
                        "operation" to "base64_decode",
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
                assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("1a2b3c1a2b", result?.structuredContent?.get("content")?.jsonPrimitive?.content)
                assertEquals(10, result?.structuredContent?.get("contentChars")?.jsonPrimitive?.int)
            }
            
            verify(exactly = 1) { randomUtils.randomString(any<Int>(), any<String>()) }
        }

        @Test
        fun `utility validation errors retain structured status and retry guidance`() = runBlocking {
            val result = client.callTool(
                "transform_data",
                mapOf(
                    "operation" to "url_encode",
                    "content" to "x".repeat(262_145),
                ),
            )

            assertEquals(true, result?.isError)
            assertEquals("invalid_argument", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("after_correction", result?.structuredContent?.get("retry")?.jsonPrimitive?.content)
            assertEquals("url_encode", result?.structuredContent?.get("operation")?.jsonPrimitive?.content)
            assertNull(result?.structuredContent?.get("content"))
        }
    }
    
    @Nested
    inner class ConfigurationToolsTests {
        @Test
        fun `configuration export rejects oversized content with a structured limit status`() = runBlocking {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.exportProjectOptionsAsJson() } returns "x".repeat(1_048_577)

            val result = client.callTool("get_burp_options", mapOf("level" to "project"))

            assertEquals(true, result?.isError)
            assertEquals("limit_exceeded", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("after_user_action", result?.structuredContent?.get("retry")?.jsonPrimitive?.content)
            assertNull(result?.structuredContent?.get("configuration"))
        }

        @Test
        fun `set task execution engine state should work properly`() {
            val taskExecutionEngine = mockk<TaskExecutionEngine>()
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.taskExecutionEngine() } returns taskExecutionEngine
            every { taskExecutionEngine.state = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_burp_control_state", mapOf(
                        "control" to "task_execution_engine",
                        "enabled" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now running")
                assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("completed", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
                assertEquals("not_applicable", result?.structuredContent?.get("retry")?.jsonPrimitive?.content)
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.RUNNING }
            
            clearMocks(taskExecutionEngine, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_burp_control_state", mapOf(
                        "control" to "task_execution_engine",
                        "enabled" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now paused")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.PAUSED }
        }

        @Test
        fun `control mutation failure reports uncertain state and forbids automatic retry`() = runBlocking {
            val taskExecutionEngine = mockk<TaskExecutionEngine>()
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.taskExecutionEngine() } returns taskExecutionEngine
            every { taskExecutionEngine.state = any() } throws IllegalStateException("write failed")

            val result = client.callTool(
                "set_burp_control_state",
                mapOf("control" to "task_execution_engine", "enabled" to true),
            )

            assertEquals(true, result?.isError)
            assertEquals("burp_error", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("uncertain", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
            assertEquals("do_not_retry", result?.structuredContent?.get("retry")?.jsonPrimitive?.content)
            assertTrue(result.expectTextContent().contains("do not retry automatically"))
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.RUNNING }
        }
        
        @Test
        fun `control approval denial is structured and never starts the mutation`() = runBlocking {
            val taskExecutionEngine = mockk<TaskExecutionEngine>(relaxed = true)
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.taskExecutionEngine() } returns taskExecutionEngine
            val previous = SensitiveActionSecurity.approvalHandler
            SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
                override suspend fun requestApproval(
                    action: String,
                    summary: String,
                    reviewContent: String?,
                    renderContentAsHttp: Boolean,
                    api: MontoyaApi,
                ) = false
            }

            try {
                val result = client.callTool(
                    "set_burp_control_state",
                    mapOf("control" to "task_execution_engine", "enabled" to true),
                )

                assertEquals(false, result?.isError)
                assertEquals("access_denied", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("not_started", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
                assertEquals("after_user_action", result?.structuredContent?.get("retry")?.jsonPrimitive?.content)
                verify(exactly = 0) { taskExecutionEngine.state = any() }
            } finally {
                SensitiveActionSecurity.approvalHandler = previous
            }
        }

        @Test
        fun `set proxy intercept state should work properly`() {
            val proxy = mockk<Proxy>()
            
            every { api.proxy() } returns proxy
            every { proxy.enableIntercept() } just runs
            every { proxy.disableIntercept() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_burp_control_state", mapOf(
                        "control" to "proxy_intercept",
                        "enabled" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been enabled")
            }
            
            verify(exactly = 1) { proxy.enableIntercept() }
            
            clearMocks(proxy, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_burp_control_state", mapOf(
                        "control" to "proxy_intercept",
                        "enabled" to false
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
            every { burpSuite.exportProjectOptionsAsJson() } returns "{\"project_options\":{}}"
            every { burpSuite.exportUserOptionsAsJson() } returns "{\"user_options\":{}}"
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { burpSuite.importUserOptionsFromJson(any()) } just runs

            runBlocking {
                val projectRead = client.callTool("get_burp_options", mapOf("level" to "project"))
                val userRead = client.callTool("get_burp_options", mapOf("level" to "user"))
                projectRead.expectTextContent("{\"project_options\":{}}")
                userRead.expectTextContent("{\"user_options\":{}}")
                assertEquals("ok", projectRead?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals(
                    "{\"project_options\":{}}",
                    projectRead?.structuredContent?.get("configuration")?.jsonPrimitive?.content,
                )
                assertEquals(false, projectRead?.structuredContent?.get("credentialsFiltered")?.jsonPrimitive?.boolean)

                val projectResult = client.callTool(
                    "set_burp_options", mapOf("level" to "project", "json" to sensitiveJson)
                )
                val userResult = client.callTool(
                    "set_burp_options", mapOf("level" to "user", "json" to sensitiveJson)
                )

                delay(100)
                projectResult.expectTextContent("Project configuration has been applied")
                userResult.expectTextContent("User configuration has been applied")
                assertEquals("ok", projectResult?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("completed", projectResult?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
                assertEquals("not_applicable", projectResult?.structuredContent?.get("retry")?.jsonPrimitive?.content)

                val tools = client.listTools()
                val readTool = tools.single { it.name == "get_burp_options" }
                assertEquals(listOf("level"), readTool.inputSchema.required)
                assertTrue(readTool.inputSchema.properties?.get("level").toString().contains("project"))
                val description = tools.single { it.name == "set_burp_options" }.description.orEmpty()
                assertTrue(description.contains("top-level 'project_options'"))
                assertTrue(description.contains("top-level 'user_options'"))
            }

            verify(exactly = 1) { burpSuite.exportProjectOptionsAsJson() }
            verify(exactly = 1) { burpSuite.exportUserOptionsAsJson() }
            verify(exactly = 1) { burpSuite.importProjectOptionsFromJson(sensitiveJson) }
            verify(exactly = 1) { burpSuite.importUserOptionsFromJson(sensitiveJson) }
            verify(exactly = 0) { apiLogging.logToOutput(match { "secret-value" in it }) }

            clearMocks(burpSuite, answers = false)

            every { config.configEditingTooling } returns false

            runBlocking {
                val result = client.callTool(
                    "set_burp_options", mapOf("level" to "project", "json" to sensitiveJson)
                )

                delay(100)
                result.expectTextContent("User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'")
                assertEquals("disabled", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("not_started", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
                assertEquals("after_user_action", result?.structuredContent?.get("retry")?.jsonPrimitive?.content)
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
                assertEquals("not_available", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("after_user_action", result?.structuredContent?.get("retry")?.jsonPrimitive?.content)
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
                assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("Editor content", result?.structuredContent?.get("content")?.jsonPrimitive?.content)
                assertEquals(14, result?.structuredContent?.get("totalChars")?.jsonPrimitive?.int)
                assertEquals(false, result?.structuredContent?.get("truncated")?.jsonPrimitive?.boolean)
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
                assertEquals("not_editable", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("not_started", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
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
                assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("completed", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
                assertEquals(11, result?.structuredContent?.get("contentChars")?.jsonPrimitive?.int)
            }
            
            verify(exactly = 1) { textArea.text = "New content" }
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
                    "get_http_message",
                    mapOf(
                        "projectId" to "another-project",
                        "ref" to mapOf("source" to "proxy", "id" to "81"),
                    ),
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

                val detailTool = client.listTools().single { it.name == "get_http_message" }
                assertEquals(setOf("projectId", "ref"), detailTool.inputSchema.required?.toSet())
                assertTrue(detailTool.inputSchema.properties?.get("ref").toString().contains("site_map"))
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
                    "route_http_message_from_id",
                    mapOf(
                        "projectId" to "project-actions",
                        "ref" to mapOf("source" to "proxy", "id" to "91"),
                        "destination" to "repeater",
                        "tabName" to "derived",
                    ),
                )

                assertEquals(false, result?.isError)
                assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("completed", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
                verify(exactly = 1) { repeater.sendToRepeater(request, "derived") }

                val tools = client.listTools()
                val repeaterTool = tools.single { it.name == "route_http_message_from_id" }
                assertEquals(setOf("projectId", "ref", "destination"), repeaterTool.inputSchema.required?.toSet())
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

                val destinations = repeaterTool.inputSchema.properties?.get("destination").toString()
                assertTrue(destinations.contains("repeater"))
                assertTrue(destinations.contains("intruder"))
                assertTrue(destinations.contains("organizer"))
                assertNull(tools.singleOrNull { it.name == "send_to_intruder_from_id" })
                assertNull(tools.singleOrNull { it.name == "send_to_organizer_from_id" })
            }
        }
    }

    @Nested
    inner class StableHistoryAccessTests {
        @Test
        fun `HTTP message lookup returns bounded structured content and read-only metadata`() {
            val project = mockk<burp.api.montoya.project.Project>()
            val proxy = mockk<Proxy>()
            val item = mockk<ProxyHttpRequestResponse>()
            val request = mockk<HttpRequest>()
            val body = mockk<MontoyaByteArray>()
            val selected = mockk<MontoyaByteArray>()
            val service = mockk<burp.api.montoya.http.HttpService>()
            val annotations = mockk<Annotations>()

            every { api.project() } returns project
            every { project.id() } returns "project-history"
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
            every { request.httpService() } returns service
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
                    "get_http_message",
                    mapOf(
                        "projectId" to "project-history",
                        "ref" to mapOf("source" to "proxy", "id" to "42"),
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
                assertTrue(structured["ref"].toString().contains("\"id\":\"42\""))
                assertTrue(structured["metadata"].toString().contains("\"time\":\"2026-01-02T03:04:05Z\""))
                assertTrue(structured["metadata"].toString().contains("\"notes\":\"reviewed\""))
                val content = structured["content"]
                assertNotNull(content)
                assertTrue(content.toString().contains("\"data\":\"cdef\""))
                assertTrue(content.toString().contains("\"nextOffsetBytes\":6"))

                val tool = client.listTools().single { it.name == "get_http_message" }
                assertEquals(setOf("projectId", "ref"), tool.inputSchema.required?.toSet())
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
            val project = mockk<burp.api.montoya.project.Project>()
            val organizer = mockk<Organizer>()
            val item = mockk<OrganizerItem>()
            val request = mockk<HttpRequest>()
            val service = mockk<burp.api.montoya.http.HttpService>()
            val annotations = mockk<Annotations>()
            val body = mockk<MontoyaByteArray>()

            every { api.project() } returns project
            every { project.id() } returns "project-history"
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
            every { request.httpService() } returns service
            every { request.body() } returns body
            every { body.length() } returns 0
            every { service.host() } returns "example.test"
            every { service.port() } returns 443
            every { service.secure() } returns true
            every { annotations.notes() } returns null

            runBlocking {
                val result = client.callTool(
                    "get_http_message",
                    mapOf(
                        "projectId" to "project-history",
                        "ref" to mapOf("source" to "organizer", "id" to "73"),
                    ),
                )
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
                    mapOf(
                        "id" to 17,
                        "projectId" to "project-default",
                        "offset" to 1,
                        "limit" to 3,
                        "encoding" to "base64",
                    ),
                )
                assertNotNull(result?.structuredContent)
                val structured = result!!.structuredContent!!
                assertEquals("ok", structured["status"]?.jsonPrimitive?.content)
                assertEquals("project-default", structured["projectId"]?.jsonPrimitive?.content)
                assertTrue(structured["content"].toString().contains("\"data\":\"AgME\""))

                val missing = client.callTool(
                    "get_websocket_message_by_id",
                    mapOf("id" to 999, "projectId" to "project-default"),
                )
                assertEquals("not_found", missing?.structuredContent?.get("status")?.jsonPrimitive?.content)

                val wrongProject = client.callTool(
                    "get_websocket_message_by_id",
                    mapOf("id" to 17, "projectId" to "different-project"),
                )
                assertEquals(
                    "project_mismatch",
                    wrongProject?.structuredContent?.get("status")?.jsonPrimitive?.content,
                )
                val invalidId = client.callTool(
                    "get_websocket_message_by_id",
                    mapOf("id" to -1, "projectId" to "project-default"),
                )
                assertEquals(true, invalidId?.isError)
            }

            verify(exactly = 2) { proxy.webSocketHistory(any()) }
            verify(exactly = 0) { proxy.webSocketHistory() }
        }

        @Test
        fun `WebSocket lookup discards a result when the project changes during resolution`() = runBlocking {
            val project = mockk<burp.api.montoya.project.Project>()
            val proxy = mockk<Proxy>()
            val item = mockk<ProxyWebSocketMessage>()
            every { api.project() } returns project
            every { project.id() } returnsMany listOf("project-before", "project-after")
            every { api.proxy() } returns proxy
            every { proxy.webSocketHistory(any()) } answers {
                val filter = firstArg<burp.api.montoya.proxy.ProxyWebSocketHistoryFilter>()
                listOf(item).filter(filter::matches)
            }
            every { item.id() } returns 21

            val result = client.callTool(
                "get_websocket_message_by_id",
                mapOf("id" to 21, "projectId" to "project-before"),
            )

            assertEquals("project_mismatch", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("project-after", result?.structuredContent?.get("projectId")?.jsonPrimitive?.content)
            verify(exactly = 0) { item.payload() }
        }
    }
    
    @Test
    fun `scope comparison and enhanced action tools expose precise structured schemas`() = runBlocking {
        val tools = client.listTools()
        assertEquals(19, tools.size)
        assertTrue(tools.all { it.annotations?.readOnlyHint != null }, "Every tool needs an explicit read-only classification")
        val toolNames = tools.mapTo(mutableSetOf()) { it.name }
        assertEquals(
            setOf(
                "send_raw_http_request",
                "route_raw_http_request",
                "transform_data",
                "generate_random_string",
                "get_burp_options",
                "set_burp_options",
                "search_http_messages",
                "summarize_http_attack_surface",
                "check_scope",
                "update_scope",
                "compare_http_messages",
                "get_http_message",
                "send_http_request_from_id",
                "route_http_message_from_id",
                "search_websocket_messages",
                "get_websocket_message_by_id",
                "set_burp_control_state",
                "get_active_editor_contents",
                "set_active_editor_contents",
            ),
            toolNames,
        )
        assertTrue(
            toolNames.intersect(
                setOf(
                    "url_encode",
                    "url_decode",
                    "base64_encode",
                    "base64_decode",
                    "output_project_options",
                    "output_user_options",
                    "set_project_options",
                    "set_user_options",
                    "set_task_execution_engine_state",
                    "set_proxy_intercept_state",
                    "get_http_message_by_id",
                    "get_organizer_item_by_id",
                    "get_sitemap_message_by_id",
                    "create_repeater_tab_from_id",
                    "send_to_intruder_from_id",
                    "send_to_organizer_from_id",
                    "get_proxy_http_history_regex",
                    "get_organizer_items_regex",
                    "get_proxy_websocket_history_regex",
                    "send_http1_request",
                    "send_http2_request",
                    "create_repeater_tab",
                    "create_repeater_tab_http2",
                    "send_to_intruder",
                    "get_proxy_http_history",
                    "get_organizer_items",
                    "get_proxy_websocket_history",
                )
            ).isEmpty()
        )

        assertTrue(tools.all { it.outputSchema != null }, "Every v4.1 tool must advertise an output schema")

        val transform = tools.single { it.name == "transform_data" }
        assertEquals(setOf("operation", "content"), transform.inputSchema.required?.toSet())
        assertTrue(transform.inputSchema.properties?.get("operation").toString().contains("base64_decode"))
        assertNotNull(transform.outputSchema?.properties?.get("status"))
        assertNotNull(transform.outputSchema?.properties?.get("retry"))
        assertTrue(transform.outputSchema?.properties?.get("content").toString().contains("\"maxLength\":1048576"))

        val optionsMutation = tools.single { it.name == "set_burp_options" }
        assertTrue(optionsMutation.outputSchema?.properties?.get("executionState").toString().contains("uncertain"))
        assertTrue(optionsMutation.outputSchema?.properties?.get("retry").toString().contains("do_not_retry"))

        val editorRead = tools.single { it.name == "get_active_editor_contents" }
        assertNotNull(editorRead.outputSchema?.properties?.get("content"))
        assertNotNull(editorRead.outputSchema?.properties?.get("truncated"))

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

        val intruder = tools.single { it.name == "route_http_message_from_id" }
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

        val rawSend = tools.single { it.name == "send_raw_http_request" }
        assertEquals(
            setOf("protocol", "targetHostname", "targetPort", "usesHttps"),
            rawSend.inputSchema.required?.toSet(),
        )
        assertNotNull(rawSend.inputSchema.properties?.get("http1"))
        assertNotNull(rawSend.inputSchema.properties?.get("http2"))
        assertNotNull(rawSend.inputSchema.properties?.get("responseTimeoutMs"))
        assertTrue(rawSend.outputSchema?.properties?.get("executionState").toString().contains("uncertain"))
        assertNotNull(rawSend.outputSchema?.properties?.get("recordedRef"))
        assertEquals(false, rawSend.annotations?.readOnlyHint)
        assertEquals(true, rawSend.annotations?.destructiveHint)
        assertEquals(true, rawSend.annotations?.openWorldHint)
        assertEquals(false, rawSend.annotations?.idempotentHint)

        val rawRoute = tools.single { it.name == "route_raw_http_request" }
        assertTrue(rawRoute.inputSchema.properties?.get("destination").toString().contains("organizer"))
        assertTrue(rawRoute.inputSchema.properties?.get("protocol").toString().contains("http_2"))
        assertEquals(false, rawRoute.annotations?.readOnlyHint)
        assertEquals(false, rawRoute.annotations?.destructiveHint)
        assertEquals(false, rawRoute.annotations?.openWorldHint)
        assertEquals(false, rawRoute.annotations?.idempotentHint)

        val search = tools.single { it.name == "search_http_messages" }
        assertTrue(search.inputSchema.properties?.get("regex").toString().contains("\"maxLength\":512"))

        val websocketSearch = tools.single { it.name == "search_websocket_messages" }
        assertEquals(setOf("projectId"), websocketSearch.inputSchema.required?.toSet())
        assertTrue(websocketSearch.inputSchema.properties?.get("regex").toString().contains("\"maxLength\":512"))
        assertTrue(websocketSearch.inputSchema.properties?.get("limit").toString().contains("\"maximum\":50"))
        assertNotNull(websocketSearch.outputSchema?.properties?.get("nextCursor"))
        assertNotNull(websocketSearch.outputSchema?.properties?.get("scannedContentBytes"))
        assertEquals(true, websocketSearch.annotations?.readOnlyHint)
        assertEquals(false, websocketSearch.annotations?.destructiveHint)

        val websocketDetail = tools.single { it.name == "get_websocket_message_by_id" }
        assertEquals(setOf("id", "projectId"), websocketDetail.inputSchema.required?.toSet())

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
            assertEquals(26, tools.size)
            assertTrue(tools.all { it.outputSchema != null }, "Every Professional tool must advertise an output schema")

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

            val issueDetail = tools.single { it.name == "get_scanner_issue_by_id" }
            assertEquals(setOf("id", "projectId"), issueDetail.inputSchema.required?.toSet())

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
                val result = client.callTool(
                    "get_scanner_issue_by_id",
                    mapOf("id" to id, "projectId" to collaboratorProjectId),
                )
                assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals(id, result?.structuredContent?.get("id")?.jsonPrimitive?.content)
                assertEquals(
                    collaboratorProjectId,
                    result?.structuredContent?.get("projectId")?.jsonPrimitive?.content,
                )
                val wrongProject = client.callTool(
                    "get_scanner_issue_by_id",
                    mapOf("id" to id, "projectId" to "different-project"),
                )
                assertEquals(
                    "project_mismatch",
                    wrongProject?.structuredContent?.get("status")?.jsonPrimitive?.content,
                )
                val invalidId = client.callTool(
                    "get_scanner_issue_by_id",
                    mapOf("id" to "not-a-stable-id", "projectId" to collaboratorProjectId),
                )
                assertEquals(true, invalidId?.isError)
            }
            verify(exactly = 1) { siteMap.issues() }
        }

        @Test
        fun `Scanner issue lookup discards bounded content after a project transition`() = runBlocking {
            val project = mockk<burp.api.montoya.project.Project>()
            val siteMap = mockk<SiteMap>()
            val issue = mockk<AuditIssue>()
            val service = mockk<burp.api.montoya.http.HttpService>()
            val definition = mockk<AuditIssueDefinition>()
            every { api.project() } returns project
            every { project.id() } returnsMany listOf("project-before", "project-before", "project-after")
            every { api.siteMap() } returns siteMap
            every { siteMap.issues() } returns listOf(issue)
            every { issue.definition() } returns definition
            every { definition.typeIndex() } returns 321
            every { issue.name() } returns "Transition issue"
            every { issue.baseUrl() } returns "https://example.test/race"
            every { issue.httpService() } returns service
            every { service.host() } returns "example.test"
            every { service.port() } returns 443
            every { service.secure() } returns true
            every { issue.severity() } returns AuditIssueSeverity.MEDIUM
            every { issue.confidence() } returns AuditIssueConfidence.FIRM
            every { issue.detail() } returns "sensitive detail"
            every { issue.remediation() } returns null
            every { issue.requestResponses() } returns emptyList()
            val id = issue.stableHistoryId()

            val result = client.callTool(
                "get_scanner_issue_by_id",
                mapOf("id" to id, "projectId" to "project-before", "field" to "detail"),
            )

            assertEquals("project_mismatch", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("project-after", result?.structuredContent?.get("projectId")?.jsonPrimitive?.content)
            assertEquals(null, result?.structuredContent?.get("content"))
            verify(atLeast = 1) { issue.detail() }
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
        assertEquals("send_raw_http_request", "SendRawHttpRequest".toLowerSnakeCase())
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
            assertTrue(tools.all { it.outputSchema != null })
            assertTrue(tools.any { it.name == "get_scanner_issues" })
            assertTrue(tools.any { it.name == "generate_collaborator_payload" })
            assertTrue(tools.any { it.name == "get_collaborator_interactions" })
        }
    }
}