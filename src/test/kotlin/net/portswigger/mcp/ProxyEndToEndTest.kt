package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import io.mockk.*
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonPrimitive
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.assertDoesNotThrow
import org.slf4j.LoggerFactory
import java.io.File
import java.net.ServerSocket
import java.time.ZonedDateTime
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.milliseconds

/**
 * End-to-end test verifying the full stack:
 * TestStdioMcpClient (stdio) ↔ proxy subprocess ↔ KtorServerManager (Streamable HTTP)
 *
 * Requires the Streamable HTTP proxy at libs/mcp-proxy-all.jar.
 */
@Timeout(30, unit = TimeUnit.SECONDS)
class ProxyEndToEndTest {
    private val logger = LoggerFactory.getLogger(ProxyEndToEndTest::class.java)

    private val api = mockk<MontoyaApi>(relaxed = true)
    private val serverManager = KtorServerManager(api)
    private val testPort = findAvailablePort()
    private val persistedObject = mockk<PersistedObject>()

    @Volatile
    private var serverStarted = false

    init {
        every { persistedObject.getBoolean(any()) } returns true
        every { persistedObject.getBoolean("requireRequestActionApproval") } returns false
        every { persistedObject.getString(any()) } returns "127.0.0.1"
        every { persistedObject.getInteger("port") } returns testPort
        every { persistedObject.setBoolean(any(), any()) } returns Unit
        every { persistedObject.setString(any(), any()) } returns Unit
        every { persistedObject.setInteger(any(), any()) } returns Unit
    }

    private val mockLogging = mockk<Logging>().apply {
        every { logToError(any<String>()) } returns Unit
        every { logToOutput(any<String>()) } returns Unit
    }

    private val config = McpConfig(persistedObject, mockLogging)

    private lateinit var proxyProcess: Process
    private lateinit var client: TestStdioMcpClient

    private fun findAvailablePort(): Int {
        return ServerSocket(0).use { it.localPort }
    }

    @BeforeEach
    fun setup(): Unit = runBlocking {
        serverManager.start(config) { state ->
            if (state is ServerState.Running) {
                serverStarted = true
            }
        }

        var attempts = 0
        while (!serverStarted && attempts < 10) {
            delay(100)
            attempts++
        }
        if (!serverStarted) {
            throw IllegalStateException("Server failed to start after timeout")
        }

        val jarFile = File("libs/mcp-proxy-all.jar")
        check(jarFile.exists()) {
            "libs/mcp-proxy-all.jar not found. Build it in the mcp-proxy repository and copy it to libs first"
        }

        proxyProcess = ProcessBuilder(
            "java",
            "-Dorg.slf4j.simpleLogger.defaultLogLevel=warn",
            "-jar",
            jarFile.absolutePath,
            "--mcp-url",
            "http://127.0.0.1:$testPort/mcp"
        ).redirectError(ProcessBuilder.Redirect.INHERIT).start()

        client = TestStdioMcpClient()
        connectClientWithRetry()
        logger.info("Test client connected to proxy on port $testPort")
    }

    private suspend fun connectClientWithRetry() {
        val maxAttempts = 10
        val retryDelay = 500.milliseconds
        for (attempt in 1..maxAttempts) {
            check(proxyProcess.isAlive) { "Proxy process died during startup" }
            try {
                client.connectToServer(proxyProcess.inputStream, proxyProcess.outputStream)
                return
            } catch (e: Exception) {
                if (attempt == maxAttempts) throw e
                logger.info("Proxy not ready (attempt $attempt/$maxAttempts), retrying...")
                delay(retryDelay)
            }
        }
    }

    @AfterEach
    fun tearDown(): Unit = runBlocking {
        try {
            if (::client.isInitialized) {
                client.close()
            }
        } catch (e: Exception) {
            logger.warn("Error closing client: ${e.message}")
        }

        try {
            if (::proxyProcess.isInitialized) {
                proxyProcess.destroy()
                if (!proxyProcess.waitFor(2, TimeUnit.SECONDS)) {
                    proxyProcess.destroyForcibly()
                }
            }
        } catch (e: Exception) {
            logger.warn("Error destroying proxy process: ${e.message}")
        }

        serverManager.shutdown()
    }

    @Test
    fun `proxy should ping server`() {
        runBlocking {
            assertDoesNotThrow { client.ping() }
        }
    }

    @Test
    fun `proxy should list tools`() {
        runBlocking {
            val tools = client.listTools()
            assertFalse(tools.isEmpty(), "Tool list should not be empty")
            assertTrue(tools.any { it.name == "url_encode" }, "url_encode tool should be present")
            val action = tools.single { it.name == "send_http_request_from_id" }
            assertEquals(true, action.annotations?.destructiveHint)
            assertEquals(true, action.annotations?.openWorldHint)
            assertNotNull(action.outputSchema?.properties?.get("executionState"))
        }
    }

    @Test
    fun `proxy should preserve structured history results`() {
        val proxy = mockk<Proxy>()
        val item = mockk<ProxyHttpRequestResponse>()
        val request = mockk<HttpRequest>()
        val body = mockk<MontoyaByteArray>()
        val service = mockk<burp.api.montoya.http.HttpService>()
        val annotations = mockk<Annotations>()
        val project = mockk<burp.api.montoya.project.Project>()
        every { api.proxy() } returns proxy
        every { api.project() } returns project
        every { project.id() } returns "proxy-e2e-project"
        every { proxy.history() } returns listOf(item)
        every { proxy.history(any()) } answers {
            val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
            listOf(item).filter(filter::matches)
        }
        every { item.id() } returns 42
        every { item.request() } returns request
        every { item.response() } returns null
        every { item.httpService() } returns service
        every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z")
        every { item.listenerPort() } returns 8080
        every { item.edited() } returns false
        every { item.annotations() } returns annotations
        every { request.method() } returns "GET"
        every { request.url() } returns "https://example.test/"
        every { request.path() } returns "/"
        every { request.isInScope() } returns true
        every { request.body() } returns body
        every { body.length() } returns 0
        every { request.bodyOffset() } returns 48
        every { request.toByteArray() } returns body
        every { request.toString() } returns "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
        every { request.httpService() } returns service
        every { request.httpVersion() } returns "HTTP/1.1"
        every { service.host() } returns "example.test"
        every { service.port() } returns 443
        every { service.secure() } returns true
        every { annotations.notes() } returns null

        runBlocking {
            val result = client.callTool("get_http_message_by_id", mapOf("id" to 42))
            assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("42", result?.structuredContent?.get("id")?.jsonPrimitive?.content)

            val search = client.callTool("search_http_messages", mapOf("host" to "example.test"))
            assertEquals("ok", search?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("proxy-e2e-project", search?.structuredContent?.get("projectId")?.jsonPrimitive?.content)
            assertTrue(search?.structuredContent?.get("items").toString().contains("\"id\":\"42\""))

            val repeater = mockk<burp.api.montoya.repeater.Repeater>(relaxed = true)
            every { api.repeater() } returns repeater
            val action = client.callTool(
                "create_repeater_tab_from_id",
                mapOf(
                    "projectId" to "proxy-e2e-project",
                    "ref" to mapOf("source" to "proxy", "id" to "42"),
                    "tabName" to "proxy-e2e",
                ),
            )
            assertEquals("ok", action?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("completed", action?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
            verify(exactly = 1) { repeater.sendToRepeater(request, "proxy-e2e") }
        }
    }

    @Test
    fun `proxy should call url_encode tool`() {
        runBlocking {
            val result = client.callTool("url_encode", mapOf("content" to "hello world"))
            assertNotNull(result, "Tool call result should not be null")
            assertFalse(result?.isError ?: false, "Tool call should not return an error")
            assertTrue(result?.content?.first() is TextContent, "Result should contain TextContent")
        }
    }
}
