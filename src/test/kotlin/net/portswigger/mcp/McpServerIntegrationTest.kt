package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.time.Duration
import java.util.concurrent.TimeUnit

class McpServerIntegrationTest {
    private val testBearerToken = "0123456789012345678901234567890123456789012"
    private val client = TestStreamableHttpMcpClient(
        mapOf("Authorization" to "Bearer $testBearerToken")
    )
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val serverManager = KtorServerManager(api)
    private val testPort = findAvailablePort()
    private val persistedObject = mockk<PersistedObject>()
    private var serverStarted = false

    init {
        every { persistedObject.getBoolean(any()) } returns true
        every { persistedObject.getString(any()) } returns "127.0.0.1"
        every { persistedObject.getString("localBearerToken") } returns testBearerToken
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
    fun `streamable HTTP endpoint should accept connections and list tools`() = runBlocking {
        try {
            client.connectToServer("http://127.0.0.1:${testPort}/mcp")
            assertTrue(client.isConnected(), "Client should be connected to server")
            
            val tools = client.listTools()
            assertFalse(tools.isEmpty(), "Server should have registered tools")
            
            val toolNames = tools.map { it.name }
            assertTrue(toolNames.contains("output_project_options"), "Server should have output_project_options tool")
            assertTrue(toolNames.contains("output_user_options"), "Server should have output_user_options tool")
            
            val pingResult = client.ping()
            assertNotNull(pingResult, "Ping should return a result")
        } catch (e: Exception) {
            fail("Connection failed: ${e.message}")
        }
    }
}