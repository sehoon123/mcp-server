package net.portswigger.mcp

import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlinx.serialization.Serializable
import net.portswigger.mcp.tools.READ_ONLY_TOOL_ANNOTATIONS
import net.portswigger.mcp.tools.mcpStructuredTool
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class McpHttpCancellationIntegrationTest {
    @Test
    fun `authenticated session deletion cancels an in-flight structured tool`() = runBlocking {
        val port = ServerSocket(0).use { it.localPort }
        val endpoint = URI("http://127.0.0.1:$port/mcp")
        val bearerToken = "0123456789012345678901234567890123456789012"
        val metrics = McpRuntimeMetrics("cancellation-integration-test", maxHttpCalls = 64, maxSessions = 2)
        val server = Server(
            serverInfo = Implementation("cancellation-integration-test", "1.0"),
            options = ServerOptions(
                capabilities = ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)),
            ),
        )
        val entered = CompletableDeferred<Unit>()
        val cancelled = CompletableDeferred<Unit>()
        val completed = AtomicBoolean(false)
        server.mcpStructuredTool<CancellationProbe, CancellationProbeResult>(
            description = "cancellation integration probe",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) {
            entered.complete(Unit)
            try {
                while (true) yield()
            } catch (error: CancellationException) {
                cancelled.complete(Unit)
                throw error
            }
            @Suppress("UNREACHABLE_CODE")
            CancellationProbeResult(completed.also { it.set(true) }.get())
        }
        val engine = embeddedServer(CIO, host = "127.0.0.1", port = port) {
            configureMcpHttpEndpoint(
                server,
                port,
                bearerToken = bearerToken,
                runtimeMetrics = metrics,
                maxSessions = 2,
            )
        }.start()
        val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build()

        try {
            val sessionId = initialize(client, endpoint, bearerToken)
            notifyInitialized(client, endpoint, sessionId, bearerToken)
            val toolCall = client.sendAsync(
                request(endpoint, bearerToken, sessionId)
                    .POST(HttpRequest.BodyPublishers.ofString(
                        """{"jsonrpc":"2.0","id":77,"method":"tools/call","params":{"name":"cancellation_probe","arguments":{}}}""",
                    ))
                    .build(),
                HttpResponse.BodyHandlers.ofString(),
            )
            withTimeout(5_000) { entered.await() }

            assertEquals(401, delete(client, endpoint, sessionId, bearerToken = null))
            assertFalse(cancelled.isCompleted)
            assertFalse(toolCall.isDone)

            assertTrue(delete(client, endpoint, sessionId, bearerToken) in setOf(200, 202))
            withTimeout(5_000) { cancelled.await() }

            runCatching { toolCall.get(5, TimeUnit.SECONDS) }
            assertFalse(completed.get())
            awaitNoActiveCalls(metrics)
        } finally {
            runCatching { engine.stop(100, 3_000) }
            server.close()
        }
    }

    private fun initialize(client: HttpClient, endpoint: URI, bearerToken: String): String {
        val response = client.send(
            request(endpoint, bearerToken)
                .POST(HttpRequest.BodyPublishers.ofString(
                    """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"cancellation-test","version":"1"}}}""",
                ))
                .build(),
            HttpResponse.BodyHandlers.discarding(),
        )
        assertEquals(200, response.statusCode())
        return response.headers().firstValue("Mcp-Session-Id").orElseThrow()
    }

    private fun notifyInitialized(
        client: HttpClient,
        endpoint: URI,
        sessionId: String,
        bearerToken: String,
    ) {
        val status = client.send(
            request(endpoint, bearerToken, sessionId)
                .POST(HttpRequest.BodyPublishers.ofString(
                    """{"jsonrpc":"2.0","method":"notifications/initialized"}""",
                ))
                .build(),
            HttpResponse.BodyHandlers.discarding(),
        ).statusCode()
        assertTrue(status in setOf(200, 202))
    }

    private fun request(
        endpoint: URI,
        bearerToken: String?,
        sessionId: String? = null,
    ): HttpRequest.Builder = HttpRequest.newBuilder(endpoint)
        .timeout(Duration.ofSeconds(5))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Protocol-Version", "2025-11-25")
        .also { builder -> bearerToken?.let { builder.header("Authorization", "Bearer $it") } }
        .also { builder -> sessionId?.let { builder.header("Mcp-Session-Id", it) } }

    private fun delete(
        client: HttpClient,
        endpoint: URI,
        sessionId: String,
        bearerToken: String?,
    ): Int = client.send(
            request(endpoint, bearerToken, sessionId).DELETE().build(),
            HttpResponse.BodyHandlers.discarding(),
        ).statusCode()

    private fun awaitNoActiveCalls(metrics: McpRuntimeMetrics) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (metrics.snapshot().activeHttpCalls != 0 && System.nanoTime() < deadline) {
            Thread.sleep(10)
        }
        assertEquals(0, metrics.snapshot().activeHttpCalls)
    }
}

@Serializable
private class CancellationProbe

@Serializable
private data class CancellationProbeResult(val completed: Boolean)
