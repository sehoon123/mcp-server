package net.portswigger.mcp

import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class McpHttpSessionStressTest {
    private data class InitializeResult(val status: Int, val sessionId: String?)

    @Test
    fun `disconnected optional streams are reclaimed before session capacity rejects a new client`() {
        val port = ServerSocket(0).use { it.localPort }
        val endpoint = URI("http://127.0.0.1:$port/mcp")
        val metrics = McpRuntimeMetrics("session-pressure-test", maxHttpCalls = 64, maxSessions = 2)
        val server = Server(
            serverInfo = Implementation("session-pressure-test", "1.0"),
            options = ServerOptions(
                capabilities = ServerCapabilities(
                    tools = ServerCapabilities.Tools(listChanged = false),
                )
            ),
        )
        val engine = embeddedServer(CIO, host = "127.0.0.1", port = port) {
            configureMcpHttpEndpoint(
                mcpServer = server,
                port = port,
                runtimeMetrics = metrics,
                maxSessions = 2,
                sseHeartbeatMillis = 25,
            )
        }.start()
        val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build()

        try {
            val first = initialize(client, endpoint, 1)
            assertEquals(200, first.status)
            val firstSession = requireNotNull(first.sessionId)
            notifyInitialized(client, endpoint, firstSession)
            disconnectOptionalStream(client, endpoint, firstSession)
            awaitNoActiveCalls(metrics)

            val second = initialize(client, endpoint, 2)
            assertEquals(200, second.status)
            val secondSession = requireNotNull(second.sessionId)
            notifyInitialized(client, endpoint, secondSession)
            disconnectOptionalStream(client, endpoint, secondSession)
            awaitNoActiveCalls(metrics)

            val replacement = initialize(client, endpoint, 3)
            assertEquals(200, replacement.status)
            val replacementSession = requireNotNull(replacement.sessionId)

            assertEquals(404, ping(client, endpoint, firstSession))
            assertEquals(200, ping(client, endpoint, secondSession))
            assertEquals(2, metrics.snapshot().activeSessions)
            assertEquals(0, metrics.snapshot().sessionCapacityRejections)

            assertTrue(delete(client, endpoint, secondSession) in setOf(200, 202))
            assertTrue(delete(client, endpoint, replacementSession) in setOf(200, 202))
        } finally {
            runCatching { engine.stop(100, 3_000) }
            runBlocking { server.close() }
        }
    }

    @Test
    fun `session capacity is enforced reclaimed and safe during concurrent shutdown`() {
        val port = ServerSocket(0).use { it.localPort }
        val endpoint = URI("http://127.0.0.1:$port/mcp")
        val server = Server(
            serverInfo = Implementation("session-stress-test", "1.0"),
            options = ServerOptions(
                capabilities = ServerCapabilities(
                    tools = ServerCapabilities.Tools(listChanged = false),
                )
            ),
        )
        val engine = embeddedServer(CIO, host = "127.0.0.1", port = port) {
            configureMcpHttpEndpoint(server, port)
        }.start()
        val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build()
        val executor = Executors.newFixedThreadPool(48)

        try {
            val firstWave = initializeConcurrently(client, endpoint, executor, 48)
            assertEquals(32, firstWave.count { it.status == 200 }, firstWave.toString())
            assertEquals(16, firstWave.count { it.status == 503 }, firstWave.toString())
            val firstSessions = firstWave.mapNotNull { it.sessionId }
            assertEquals(32, firstSessions.distinct().size)

            val deleteStatuses = firstSessions.map { sessionId ->
                CompletableFuture.supplyAsync({ delete(client, endpoint, sessionId) }, executor)
            }.map { it.get(10, TimeUnit.SECONDS) }
            assertTrue(deleteStatuses.all { it == 200 || it == 202 }, deleteStatuses.toString())

            val secondWave = initializeConcurrently(client, endpoint, executor, 32)
            assertEquals(32, secondWave.count { it.status == 200 }, secondWave.toString())
            val secondSessions = secondWave.mapNotNull { it.sessionId }
            assertEquals(32, secondSessions.distinct().size)

            val shutdownStarted = System.nanoTime()
            val stop = CompletableFuture.runAsync({ engine.stop(100, 3_000) }, executor)
            val racingDeletes = secondSessions.map { sessionId ->
                CompletableFuture.runAsync({ runCatching { delete(client, endpoint, sessionId) } }, executor)
            }
            stop.get(5, TimeUnit.SECONDS)
            racingDeletes.forEach { runCatching { it.get(5, TimeUnit.SECONDS) } }
            val shutdownMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - shutdownStarted)
            assertTrue(shutdownMillis < 5_000, "Shutdown took ${shutdownMillis}ms")
        } finally {
            runCatching { engine.stop(100, 3_000) }
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
            runBlocking { server.close() }
        }
    }

    private fun initializeConcurrently(
        client: HttpClient,
        endpoint: URI,
        executor: java.util.concurrent.Executor,
        count: Int,
    ): List<InitializeResult> {
        val gate = CountDownLatch(1)
        val futures = (1..count).map { id ->
            CompletableFuture.supplyAsync({
                gate.await()
                initialize(client, endpoint, id)
            }, executor)
        }
        gate.countDown()
        return futures.map { it.get(10, TimeUnit.SECONDS) }
    }

    private fun initialize(client: HttpClient, endpoint: URI, id: Int): InitializeResult {
        val body = """
            {"jsonrpc":"2.0","id":$id,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"stress-$id","version":"1.0"}}}
        """.trimIndent()
        val request = HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(5))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("Mcp-Protocol-Version", "2025-11-25")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()
        val response = client.send(request, HttpResponse.BodyHandlers.discarding())
        return InitializeResult(
            response.statusCode(),
            response.headers().firstValue("Mcp-Session-Id").orElse(null),
        )
    }

    private fun notifyInitialized(client: HttpClient, endpoint: URI, sessionId: String) {
        val request = HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(5))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("Mcp-Protocol-Version", "2025-11-25")
            .header("Mcp-Session-Id", sessionId)
            .POST(HttpRequest.BodyPublishers.ofString(
                "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"
            ))
            .build()
        val status = client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode()
        assertTrue(status in setOf(200, 202), "Initialized notification returned HTTP $status")
    }

    private fun disconnectOptionalStream(client: HttpClient, endpoint: URI, sessionId: String) {
        val request = HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(5))
            .header("Accept", "text/event-stream")
            .header("Mcp-Protocol-Version", "2025-11-25")
            .header("Mcp-Session-Id", sessionId)
            .GET()
            .build()
        val response = client.send(request, HttpResponse.BodyHandlers.ofInputStream())
        assertEquals(200, response.statusCode())
        response.body().close()
    }

    private fun awaitNoActiveCalls(metrics: McpRuntimeMetrics) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (metrics.snapshot().activeHttpCalls != 0 && System.nanoTime() < deadline) {
            Thread.sleep(10)
        }
        assertEquals(0, metrics.snapshot().activeHttpCalls)
    }

    private fun ping(client: HttpClient, endpoint: URI, sessionId: String): Int {
        val request = HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(5))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("Mcp-Protocol-Version", "2025-11-25")
            .header("Mcp-Session-Id", sessionId)
            .POST(HttpRequest.BodyPublishers.ofString("{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"ping\"}"))
            .build()
        return client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode()
    }

    private fun delete(client: HttpClient, endpoint: URI, sessionId: String): Int {
        val request = HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(5))
            .header("Accept", "application/json, text/event-stream")
            .header("Mcp-Protocol-Version", "2025-11-25")
            .header("Mcp-Session-Id", sessionId)
            .DELETE()
            .build()
        return client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode()
    }
}
