package net.portswigger.mcp

import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import io.ktor.server.testing.testApplication
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class McpHttpEndpointBoundsTest {
    @Test
    fun `chunked initialize body is accepted`() = testApplication {
        val server = testServer()
        application { configureMcpHttpEndpoint(server, port = 80) }

        val response = client.post("/mcp") {
            header(HttpHeaders.Host, "localhost:80")
            header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            header(HttpHeaders.Accept, "application/json, text/event-stream")
            setBody(chunkedInitializeBody(delayMillis = 10))
        }

        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        assertTrue(response.bodyAsText().contains("\"protocolVersion\":\"2025-11-25\""))
        runBlocking { server.close() }
    }

    @Test
    fun `malformed and noncanonical Host headers are rejected before MCP handling`() {
        val port = ServerSocket(0).use { it.localPort }
        val server = testServer()
        val engine = embeddedServer(CIO, host = "127.0.0.1", port = port) {
            configureMcpHttpEndpoint(server, port)
        }.start()

        try {
            listOf(
                "localhost:",
                "localhost:000$port",
                "localhost:0",
                "localhost:65535",
                "user@localhost:$port",
                "127.0.0.2:$port",
            ).forEach { host ->
                val response = sendRawRequest(port, host, "{}")
                assertTrue(
                    response.startsWith("HTTP/1.1 403") || response.startsWith("HTTP/1.0 400") ||
                        response.startsWith("HTTP/1.1 400"),
                    "$host: $response",
                )
            }
        } finally {
            engine.stop(100, 1_000)
            runBlocking { server.close() }
        }
    }

    @Test
    fun `oversized chunked body is rejected`() = testApplication {
        val server = testServer()
        application { configureMcpHttpEndpoint(server, port = 80) }

        val response = client.post("/mcp") {
            header(HttpHeaders.Host, "localhost:80")
            header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            header(HttpHeaders.Accept, "application/json, text/event-stream")
            setBody(object : OutgoingContent.WriteChannelContent() {
                override val contentType: ContentType = ContentType.Application.Json
                override suspend fun writeTo(channel: ByteWriteChannel) {
                    channel.writeFully(ByteArray(2 * 1024 * 1024 + 1) { 'x'.code.toByte() })
                }
            })
        }

        assertEquals(HttpStatusCode.PayloadTooLarge, response.status, response.bodyAsText())
        runBlocking { server.close() }
    }

    @Test
    fun `slow chunked body within the CIO idle bound is accepted`() {
        val port = ServerSocket(0).use { it.localPort }
        val server = testServer()
        val engine = embeddedServer(CIO, host = "127.0.0.1", port = port) {
            configureMcpHttpEndpoint(server, port)
        }.start()

        try {
            val response = sendSlowChunkedRequest(port)
            assertTrue(response.startsWith("HTTP/1.1 200"), response)
            assertTrue(response.contains("\"protocolVersion\":\"2025-11-25\""), response)
        } finally {
            engine.stop(100, 1_000)
            runBlocking { server.close() }
        }
    }

    private fun testServer(): Server = Server(
        serverInfo = Implementation("endpoint-bounds-test", "1.0"),
        options = ServerOptions(
            capabilities = ServerCapabilities(
                tools = ServerCapabilities.Tools(listChanged = false),
            )
        ),
    )

    private fun sendRawRequest(port: Int, host: String, body: String): String =
        Socket("127.0.0.1", port).use { socket ->
            socket.soTimeout = 2_000
            val bytes = body.toByteArray(StandardCharsets.UTF_8)
            socket.getOutputStream().write(
                ("POST /mcp HTTP/1.1\r\n" +
                    "Host: $host\r\n" +
                    "Content-Type: application/json\r\n" +
                    "Accept: application/json, text/event-stream\r\n" +
                    "Content-Length: ${bytes.size}\r\n" +
                    "Connection: close\r\n\r\n").toByteArray(StandardCharsets.US_ASCII) + bytes
            )
            socket.getOutputStream().flush()
            socket.getInputStream().readBytes().toString(StandardCharsets.UTF_8)
        }

    private fun sendSlowChunkedRequest(port: Int): String = Socket("127.0.0.1", port).use { socket ->
        socket.soTimeout = 2_000
        val output = socket.getOutputStream()
        output.write(
            ("POST /mcp HTTP/1.1\r\n" +
                "Host: 127.0.0.1:$port\r\n" +
                "Content-Type: application/json\r\n" +
                "Accept: application/json, text/event-stream\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "Connection: close\r\n\r\n").toByteArray(StandardCharsets.US_ASCII)
        )
        val firstChunk = "{\"jsonrpc\":\"2.0\",".toByteArray(StandardCharsets.UTF_8)
        output.write("${firstChunk.size.toString(16)}\r\n".toByteArray(StandardCharsets.US_ASCII))
        output.write(firstChunk)
        output.write("\r\n".toByteArray(StandardCharsets.US_ASCII))
        output.flush()
        Thread.sleep(300)
        val finalChunk = (
            "\"id\":1,\"method\":\"initialize\",\"params\":{" +
                "\"protocolVersion\":\"2025-11-25\",\"capabilities\":{}," +
                "\"clientInfo\":{\"name\":\"slow-chunk-test\",\"version\":\"1.0\"}}}"
            ).toByteArray(StandardCharsets.UTF_8)
        output.write("${finalChunk.size.toString(16)}\r\n".toByteArray(StandardCharsets.US_ASCII))
        output.write(finalChunk)
        output.write("\r\n0\r\n\r\n".toByteArray(StandardCharsets.US_ASCII))
        output.flush()
        socket.getInputStream().readBytes().toString(StandardCharsets.UTF_8)
    }

    private fun chunkedInitializeBody(delayMillis: Long): OutgoingContent =
        object : OutgoingContent.WriteChannelContent() {
            override val contentType: ContentType = ContentType.Application.Json

            override suspend fun writeTo(channel: ByteWriteChannel) {
                channel.writeStringUtf8(
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{"
                )
                channel.flush()
                delay(delayMillis)
                channel.writeStringUtf8(
                    "\"protocolVersion\":\"2025-11-25\",\"capabilities\":{}," +
                        "\"clientInfo\":{\"name\":\"chunked-test\",\"version\":\"1.0\"}}}"
                )
            }
        }
}
