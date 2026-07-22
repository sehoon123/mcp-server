package net.portswigger.mcp

import io.ktor.server.engine.embeddedServer
import io.ktor.server.cio.CIO
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import net.portswigger.mcp.tools.StructuredToolResponse
import net.portswigger.mcp.tools.mcpStructuredToolWithContext

@Serializable
private data class TestToolWithProgress(val fixture: String? = null)

@Serializable
private data class TestToolWithProgressResult(val status: String)

/** Minimal executable fixture that exercises the production HTTP endpoint configuration. */
fun main() {
    val port = System.getenv("MCP_CONFORMANCE_PORT")?.toIntOrNull() ?: 9877
    val mcpServer = Server(
        serverInfo = Implementation(name = "burp-mcp-conformance", version = "2.1.1"),
        options = ServerOptions(
            capabilities = ServerCapabilities(
                tools = ServerCapabilities.Tools(listChanged = false),
            ),
        ),
    ).apply {
        mcpStructuredToolWithContext<TestToolWithProgress, TestToolWithProgressResult>(
            description = "Conformance fixture that emits monotonic progress notifications",
        ) {
            reportProgress(0.0, 100.0, "started")
            delay(50)
            reportProgress(50.0, 100.0, "halfway")
            delay(50)
            reportProgress(100.0, 100.0, "completed")
            StructuredToolResponse(TestToolWithProgressResult("ok"), "ok")
        }
        addTool(
            name = "conformance_probe",
            description = "Returns a deterministic response for transport conformance checks",
        ) {
            CallToolResult(content = listOf(TextContent("ok")))
        }
    }
    val engine = embeddedServer(CIO, host = "127.0.0.1", port = port) {
        configureMcpHttpEndpoint(mcpServer, port)
    }

    Runtime.getRuntime().addShutdownHook(Thread {
        engine.stop(500, 1_000)
        runBlocking { mcpServer.close() }
    })
    engine.start(wait = true)
}
