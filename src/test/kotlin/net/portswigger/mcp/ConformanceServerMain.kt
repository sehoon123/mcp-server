package net.portswigger.mcp

import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.runBlocking

/** Minimal executable fixture that exercises the production HTTP endpoint configuration. */
fun main() {
    val port = System.getenv("MCP_CONFORMANCE_PORT")?.toIntOrNull() ?: 9877
    val mcpServer = Server(
        serverInfo = Implementation(name = "burp-mcp-conformance", version = "2.0.0"),
        options = ServerOptions(
            capabilities = ServerCapabilities(
                tools = ServerCapabilities.Tools(listChanged = false),
            ),
        ),
    ).apply {
        addTool(
            name = "conformance_probe",
            description = "Returns a deterministic response for transport conformance checks",
        ) {
            CallToolResult(content = listOf(TextContent("ok")))
        }
    }
    val engine = embeddedServer(Netty, host = "127.0.0.1", port = port) {
        configureMcpHttpEndpoint(mcpServer, port)
    }

    Runtime.getRuntime().addShutdownHook(Thread {
        engine.stop(500, 1_000)
        runBlocking { mcpServer.close() }
    })
    engine.start(wait = true)
}
