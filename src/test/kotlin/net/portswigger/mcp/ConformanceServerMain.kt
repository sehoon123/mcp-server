package net.portswigger.mcp

import io.ktor.server.engine.embeddedServer
import io.ktor.server.cio.CIO
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.GetPromptResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.Prompt
import io.modelcontextprotocol.kotlin.sdk.types.PromptArgument
import io.modelcontextprotocol.kotlin.sdk.types.PromptMessage
import io.modelcontextprotocol.kotlin.sdk.types.ReadResourceResult
import io.modelcontextprotocol.kotlin.sdk.types.ResourceTemplate
import io.modelcontextprotocol.kotlin.sdk.types.Role
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.TextResourceContents
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
        serverInfo = Implementation(name = "burp-mcp-conformance", version = "4.4.0"),
        options = ServerOptions(
            capabilities = ServerCapabilities(
                tools = ServerCapabilities.Tools(listChanged = false),
                resources = ServerCapabilities.Resources(listChanged = false, subscribe = false),
                prompts = ServerCapabilities.Prompts(listChanged = false),
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
        addResource(
            uri = "test://static-text",
            name = "conformance_static_text",
            description = "Deterministic text resource for MCP conformance checks.",
            mimeType = "text/plain",
        ) { request ->
            ReadResourceResult(
                listOf(
                    TextResourceContents(
                        text = "This is the content of the static text resource.",
                        uri = request.uri,
                        mimeType = "text/plain",
                    )
                )
            )
        }
        addResourceTemplate(
            ResourceTemplate(
                uriTemplate = "test://template/{id}/data",
                name = "conformance_template",
                description = "Deterministic resource-template fixture.",
                mimeType = "application/json",
            ),
        ) { request, variables ->
            val id = variables.getValue("id")
            ReadResourceResult(
                listOf(
                    TextResourceContents(
                        text = "{\"id\":\"$id\",\"templateTest\":true,\"data\":\"Data for ID: $id\"}",
                        uri = request.uri,
                        mimeType = "application/json",
                    )
                )
            )
        }
        addPrompt(
            Prompt(
                name = "test_simple_prompt",
                description = "Deterministic simple prompt for MCP conformance checks.",
            )
        ) {
            GetPromptResult(
                messages = listOf(
                    PromptMessage(Role.User, TextContent("This is a simple prompt for testing."))
                )
            )
        }
        addPrompt(
            Prompt(
                name = "test_prompt_with_arguments",
                description = "Deterministic argument-substitution prompt for MCP conformance checks.",
                arguments = listOf(
                    PromptArgument("arg1", "First test argument.", required = true),
                    PromptArgument("arg2", "Second test argument.", required = true),
                ),
            )
        ) { request ->
            val arguments = request.arguments.orEmpty()
            GetPromptResult(
                messages = listOf(
                    PromptMessage(
                        Role.User,
                        TextContent(
                            "Prompt with arguments: arg1='${arguments["arg1"]}', arg2='${arguments["arg2"]}'"
                        ),
                    )
                )
            )
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
