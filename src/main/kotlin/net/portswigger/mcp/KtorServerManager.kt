package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcp
import io.modelcontextprotocol.kotlin.sdk.server.mcpStreamableHttp
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.tools.registerTools
import java.net.URI
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class KtorServerManager(private val api: MontoyaApi) : ServerManager {

    private companion object {
        val LOOPBACK_HOSTS = setOf("localhost", "127.0.0.1", "::1", "[::1]")
    }

    private val serverVersion = KtorServerManager::class.java.`package`.implementationVersion ?: "dev"
    private var server: EmbeddedServer<*, *>? = null
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()

    override fun start(config: McpConfig, callback: (ServerState) -> Unit) {
        callback(ServerState.Starting)

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null

                val mcpServer = Server(
                    serverInfo = Implementation("burp-suite", serverVersion), options = ServerOptions(
                        capabilities = ServerCapabilities(
                            tools = ServerCapabilities.Tools(listChanged = false)
                        )
                    )
                )
                mcpServer.registerTools(api, config)

                server = embeddedServer(Netty, port = config.port, host = config.host) {
                    install(CORS) {
                        allowHost("localhost:${config.port}")
                        allowHost("127.0.0.1:${config.port}")
                        allowOrigins(::isLoopbackOrigin)

                        allowMethod(HttpMethod.Options)
                        allowMethod(HttpMethod.Get)
                        allowMethod(HttpMethod.Post)
                        allowMethod(HttpMethod.Delete)

                        allowHeader(HttpHeaders.ContentType)
                        allowHeader(HttpHeaders.Accept)
                        allowHeader("Last-Event-ID")
                        allowHeader("Mcp-Session-Id")
                        allowHeader("Mcp-Protocol-Version")
                        exposeHeader("Mcp-Session-Id")
                        exposeHeader("Mcp-Protocol-Version")

                        allowCredentials = false
                        allowNonSimpleContentTypes = true
                        maxAgeInSeconds = 3600
                    }

                    intercept(ApplicationCallPipeline.Call) {
                        call.response.header("X-Frame-Options", "DENY")
                        call.response.header("X-Content-Type-Options", "nosniff")
                        call.response.header("Referrer-Policy", "same-origin")
                        call.response.header("Content-Security-Policy", "default-src 'none'")
                    }

                    // Streamable HTTP is the primary transport. It uses one MCP endpoint and
                    // returns JSON for ordinary request/response calls instead of the legacy two-endpoint SSE flow.
                    mcpStreamableHttp(path = "/mcp") {
                        mcpServer
                    }

                    // Keep the deprecated HTTP+SSE transport at the original root endpoint
                    // temporarily for existing proxy installations.
                    routing {
                        mcp(path = "/") { mcpServer }
                    }
                }.apply {
                    start(wait = false)
                }

                api.logging().logToOutput(
                    "Started MCP server on ${config.host}:${config.port} " +
                        "(Streamable HTTP: /mcp, legacy SSE: /)"
                )
                callback(ServerState.Running)

            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun stop(callback: (ServerState) -> Unit) {
        callback(ServerState.Stopping)

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null
                api.logging().logToOutput("Stopped MCP server")
                callback(ServerState.Stopped)
            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    private fun isLoopbackOrigin(origin: String): Boolean = runCatching {
        URI(origin).host?.lowercase() in LOOPBACK_HOSTS
    }.getOrDefault(false)

    override fun shutdown() {
        server?.stop(1000, 5000)
        server = null

        executor.shutdown()
        executor.awaitTermination(10, TimeUnit.SECONDS)
    }
}
