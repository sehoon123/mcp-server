package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.response.*
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcpStreamableHttp
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.tools.registerTools
import java.net.URI
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

private val LOOPBACK_HOSTS = setOf("localhost", "127.0.0.1", "::1", "[::1]")

internal fun Application.configureMcpHttpEndpoint(mcpServer: Server, port: Int) {
    install(CORS) {
        allowHost("localhost:$port")
        allowHost("127.0.0.1:$port")
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

    // All HTTP clients, including the packaged stdio proxy, use the single
    // Streamable HTTP endpoint. The deprecated two-endpoint SSE transport is removed.
    mcpStreamableHttp(path = "/mcp") {
        mcpServer
    }
}

private fun isLoopbackOrigin(origin: String): Boolean = runCatching {
    URI(origin).host?.lowercase() in LOOPBACK_HOSTS
}.getOrDefault(false)

class KtorServerManager(private val api: MontoyaApi) : ServerManager {

    private val serverVersion = KtorServerManager::class.java.`package`.implementationVersion ?: "dev"
    private var server: EmbeddedServer<*, *>? = null
    private var mcpServer: Server? = null
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()

    override fun start(config: McpConfig, callback: (ServerState) -> Unit) {
        callback(ServerState.Starting)

        executor.submit {
            try {
                stopCurrentServer()

                val newMcpServer = Server(
                    serverInfo = Implementation("burp-suite", serverVersion), options = ServerOptions(
                        capabilities = ServerCapabilities(
                            tools = ServerCapabilities.Tools(listChanged = false)
                        )
                    )
                )
                newMcpServer.registerTools(api, config)
                mcpServer = newMcpServer

                val newEngine = embeddedServer(Netty, port = config.port, host = config.host) {
                    configureMcpHttpEndpoint(newMcpServer, config.port)
                }
                server = newEngine
                newEngine.start(wait = false)

                api.logging().logToOutput(
                    "Started MCP Streamable HTTP server at http://${config.host}:${config.port}/mcp"
                )
                callback(ServerState.Running)

            } catch (e: Exception) {
                runCatching { stopCurrentServer() }
                    .onFailure { cleanupError -> api.logging().logToError(cleanupError) }
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun stop(callback: (ServerState) -> Unit) {
        callback(ServerState.Stopping)

        executor.submit {
            try {
                stopCurrentServer()
                api.logging().logToOutput("Stopped MCP server")
                callback(ServerState.Stopped)
            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    private fun stopCurrentServer() {
        val currentEngine = server
        server = null
        try {
            currentEngine?.stop(1000, 5000)
        } finally {
            val currentMcpServer = mcpServer
            mcpServer = null
            if (currentMcpServer != null) {
                runBlocking { currentMcpServer.close() }
            }
        }
    }

    override fun shutdown() {
        runCatching {
            executor.submit { stopCurrentServer() }.get(10, TimeUnit.SECONDS)
        }.onFailure { api.logging().logToError(it) }

        executor.shutdown()
        if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
            executor.shutdownNow()
        }
    }
}
