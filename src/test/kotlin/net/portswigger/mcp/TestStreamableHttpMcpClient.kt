package net.portswigger.mcp

import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.sse.SSE
import io.ktor.client.request.header
import io.modelcontextprotocol.kotlin.sdk.client.Client
import io.modelcontextprotocol.kotlin.sdk.client.StreamableHttpClientTransport
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.EmptyResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.Tool
import org.slf4j.LoggerFactory

class TestStreamableHttpMcpClient(
    private val requestHeaders: Map<String, String> = emptyMap()
) {
    private val logger = LoggerFactory.getLogger(TestStreamableHttpMcpClient::class.java)
    private val mcp = Client(clientInfo = Implementation(name = "test-mcp-client", version = "1.0.0"))
    private val httpClient = HttpClient {
        install(SSE)
        install(HttpTimeout) {
            requestTimeoutMillis = 30000
            connectTimeoutMillis = 15000
        }
    }
    private var connected = false

    suspend fun connectToServer(url: String) {
        try {
            mcp.connect(
                StreamableHttpClientTransport(httpClient, url = url) {
                    requestHeaders.forEach { (name, value) -> header(name, value) }
                }
            )
            connected = true
            logger.info("Connected to Streamable HTTP MCP server")
        } catch (e: Exception) {
            logger.error("Failed to connect to Streamable HTTP MCP server", e)
            throw e
        }
    }

    fun isConnected(): Boolean = connected

    suspend fun ping(): EmptyResult = mcp.ping()

    suspend fun listTools(): List<Tool> = mcp.listTools().tools

    suspend fun callTool(toolName: String, arguments: Map<String, Any>): CallToolResult? =
        mcp.callTool(toolName, arguments)

    suspend fun close() {
        try {
            mcp.close()
        } finally {
            connected = false
            httpClient.close()
        }
    }
}
