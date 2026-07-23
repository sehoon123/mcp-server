package net.portswigger.mcp

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.ktor.client.request.delete
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.McpSessionApproval
import net.portswigger.mcp.security.McpSessionApprovalRegistry
import net.portswigger.mcp.security.McpSessionApprovalSummary
import net.portswigger.mcp.security.NoOpMcpAuditSink
import net.portswigger.mcp.security.grantCurrentSessionApproval
import net.portswigger.mcp.tools.READ_ONLY_TOOL_ANNOTATIONS
import net.portswigger.mcp.tools.bindToolRuntimePolicy
import net.portswigger.mcp.tools.mcpTool
import net.portswigger.mcp.tools.unbindToolRuntimePolicy
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class McpSessionApprovalIntegrationTest {
    @Test
    fun `tool grant follows the HTTP session and authenticated DELETE removes it`() = testApplication {
        val approvals = McpSessionApprovalRegistry(maxSessions = 2)
        val server = Server(
            serverInfo = Implementation("session-approval-test", "1.0"),
            options = ServerOptions(
                capabilities = ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)),
            ),
        )
        server.bindToolRuntimePolicy(configFixture(), NoOpMcpAuditSink, approvals)
        server.mcpTool(
            name = "grant_http_for_session",
            description = "test-only session grant",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) {
            grantCurrentSessionApproval(McpSessionApproval.OUTBOUND_HTTP)
            "granted"
        }
        application {
            configureMcpHttpEndpoint(
                mcpServer = server,
                port = 80,
                maxSessions = 2,
                sessionApprovals = approvals,
            )
        }

        fun io.ktor.client.request.HttpRequestBuilder.mcpHeaders(sessionId: String? = null) {
            header(HttpHeaders.Host, "localhost:80")
            header(HttpHeaders.Accept, "application/json, text/event-stream")
            header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            header("Mcp-Protocol-Version", PRODUCTION_MCP_PROTOCOL_VERSION)
            if (sessionId != null) header("Mcp-Session-Id", sessionId)
        }

        try {
            val initialized = client.post("/mcp") {
                mcpHeaders()
                setBody(
                    """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"session-approval-test","version":"1"}}}"""
                )
            }
            assertEquals(HttpStatusCode.OK, initialized.status, initialized.bodyAsText())
            val sessionId = requireNotNull(initialized.headers["Mcp-Session-Id"])

            val notification = client.post("/mcp") {
                mcpHeaders(sessionId)
                setBody("""{"jsonrpc":"2.0","method":"notifications/initialized"}""")
            }
            assertTrue(notification.status == HttpStatusCode.OK || notification.status == HttpStatusCode.Accepted)

            val toolCall = client.post("/mcp") {
                mcpHeaders(sessionId)
                setBody(
                    """{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"grant_http_for_session","arguments":{}}}"""
                )
            }
            assertEquals(HttpStatusCode.OK, toolCall.status, toolCall.bodyAsText())
            assertTrue(toolCall.bodyAsText().contains("granted"))
            assertEquals(McpSessionApprovalSummary(1, 1), approvals.summary())

            val deleted = client.delete("/mcp") { mcpHeaders(sessionId) }
            assertTrue(deleted.status == HttpStatusCode.OK || deleted.status == HttpStatusCode.Accepted)
            assertEquals(McpSessionApprovalSummary(0, 0), approvals.summary())
        } finally {
            server.unbindToolRuntimePolicy()
            runBlocking { server.close() }
        }
    }

    private fun configFixture(): McpConfig {
        val storage = mutableMapOf<String, Any>()
        val persisted = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { storage[firstArg()] as? Boolean }
            every { getString(any()) } answers { storage[firstArg()] as? String }
            every { getInteger(any()) } answers { storage[firstArg()] as? Int }
            every { setBoolean(any(), any()) } answers { storage[firstArg()] = secondArg<Boolean>() }
            every { setString(any(), any()) } answers { storage[firstArg()] = secondArg<String>() }
            every { setInteger(any(), any()) } answers { storage[firstArg()] = secondArg<Int>() }
        }
        return McpConfig(persisted, mockk<Logging>(relaxed = true))
    }
}
