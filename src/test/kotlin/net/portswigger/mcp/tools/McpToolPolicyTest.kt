package net.portswigger.mcp.tools

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.modelcontextprotocol.kotlin.sdk.server.ClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.McpAuditRecord
import net.portswigger.mcp.security.McpAuditSink
import net.portswigger.mcp.security.McpSessionApproval
import net.portswigger.mcp.security.McpSessionApprovalRegistry
import net.portswigger.mcp.security.grantCurrentSessionApproval
import net.portswigger.mcp.security.isCurrentSessionApproved
import net.portswigger.mcp.security.recordCurrentToolApproval
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.CopyOnWriteArrayList

class McpToolPolicyTest {
    @Test
    fun `emergency read-only mode allows annotated reads and blocks mutation before execution`() = runBlocking {
        val config = configFixture()
        config.emergencyReadOnlyMode = true
        val audit = RecordingAuditSink()
        val server = Server(
            serverInfo = Implementation("test", "1"),
            options = ServerOptions(capabilities = ServerCapabilities(tools = ServerCapabilities.Tools())),
        )
        server.bindToolRuntimePolicy(config, audit)
        var mutationExecuted = false

        server.mcpTool(
            name = "safe_read",
            description = "read",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) {
            recordCurrentToolApproval("data_access:test", "policy_allow")
            "read result"
        }
        server.mcpTool(
            name = "unsafe_write",
            description = "write",
            annotations = PROJECT_MUTATION_TOOL_ANNOTATIONS,
        ) {
            mutationExecuted = true
            "write result"
        }

        val connection = mockk<ClientConnection>(relaxed = true) {
            every { sessionId } returns "session-to-correlate"
        }
        val readResult = server.tools.getValue("safe_read").handler(
            connection,
            CallToolRequest(CallToolRequestParams("safe_read")),
        )
        val writeResult = server.tools.getValue("unsafe_write").handler(
            connection,
            CallToolRequest(CallToolRequestParams("unsafe_write")),
        )

        assertFalse(readResult.isError == true)
        assertTrue(writeResult.isError == true)
        assertFalse(mutationExecuted)
        assertEquals(listOf("completed", "blocked_read_only"), audit.records.map { it.outcome })
        assertEquals("policy_allow", audit.records.first().approvals.single().decision)
        assertTrue(audit.records.all { it.sessionCorrelation.matches(Regex("[a-f0-9]{12}")) })

        config.emergencyReadOnlyMode = false
        server.bindToolRuntimePolicy(config, ThrowingAuditSink())
        val resultWithBrokenAudit = server.tools.getValue("safe_read").handler(
            connection,
            CallToolRequest(CallToolRequestParams("safe_read")),
        )
        assertFalse(resultWithBrokenAudit.isError == true, "Audit failure must not change a completed tool result")

        server.unbindToolRuntimePolicy()
        server.close()
    }

    @Test
    fun `audit stores only declared argument field names`() = runBlocking {
        val config = configFixture()
        val audit = RecordingAuditSink()
        val server = Server(
            serverInfo = Implementation("test", "1"),
            options = ServerOptions(capabilities = ServerCapabilities(tools = ServerCapabilities.Tools())),
        )
        server.bindToolRuntimePolicy(config, audit)
        server.mcpTool<AuditArgumentProbe>(
            description = "audit argument probe",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) {
            "ok"
        }

        val connection = mockk<ClientConnection>(relaxed = true) {
            every { sessionId } returns "audit-argument-session"
        }
        val arguments = buildJsonObject {
            put("allowed", JsonPrimitive("ok"))
            put("credentialSmugglingField", JsonPrimitive("ignored"))
        }
        server.tools.getValue("audit_argument_probe").handler(
            connection,
            CallToolRequest(CallToolRequestParams("audit_argument_probe", arguments)),
        )

        assertEquals(listOf("allowed"), audit.records.single().argumentKeys)
        server.unbindToolRuntimePolicy()
        server.close()
    }

    @Test
    fun `tool execution receives only the approval state for its actual MCP session`() = runBlocking {
        val config = configFixture()
        val audit = RecordingAuditSink()
        val approvals = McpSessionApprovalRegistry(2)
        assertTrue(approvals.activate("approval-session"))
        assertTrue(approvals.activate("other-session"))
        val server = Server(
            serverInfo = Implementation("test", "1"),
            options = ServerOptions(capabilities = ServerCapabilities(tools = ServerCapabilities.Tools())),
        )
        server.bindToolRuntimePolicy(config, audit, approvals)
        server.mcpTool(
            name = "approval_context_probe",
            description = "approval context probe",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) {
            if (!isCurrentSessionApproved(McpSessionApproval.OUTBOUND_HTTP)) {
                grantCurrentSessionApproval(McpSessionApproval.OUTBOUND_HTTP)
            }
            assertTrue(isCurrentSessionApproved(McpSessionApproval.OUTBOUND_HTTP))
            "ok"
        }
        val approvedConnection = mockk<ClientConnection>(relaxed = true) {
            every { sessionId } returns "approval-session"
        }
        val otherConnection = mockk<ClientConnection>(relaxed = true) {
            every { sessionId } returns "other-session"
        }

        server.tools.getValue("approval_context_probe").handler(
            approvedConnection,
            CallToolRequest(CallToolRequestParams("approval_context_probe")),
        )
        assertTrue(approvals.isGranted("approval-session", McpSessionApproval.OUTBOUND_HTTP))
        assertFalse(approvals.isGranted("other-session", McpSessionApproval.OUTBOUND_HTTP))

        server.tools.getValue("approval_context_probe").handler(
            otherConnection,
            CallToolRequest(CallToolRequestParams("approval_context_probe")),
        )
        assertTrue(approvals.isGranted("other-session", McpSessionApproval.OUTBOUND_HTTP))
        assertEquals(listOf("session_grant", "session_grant"), audit.records.map { it.approvals.single().decision })

        server.unbindToolRuntimePolicy()
        server.close()
    }

    @Test
    fun `unavailable connection session ID cannot inherit a synthetic session approval`() = runBlocking {
        val approvals = McpSessionApprovalRegistry(1)
        assertTrue(approvals.activate("unknown"))
        requireNotNull(approvals.contextFor("unknown")).grant(McpSessionApproval.OUTBOUND_HTTP)
        val server = Server(
            serverInfo = Implementation("test", "1"),
            options = ServerOptions(capabilities = ServerCapabilities(tools = ServerCapabilities.Tools())),
        )
        server.bindToolRuntimePolicy(configFixture(), RecordingAuditSink(), approvals)
        server.mcpTool(
            name = "missing_session_context_probe",
            description = "missing session context probe",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) {
            assertFalse(isCurrentSessionApproved(McpSessionApproval.OUTBOUND_HTTP))
            "ok"
        }
        val connection = mockk<ClientConnection>(relaxed = true) {
            every { sessionId } throws IllegalStateException("session unavailable")
        }

        val result = server.tools.getValue("missing_session_context_probe").handler(
            connection,
            CallToolRequest(CallToolRequestParams("missing_session_context_probe")),
        )

        assertFalse(result.isError == true)
        server.unbindToolRuntimePolicy()
        server.close()
    }

    @Test
    fun `paginated source status is preserved at nonzero offsets`() = runBlocking {
        val server = Server(
            serverInfo = Implementation("test", "1"),
            options = ServerOptions(capabilities = ServerCapabilities(tools = ServerCapabilities.Tools())),
        )
        server.bindToolRuntimePolicy(configFixture(), RecordingAuditSink())
        server.mcpPaginatedSequenceTool<PageProbe, String>(description = "page probe") {
            PaginatedSource.Message("source access denied")
        }
        val connection = mockk<ClientConnection>(relaxed = true) {
            every { sessionId } returns "page-session"
        }
        val arguments = buildJsonObject {
            put("count", JsonPrimitive(1))
            put("offset", JsonPrimitive(10))
        }

        val result = server.tools.getValue("page_probe").handler(
            connection,
            CallToolRequest(CallToolRequestParams("page_probe", arguments)),
        )

        assertEquals("source access denied", (result.content.single() as TextContent).text)
        server.unbindToolRuntimePolicy()
        server.close()
    }

    private fun configFixture(): McpConfig {
        val storage = mutableMapOf<String, Any>()
        val persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { storage[firstArg<String>()] as? Boolean }
            every { getString(any()) } answers { storage[firstArg<String>()] as? String }
            every { getInteger(any()) } answers { storage[firstArg<String>()] as? Int }
            every { setBoolean(any(), any()) } answers {
                storage[firstArg<String>()] = secondArg<Boolean>()
            }
            every { setString(any(), any()) } answers {
                storage[firstArg<String>()] = secondArg<String>()
            }
            every { setInteger(any(), any()) } answers {
                storage[firstArg<String>()] = secondArg<Int>()
            }
        }
        return McpConfig(persistedObject, mockk<Logging>(relaxed = true))
    }

    @Serializable
    private data class AuditArgumentProbe(val allowed: String)

    @Serializable
    private data class PageProbe(
        override val count: Int = 10,
        override val offset: Int = 0,
    ) : Paginated

    private class ThrowingAuditSink : McpAuditSink {
        override fun append(record: McpAuditRecord): Unit = error("audit unavailable")
        override fun recordLocalEvent(tool: String, outcome: String) = Unit
        override fun snapshot(limit: Int): List<McpAuditRecord> = emptyList()
        override fun size(): Int = 0
        override fun clear() = Unit
        override fun trimToConfiguredRetention() = Unit
        override fun flush() = Unit
        override fun exportJsonLines(limit: Int): String = ""
        override fun close() = Unit
    }

    private class RecordingAuditSink : McpAuditSink {
        val records = CopyOnWriteArrayList<McpAuditRecord>()
        override fun append(record: McpAuditRecord) {
            records += record
        }
        override fun recordLocalEvent(tool: String, outcome: String) = Unit
        override fun snapshot(limit: Int): List<McpAuditRecord> = records.takeLast(limit)
        override fun size(): Int = records.size
        override fun clear() = records.clear()
        override fun trimToConfiguredRetention() = Unit
        override fun flush() = Unit
        override fun exportJsonLines(limit: Int): String = ""
        override fun close() = Unit
    }
}
