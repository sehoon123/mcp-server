package net.portswigger.mcp.tools

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.modelcontextprotocol.kotlin.sdk.server.ClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ReadResourceResult
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.TextResourceContents
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
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
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.CopyOnWriteArrayList

class McpToolPolicyTest {
    @Test
    fun `emergency read-only mode allows annotated reads and blocks mutation before execution`() = runBlocking {
        val config = configFixture()
        config.approvalYoloMode = true
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
    fun `resource execution shares session approval audit and cancellation policy`() = runBlocking {
        val audit = RecordingAuditSink()
        val approvals = McpSessionApprovalRegistry(1)
        assertTrue(approvals.activate("resource-session"))
        val server = Server(
            serverInfo = Implementation("test", "1"),
            options = ServerOptions(capabilities = ServerCapabilities(resources = ServerCapabilities.Resources())),
        )
        server.bindToolRuntimePolicy(configFixture(), audit, approvals)
        val connection = mockk<ClientConnection>(relaxed = true) {
            every { sessionId } returns "resource-session"
        }
        val errorResult: (String) -> ReadResourceResult = { message ->
            ReadResourceResult(listOf(TextResourceContents(message, "burp://error", "application/json")))
        }

        val result = server.executeRegisteredResource(
            connection = connection,
            resourceName = "policy_probe",
            argumentKeys = listOf("projectId", "id"),
            onError = errorResult,
        ) {
            assertFalse(isCurrentSessionApproved(McpSessionApproval.HTTP_HISTORY))
            grantCurrentSessionApproval(McpSessionApproval.HTTP_HISTORY)
            ReadResourceResult(listOf(TextResourceContents("ok", "burp://probe", "application/json")))
        }
        assertEquals("ok", (result.contents.single() as TextResourceContents).text)
        assertTrue(approvals.isGranted("resource-session", McpSessionApproval.HTTP_HISTORY))

        var cancellationPropagated = false
        try {
            server.executeRegisteredResource(
                connection = connection,
                resourceName = "cancel_probe",
                onError = errorResult,
            ) {
                throw CancellationException("cancel test")
            }
        } catch (_: CancellationException) {
            cancellationPropagated = true
        }
        assertTrue(cancellationPropagated)
        assertEquals(listOf("completed", "cancelled"), audit.records.map { it.outcome })
        assertEquals("resource:policy_probe", audit.records.first().tool)
        assertEquals(listOf("id", "projectId"), audit.records.first().argumentKeys)

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
            // Explicit content avoids Unit-coercion overload ambiguity under Kotlin 2.4.
            listOf(TextContent("ok"))
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

    @Test
    fun `typed input errors give only bounded schema-owned hints in both wrappers`() = runBlocking {
        for (structured in listOf(false, true)) {
            val server = Server(
                Implementation("test", "1"),
                ServerOptions(capabilities = ServerCapabilities(tools = ServerCapabilities.Tools())),
            )
            val audit = RecordingAuditSink()
            server.bindToolRuntimePolicy(configFixture(), audit)
            var calls = 0
            if (structured) {
                server.mcpStructuredTool<DecodeProbe, DecodeOutput>("decode probe", READ_ONLY_TOOL_ANNOTATIONS) {
                    calls++
                    DecodeOutput(count.toDouble())
                }
            } else {
                server.mcpTool<DecodeProbe>("decode probe", READ_ONLY_TOOL_ANNOTATIONS) {
                    calls++
                    listOf(TextContent("ok"))
                }
            }
            val connection = mockk<ClientConnection>(relaxed = true) {
                every { sessionId } returns "decode-session"
            }
            suspend fun call(json: String?) = server.tools.getValue("decode_probe").handler(
                connection,
                CallToolRequest(CallToolRequestParams("decode_probe", json?.let { Json.parseToJsonElement(it).jsonObject })),
            )
            try {
                val invalid = listOf(
                    null to "MissingFieldException",
                    """{"PRIVATE_KEY":"PRIVATE_VALUE"}""" to "JsonDecodingException",
                    """{"required":"ok","count":"PRIVATE_VALUE"}""" to "JsonDecodingException",
                    """{"required":"ok","mode":"PRIVATE_ENUM"}""" to "SerializationException",
                    """{"required":"ok","nested":{}}""" to "MissingFieldException",
                    """{"required":null}""" to "JsonDecodingException",
                    """{"required":"ok","nested":[]}""" to "JsonDecodingException",
                    """{"required":"ok","labels":{"PRIVATE_MAP_KEY":1}}""" to "JsonDecodingException",
                    """{"required":"ok","nested":{"child":"ok","PRIVATE_NESTED_KEY":"PRIVATE_VALUE"}}""" to "JsonDecodingException",
                )
                for ((index, entry) in invalid.withIndex()) {
                    val result = call(entry.first)
                    val text = (result.content.single() as TextContent).text
                    assertTrue(result.isError == true)
                    assertNull(result.structuredContent)
                    assertTrue(text.contains("this call's handler was not started"), text)
                    assertTrue(text.contains("inputSchema"), text)
                    assertTrue(text.length <= MAX_STRUCTURED_TOOL_ERROR_CHARS)
                    assertFalse(text.contains("PRIVATE"), text)
                    assertFalse(text.contains("JSON input"), text)
                    assertEquals(index <= 1, text.contains("Missing required top-level fields: required."), text)
                    assertEquals(index == 1, text.contains("Unknown top-level fields"), text)
                    assertEquals(entry.second, audit.records.last().errorType)
                    assertEquals("error", audit.records.last().outcome)
                    assertEquals(0, calls)
                }
                assertFalse(audit.records.toString().contains("PRIVATE"))
                val valid = call("""{"required":"ok","count":2,"mode":"FIRST","nested":{"child":"ok"},"labels":{"key":"value"}}""")
                assertFalse(valid.isError == true)
                assertEquals(structured, valid.structuredContent != null)
                if (structured) assertEquals(JsonPrimitive(2.0), valid.structuredContent?.get("value"))
                assertEquals(1, calls)
                assertEquals("completed", audit.records.last().outcome)
            } finally {
                server.unbindToolRuntimePolicy()
                server.close()
            }
        }
    }

    @Test
    fun `typed tool gates handler errors output errors and cancellation are not decoding errors`() = runBlocking {
        val config = configFixture().apply { emergencyReadOnlyMode = true }
        val audit = RecordingAuditSink()
        val server = Server(
            Implementation("test", "1"),
            ServerOptions(capabilities = ServerCapabilities(tools = ServerCapabilities.Tools())),
        )
        server.bindToolRuntimePolicy(config, audit)
        var calls = 0
        server.mcpStructuredTool<DecodeProbe, DecodeOutput>("decode probe", PROJECT_MUTATION_TOOL_ANNOTATIONS) {
            calls++
            when (required) {
                "handler" -> throw SerializationException("PRIVATE_HANDLER_VALUE")
                "cancel" -> throw CancellationException("PRIVATE_CANCELLATION_VALUE")
                else -> DecodeOutput(Double.NaN) // Default Json rejects this during output encoding, after the handler.
            }
        }
        val connection = mockk<ClientConnection>(relaxed = true) {
            every { sessionId } returns "decode-boundary-session"
        }
        suspend fun call(json: String) = server.tools.getValue("decode_probe").handler(
            connection,
            CallToolRequest(CallToolRequestParams("decode_probe", Json.parseToJsonElement(json).jsonObject)),
        )
        try {
            val blocked = call("{}")
            assertEquals("Error: MCP emergency read-only mode blocks this tool", (blocked.content.single() as TextContent).text)
            assertTrue(blocked.isError == true)
            assertEquals(0, calls)
            assertEquals("blocked_read_only", audit.records.last().outcome)
            config.emergencyReadOnlyMode = false
            for ((input, errorType) in listOf("handler" to "SerializationException", "output" to "JsonEncodingException")) {
                val result = call("""{"required":"$input"}""")
                assertTrue(result.isError == true)
                val text = (result.content.single() as TextContent).text
                assertTrue(text.contains(errorType), text)
                assertTrue(text.contains("Tool outcome is unconfirmed; changes may already have occurred."), text)
                assertTrue(text.contains("Do not retry automatically. Verify the actual outcome before any manual retry."), text)
                assertFalse(text.contains("handler was not started"), text)
                assertFalse(text.contains("PRIVATE"), text)
                assertNull(result.structuredContent)
                assertEquals(errorType, audit.records.last().errorType)
            }
            assertEquals(2, calls)
            var cancelled = false
            try {
                call("""{"required":"cancel"}""")
            } catch (_: CancellationException) {
                cancelled = true
            }
            assertTrue(cancelled)
            assertEquals(3, calls)
            assertEquals("cancelled", audit.records.last().outcome)
            assertFalse(audit.records.toString().contains("PRIVATE"))
        } finally {
            server.unbindToolRuntimePolicy()
            server.close()
        }
    }

    @Test
    fun `fallback errors retain privacy and conservative guidance across every registration style`() = runBlocking {
        for (annotations in listOf(READ_ONLY_TOOL_ANNOTATIONS, PROJECT_MUTATION_TOOL_ANNOTATIONS, null)) {
            for (style in 0..2) {
                val server = Server(
                    Implementation("test", "1"),
                    ServerOptions(capabilities = ServerCapabilities(tools = ServerCapabilities.Tools())),
                )
                val audit = RecordingAuditSink()
                server.bindToolRuntimePolicy(configFixture(), audit)
                var calls = 0
                when (style) {
                    0 -> server.mcpTool("decode_probe", "named probe", annotations) {
                        calls++
                        throw IllegalStateException("PRIVATE_HANDLER_VALUE")
                    }
                    1 -> server.mcpTool<DecodeProbe>("generic probe", annotations) {
                        calls++
                        if (required == "fail") throw IllegalStateException("PRIVATE_HANDLER_VALUE")
                        listOf(TextContent("ok"))
                    }
                    2 -> server.mcpStructuredTool<DecodeProbe, DecodeOutput>("structured probe", annotations) {
                        calls++
                        DecodeOutput(Double.NaN)
                    }
                }
                val connection = mockk<ClientConnection>(relaxed = true) {
                    every { sessionId } returns "fallback-session"
                }
                try {
                    val result = server.tools.getValue("decode_probe").handler(
                        connection,
                        CallToolRequest(CallToolRequestParams("decode_probe", buildJsonObject {
                            put("required", JsonPrimitive("fail"))
                        })),
                    )
                    val text = (result.content.single() as TextContent).text
                    val readOnly = annotations?.readOnlyHint == true
                    assertTrue(result.isError == true)
                    assertNull(result.structuredContent)
                    assertEquals(1, calls)
                    assertEquals(readOnly, text.contains("Read failed to produce a usable result."), text)
                    assertEquals(!readOnly, text.contains("Tool outcome is unconfirmed"), text)
                    assertEquals(!readOnly, text.contains("Do not retry automatically"), text)
                    assertEquals(!readOnly, text.contains("Verify the actual outcome before any manual retry"), text)
                    assertFalse(text.contains("handler was not started"), text)
                    assertFalse(text.contains("PRIVATE"), text)
                    assertTrue(text.length <= MAX_STRUCTURED_TOOL_ERROR_CHARS)
                    assertEquals("error", audit.records.single().outcome)
                    assertEquals(if (style == 2) "JsonEncodingException" else "IllegalStateException", audit.records.single().errorType)
                } finally {
                    server.unbindToolRuntimePolicy()
                    server.close()
                }
            }
        }
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
        return McpConfig(persistedObject, mockk<Logging>(relaxed = true), net.portswigger.mcp.testPreferences())
    }

    @Serializable
    private data class AuditArgumentProbe(val allowed: String)

    @Serializable
    private data class DecodeProbe(
        val required: String,
        val count: Int = 1,
        val mode: DecodeMode = DecodeMode.FIRST,
        val nested: DecodeNested? = null,
        val labels: Map<String, String> = emptyMap(),
    )

    @Serializable
    private enum class DecodeMode { FIRST, SECOND }

    @Serializable
    private data class DecodeNested(val child: String)

    @Serializable
    private data class DecodeOutput(val value: Double)

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
