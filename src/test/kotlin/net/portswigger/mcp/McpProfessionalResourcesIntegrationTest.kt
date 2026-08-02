package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.persistence.Preferences
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import io.mockk.every
import io.mockk.mockk
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.TextResourceContents
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.tools.HistoryPerformanceMetric
import net.portswigger.mcp.tools.stableHistoryId
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.net.ServerSocket
import java.util.concurrent.TimeUnit
import kotlin.test.assertIs

@Timeout(30, unit = TimeUnit.SECONDS)
class McpProfessionalResourcesIntegrationTest {
    private val token = "0123456789012345678901234567890123456789012"
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val storage = mockk<PersistedObject>()
    private val logging = mockk<Logging>(relaxed = true)
    private val port = ServerSocket(0).use { it.localPort }
    private val manager = KtorServerManager(api)
    private val client = TestStreamableHttpMcpClient(mapOf("Authorization" to "Bearer $token"))
    private val config: McpConfig
    private var started = false

    init {
        every { storage.getBoolean(any()) } returns true
        every { storage.getBoolean("approvalYoloMode") } returns false
        every { storage.getBoolean("emergencyReadOnlyMode") } returns false
        every { storage.getString(any()) } returns "127.0.0.1"
        every { storage.getInteger("port") } returns port
        every { storage.setBoolean(any(), any()) } returns Unit
        every { storage.setString(any(), any()) } returns Unit
        every { storage.setInteger(any(), any()) } returns Unit
        every { api.project().id() } returns "professional-project"
        every { api.burpSuite().version().edition() } returns BurpSuiteEdition.PROFESSIONAL
        val preferences = mockk<Preferences>(relaxed = true)
        every { preferences.getString("independentMcpBridge.localBearerToken.v1") } returns token
        config = McpConfig(storage, logging, preferences)
    }

    @BeforeEach
    fun start() = runBlocking {
        manager.start(config) { if (it is ServerState.Running) started = true }
        repeat(30) {
            if (started) return@runBlocking
            delay(100)
        }
        error("Professional resource test server did not start")
    }

    @AfterEach
    fun stop() = runBlocking {
        if (client.isConnected()) client.close()
        manager.shutdown()
    }

    @Test
    fun `Professional Scanner delta completes a signed baseline and append round trip over MCP`() = runBlocking {
        every { storage.getBoolean("_alwaysAllowScannerIssues") } returns true
        val issues = mutableListOf(
            scannerIssueFixture(typeIndex = 1_001, name = "Baseline issue", basePath = "/baseline", includeDetails = false),
        )
        every { api.siteMap().issues() } answers { issues.toList() }
        client.connectToServer("http://127.0.0.1:$port/mcp")

        val baseline = client.callTool(
            "get_scanner_issues",
            mapOf(
                "count" to 50,
                "offset" to 0,
                "summariesOnly" to true,
                "cursorMode" to true,
            ),
        ).singleTextToolJson()
        assertEquals("ok", baseline["status"]?.jsonPrimitive?.content)
        assertEquals(false, baseline["legacyMode"]?.jsonPrimitive?.content?.toBoolean())
        assertEquals(false, baseline["deltaMode"]?.jsonPrimitive?.content?.toBoolean())
        assertEquals(1, baseline["returned"]?.jsonPrimitive?.content?.toInt())
        val snapshotCursor = baseline["snapshotCursor"]?.jsonPrimitive?.content
        assertTrue(!snapshotCursor.isNullOrBlank())

        issues += scannerIssueFixture(
            typeIndex = 1_002,
            name = "Appended issue",
            basePath = "/appended",
            includeDetails = false,
        )
        val delta = client.callTool(
            "get_scanner_issues",
            mapOf(
                "count" to 1,
                "offset" to 0,
                "summariesOnly" to true,
                "sinceSnapshotCursor" to snapshotCursor!!,
            ),
        ).singleTextToolJson()

        assertEquals("ok", delta["status"]?.jsonPrimitive?.content)
        assertEquals(true, delta["deltaMode"]?.jsonPrimitive?.content?.toBoolean())
        assertEquals(false, delta["legacyMode"]?.jsonPrimitive?.content?.toBoolean())
        assertEquals(false, delta["hasMore"]?.jsonPrimitive?.content?.toBoolean())
        assertEquals(1, delta["returned"]?.jsonPrimitive?.content?.toInt())
        assertEquals(
            "Appended issue",
            delta["items"]?.jsonArray?.single()?.jsonObject?.get("name")?.jsonPrimitive?.content,
        )
        assertTrue(delta["snapshotCursor"]?.jsonPrimitive?.content?.isNotBlank() == true)
        assertTrue(delta["nextDeltaCursor"] == null || delta["nextDeltaCursor"].toString() == "null")
        val evidence = delta["delta"]?.jsonObject
        assertEquals("append_stable_currently_visible_range", evidence?.get("basis")?.jsonPrimitive?.content)
        assertEquals(1, evidence?.get("baselineSnapshotSize")?.jsonPrimitive?.content?.toInt())
        assertEquals(2, evidence?.get("currentSnapshotSize")?.jsonPrimitive?.content?.toInt())
        assertEquals(1, evidence?.get("appendedRangeSize")?.jsonPrimitive?.content?.toInt())
        assertEquals(false, evidence?.get("regressionEstablished")?.jsonPrimitive?.content?.toBoolean())
        assertEquals(false, evidence?.get("removedOrChangedEstablished")?.jsonPrimitive?.content?.toBoolean())
        assertEquals(false, evidence?.get("completeHistoryEstablished")?.jsonPrimitive?.content?.toBoolean())
        assertFalse(delta.toString().contains("issue detail"))

        val diagnostics = client.readResource(DIAGNOSTICS_RESOURCE_URI).singleTextJson()
        val metrics = diagnostics["diagnostics"]?.jsonObject
            ?.get("historyPerformance")?.jsonObject
            ?.get("metrics")?.jsonArray.orEmpty()
            .associateBy { it.jsonObject.getValue("metric").jsonPrimitive.content }
        listOf(
            HistoryPerformanceMetric.SCANNER_DELTA_MONTOYA_ACQUISITION,
            HistoryPerformanceMetric.SCANNER_DELTA_EXTENSION_PROCESSING,
        ).forEach { metric ->
            val snapshot = requireNotNull(metrics[metric.name]).jsonObject
            assertEquals(1, snapshot.getValue("attempts").jsonPrimitive.content.toInt())
            assertEquals(1, snapshot.getValue("completed").jsonPrimitive.content.toInt())
            assertEquals(0, snapshot.getValue("failed").jsonPrimitive.content.toInt())
            assertEquals(0, snapshot.getValue("cancelled").jsonPrimitive.content.toInt())
        }
    }

    @Test
    fun `Professional advertises and enforces Scanner issue resource templates`() = runBlocking {
        val issue = scannerIssueFixture()
        every { api.siteMap().issues() } returns listOf(issue)
        val issueId = issue.stableHistoryId()
        client.connectToServer("http://127.0.0.1:$port/mcp")

        val tools = client.listTools()
        assertEquals(
            setOf(
                "send_raw_http_request",
                "route_raw_http_request",
                "get_burp_options",
                "set_burp_options",
                "search_http_messages",
                "summarize_http_attack_surface",
                "correlate_http_activity",
                "check_scope",
                "update_scope",
                "compare_http_messages",
                "analyze_http_session_security",
                "save_workflow_preset",
                "list_workflow_presets",
                "delete_workflow_preset",
                "execute_workflow_preset",
                "get_http_message",
                "send_http_request_from_id",
                "route_http_message_from_id",
                "search_websocket_messages",
                "get_websocket_message_by_id",
                "set_burp_control_state",
                "get_scanner_issues",
                "get_scanner_issue_by_id",
                "start_scanner_audit_from_ids",
                "get_scanner_audit",
                "cancel_scanner_audit",
                "generate_collaborator_payload",
                "get_collaborator_interactions",
            ),
            tools.map { it.name }.toSet(),
        )
        val descriptions = tools.associate { it.name to it.description.orEmpty() }
        assertTrue(descriptions.values.all { it.isNotBlank() && it.length <= 512 })
        tools.forEach { tool ->
            tool.inputSchema.properties.orEmpty().forEach { (propertyName, propertySchema) ->
                assertTrue(
                    propertySchema.jsonObject["description"]?.jsonPrimitive?.content?.isNotBlank() == true,
                    "${tool.name}.$propertyName lacks an input schema description",
                )
            }
        }
        assertTrue(descriptions.getValue("get_scanner_issues").contains("hasMore=true"))
        assertTrue(descriptions.getValue("get_scanner_issues").contains("nextCursor as cursor"))
        assertTrue(descriptions.getValue("get_scanner_issues").contains("nextDeltaCursor as sinceSnapshotCursor"))
        assertTrue(descriptions.getValue("get_scanner_issues").contains("does not prove regression"))
        assertTrue(descriptions.getValue("get_scanner_issue_by_id").contains("evidenceIndex is required"))
        assertTrue(descriptions.getValue("start_scanner_audit_from_ids").contains("Both modes reject out-of-scope requests"))
        assertTrue(descriptions.getValue("start_scanner_audit_from_ids").contains("active mode requires insertionPoints and can send requests"))
        assertTrue(descriptions.getValue("get_collaborator_interactions").contains("payload ID from generate_collaborator_payload"))
        assertFalse(descriptions.values.any { it.contains("until verified") })
        assertFalse(descriptions.values.any { it.contains("with no error") })
        assertFalse(descriptions.values.any { it.contains("safe workflow preset") })
        assertFalse(descriptions.values.any { it.contains("atomic project-bound add") })
        assertFalse(descriptions.values.any { it.contains("coroutine cancellation") })
        assertFalse(descriptions.values.any { it.contains("Montoya objects") })

        val scannerListSchema = tools.single { it.name == "get_scanner_issues" }.inputSchema.toString()
        assertTrue(scannerListSchema.contains("does not enable cursor mode"))
        assertTrue(scannerListSchema.contains("sinceSnapshotCursor"))
        assertTrue(scannerListSchema.contains("append-stable range"))
        val scannerReadSchema = tools.single { it.name == "get_scanner_issue_by_id" }.inputSchema.toString()
        assertTrue(scannerReadSchema.contains("Required when `field` is `evidence_request` or `evidence_response`"))
        val collaboratorSchema = tools.single { it.name == "get_collaborator_interactions" }.inputSchema.toString()
        assertTrue(collaboratorSchema.contains("Exclusive ISO-8601 instant lower-bound filter"))

        val templates = client.listResourceTemplates().resourceTemplates.map { it.uriTemplate }.toSet()
        assertEquals(
            setOf(
                HTTP_RESOURCE_TEMPLATE,
                HTTP_PART_RESOURCE_TEMPLATE,
                WEBSOCKET_RESOURCE_TEMPLATE,
                WEBSOCKET_VARIANT_RESOURCE_TEMPLATE,
                SCANNER_ISSUE_RESOURCE_TEMPLATE,
                SCANNER_ISSUE_FIELD_RESOURCE_TEMPLATE,
                SCANNER_ISSUE_EVIDENCE_RESOURCE_TEMPLATE,
            ),
            templates,
        )

        val prompts = client.listPrompts().map { it.name }.toSet()
        assertEquals(
            setOf(
                "analyze_http_without_sending",
                "compare_http_references",
                "review_auth_session_handling",
                "plan_repeater_tests_without_sending",
                "summarize_scanner_issue",
            ),
            prompts,
        )

        val project = client.readResource(PROJECT_SUMMARY_RESOURCE_URI).singleTextJson()
        assertEquals(
            listOf("http", "websocket", "scanner_issue"),
            project["referenceKinds"]?.jsonArray?.map { it.jsonPrimitive.content },
        )

        val expectedFields = linkedMapOf(
            "metadata" to null,
            "detail" to "issue detail",
            "remediation" to "issue remediation",
            "evidence_request" to "evidence request",
            "evidence_response" to "evidence response",
        )
        expectedFields.forEach { (field, expected) ->
            val uri = when (field) {
                "metadata" -> "burp://scanner-issue/professional-project/$issueId"
                "evidence_request", "evidence_response" ->
                    "burp://scanner-issue/professional-project/$issueId/$field/0"
                else -> "burp://scanner-issue/professional-project/$issueId/$field"
            }
            val result = client.readResource(uri).singleTextJson()
            assertEquals("ok", result["status"]?.jsonPrimitive?.content)
            assertEquals(field, result["field"]?.jsonPrimitive?.content)
            if (expected != null) {
                assertEquals(expected, result["content"]?.jsonObject?.get("data")?.jsonPrimitive?.content)
            }
        }

        val missing = "issue_v2_x_00000000000000000000000000000000"
        val notFound = client.readResource(
            "burp://scanner-issue/professional-project/$missing"
        ).singleTextJson()
        assertEquals("not_found", notFound["status"]?.jsonPrimitive?.content)

        val noncanonical = client.readResource(
            "burp://scanner-issue/professional-project/$issueId/evidence_request/00"
        ).singleTextJson()
        assertEquals("invalid_argument", noncanonical["status"]?.jsonPrimitive?.content)
    }

    private fun scannerIssueFixture(
        typeIndex: Int = 1234,
        name: String = "Test issue",
        basePath: String = "/issue",
        includeDetails: Boolean = true,
    ): AuditIssue {
        val issue = mockk<AuditIssue>()
        val definition = mockk<AuditIssueDefinition>()
        val service = mockk<HttpService>()
        val evidence = mockk<HttpRequestResponse>()
        val request = mockk<HttpRequest>()
        val response = mockk<HttpResponse>()
        every { issue.definition() } returns definition
        every { definition.typeIndex() } returns typeIndex
        every { issue.name() } returns name
        every { issue.baseUrl() } returns "https://example.test$basePath"
        every { issue.httpService() } returns service
        every { service.host() } returns "example.test"
        every { service.port() } returns 443
        every { service.secure() } returns true
        every { issue.severity() } returns AuditIssueSeverity.HIGH
        every { issue.confidence() } returns AuditIssueConfidence.CERTAIN
        if (includeDetails) {
            every { issue.detail() } returns "issue detail"
            every { issue.remediation() } returns "issue remediation"
            every { issue.requestResponses() } returns listOf(evidence)
            every { evidence.request() } returns request
            every { evidence.response() } returns response
            every { request.toByteArray() } returns montoyaBytes("evidence request")
            every { response.toByteArray() } returns montoyaBytes("evidence response")
        }
        return issue
    }

    private fun montoyaBytes(text: String): MontoyaByteArray {
        val raw = text.toByteArray(Charsets.UTF_8)
        return mockk<MontoyaByteArray>().also { value ->
            every { value.length() } returns raw.size
            every { value.getBytes() } returns raw
            every { value.toString() } returns text
            every { value.subArray(any(), any()) } answers {
                val start = firstArg<Int>()
                val end = secondArg<Int>()
                montoyaBytes(raw.copyOfRange(start, end).toString(Charsets.UTF_8))
            }
        }
    }

    private fun io.modelcontextprotocol.kotlin.sdk.types.ReadResourceResult.singleTextJson() =
        Json.parseToJsonElement(assertIs<TextResourceContents>(contents.single()).text).jsonObject

    private fun CallToolResult?.singleTextToolJson() = Json.parseToJsonElement(
        assertIs<TextContent>(requireNotNull(this).content.single()).text!!,
    ).jsonObject
}
