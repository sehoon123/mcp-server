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
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import io.mockk.every
import io.mockk.mockk
import io.modelcontextprotocol.kotlin.sdk.types.TextResourceContents
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.tools.stableHistoryId
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
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
        every { storage.getBoolean("emergencyReadOnlyMode") } returns false
        every { storage.getString(any()) } returns "127.0.0.1"
        every { storage.getString("localBearerToken") } returns token
        every { storage.getInteger("port") } returns port
        every { storage.setBoolean(any(), any()) } returns Unit
        every { storage.setString(any(), any()) } returns Unit
        every { storage.setInteger(any(), any()) } returns Unit
        every { api.project().id() } returns "professional-project"
        every { api.burpSuite().version().edition() } returns BurpSuiteEdition.PROFESSIONAL
        config = McpConfig(storage, logging)
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
    fun `Professional advertises and enforces Scanner issue resource templates`() = runBlocking {
        val issue = scannerIssueFixture()
        every { api.siteMap().issues() } returns listOf(issue)
        val issueId = issue.stableHistoryId()
        client.connectToServer("http://127.0.0.1:$port/mcp")

        assertEquals(
            setOf(
                "send_raw_http_request",
                "route_raw_http_request",
                "transform_data",
                "generate_random_string",
                "get_burp_options",
                "set_burp_options",
                "search_http_messages",
                "summarize_http_attack_surface",
                "check_scope",
                "update_scope",
                "compare_http_messages",
                "get_http_message",
                "send_http_request_from_id",
                "route_http_message_from_id",
                "search_websocket_messages",
                "get_websocket_message_by_id",
                "set_burp_control_state",
                "get_active_editor_contents",
                "set_active_editor_contents",
                "get_scanner_issues",
                "get_scanner_issue_by_id",
                "start_scanner_audit_from_ids",
                "get_scanner_audit",
                "cancel_scanner_audit",
                "generate_collaborator_payload",
                "get_collaborator_interactions",
            ),
            client.listTools().map { it.name }.toSet(),
        )
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

        val missing = "issue_00000000000000000000000000000000"
        val notFound = client.readResource(
            "burp://scanner-issue/professional-project/$missing"
        ).singleTextJson()
        assertEquals("not_found", notFound["status"]?.jsonPrimitive?.content)

        val noncanonical = client.readResource(
            "burp://scanner-issue/professional-project/$issueId/evidence_request/00"
        ).singleTextJson()
        assertEquals("invalid_argument", noncanonical["status"]?.jsonPrimitive?.content)
    }

    private fun scannerIssueFixture(): AuditIssue {
        val issue = mockk<AuditIssue>()
        val definition = mockk<AuditIssueDefinition>()
        val service = mockk<HttpService>()
        val evidence = mockk<HttpRequestResponse>()
        val request = mockk<HttpRequest>()
        val response = mockk<HttpResponse>()
        every { issue.definition() } returns definition
        every { definition.typeIndex() } returns 1234
        every { issue.name() } returns "Test issue"
        every { issue.baseUrl() } returns "https://example.test/issue"
        every { issue.httpService() } returns service
        every { service.host() } returns "example.test"
        every { service.port() } returns 443
        every { service.secure() } returns true
        every { issue.severity() } returns AuditIssueSeverity.HIGH
        every { issue.confidence() } returns AuditIssueConfidence.CERTAIN
        every { issue.detail() } returns "issue detail"
        every { issue.remediation() } returns "issue remediation"
        every { issue.requestResponses() } returns listOf(evidence)
        every { evidence.request() } returns request
        every { evidence.response() } returns response
        every { request.toByteArray() } returns montoyaBytes("evidence request")
        every { response.toByteArray() } returns montoyaBytes("evidence response")
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
}
