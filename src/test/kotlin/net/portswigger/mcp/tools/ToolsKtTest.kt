package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine
import burp.api.montoya.collaborator.*
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpProtocol
import burp.api.montoya.http.RedirectionMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.organizer.Organizer
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.persistence.Preferences
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.sitemap.SiteMap
import burp.api.montoya.websocket.Direction
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.Tool
import io.mockk.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.portswigger.mcp.KtorServerManager
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.TestStreamableHttpMcpClient
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.NoOpMcpAuditSink
import net.portswigger.mcp.security.RequestActionApprovalHandler
import net.portswigger.mcp.security.RequestActionSecurity
import net.portswigger.mcp.security.SensitiveActionApprovalHandler
import net.portswigger.mcp.security.SensitiveActionSecurity
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.security.MessageDigest
import java.time.ZonedDateTime
import java.util.HexFormat
import java.util.Optional

class ToolsKtTest {
    private val testBearerToken = "0123456789012345678901234567890123456789012"
    private val client = TestStreamableHttpMcpClient(
        mapOf("Authorization" to "Bearer $testBearerToken")
    )
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val workflowStorageValues = mutableMapOf<String, String>()
    private val workflowStorage = mockk<PersistedObject>(relaxed = true).also { storage ->
        every { storage.getString(any()) } answers { workflowStorageValues[firstArg()] }
        every { storage.setString(any(), any()) } answers {
            workflowStorageValues[firstArg()] = secondArg()
        }
    }
    // Tool-contract fixtures deliberately replace their mocked project after the client connects. Project-bound
    // session lifecycle is covered by McpServerIntegrationTest and McpProjectEpochGuardTest instead.
    private val serverManager = KtorServerManager(
        api, NoOpMcpAuditSink, projectIdProvider = null, extensionStorage = workflowStorage
    )
    private val testPort = findAvailablePort()
    private var serverStarted = false
    private val config: McpConfig
    private val mockHeaders = mutableListOf<HttpHeader>()
    private var requireDataAccessApproval = false
    private lateinit var originalRequestActionHandler: RequestActionApprovalHandler
    private lateinit var originalSensitiveActionHandler: SensitiveActionApprovalHandler
    private val catalogJson = Json { encodeDefaults = true; explicitNulls = true }

    init {
        val persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean("enabled") } returns true
            every { getBoolean("emergencyReadOnlyMode") } returns false
            every { getBoolean("configEditingTooling") } returns true
            every { getBoolean("filterConfigCredentials") } returns false
            every { getBoolean("requireHttpRequestApproval") } returns false
            every { getBoolean("requireRequestActionApproval") } returns false
            every { getBoolean("requireDataAccessApproval") } answers { requireDataAccessApproval }
            every { getBoolean("_alwaysAllowHttpHistory") } returns false
            every { getBoolean("_alwaysAllowSiteMap") } returns false
            every { getBoolean("_alwaysAllowWebSocketHistory") } returns false
            every { getBoolean("_alwaysAllowOrganizer") } returns false
            every { getBoolean("_alwaysAllowScannerIssues") } returns false
            every { getBoolean("_alwaysAllowCollaboratorInteractions") } returns false
            every { getString("host") } returns "127.0.0.1"
            every { getString("_autoApproveTargets") } returns ""
            every { getInteger("port") } returns testPort
            every { setBoolean(any(), any()) } answers {
                if (firstArg<String>() == "requireDataAccessApproval") {
                    requireDataAccessApproval = secondArg()
                }
            }
            every { setString(any(), any()) } returns Unit
            every { setInteger(any(), any()) } returns Unit
        }
        val mockLogging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
            every { logToOutput(any<String>()) } returns Unit
        }

        val preferences = mockk<Preferences>(relaxed = true)
        every { preferences.getString("independentMcpBridge.localBearerToken.v1") } returns testBearerToken
        config = McpConfig(persistedObject, mockLogging, preferences)
        
        mockkStatic(HttpHeader::class)
        mockkStatic(burp.api.montoya.http.HttpService::class)
        mockkStatic(HttpRequest::class)
        mockkStatic(RequestOptions::class)
    }

    private fun CallToolResult?.expectTextContent(
        expected: String? = null,
    ): String {
        assertNotNull(this, "Tool result cannot be null")
        val result = this!!

        val content = result.content
        assertNotNull(content, "Tool result content cannot be null")

        val nonNullContent = content
        assertEquals(1, nonNullContent.size, "Expected exactly one content element")

        val textContent = nonNullContent.firstOrNull() as? TextContent
        assertNotNull(textContent, "Expected content to be TextContent")

        val text = textContent!!.text
        assertNotNull(text, "Text content cannot be null")

        if (expected != null) {
            assertEquals(expected, text, "Text content doesn't match expected value")
        }

        return text!!
    }

    private fun assertCatalogFingerprint(edition: String, tools: Collection<Tool>, expected: String) {
        val canonicalTools = tools.sortedBy { it.name }.map(::canonicalTool)
        val canonicalCatalog = JsonArray(canonicalTools).toString()
        val actual = sha256(canonicalCatalog)
        val perTool = canonicalTools.joinToString("\n") { tool ->
            val name = tool.jsonObject.getValue("name").jsonPrimitive.content
            "  $name ${sha256(tool.toString())}"
        }
        assertEquals(
            expected,
            actual,
            "$edition catalog fingerprint changed. Review every intended contract change, then update the " +
                "expected fingerprint.\nActual: $actual\nPer-tool fingerprints:\n$perTool",
        )
    }

    private fun canonicalTool(tool: Tool): JsonObject = canonicalJson(
        catalogJson.encodeToJsonElement(Tool.serializer(), tool),
    ).jsonObject

    private fun canonicalJson(element: JsonElement): JsonElement = when (element) {
        is JsonObject -> JsonObject(
            element.entries.sortedBy { it.key }.associate { (key, value) -> key to canonicalJson(value) },
        )
        is JsonArray -> JsonArray(element.map(::canonicalJson))
        else -> element
    }

    private fun sha256(value: String): String = HexFormat.of().formatHex(
        MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8)),
    )

    private fun assertBurpErrorGuidanceIsSelfContained(tool: Tool) {
        val output = requireNotNull(tool.outputSchema)
        val statusSchema = output.properties?.get("status")?.jsonObject ?: return
        if (!statusSchema.toString().contains("\"burp_error\"")) return
        val descriptions = listOf("status", "retry", "executionState", "actionState").mapNotNull { name ->
            output.properties?.get(name)?.jsonObject?.get("description")?.jsonPrimitive?.content
        }
        assertTrue(
            descriptions.any { description ->
                "burp_error" in description || "Authoritative retry" in description ||
                    "must not be retried automatically" in description
            },
            "${tool.name} exposes burp_error without self-contained retry/execution guidance",
        )
    }

    private fun assertTruncatedStringsAdvertiseBounds(tool: Tool) {
        fun containsString(schema: JsonObject): Boolean {
            val type = schema["type"]
            if (type is JsonPrimitive && type.content == "string") return true
            if (type is JsonArray && type.any { it.jsonPrimitive.content == "string" }) return true
            return listOf("anyOf", "oneOf", "allOf").any { keyword ->
                (schema[keyword] as? JsonArray)?.any { candidate ->
                    (candidate as? JsonObject)?.let(::containsString) == true
                } == true
            }
        }

        fun maxLengths(schema: JsonObject): Set<Int> = buildSet {
            (schema["maxLength"] as? JsonPrimitive)?.content?.toIntOrNull()?.let(::add)
            listOf("anyOf", "oneOf", "allOf").forEach { keyword ->
                (schema[keyword] as? JsonArray)?.forEach { candidate ->
                    (candidate as? JsonObject)?.let { addAll(maxLengths(it)) }
                }
            }
        }

        fun expectedBound(path: String, name: String, siblings: JsonObject): Int = when (name) {
            "url", "baseUrl" -> 2_048
            "host" -> 253
            "name" -> 512
            "customData" -> 1_024
            "notes" -> if ("webSocketId" in siblings) 2_000 else 512
            else -> error("$path.$name has a truncation flag but no explicit expected bound")
        }

        fun walk(path: String, schema: JsonObject) {
            val properties = schema["properties"] as? JsonObject
            properties?.forEach { (name, property) ->
                val propertySchema = property.jsonObject
                if (properties.containsKey("${name}Truncated") && containsString(propertySchema)) {
                    val advertised = maxLengths(propertySchema)
                    assertEquals(
                        setOf(expectedBound(path, name, properties)),
                        advertised,
                        "$path.$name must advertise its exact runtime truncation bound",
                    )
                    val truncationDescription = properties.getValue("${name}Truncated").jsonObject["description"]
                        ?.jsonPrimitive?.content.orEmpty()
                    val documented = Regex("([0-9][0-9,]*)-character output bound")
                        .find(truncationDescription)?.groupValues?.get(1)?.replace(",", "")?.toIntOrNull()
                    assertEquals(
                        advertised.single(),
                        documented,
                        "$path.${name}Truncated must document the same exact bound",
                    )
                }
                walk("$path.$name", propertySchema)
            }
            (schema["items"] as? JsonObject)?.let { walk("$path[]", it) }
            listOf("anyOf", "oneOf", "allOf").forEach { keyword ->
                (schema[keyword] as? JsonArray)?.forEachIndexed { index, candidate ->
                    (candidate as? JsonObject)?.let { walk("$path.$keyword[$index]", it) }
                }
            }
            (schema["additionalProperties"] as? JsonObject)?.let { walk("$path{}", it) }
        }

        val output = requireNotNull(tool.outputSchema)
        val root = JsonObject(
            mapOf(
                "type" to JsonPrimitive("object"),
                "properties" to (output.properties ?: JsonObject(emptyMap())),
                "required" to JsonArray(output.required.orEmpty().map(::JsonPrimitive)),
            )
        )
        walk(tool.name, root)
    }

    private fun assertNonNullOutputFieldsAreRequired(tool: Tool) {
        fun acceptsNull(schema: JsonObject): Boolean {
            val type = schema["type"]
            if (type is JsonPrimitive && type.content == "null") return true
            if (type is JsonArray && type.any { it.jsonPrimitive.content == "null" }) return true
            return (schema["anyOf"] as? JsonArray)?.any { candidate ->
                (candidate as? JsonObject)?.let(::acceptsNull) == true
            } == true
        }

        fun walk(path: String, schema: JsonObject) {
            val properties = schema["properties"] as? JsonObject
            if (properties != null) {
                val required = (schema["required"] as? JsonArray)
                    ?.mapTo(HashSet()) { it.jsonPrimitive.content }
                    .orEmpty()
                properties.forEach { (name, property) ->
                    val propertySchema = property.jsonObject
                    assertTrue(
                        acceptsNull(propertySchema) || name in required,
                        "$path.$name is non-null but omittable; make stable output fields constructor-required",
                    )
                    walk("$path.$name", propertySchema)
                }
            }
            (schema["items"] as? JsonObject)?.let { walk("$path[]", it) }
            listOf("anyOf", "oneOf", "allOf").forEach { keyword ->
                (schema[keyword] as? JsonArray)?.forEachIndexed { index, candidate ->
                    (candidate as? JsonObject)?.let { walk("$path.$keyword[$index]", it) }
                }
            }
            (schema["additionalProperties"] as? JsonObject)?.let { walk("$path{}", it) }
        }

        val output = requireNotNull(tool.outputSchema)
        val root = JsonObject(
            mapOf(
                "type" to JsonPrimitive("object"),
                "properties" to (output.properties ?: JsonObject(emptyMap())),
                "required" to JsonArray(output.required.orEmpty().map(::JsonPrimitive)),
            )
        )
        walk(tool.name, root)
    }

    private fun montoyaBytes(raw: ByteArray): MontoyaByteArray = mockk<MontoyaByteArray>().also { bytes ->
        every { bytes.length() } returns raw.size
        every { bytes.toString() } returns raw.toString(Charsets.ISO_8859_1)
        every { bytes.getBytes() } returns raw
        every { bytes.subArray(any(), any()) } answers {
            montoyaBytes(raw.copyOfRange(firstArg(), secondArg()))
        }
    }

    private fun stubProxyHistorySummary(item: ProxyHttpRequestResponse, index: Int) {
        val request = mockk<HttpRequest>()
        val body = montoyaBytes(byteArrayOf())
        val service = mockk<burp.api.montoya.http.HttpService>()
        val annotations = mockk<Annotations>()
        every { item.id() } returns index
        every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z")
        every { item.request() } returns request
        every { item.response() } returns null
        every { item.httpService() } returns service
        every { item.listenerPort() } returns 8080
        every { item.edited() } returns false
        every { item.annotations() } returns annotations
        every { request.method() } returns "GET"
        every { request.url() } returns "https://example.test/item$index"
        every { request.path() } returns "/item$index"
        every { request.isInScope() } returns true
        every { request.body() } returns body
        every { service.host() } returns "example.test"
        every { service.port() } returns 443
        every { service.secure() } returns true
        every { annotations.notes() } returns null
    }

    private fun setupHttpHeaderMocks() {
        every { HttpHeader.httpHeader(any<String>(), any<String>()) } answers {
            val name = firstArg<String>()
            val value = secondArg<String>()
            mockk<HttpHeader>().also {
                every { it.name() } returns name
                every { it.value() } returns value
                mockHeaders.add(it)
            }
        }

        every { burp.api.montoya.http.HttpService.httpService(any(), any(), any()) } answers {
            val host = firstArg<String>()
            val port = secondArg<Int>()
            val secure = thirdArg<Boolean>()
            mockk<burp.api.montoya.http.HttpService>().also {
                every { it.host() } returns host
                every { it.port() } returns port
                every { it.secure() } returns secure
            }
        }
    }
    
    @BeforeEach
    fun setup() {
        requireDataAccessApproval = false
        originalRequestActionHandler = RequestActionSecurity.approvalHandler
        originalSensitiveActionHandler = SensitiveActionSecurity.approvalHandler
        RequestActionSecurity.approvalHandler = object : RequestActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                source: String,
                target: String,
                changes: String,
                requestContent: String,
                config: McpConfig,
                api: MontoyaApi,
            ) = true
        }
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ) = true
        }
        setupHttpHeaderMocks()
        val defaultProject = mockk<burp.api.montoya.project.Project>()
        every { defaultProject.id() } returns "project-default"
        every { api.project() } returns defaultProject

        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")

            client.connectToServer("http://127.0.0.1:${testPort}/mcp")
            assertNotNull(client.ping(), "Ping should return a result")
        }
    }

    private fun findAvailablePort() = ServerSocket(0).use { it.localPort }

    @AfterEach
    fun tearDown() {
        RequestActionSecurity.approvalHandler = originalRequestActionHandler
        SensitiveActionSecurity.approvalHandler = originalSensitiveActionHandler
        runBlocking { if (client.isConnected()) client.close() }
        serverManager.shutdown()
    }

    @Test
    fun `Community catalog descriptions expose corrected contracts without implementation jargon`() = runBlocking {
        val tools = client.listTools().associateBy { it.name }
        assertEquals(21, tools.size)

        fun description(name: String) = requireNotNull(tools[name]).description.orEmpty()
        assertTrue(tools.values.all { !it.description.isNullOrBlank() })
        assertTrue(tools.values.all { it.description.orEmpty().length <= 512 })
        tools.values.forEach(::assertNonNullOutputFieldsAreRequired)
        tools.values.forEach(::assertTruncatedStringsAdvertiseBounds)
        tools.values.forEach(::assertBurpErrorGuidanceIsSelfContained)
        assertCatalogFingerprint(
            "Community",
            tools.values,
            "15b9b63ea145194e982fdc4f073931cdbf7afdb340e4b7ad5011222b3c04cdbb",
        )
        tools.forEach { (toolName, tool) ->
            tool.inputSchema.properties.orEmpty().forEach { (propertyName, propertySchema) ->
                assertTrue(
                    propertySchema.jsonObject["description"]?.jsonPrimitive?.content?.isNotBlank() == true,
                    "$toolName.$propertyName lacks an input schema description",
                )
            }
            tool.inputSchema.properties?.get("projectId")?.jsonObject?.let { projectSchema ->
                assertEquals(
                    MCP_PROJECT_ID_INPUT_DESCRIPTION,
                    projectSchema.getValue("description").jsonPrimitive.content,
                    "$toolName.projectId must use the common opaque project-binding contract",
                )
            }
        }
        assertTrue(description("send_raw_http_request").contains("caller-supplied HTTP/1.1 or HTTP/2"))
        assertTrue(description("route_raw_http_request").contains("HTTP/2 Intruder routing is unsupported"))
        assertTrue(description("get_burp_options").contains("Credentials are filtered by default"))
        assertTrue(description("set_burp_options").contains("captures and rechecks the project current"))
        assertTrue(description("search_http_messages").contains("items=[] with hasMore=true"))
        assertTrue(description("search_http_messages").contains("scanning to 10,000 records"))
        assertTrue(description("search_http_messages").contains("MCP sends are absent"))
        assertTrue(description("correlate_http_activity").contains("similarity without identity or deduplication"))
        assertTrue(description("correlate_http_activity").contains("Site Map stable-ID validation may privately inspect bounded identity samples"))
        assertTrue(description("update_scope").contains("before any approval prompt or policy bypass and before mutation"))
        assertTrue(description("analyze_http_session_security").contains("privately inspect bounded body and header samples"))
        assertTrue(description("save_workflow_preset").contains("Names are trimmed"))
        assertTrue(description("list_workflow_presets").contains("stored workflow preset definitions"))
        assertTrue(description("execute_workflow_preset").contains("runtime limit overrides the saved defaultLimit"))
        assertTrue(description("route_http_message_from_id").contains("sends no network traffic"))
        assertTrue(description("send_raw_http_request").contains("independent outbound-target policy"))
        assertTrue(description("send_http_request_from_id").contains("independent outbound-target policy"))
        assertTrue(description("search_websocket_messages").contains("items=[] with hasMore=true"))
        assertTrue(description("set_burp_control_state").contains("intentionally not project-scoped"))

        val catalogText = tools.values.joinToString("\n") { it.description.orEmpty() }
        listOf(
            "until verified",
            "with no error",
            "safe workflow preset",
            "atomic project-bound add",
            "coroutine cancellation",
            "Montoya objects",
            "oneOf",
            "this extension instance",
            "v4.8",
        ).forEach { obsolete -> assertFalse(catalogText.contains(obsolete), obsolete) }

        val rawSchema = requireNotNull(tools["send_raw_http_request"]).inputSchema.toString()
        assertTrue(rawSchema.contains("request-line and header line endings"))
        assertTrue(rawSchema.contains("content after the first blank line is preserved"))
        assertTrue(rawSchema.contains("Protocol to use"))
        assertTrue(rawSchema.contains("Connect to the destination using TLS"))
    }

    @Test
    fun `retained HTTP correction failures are MCP errors without unverified project echoes`() = runBlocking {
        val cases = listOf(
            "get_http_message" to mapOf<String, Any>(
                "projectId" to "caller-forged",
                "ref" to mapOf("source" to "proxy", "id" to "1"),
                "limit" to 0,
            ),
            "send_http_request_from_id" to mapOf<String, Any>(
                "projectId" to "caller-forged",
                "ref" to mapOf("source" to "proxy", "id" to "1"),
                "redirection" to "always",
            ),
            "route_http_message_from_id" to mapOf<String, Any>(
                "projectId" to "caller-forged",
                "ref" to mapOf("source" to "proxy", "id" to "1"),
                "destination" to "organizer",
                "tabName" to "unsupported",
            ),
            "check_scope" to mapOf<String, Any>(
                "projectId" to "caller-forged",
                "targets" to emptyList<Any>(),
            ),
            "compare_http_messages" to mapOf<String, Any>(
                "projectId" to "caller-forged",
                "refs" to emptyList<Any>(),
            ),
            "summarize_http_attack_surface" to mapOf<String, Any>(
                "projectId" to "caller-forged",
                "pathDepth" to 0,
            ),
        )

        cases.forEach { (toolName, arguments) ->
            val result = client.callTool(toolName, arguments)
            assertEquals(true, result?.isError, "$toolName correction result must be an MCP error")
            assertEquals(
                "invalid_argument",
                result?.structuredContent?.get("status")?.jsonPrimitive?.content,
                toolName,
            )
            assertEquals(
                JsonNull,
                result?.structuredContent?.get("projectId"),
                "$toolName must not echo caller-forged projectId before capture",
            )
        }
    }

    @Test
    fun `attack surface correction and Burp failures are MCP errors`() = runBlocking {
        val invalid = client.callTool(
            "summarize_http_attack_surface",
            mapOf("projectId" to "caller-forged", "pathDepth" to 0),
        )
        assertEquals(true, invalid?.isError)
        assertEquals("invalid_argument", invalid?.structuredContent?.get("status")?.jsonPrimitive?.content)
        assertEquals(JsonNull, invalid?.structuredContent?.get("projectId"))

        val failingProject = mockk<burp.api.montoya.project.Project>()
        every { failingProject.id() } throws IllegalStateException("PRIVATE_SENTINEL")
        every { api.project() } returns failingProject
        val failed = client.callTool(
            "summarize_http_attack_surface",
            mapOf("projectId" to "project-default"),
        )
        assertEquals(true, failed?.isError)
        assertEquals("burp_error", failed?.structuredContent?.get("status")?.jsonPrimitive?.content)
        assertEquals(JsonNull, failed?.structuredContent?.get("projectId"))
        assertFalse(failed?.structuredContent.toString().contains("PRIVATE_SENTINEL"))
    }

    @Test
    fun `correlation and session ordinary denial and unavailable outcomes remain non-errors`() = runBlocking {
        val previousApprovalHandler = DataAccessSecurity.approvalHandler
        requireDataAccessApproval = true
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig) = false
        }
        try {
            val deniedCorrelation = client.callTool(
                "correlate_http_activity",
                mapOf(
                    "projectId" to "project-default",
                    "baselineRefs" to listOf(mapOf("source" to "proxy", "id" to "1")),
                    "comparisonRefs" to listOf(mapOf("source" to "proxy", "id" to "2")),
                ),
            )
            assertEquals("access_denied", deniedCorrelation?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals(false, deniedCorrelation?.isError)

            val deniedSession = client.callTool(
                "analyze_http_session_security",
                mapOf(
                    "projectId" to "project-default",
                    "refs" to listOf(mapOf("source" to "proxy", "id" to "1")),
                ),
            )
            assertEquals("access_denied", deniedSession?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals(false, deniedSession?.isError)
        } finally {
            requireDataAccessApproval = false
            DataAccessSecurity.approvalHandler = previousApprovalHandler
        }

        val proxy = mockk<Proxy>()
        val unavailable = mockk<ProxyHttpRequestResponse>()
        every { api.proxy() } returns proxy
        every { proxy.history(any()) } returns listOf(unavailable)
        every { unavailable.id() } returns 1
        every { unavailable.request() } returns null

        val unavailableCorrelation = client.callTool(
            "correlate_http_activity",
            mapOf(
                "projectId" to "project-default",
                "baselineRefs" to listOf(mapOf("source" to "proxy", "id" to "1")),
                "comparisonRefs" to listOf(mapOf("source" to "proxy", "id" to "2")),
            ),
        )
        assertEquals(
            "request_unavailable",
            unavailableCorrelation?.structuredContent?.get("status")?.jsonPrimitive?.content,
        )
        assertEquals(false, unavailableCorrelation?.isError)

        val unavailableSession = client.callTool(
            "analyze_http_session_security",
            mapOf(
                "projectId" to "project-default",
                "refs" to listOf(mapOf("source" to "proxy", "id" to "1")),
            ),
        )
        assertEquals(
            "request_unavailable",
            unavailableSession?.structuredContent?.get("status")?.jsonPrimitive?.content,
        )
        assertEquals(false, unavailableSession?.isError)
    }

    @Nested
    inner class RawHttpToolsTests {
        @Test
        fun `unified raw HTTP1 send normalizes input and returns structured state`() = runBlocking {
            val http = mockk<Http>()
            val request = mockk<HttpRequest>()
            val body = montoyaBytes(byteArrayOf())
            val options = mockk<RequestOptions>()
            val content = slot<String>()
            every { HttpRequest.httpRequest(any(), capture(content)) } returns request
            every { request.bodyOffset() } returns 48
            every { request.body() } returns body
            every { RequestOptions.requestOptions() } returns options
            every { options.withHttpMode(HttpMode.HTTP_1) } returns options
            every { options.withRedirectionMode(RedirectionMode.NEVER) } returns options
            every { options.withResponseTimeout(30_000) } returns options
            every { api.http() } returns http
            every { http.sendRequest(request, options) } returns null

            val result = client.callTool(
                "send_raw_http_request",
                mapOf(
                    "protocol" to "http_1",
                    "http1" to mapOf("content" to "GET / HTTP/1.1\nHost: example.test\n\n"),
                    "targetHostname" to "example.test",
                    "targetPort" to 443,
                    "usesHttps" to true,
                ),
            )

            assertEquals(false, result?.isError)
            assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("completed", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
            assertEquals("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", content.captured)
            verify(exactly = 1) { options.withRedirectionMode(RedirectionMode.NEVER) }
            verify(exactly = 1) { http.sendRequest(request, options) }
        }

        @Test
        fun `unified raw HTTP2 routing creates exactly one approved Repeater tab`() = runBlocking {
            val repeater = mockk<burp.api.montoya.repeater.Repeater>(relaxed = true)
            val request = mockk<HttpRequest>()
            val body = montoyaBytes(byteArrayOf())
            val headers = slot<List<HttpHeader>>()
            every { HttpRequest.http2Request(any(), capture(headers), "payload") } returns request
            every { request.bodyOffset() } returns 64
            every { request.body() } returns body
            every { api.repeater() } returns repeater

            val result = client.callTool(
                "route_raw_http_request",
                mapOf(
                    "destination" to "repeater",
                    "protocol" to "http_2",
                    "http2" to mapOf(
                        "pseudoHeaders" to mapOf("method" to "POST", "path" to "/api"),
                        "headers" to mapOf("Content-Type" to "text/plain"),
                        "requestBody" to "payload",
                    ),
                    "targetHostname" to "example.test",
                    "targetPort" to 443,
                    "usesHttps" to true,
                    "tabName" to "v4",
                ),
            )

            assertEquals(false, result?.isError)
            assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("completed", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
            assertEquals(listOf(":method", ":path"), headers.captured.take(2).map { it.name() })
            verify(exactly = 1) { repeater.sendToRepeater(request, "v4") }
        }

        @Test
        fun `raw HTTP correction failures are MCP errors`() = runBlocking {
            val send = client.callTool(
                "send_raw_http_request",
                mapOf(
                    "protocol" to "http_1",
                    "http1" to mapOf("content" to "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
                    "targetHostname" to "example.test",
                    "targetPort" to 443,
                    "usesHttps" to true,
                    "responseTimeoutMs" to 0,
                ),
            )
            val route = client.callTool(
                "route_raw_http_request",
                mapOf(
                    "destination" to "organizer",
                    "protocol" to "http_1",
                    "http1" to mapOf("content" to "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
                    "targetHostname" to "example.test",
                    "targetPort" to 443,
                    "usesHttps" to true,
                    "tabName" to "unsupported",
                ),
            )

            listOf(send, route).forEach { result ->
                assertEquals(true, result?.isError)
                assertEquals("invalid_argument", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            }
        }
    }

    @Nested
    inner class ConfigurationToolsTests {
        @Test
        fun `configuration export rejects oversized content with a structured limit status`() = runBlocking {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.exportProjectOptionsAsJson() } returns "x".repeat(1_048_577)

            val result = client.callTool("get_burp_options", mapOf("level" to "project"))

            assertEquals(true, result?.isError)
            assertEquals("limit_exceeded", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("after_user_action", result?.structuredContent?.get("retry")?.jsonPrimitive?.content)
            assertNull(result?.structuredContent?.get("configuration"))
        }

        @Test
        fun `project configuration read stops before export when approval crosses projects`() = runBlocking {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>(relaxed = true)
            val project = mockk<burp.api.montoya.project.Project>()
            var currentProjectId = "project-a"
            every { api.burpSuite() } returns burpSuite
            every { api.project() } returns project
            every { project.id() } answers { currentProjectId }
            SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
                override suspend fun requestApproval(
                    action: String,
                    summary: String,
                    reviewContent: String?,
                    renderContentAsHttp: Boolean,
                    api: MontoyaApi,
                ): Boolean {
                    currentProjectId = "project-b"
                    return true
                }
            }

            val result = client.callTool("get_burp_options", mapOf("level" to "project"))

            assertEquals("project_mismatch", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertNull(result?.structuredContent?.get("configuration"))
            verify(exactly = 0) { burpSuite.exportProjectOptionsAsJson() }
        }

        @Test
        fun `project configuration write stops before import when approval crosses projects`() = runBlocking {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>(relaxed = true)
            val project = mockk<burp.api.montoya.project.Project>()
            var currentProjectId = "project-a"
            every { api.burpSuite() } returns burpSuite
            every { api.project() } returns project
            every { project.id() } answers { currentProjectId }
            SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
                override suspend fun requestApproval(
                    action: String,
                    summary: String,
                    reviewContent: String?,
                    renderContentAsHttp: Boolean,
                    api: MontoyaApi,
                ): Boolean {
                    currentProjectId = "project-b"
                    return true
                }
            }

            val result = client.callTool(
                "set_burp_options",
                mapOf("level" to "project", "json" to "{\"project_options\":{}}"),
            )

            assertEquals("project_mismatch", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("not_started", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
            verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
        }

        @Test
        fun `project configuration transition after import is execution uncertain`() = runBlocking {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            val project = mockk<burp.api.montoya.project.Project>()
            var currentProjectId = "project-a"
            every { api.burpSuite() } returns burpSuite
            every { api.project() } returns project
            every { project.id() } answers { currentProjectId }
            every { burpSuite.importProjectOptionsFromJson(any()) } answers {
                currentProjectId = "project-b"
            }

            val result = client.callTool(
                "set_burp_options",
                mapOf("level" to "project", "json" to "{\"project_options\":{}}"),
            )

            assertEquals("project_mismatch", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("uncertain", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
            assertEquals("do_not_retry", result?.structuredContent?.get("retry")?.jsonPrimitive?.content)
            verify(exactly = 1) { burpSuite.importProjectOptionsFromJson(any()) }
        }

        @Test
        fun `configuration import cancellation after invocation is execution uncertain`() = runBlocking {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.importUserOptionsFromJson(any()) } throws kotlinx.coroutines.CancellationException("cancelled")

            val result = client.callTool(
                "set_burp_options",
                mapOf("level" to "user", "json" to "{\"user_options\":{}}"),
            )

            assertEquals("burp_error", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("uncertain", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
            assertEquals("do_not_retry", result?.structuredContent?.get("retry")?.jsonPrimitive?.content)
        }

        @Test
        fun `set task execution engine state should work properly`() {
            val taskExecutionEngine = mockk<TaskExecutionEngine>()
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.taskExecutionEngine() } returns taskExecutionEngine
            every { taskExecutionEngine.state = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_burp_control_state", mapOf(
                        "control" to "task_execution_engine",
                        "enabled" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now running")
                assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("completed", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
                assertEquals("not_applicable", result?.structuredContent?.get("retry")?.jsonPrimitive?.content)
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.RUNNING }
            
            clearMocks(taskExecutionEngine, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_burp_control_state", mapOf(
                        "control" to "task_execution_engine",
                        "enabled" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now paused")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.PAUSED }
        }

        @Test
        fun `control mutation failure reports uncertain state and forbids automatic retry`() = runBlocking {
            val taskExecutionEngine = mockk<TaskExecutionEngine>()
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.taskExecutionEngine() } returns taskExecutionEngine
            every { taskExecutionEngine.state = any() } throws IllegalStateException("write failed")

            val result = client.callTool(
                "set_burp_control_state",
                mapOf("control" to "task_execution_engine", "enabled" to true),
            )

            assertEquals(true, result?.isError)
            assertEquals("burp_error", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("uncertain", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
            assertEquals("do_not_retry", result?.structuredContent?.get("retry")?.jsonPrimitive?.content)
            assertTrue(result.expectTextContent().contains("do not retry automatically"))
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.RUNNING }
        }
        
        @Test
        fun `control approval denial is structured and never starts the mutation`() = runBlocking {
            val taskExecutionEngine = mockk<TaskExecutionEngine>(relaxed = true)
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.taskExecutionEngine() } returns taskExecutionEngine
            val previous = SensitiveActionSecurity.approvalHandler
            SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
                override suspend fun requestApproval(
                    action: String,
                    summary: String,
                    reviewContent: String?,
                    renderContentAsHttp: Boolean,
                    api: MontoyaApi,
                ) = false
            }

            try {
                val result = client.callTool(
                    "set_burp_control_state",
                    mapOf("control" to "task_execution_engine", "enabled" to true),
                )

                assertEquals(false, result?.isError)
                assertEquals("access_denied", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("not_started", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
                assertEquals("after_user_action", result?.structuredContent?.get("retry")?.jsonPrimitive?.content)
                verify(exactly = 0) { taskExecutionEngine.state = any() }
            } finally {
                SensitiveActionSecurity.approvalHandler = previous
            }
        }

        @Test
        fun `set proxy intercept state should work properly`() {
            val proxy = mockk<Proxy>()
            
            every { api.proxy() } returns proxy
            every { proxy.enableIntercept() } just runs
            every { proxy.disableIntercept() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_burp_control_state", mapOf(
                        "control" to "proxy_intercept",
                        "enabled" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been enabled")
            }
            
            verify(exactly = 1) { proxy.enableIntercept() }
            
            clearMocks(proxy, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_burp_control_state", mapOf(
                        "control" to "proxy_intercept",
                        "enabled" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been disabled")
            }
            
            verify(exactly = 1) { proxy.disableIntercept() }
        }
        
        @Test
        fun `config editing tools should respect config settings without logging their contents`() {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            val apiLogging = mockk<Logging>(relaxed = true)
            val sensitiveJson = "{\"api_key\":\"secret-value\"}"

            every { api.burpSuite() } returns burpSuite
            every { api.logging() } returns apiLogging
            every { burpSuite.exportProjectOptionsAsJson() } returns "{\"project_options\":{}}"
            every { burpSuite.exportUserOptionsAsJson() } returns "{\"user_options\":{}}"
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { burpSuite.importUserOptionsFromJson(any()) } just runs

            runBlocking {
                val projectRead = client.callTool("get_burp_options", mapOf("level" to "project"))
                val userRead = client.callTool("get_burp_options", mapOf("level" to "user"))
                projectRead.expectTextContent("{\"project_options\":{}}")
                userRead.expectTextContent("{\"user_options\":{}}")
                assertEquals("ok", projectRead?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals(
                    "{\"project_options\":{}}",
                    projectRead?.structuredContent?.get("configuration")?.jsonPrimitive?.content,
                )
                assertEquals(false, projectRead?.structuredContent?.get("credentialsFiltered")?.jsonPrimitive?.boolean)

                val projectResult = client.callTool(
                    "set_burp_options", mapOf("level" to "project", "json" to sensitiveJson)
                )
                val userResult = client.callTool(
                    "set_burp_options", mapOf("level" to "user", "json" to sensitiveJson)
                )

                delay(100)
                projectResult.expectTextContent("Project configuration has been applied")
                userResult.expectTextContent("User configuration has been applied")
                assertEquals("ok", projectResult?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("completed", projectResult?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
                assertEquals("not_applicable", projectResult?.structuredContent?.get("retry")?.jsonPrimitive?.content)

                val tools = client.listTools()
                val readTool = tools.single { it.name == "get_burp_options" }
                assertEquals(listOf("level"), readTool.inputSchema.required)
                assertTrue(readTool.inputSchema.properties?.get("level").toString().contains("project"))
                val setTool = tools.single { it.name == "set_burp_options" }
                assertTrue(setTool.description.orEmpty().contains("captures and rechecks the project current"))
                val jsonSchema = setTool.inputSchema.properties?.get("json").toString()
                assertTrue(jsonSchema.contains("project_options"))
                assertTrue(jsonSchema.contains("user_options"))
            }

            verify(exactly = 1) { burpSuite.exportProjectOptionsAsJson() }
            verify(exactly = 1) { burpSuite.exportUserOptionsAsJson() }
            verify(exactly = 1) { burpSuite.importProjectOptionsFromJson(sensitiveJson) }
            verify(exactly = 1) { burpSuite.importUserOptionsFromJson(sensitiveJson) }
            verify(exactly = 0) { apiLogging.logToOutput(match { "secret-value" in it }) }

            clearMocks(burpSuite, answers = false)

            every { config.configEditingTooling } returns false

            runBlocking {
                val result = client.callTool(
                    "set_burp_options", mapOf("level" to "project", "json" to sensitiveJson)
                )

                delay(100)
                result.expectTextContent("User has disabled configuration editing. They can enable it in Burp's MCP Bridge tab by selecting 'Enable tools that can edit your config'")
                assertEquals("disabled", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("not_started", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
                assertEquals("after_user_action", result?.structuredContent?.get("retry")?.jsonPrimitive?.content)
            }

            verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
        }
    }

    @Nested
    inner class HttpMessageSearchToolsTests {
        @Test
        fun `HTTP search nextCursor continues through the cursor input`() = runBlocking {
            val project = mockk<burp.api.montoya.project.Project>()
            val proxy = mockk<Proxy>()
            val first = mockk<ProxyHttpRequestResponse>()
            val second = mockk<ProxyHttpRequestResponse>()
            stubProxyHistorySummary(first, 1)
            stubProxyHistorySummary(second, 2)
            every { api.project() } returns project
            every { project.id() } returns "project-cursor-integration"
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(first, second)

            val pageOne = client.callTool(
                "search_http_messages",
                mapOf("limit" to 1, "newestFirst" to false),
            )
            val cursor = pageOne?.structuredContent?.get("nextCursor")?.jsonPrimitive?.content
            assertNotNull(cursor)
            assertTrue(pageOne?.structuredContent?.get("items").toString().contains("\"id\":\"1\""))

            val pageTwo = client.callTool(
                "search_http_messages",
                mapOf("cursor" to cursor!!, "limit" to 1),
            )
            assertEquals("ok", pageTwo?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertTrue(pageTwo?.structuredContent?.get("items").toString().contains("\"id\":\"2\""))
        }

        @Test
        fun `HTTP search marks correction and Burp failures as MCP errors`() = runBlocking {
            val project = mockk<burp.api.montoya.project.Project>()
            val proxy = mockk<Proxy>()
            every { api.project() } returns project
            every { project.id() } returns "project-http-error"
            every { api.proxy() } returns proxy
            every { proxy.history() } throws IllegalStateException("synthetic HTTP source failure")

            val invalid = client.callTool("search_http_messages", mapOf("limit" to 0))
            assertEquals(true, invalid?.isError)
            assertEquals("invalid_argument", invalid?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals(JsonNull, invalid?.structuredContent?.get("projectId"))

            val failed = client.callTool("search_http_messages", emptyMap())
            assertEquals(true, failed?.isError)
            assertEquals("burp_error", failed?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("project-http-error", failed?.structuredContent?.get("projectId")?.jsonPrimitive?.content)
            assertEquals(emptyList<JsonElement>(), failed?.structuredContent?.get("items")?.jsonArray)
        }

        @Test
        fun `unified HTTP search returns structured compact results and precise schemas`() {
            val project = mockk<burp.api.montoya.project.Project>()
            val proxy = mockk<Proxy>()
            val item = mockk<ProxyHttpRequestResponse>()
            val request = mockk<HttpRequest>()
            val body = mockk<MontoyaByteArray>()
            val service = mockk<burp.api.montoya.http.HttpService>()
            val annotations = mockk<Annotations>()

            every { api.project() } returns project
            every { project.id() } returns "project-integration"
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(item)
            every { item.id() } returns 81
            every { item.request() } returns request
            every { item.response() } returns null
            every { item.httpService() } returns service
            every { item.annotations() } returns annotations
            every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z")
            every { item.listenerPort() } returns 8080
            every { item.edited() } returns false
            every { request.method() } returns "GET"
            every { request.url() } returns "https://example.test/search"
            every { request.path() } returns "/search"
            every { request.isInScope() } returns true
            every { request.body() } returns body
            every { body.length() } returns 0
            every { service.host() } returns "example.test"
            every { service.port() } returns 443
            every { service.secure() } returns true
            every { annotations.notes() } returns null

            runBlocking {
                val result = client.callTool(
                    "search_http_messages",
                    mapOf("host" to "example.test", "pathContains" to "/search"),
                )
                assertEquals(false, result?.isError)
                assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("project-integration", result?.structuredContent?.get("projectId")?.jsonPrimitive?.content)
                assertTrue(result?.structuredContent?.get("items").toString().contains("\"id\":\"81\""))

                val attackSurface = client.callTool(
                    "summarize_http_attack_surface",
                    mapOf("projectId" to "project-integration", "pathDepth" to 1),
                )
                assertEquals(false, attackSurface?.isError)
                assertEquals("ok", attackSurface?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals(1, attackSurface?.structuredContent?.get("matchedRecords")?.jsonPrimitive?.content?.toInt())
                assertTrue(attackSurface?.structuredContent?.get("pathPrefixes").toString().contains("/search"))

                val wrongProject = client.callTool(
                    "get_http_message",
                    mapOf(
                        "projectId" to "another-project",
                        "ref" to mapOf("source" to "proxy", "id" to "81"),
                    ),
                )
                assertEquals(
                    "project_mismatch",
                    wrongProject?.structuredContent?.get("status")?.jsonPrimitive?.content,
                )
                assertEquals(true, wrongProject?.isError)

                val searchTool = client.listTools().single { it.name == "search_http_messages" }
                assertEquals(emptyList<String>(), searchTool.inputSchema.required)
                val sourceSchema = searchTool.inputSchema.properties?.get("sources").toString()
                assertTrue(sourceSchema.contains("\"proxy\""))
                assertTrue(sourceSchema.contains("\"site_map\""))
                assertTrue(sourceSchema.contains("\"organizer\""))
                val cursorSchema = searchTool.inputSchema.properties?.get("cursor").toString()
                assertTrue(cursorSchema.contains("Returned nextCursor"))
                assertTrue(cursorSchema.contains("repeat exactly the same filters"))
                assertTrue(cursorSchema.contains("only limit may change"))
                assertNotNull(searchTool.outputSchema?.properties?.get("items"))
                assertEquals(true, searchTool.annotations?.readOnlyHint)
                assertEquals(false, searchTool.annotations?.destructiveHint)

                val detailTool = client.listTools().single { it.name == "get_http_message" }
                assertEquals(setOf("projectId", "ref"), detailTool.inputSchema.required?.toSet())
                assertTrue(detailTool.inputSchema.properties?.get("ref").toString().contains("site_map"))
                assertTrue(detailTool.outputSchema?.properties?.get("status").toString().contains("project_mismatch"))
            }
        }
    }

    @Nested
    inner class HttpMessageActionToolsTests {
        @Test
        fun `ID based Repeater action is structured bounded and correctly annotated`() {
            val project = mockk<burp.api.montoya.project.Project>()
            val proxy = mockk<Proxy>()
            val item = mockk<ProxyHttpRequestResponse>()
            val request = mockk<HttpRequest>()
            val raw = mockk<MontoyaByteArray>()
            val service = mockk<burp.api.montoya.http.HttpService>()
            val repeater = mockk<burp.api.montoya.repeater.Repeater>(relaxed = true)

            every { api.project() } returns project
            every { project.id() } returns "project-actions"
            every { api.proxy() } returns proxy
            every { proxy.history(any()) } answers {
                val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
                listOf(item).filter(filter::matches)
            }
            every { item.id() } returns 91
            every { item.request() } returns request
            every { item.response() } returns null
            every { item.httpService() } returns service
            every { request.toByteArray() } returns raw
            every { request.bodyOffset() } returns 48
            every { request.body() } returns raw
            every { raw.length() } returns 0
            every { request.toString() } returns "GET /action HTTP/1.1\r\nHost: example.test\r\n\r\n"
            every { request.httpService() } returns service
            every { request.method() } returns "GET"
            every { request.path() } returns "/action"
            every { request.httpVersion() } returns "HTTP/1.1"
            every { service.host() } returns "example.test"
            every { service.port() } returns 443
            every { service.secure() } returns true
            every { api.repeater() } returns repeater

            runBlocking {
                val result = client.callTool(
                    "route_http_message_from_id",
                    mapOf(
                        "projectId" to "project-actions",
                        "ref" to mapOf("source" to "proxy", "id" to "91"),
                        "destination" to "repeater",
                        "tabName" to "derived",
                    ),
                )

                assertEquals(false, result?.isError)
                assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals("completed", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
                verify(exactly = 1) { repeater.sendToRepeater(request, "derived") }

                val tools = client.listTools()
                val repeaterTool = tools.single { it.name == "route_http_message_from_id" }
                assertEquals(setOf("projectId", "ref", "destination"), repeaterTool.inputSchema.required?.toSet())
                assertEquals(false, repeaterTool.annotations?.readOnlyHint)
                assertEquals(false, repeaterTool.annotations?.destructiveHint)
                assertEquals(false, repeaterTool.annotations?.idempotentHint)
                assertEquals(false, repeaterTool.annotations?.openWorldHint)
                assertTrue(repeaterTool.outputSchema?.properties?.get("status").toString().contains("execution_uncertain"))

                val sendTool = tools.single { it.name == "send_http_request_from_id" }
                assertEquals(true, sendTool.annotations?.destructiveHint)
                assertEquals(true, sendTool.annotations?.openWorldHint)
                val modeSchema = sendTool.inputSchema.properties?.get("httpMode").toString()
                assertTrue(modeSchema.contains("http_2_ignore_alpn"))

                val destinations = repeaterTool.inputSchema.properties?.get("destination").toString()
                assertTrue(destinations.contains("repeater"))
                assertTrue(destinations.contains("intruder"))
                assertTrue(destinations.contains("organizer"))
                assertNull(tools.singleOrNull { it.name == "send_to_intruder_from_id" })
                assertNull(tools.singleOrNull { it.name == "send_to_organizer_from_id" })
            }
        }
    }

    @Nested
    inner class StableHistoryAccessTests {
        @Test
        fun `HTTP message lookup returns bounded structured content and read-only metadata`() {
            val project = mockk<burp.api.montoya.project.Project>()
            val proxy = mockk<Proxy>()
            val item = mockk<ProxyHttpRequestResponse>()
            val request = mockk<HttpRequest>()
            val body = mockk<MontoyaByteArray>()
            val selected = mockk<MontoyaByteArray>()
            val service = mockk<burp.api.montoya.http.HttpService>()
            val annotations = mockk<Annotations>()

            every { api.project() } returns project
            every { project.id() } returns "project-history"
            every { api.proxy() } returns proxy
            every { proxy.history(any()) } answers {
                val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
                listOf(item).filter(filter::matches)
            }
            every { item.id() } returns 42
            every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z")
            every { item.request() } returns request
            every { item.response() } returns null
            every { item.httpService() } returns service
            every { item.listenerPort() } returns 8080
            every { item.edited() } returns false
            every { item.annotations() } returns annotations
            every { request.method() } returns "POST"
            every { request.url() } returns "https://example.test/upload"
            every { request.httpService() } returns service
            every { request.body() } returns body
            every { body.length() } returns 10
            every { body.subArray(2, 6) } returns selected
            every { selected.toString() } returns "cdef"
            every { service.host() } returns "example.test"
            every { service.port() } returns 443
            every { service.secure() } returns true
            every { annotations.notes() } returns "reviewed"

            runBlocking {
                val result = client.callTool(
                    "get_http_message",
                    mapOf(
                        "projectId" to "project-history",
                        "ref" to mapOf("source" to "proxy", "id" to "42"),
                        "part" to "request_body",
                        "offset" to 2,
                        "limit" to 4,
                        "encoding" to "text",
                    ),
                )
                assertEquals(false, result?.isError)
                assertNotNull(result?.structuredContent)
                val structured = result!!.structuredContent!!
                assertEquals("ok", structured["status"]?.jsonPrimitive?.content)
                assertTrue(structured["ref"].toString().contains("\"id\":\"42\""))
                assertTrue(structured["metadata"].toString().contains("\"time\":\"2026-01-02T03:04:05Z\""))
                assertTrue(structured["metadata"].toString().contains("\"notes\":\"reviewed\""))
                assertTrue(structured["metadata"].toString().contains("\"notesTruncated\":false"))
                val content = structured["content"]
                assertNotNull(content)
                assertTrue(content.toString().contains("\"data\":\"cdef\""))
                assertTrue(content.toString().contains("\"nextOffsetBytes\":6"))

                val tool = client.listTools().single { it.name == "get_http_message" }
                assertEquals(setOf("projectId", "ref"), tool.inputSchema.required?.toSet())
                val outputProperties = tool.outputSchema?.properties
                assertNotNull(outputProperties)
                assertTrue(outputProperties!!.containsKey("status"))
                assertTrue(outputProperties["status"].toString().contains("\"not_found\""))
                assertTrue(outputProperties.containsKey("content"))
                assertEquals(true, tool.annotations?.readOnlyHint)
                assertEquals(false, tool.annotations?.destructiveHint)
                assertEquals(true, tool.annotations?.idempotentHint)
                assertEquals(false, tool.annotations?.openWorldHint)
            }

            verify(exactly = 1) { proxy.history(any()) }
            verify(exactly = 0) { proxy.history() }
        }

        @Test
        fun `Organizer lookup returns metadata by stable ID`() {
            val project = mockk<burp.api.montoya.project.Project>()
            val organizer = mockk<Organizer>()
            val item = mockk<OrganizerItem>()
            val request = mockk<HttpRequest>()
            val service = mockk<burp.api.montoya.http.HttpService>()
            val annotations = mockk<Annotations>()
            val body = mockk<MontoyaByteArray>()

            every { api.project() } returns project
            every { project.id() } returns "project-history"
            every { api.organizer() } returns organizer
            every { organizer.items(any()) } answers {
                val filter = firstArg<burp.api.montoya.organizer.OrganizerItemFilter>()
                listOf(item).filter(filter::matches)
            }
            every { item.id() } returns 73
            every { item.request() } returns request
            every { item.response() } returns null
            every { item.httpService() } returns service
            every { item.annotations() } returns annotations
            every { request.method() } returns "GET"
            every { request.url() } returns "https://example.test/organized"
            every { request.httpService() } returns service
            every { request.body() } returns body
            every { body.length() } returns 0
            every { service.host() } returns "example.test"
            every { service.port() } returns 443
            every { service.secure() } returns true
            every { annotations.notes() } returns null

            runBlocking {
                val result = client.callTool(
                    "get_http_message",
                    mapOf(
                        "projectId" to "project-history",
                        "ref" to mapOf("source" to "organizer", "id" to "73"),
                    ),
                )
                assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertTrue(result?.structuredContent?.get("metadata").toString().contains("\"source\":\"organizer\""))
            }

            verify(exactly = 1) { organizer.items(any()) }
            verify(exactly = 0) { organizer.items() }
        }

        @Test
        fun `WebSocket lookup supports base64 slices and missing IDs`() {
            val proxy = mockk<Proxy>()
            val item = mockk<ProxyWebSocketMessage>()
            val payload = mockk<MontoyaByteArray>()
            val selected = mockk<MontoyaByteArray>()
            val annotations = mockk<Annotations>()

            every { api.proxy() } returns proxy
            every { proxy.webSocketHistory(any()) } answers {
                val filter = firstArg<burp.api.montoya.proxy.ProxyWebSocketHistoryFilter>()
                listOf(item).filter(filter::matches)
            }
            every { item.id() } returns 17
            every { item.webSocketId() } returns 9
            every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z")
            every { item.direction() } returns Direction.SERVER_TO_CLIENT
            every { item.listenerPort() } returns 8080
            every { item.payload() } returns payload
            every { item.annotations() } returns annotations
            every { annotations.notes() } returns null
            every { payload.length() } returns 5
            every { payload.subArray(1, 4) } returns selected
            every { selected.getBytes() } returns byteArrayOf(2, 3, 4)

            runBlocking {
                val result = client.callTool(
                    "get_websocket_message_by_id",
                    mapOf(
                        "id" to 17,
                        "projectId" to "project-default",
                        "offset" to 1,
                        "limit" to 3,
                        "encoding" to "base64",
                    ),
                )
                assertNotNull(result?.structuredContent)
                val structured = result!!.structuredContent!!
                assertEquals("ok", structured["status"]?.jsonPrimitive?.content)
                assertEquals("project-default", structured["projectId"]?.jsonPrimitive?.content)
                assertTrue(structured["metadata"].toString().contains("\"notesTruncated\":false"))
                assertTrue(structured["content"].toString().contains("\"data\":\"AgME\""))

                val missing = client.callTool(
                    "get_websocket_message_by_id",
                    mapOf("id" to 999, "projectId" to "project-default"),
                )
                assertEquals("not_found", missing?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals(true, missing?.isError)

                val wrongProject = client.callTool(
                    "get_websocket_message_by_id",
                    mapOf("id" to 17, "projectId" to "different-project"),
                )
                assertEquals(
                    "project_mismatch",
                    wrongProject?.structuredContent?.get("status")?.jsonPrimitive?.content,
                )
                assertEquals(true, wrongProject?.isError)
                val invalidId = client.callTool(
                    "get_websocket_message_by_id",
                    mapOf("id" to -1, "projectId" to "project-default"),
                )
                assertEquals(true, invalidId?.isError)
            }

            verify(exactly = 2) { proxy.webSocketHistory(any()) }
            verify(exactly = 0) { proxy.webSocketHistory() }
        }

        @Test
        fun `WebSocket lookup discards a result when the project changes during resolution`() = runBlocking {
            val project = mockk<burp.api.montoya.project.Project>()
            val proxy = mockk<Proxy>()
            val item = mockk<ProxyWebSocketMessage>()
            every { api.project() } returns project
            every { project.id() } returnsMany listOf("project-before", "project-after")
            every { api.proxy() } returns proxy
            every { proxy.webSocketHistory(any()) } answers {
                val filter = firstArg<burp.api.montoya.proxy.ProxyWebSocketHistoryFilter>()
                listOf(item).filter(filter::matches)
            }
            every { item.id() } returns 21

            val result = client.callTool(
                "get_websocket_message_by_id",
                mapOf("id" to 21, "projectId" to "project-before"),
            )

            assertEquals("project_mismatch", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("project-after", result?.structuredContent?.get("projectId")?.jsonPrimitive?.content)
            verify(exactly = 0) { item.payload() }
        }
    }
    
    @Test
    fun `WebSocket search and detail expose bounded MCP error outcomes`() = runBlocking {
        val project = mockk<burp.api.montoya.project.Project>()
        val proxy = mockk<Proxy>()
        every { api.project() } returns project
        every { project.id() } returns "project-websocket-error"
        every { api.proxy() } returns proxy
        every { proxy.webSocketHistory() } throws IllegalStateException("synthetic WebSocket search failure")
        every { proxy.webSocketHistory(any()) } throws IllegalStateException("synthetic WebSocket read failure")

        val invalidSearch = client.callTool(
            "search_websocket_messages",
            mapOf("projectId" to "project-websocket-error", "limit" to 0),
        )
        assertEquals(true, invalidSearch?.isError)
        assertEquals("invalid_argument", invalidSearch?.structuredContent?.get("status")?.jsonPrimitive?.content)
        assertEquals(JsonNull, invalidSearch?.structuredContent?.get("projectId"))

        val search = client.callTool(
            "search_websocket_messages",
            mapOf("projectId" to "project-websocket-error"),
        )
        assertEquals(true, search?.isError)
        assertEquals("burp_error", search?.structuredContent?.get("status")?.jsonPrimitive?.content)
        assertEquals("project-websocket-error", search?.structuredContent?.get("projectId")?.jsonPrimitive?.content)

        val detail = client.callTool(
            "get_websocket_message_by_id",
            mapOf("id" to 7, "projectId" to "project-websocket-error"),
        )
        assertEquals(true, detail?.isError)
        assertEquals("burp_error", detail?.structuredContent?.get("status")?.jsonPrimitive?.content)
        assertEquals("project-websocket-error", detail?.structuredContent?.get("projectId")?.jsonPrimitive?.content)
    }

    @Test
    fun `WebSocket empty success keeps complete page content and required output schema`() = runBlocking {
        val project = mockk<burp.api.montoya.project.Project>()
        val proxy = mockk<Proxy>()
        every { api.project() } returns project
        every { project.id() } returns "project-websocket-empty"
        every { api.proxy() } returns proxy
        every { proxy.webSocketHistory() } returns emptyList()

        val tool = client.listTools().single { it.name == "search_websocket_messages" }
        val expectedKeys = setOf(
            "status",
            "projectId",
            "items",
            "returned",
            "scanned",
            "scannedContentBytes",
            "oversizedContentSkipped",
            "scanLimitReached",
            "contentLimitReached",
            "hasMore",
            "nextCursor",
            "error",
        )
        assertEquals(expectedKeys, tool.outputSchema?.required?.toSet())

        val result = client.callTool(
            "search_websocket_messages",
            mapOf("projectId" to "project-websocket-empty"),
        )
        assertNotNull(result?.structuredContent)
        val structured = result!!.structuredContent!!
        assertEquals(expectedKeys, structured.keys)
        assertEquals("ok", structured.getValue("status").jsonPrimitive.content)
        assertEquals(emptyList<JsonElement>(), structured.getValue("items").jsonArray)
        assertEquals(0, structured.getValue("returned").jsonPrimitive.content.toInt())
        assertEquals(false, structured.getValue("hasMore").jsonPrimitive.boolean)
        assertEquals(JsonNull, structured.getValue("nextCursor"))
        assertEquals(JsonNull, structured.getValue("error"))
    }

    @Test
    fun `scope comparison and enhanced action tools expose precise structured schemas`() = runBlocking {
        val tools = client.listTools()
        assertEquals(21, tools.size)
        assertTrue(tools.all { it.annotations?.readOnlyHint != null }, "Every tool needs an explicit read-only classification")
        val toolNames = tools.mapTo(mutableSetOf()) { it.name }
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
            ),
            toolNames,
        )
        assertTrue(
            toolNames.intersect(
                setOf(
                    "url_encode",
                    "url_decode",
                    "base64_encode",
                    "base64_decode",
                    "output_project_options",
                    "output_user_options",
                    "set_project_options",
                    "set_user_options",
                    "set_task_execution_engine_state",
                    "set_proxy_intercept_state",
                    "get_http_message_by_id",
                    "get_organizer_item_by_id",
                    "get_sitemap_message_by_id",
                    "create_repeater_tab_from_id",
                    "send_to_intruder_from_id",
                    "send_to_organizer_from_id",
                    "get_proxy_http_history_regex",
                    "get_organizer_items_regex",
                    "get_proxy_websocket_history_regex",
                    "send_http1_request",
                    "send_http2_request",
                    "create_repeater_tab",
                    "create_repeater_tab_http2",
                    "send_to_intruder",
                    "get_proxy_http_history",
                    "get_organizer_items",
                    "get_proxy_websocket_history",
                )
            ).isEmpty()
        )

        assertTrue(tools.all { it.outputSchema != null }, "Every v4.1 tool must advertise an output schema")

        val optionsMutation = tools.single { it.name == "set_burp_options" }
        assertTrue(optionsMutation.outputSchema?.properties?.get("executionState").toString().contains("uncertain"))
        assertTrue(optionsMutation.outputSchema?.properties?.get("retry").toString().contains("do_not_retry"))
        val sharedStatusSchema = optionsMutation.outputSchema?.properties?.get("status").toString()
        assertTrue(sharedStatusSchema.contains("not_available"))
        assertTrue(sharedStatusSchema.contains("not_editable"))

        val attackSurface = tools.single { it.name == "summarize_http_attack_surface" }
        assertEquals(setOf("projectId"), attackSurface.inputSchema.required?.toSet())
        assertTrue(attackSurface.inputSchema.properties?.get("sources").toString().contains("\"maxItems\":3"))
        assertTrue(attackSurface.inputSchema.properties?.get("pathDepth").toString().contains("\"maximum\":4"))
        assertNotNull(attackSurface.outputSchema?.properties?.get("services"))
        assertNotNull(attackSurface.outputSchema?.properties?.get("pathPrefixes"))
        assertNotNull(attackSurface.outputSchema?.properties?.get("extensions"))
        assertNotNull(attackSurface.outputSchema?.properties?.get("availableInScopeRecords"))
        assertEquals(true, attackSurface.annotations?.readOnlyHint)
        assertEquals(false, attackSurface.annotations?.destructiveHint)

        val correlation = tools.single { it.name == "correlate_http_activity" }
        assertEquals(
            setOf("projectId", "baselineRefs", "comparisonRefs"),
            correlation.inputSchema.required?.toSet(),
        )
        assertTrue(correlation.inputSchema.properties?.get("baselineRefs").toString().contains("\"maxItems\":16"))
        assertTrue(correlation.inputSchema.properties?.get("comparisonRefs").toString().contains("\"maxItems\":16"))
        assertTrue(correlation.inputSchema.properties?.get("pathDepth").toString().contains("\"maximum\":4"))
        assertNotNull(correlation.outputSchema?.properties?.get("timeline"))
        assertNotNull(correlation.outputSchema?.properties?.get("similarityGroups"))
        assertNotNull(correlation.outputSchema?.properties?.get("delta"))
        val correlationEvidenceSchema = correlation.outputSchema?.properties?.get("evidence")!!.jsonObject
        assertTrue(
            setOf(
                "ordering",
                "chronologyEstablished",
                "cohortBoundaryEstablishesTime",
                "exactCrossSourceIdentityEstablished",
                "probableDuplicatesDeduplicated",
                "maxReferences",
                "maxReferencesPerCohort",
                "maxPathDepth",
                "maxIndexedPathChars",
                "limitations",
            ).all { required -> correlationEvidenceSchema.getValue("required").jsonArray.any { it.jsonPrimitive.content == required } }
        )
        assertEquals(true, correlation.annotations?.readOnlyHint)
        assertEquals(false, correlation.annotations?.destructiveHint)
        val invalidCorrelation = client.callTool(
            "correlate_http_activity",
            mapOf(
                "projectId" to "project-schema",
                "baselineRefs" to emptyList<Map<String, String>>(),
                "comparisonRefs" to listOf(mapOf("source" to "proxy", "id" to "1")),
            ),
        )
        assertEquals("invalid_argument", invalidCorrelation?.structuredContent?.get("status")?.jsonPrimitive?.content)
        val invalidCorrelationEvidence = invalidCorrelation?.structuredContent?.get("evidence")!!.jsonObject
        assertEquals("caller_supplied", invalidCorrelationEvidence.getValue("ordering").jsonPrimitive.content)
        assertEquals(false, invalidCorrelationEvidence.getValue("chronologyEstablished").jsonPrimitive.boolean)
        assertEquals(false, invalidCorrelationEvidence.getValue("exactCrossSourceIdentityEstablished").jsonPrimitive.boolean)
        assertTrue(invalidCorrelationEvidence.getValue("limitations").jsonArray.isNotEmpty())
        assertEquals(true, invalidCorrelation?.isError)

        val checkScope = tools.single { it.name == "check_scope" }
        assertEquals(setOf("projectId", "targets"), checkScope.inputSchema.required?.toSet())
        assertNotNull(checkScope.outputSchema?.properties?.get("targets"))
        assertEquals(true, checkScope.annotations?.readOnlyHint)
        assertEquals(true, checkScope.annotations?.idempotentHint)
        assertTrue(checkScope.inputSchema.properties?.get("targets").toString().contains("\"maxItems\":32"))
        assertTrue(checkScope.inputSchema.properties?.get("targets").toString().contains("\"additionalProperties\":false"))

        val updateScope = tools.single { it.name == "update_scope" }
        assertTrue(updateScope.inputSchema.properties?.get("operation").toString().contains("include"))
        assertTrue(updateScope.inputSchema.properties?.get("operation").toString().contains("exclude"))
        assertTrue(updateScope.outputSchema?.properties?.get("executionState").toString().contains("uncertain"))
        assertEquals(true, updateScope.annotations?.destructiveHint)
        assertEquals(true, updateScope.annotations?.idempotentHint)
        assertEquals(false, updateScope.annotations?.openWorldHint)

        val comparison = tools.single { it.name == "compare_http_messages" }
        assertEquals(setOf("projectId", "refs"), comparison.inputSchema.required?.toSet())
        assertTrue(comparison.inputSchema.properties?.get("part").toString().contains("response_body"))
        assertTrue(comparison.inputSchema.properties?.get("excerptEncoding").toString().contains("base64"))
        assertNotNull(comparison.outputSchema?.properties?.get("responseVariations"))
        assertEquals(true, comparison.annotations?.readOnlyHint)

        val savePreset = tools.single { it.name == "save_workflow_preset" }
        assertEquals(setOf("projectId", "name", "definition"), savePreset.inputSchema.required?.toSet())
        val definitionSchema = savePreset.inputSchema.properties?.get("definition").toString()
        assertTrue(definitionSchema.contains("\"oneOf\""))
        assertTrue(definitionSchema.contains("httpSearch"))
        assertTrue(definitionSchema.contains("webSocketSearch"))
        assertTrue(definitionSchema.contains("httpComparison"))
        listOf("projectId", "cursor", "refs", "text", "regex", "searchIn", "caseSensitive", "webSocketId").forEach {
            assertFalse(definitionSchema.contains("\"$it\":"), "saved definition must not expose $it")
        }
        assertEquals(false, savePreset.annotations?.readOnlyHint)
        assertEquals(true, savePreset.annotations?.destructiveHint)
        assertEquals(true, savePreset.annotations?.idempotentHint)
        assertEquals(false, savePreset.annotations?.openWorldHint)
        val listPreset = tools.single { it.name == "list_workflow_presets" }
        val deletePreset = tools.single { it.name == "delete_workflow_preset" }
        val executePreset = tools.single { it.name == "execute_workflow_preset" }
        assertEquals(true, listPreset.annotations?.readOnlyHint)
        assertEquals(true, executePreset.annotations?.readOnlyHint)
        assertEquals(false, deletePreset.annotations?.readOnlyHint)
        assertEquals(true, deletePreset.annotations?.destructiveHint)
        assertNotNull(executePreset.outputSchema?.properties?.get("httpSearch"))
        assertNotNull(executePreset.outputSchema?.properties?.get("webSocketSearch"))
        assertNotNull(executePreset.outputSchema?.properties?.get("httpComparison"))

        val invalidPresetSave = client.callTool(
            "save_workflow_preset",
            mapOf(
                "projectId" to "wrong-project",
                "name" to "metadata",
                "definition" to mapOf("httpSearch" to emptyMap<String, Any>()),
            ),
        )
        assertEquals(true, invalidPresetSave?.isError)
        assertEquals("project_mismatch", invalidPresetSave?.structuredContent?.get("status")?.jsonPrimitive?.content)
        val validPresetSave = client.callTool(
            "save_workflow_preset",
            mapOf(
                "projectId" to "project-default",
                "name" to "metadata",
                "definition" to mapOf("httpSearch" to mapOf("defaultLimit" to 5)),
            ),
        )
        assertEquals(false, validPresetSave?.isError)
        assertEquals("ok", validPresetSave?.structuredContent?.get("status")?.jsonPrimitive?.content)
        val presetList = client.callTool(
            "list_workflow_presets", mapOf("projectId" to "project-default")
        )
        assertEquals(false, presetList?.isError)
        val delegatedNonOk = client.callTool(
            "execute_workflow_preset",
            mapOf(
                "projectId" to "project-default",
                "name" to "metadata",
                "cursor" to "invalid-runtime-cursor",
            ),
        )
        assertEquals(true, delegatedNonOk?.isError)
        assertEquals("ok", delegatedNonOk?.structuredContent?.get("status")?.jsonPrimitive?.content)
        assertEquals(
            "invalid_cursor",
            delegatedNonOk?.structuredContent?.get("httpSearch")?.jsonObject
                ?.get("status")?.jsonPrimitive?.content,
        )
        assertEquals(null, delegatedNonOk?.structuredContent?.get("webSocketSearch"))
        assertEquals(null, delegatedNonOk?.structuredContent?.get("httpComparison"))
        val absentDelete = client.callTool(
            "delete_workflow_preset", mapOf("projectId" to "project-default", "name" to "absent")
        )
        assertEquals(false, absentDelete?.isError)
        assertEquals(false, absentDelete?.structuredContent?.get("deleted")?.jsonPrimitive?.boolean)
        val absentExecute = client.callTool(
            "execute_workflow_preset", mapOf("projectId" to "project-default", "name" to "absent")
        )
        assertEquals(true, absentExecute?.isError)
        assertEquals("not_found", absentExecute?.structuredContent?.get("status")?.jsonPrimitive?.content)

        val sessionAnalysis = tools.single { it.name == "analyze_http_session_security" }
        assertEquals(setOf("projectId", "refs"), sessionAnalysis.inputSchema.required?.toSet())
        assertTrue(sessionAnalysis.inputSchema.properties?.get("refs").toString().contains("\"minItems\":1"))
        assertTrue(sessionAnalysis.inputSchema.properties?.get("refs").toString().contains("\"maxItems\":32"))
        assertNotNull(sessionAnalysis.outputSchema?.properties?.get("messages"))
        assertNotNull(sessionAnalysis.outputSchema?.properties?.get("cookieSummaries"))
        assertNotNull(sessionAnalysis.outputSchema?.properties?.get("invariants"))
        assertNotNull(sessionAnalysis.outputSchema?.properties?.get("variants"))
        val sessionEvidenceSchema = sessionAnalysis.outputSchema?.properties?.get("evidence")!!.jsonObject
        assertTrue(
            setOf(
                "proposedFlowOnly",
                "chronologyOrCausalityEstablished",
                "vulnerabilityAssessment",
                "maxMessages",
                "maxHeadersPerRequestOrResponse",
                "maxHeaderLineChars",
                "maxSelectedHeaderChars",
                "maxRequestCookieNamesPerMessage",
                "maxResponseCookiesPerMessage",
                "maxCookiesPerAnalysis",
                "maxRedirectHops",
                "limitations",
            ).all { required -> sessionEvidenceSchema.getValue("required").jsonArray.any { it.jsonPrimitive.content == required } }
        )
        val sessionMessagesSchema = sessionAnalysis.outputSchema?.properties?.get("messages").toString()
        assertTrue(sessionMessagesSchema.contains("partitioned"))
        assertTrue(sessionMessagesSchema.contains("domainScope"))
        assertTrue(sessionMessagesSchema.contains("pathScope"))
        assertTrue(sessionMessagesSchema.contains("lifetime"))
        assertTrue(sessionMessagesSchema.contains("prefixCompliant"))
        assertEquals(true, sessionAnalysis.annotations?.readOnlyHint)
        assertEquals(false, sessionAnalysis.annotations?.destructiveHint)
        assertEquals(true, sessionAnalysis.annotations?.idempotentHint)
        assertEquals(false, sessionAnalysis.annotations?.openWorldHint)

        val intruder = tools.single { it.name == "route_http_message_from_id" }
        val insertionSchema = intruder.inputSchema.properties?.get("insertionPoints").toString()
        assertTrue(insertionSchema.contains("parameter"))
        assertTrue(insertionSchema.contains("header"))
        assertTrue(insertionSchema.contains("body"))
        assertNotNull(intruder.outputSchema?.properties?.get("insertionPointCount"))

        val replay = tools.single { it.name == "send_http_request_from_id" }
        assertNotNull(replay.outputSchema?.properties?.get("recordedRef"))
        assertTrue("patchApplied" in replay.outputSchema?.required.orEmpty())
        val redirectSchema = replay.inputSchema.properties?.get("redirection").toString()
        assertTrue(redirectSchema.contains("\"enum\":[\"never\",null]"))
        assertTrue(redirectSchema.contains("\"default\":\"never\""))

        val rawSend = tools.single { it.name == "send_raw_http_request" }
        assertEquals(
            setOf("protocol", "targetHostname", "targetPort", "usesHttps"),
            rawSend.inputSchema.required?.toSet(),
        )
        assertNotNull(rawSend.inputSchema.properties?.get("http1"))
        assertNotNull(rawSend.inputSchema.properties?.get("http2"))
        assertNotNull(rawSend.inputSchema.properties?.get("responseTimeoutMs"))
        assertTrue(rawSend.outputSchema?.properties?.get("executionState").toString().contains("uncertain"))
        assertNotNull(rawSend.outputSchema?.properties?.get("recordedRef"))
        assertEquals(false, rawSend.annotations?.readOnlyHint)
        assertEquals(true, rawSend.annotations?.destructiveHint)
        assertEquals(true, rawSend.annotations?.openWorldHint)
        assertEquals(false, rawSend.annotations?.idempotentHint)

        val rawRoute = tools.single { it.name == "route_raw_http_request" }
        assertTrue(rawRoute.inputSchema.properties?.get("destination").toString().contains("organizer"))
        assertTrue(rawRoute.inputSchema.properties?.get("protocol").toString().contains("http_2"))
        assertEquals(false, rawRoute.annotations?.readOnlyHint)
        assertEquals(false, rawRoute.annotations?.destructiveHint)
        assertEquals(false, rawRoute.annotations?.openWorldHint)
        assertEquals(false, rawRoute.annotations?.idempotentHint)

        val search = tools.single { it.name == "search_http_messages" }
        assertTrue(search.inputSchema.properties?.get("regex").toString().contains("\"maxLength\":512"))
        assertTrue(search.outputSchema?.properties?.get("status").toString().contains("burp_error"))
        assertTrue(search.outputSchema?.properties?.get("hasMore").toString().contains("items is empty"))

        val websocketSearch = tools.single { it.name == "search_websocket_messages" }
        assertEquals(setOf("projectId"), websocketSearch.inputSchema.required?.toSet())
        assertTrue(websocketSearch.inputSchema.properties?.get("regex").toString().contains("\"maxLength\":512"))
        assertTrue(websocketSearch.inputSchema.properties?.get("limit").toString().contains("\"maximum\":50"))
        assertNotNull(websocketSearch.outputSchema?.properties?.get("nextCursor"))
        assertNotNull(websocketSearch.outputSchema?.properties?.get("scannedContentBytes"))
        assertEquals(true, websocketSearch.annotations?.readOnlyHint)
        assertEquals(false, websocketSearch.annotations?.destructiveHint)

        val websocketDetail = tools.single { it.name == "get_websocket_message_by_id" }
        assertEquals(setOf("id", "projectId"), websocketDetail.inputSchema.required?.toSet())
        assertTrue(websocketDetail.outputSchema?.properties?.get("status").toString().contains("invalid_argument"))
        assertTrue(websocketDetail.outputSchema?.properties?.get("status").toString().contains("burp_error"))

        val project = mockk<burp.api.montoya.project.Project>()
        val scope = mockk<burp.api.montoya.scope.Scope>()
        every { api.project() } returns project
        every { project.id() } returns "project-schema"
        every { api.scope() } returns scope
        every { scope.isInScope("https://example.test/") } returns true
        val scopeResult = client.callTool(
            "check_scope",
            mapOf(
                "projectId" to "project-schema",
                "targets" to listOf(mapOf("url" to "https://EXAMPLE.test:443")),
            ),
        )
        assertEquals("ok", scopeResult?.structuredContent?.get("status")?.jsonPrimitive?.content)
        assertTrue(scopeResult?.structuredContent?.get("targets").toString().contains("https://example.test/"))

        val invalidComparison = client.callTool(
            "compare_http_messages",
            mapOf("projectId" to "project-schema", "refs" to emptyList<Any>()),
        )
        assertEquals(
            "invalid_argument",
            invalidComparison?.structuredContent?.get("status")?.jsonPrimitive?.content,
        )

        val sessionProxy = mockk<Proxy>()
        val sessionItem = mockk<ProxyHttpRequestResponse>()
        val sessionRequest = mockk<HttpRequest>()
        val sessionService = mockk<burp.api.montoya.http.HttpService>()
        every { api.proxy() } returns sessionProxy
        every { sessionProxy.history(any()) } returns listOf(sessionItem)
        every { sessionItem.id() } returns 31
        every { sessionItem.request() } returns sessionRequest
        every { sessionItem.response() } returns null
        every { sessionRequest.method() } returns "GET"
        every { sessionRequest.path() } returns "/login"
        every { sessionRequest.headers() } returns emptyList()
        every { sessionRequest.httpService() } returns sessionService
        every { sessionService.host() } returns "example.test"
        every { sessionService.port() } returns 443
        every { sessionService.secure() } returns true
        val sessionResult = client.callTool(
            "analyze_http_session_security",
            mapOf(
                "projectId" to "project-schema",
                "refs" to listOf(mapOf("source" to "proxy", "id" to "31")),
            ),
        )
        assertEquals("ok", sessionResult?.structuredContent?.get("status")?.jsonPrimitive?.content)
        assertEquals(false, sessionResult?.isError)
        assertTrue(sessionResult?.structuredContent?.get("messages").toString().contains("\"index\":0"))
        val sessionEvidence = sessionResult?.structuredContent?.get("evidence")!!.jsonObject
        assertEquals(true, sessionEvidence.getValue("proposedFlowOnly").jsonPrimitive.boolean)
        assertEquals(false, sessionEvidence.getValue("chronologyOrCausalityEstablished").jsonPrimitive.boolean)
        assertEquals(false, sessionEvidence.getValue("vulnerabilityAssessment").jsonPrimitive.boolean)
        assertTrue(sessionEvidence.getValue("limitations").jsonArray.isNotEmpty())

        val invalidSessionResult = client.callTool(
            "analyze_http_session_security",
            mapOf(
                "projectId" to "project-schema",
                "refs" to (1..33).map { mapOf("source" to "proxy", "id" to it.toString()) },
            ),
        )
        assertEquals(
            "invalid_argument",
            invalidSessionResult?.structuredContent?.get("status")?.jsonPrimitive?.content,
        )
        assertEquals(true, invalidSessionResult?.isError)
    }

    @Nested
    inner class CollaboratorToolsTests {
        private val collaborator = mockk<Collaborator>()
        private val collaboratorClient = mockk<CollaboratorClient>()
        private val collaboratorServer = mockk<CollaboratorServer>()
        private val collaboratorProjectId = "project-collaborator"

        @BeforeEach
        fun setupCollaborator() {
            mockkStatic(InteractionFilter::class)

            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            val version = mockk<burp.api.montoya.core.Version>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.version() } returns version
            every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
            every { burpSuite.taskExecutionEngine() } returns mockk(relaxed = true)
            every { burpSuite.exportProjectOptionsAsJson() } returns "{}"
            every { burpSuite.exportUserOptionsAsJson() } returns "{}"
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { burpSuite.importUserOptionsFromJson(any()) } just runs

            val project = mockk<burp.api.montoya.project.Project>()
            every { api.project() } returns project
            every { project.id() } returns collaboratorProjectId
            every { api.collaborator() } returns collaborator
            every { collaborator.createClient() } returns collaboratorClient
            every { collaboratorClient.server() } returns collaboratorServer
            every { collaboratorServer.address() } returns "burpcollaborator.net"

            serverManager.stop {}
            serverStarted = false
            serverManager.start(config) { state ->
                if (state is ServerState.Running) serverStarted = true
            }

            runBlocking {
                var attempts = 0
                while (!serverStarted && attempts < 30) {
                    delay(100)
                    attempts++
                }
                if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")
                client.connectToServer("http://127.0.0.1:${testPort}/mcp")
            }
        }

        @AfterEach
        fun cleanupCollaborator() {
            unmockkStatic(InteractionFilter::class)
        }

        private fun mockInteraction(
            id: String,
            type: InteractionType,
            clientIp: String = "10.0.0.1",
            clientPort: Int = 54321,
            customData: String? = null,
            dnsDetails: DnsDetails? = null,
            httpDetails: HttpDetails? = null,
            smtpDetails: SmtpDetails? = null
        ): Interaction {
            val interactionId = mockk<InteractionId>()
            every { interactionId.toString() } returns id

            return mockk<Interaction>().also {
                every { it.id() } returns interactionId
                every { it.type() } returns type
                every { it.timeStamp() } returns ZonedDateTime.parse("2025-01-01T12:00:00Z")
                every { it.clientIp() } returns InetAddress.getByName(clientIp)
                every { it.clientPort() } returns clientPort
                every { it.customData() } returns Optional.ofNullable(customData)
                every { it.dnsDetails() } returns Optional.ofNullable(dnsDetails)
                every { it.httpDetails() } returns Optional.ofNullable(httpDetails)
                every { it.smtpDetails() } returns Optional.ofNullable(smtpDetails)
            }
        }

        @Test
        fun `Professional Scanner Collaborator and issue search tools expose bounded schemas`() = runBlocking {
            val tools = client.listTools()
            assertEquals(28, tools.size)
            assertTrue(tools.all { it.outputSchema != null }, "Every Professional tool must advertise an output schema")
            tools.forEach(::assertNonNullOutputFieldsAreRequired)
            tools.forEach(::assertTruncatedStringsAdvertiseBounds)
            tools.forEach(::assertBurpErrorGuidanceIsSelfContained)
            assertCatalogFingerprint(
                "Professional",
                tools,
                "eb0415096841f806d4f93954126dcf46906b42aa75f130bb4075661690d04486",
            )
            tools.forEach { tool ->
                tool.inputSchema.properties?.get("projectId")?.jsonObject?.let { projectSchema ->
                    assertEquals(
                        MCP_PROJECT_ID_INPUT_DESCRIPTION,
                        projectSchema.getValue("description").jsonPrimitive.content,
                        "${tool.name}.projectId must use the common opaque project-binding contract",
                    )
                }
            }

            val start = tools.single { it.name == "start_scanner_audit_from_ids" }
            assertEquals(setOf("projectId", "mode", "targets"), start.inputSchema.required?.toSet())
            assertTrue(start.inputSchema.properties?.get("mode").toString().contains("active"))
            assertTrue(start.inputSchema.properties?.get("targets").toString().contains("insertionPoints"))
            assertTrue(start.outputSchema?.properties?.get("actionState").toString().contains("uncertain"))
            assertTrue(
                setOf(
                    "targets",
                    "targetCount",
                    "insertionPointCount",
                    "issues",
                    "issuesTruncated",
                    "issuesAccessDenied",
                    "issuesUnavailable",
                ).all { it in start.outputSchema?.required.orEmpty() }
            )
            assertEquals(false, start.annotations?.readOnlyHint)
            assertEquals(true, start.annotations?.destructiveHint)
            assertEquals(true, start.annotations?.openWorldHint)
            assertEquals(false, start.annotations?.idempotentHint)

            val get = tools.single { it.name == "get_scanner_audit" }
            assertEquals(setOf("projectId", "taskId"), get.inputSchema.required?.toSet())
            assertNotNull(get.outputSchema?.properties?.get("issues"))
            assertTrue(get.description.orEmpty().contains("issuesAccessDenied identifies an operator denial"))
            val issuesUnavailableDescription = get.outputSchema?.properties?.get("issuesUnavailable")
                ?.jsonObject?.get("description")?.jsonPrimitive?.content.orEmpty()
            assertTrue(issuesUnavailableDescription.contains("access failed technically"))
            assertTrue(issuesUnavailableDescription.contains("already cancelled"))
            assertEquals(true, get.annotations?.readOnlyHint)

            val cancel = tools.single { it.name == "cancel_scanner_audit" }
            assertEquals(false, cancel.annotations?.readOnlyHint)
            assertEquals(true, cancel.annotations?.destructiveHint)
            assertEquals(true, cancel.annotations?.idempotentHint)
            assertEquals(false, cancel.annotations?.openWorldHint)

            val issues = tools.single { it.name == "get_scanner_issues" }
            assertTrue(issues.description.orEmpty().contains("captured project is rechecked and returned as projectId"))
            assertTrue(issues.description.orEmpty().contains("Reached end of items"))
            assertNotNull(issues.inputSchema.properties?.get("cursor"))
            assertNotNull(issues.inputSchema.properties?.get("severities"))
            assertNotNull(issues.outputSchema?.properties?.get("nextCursor"))
            val scannerCursorSchema = issues.outputSchema?.properties?.get("nextCursor")!!.jsonObject
            val scannerCursorVariant = scannerCursorSchema.takeIf { it["maxLength"] != null }
                ?: scannerCursorSchema.getValue("anyOf").jsonArray.first {
                    it.jsonObject["type"]?.jsonPrimitive?.content == "string"
                }.jsonObject
            assertEquals(16_384, scannerCursorVariant.getValue("maxLength").jsonPrimitive.int)
            assertTrue("legacyTextTruncated" in issues.outputSchema?.required.orEmpty())

            val issueDetail = tools.single { it.name == "get_scanner_issue_by_id" }
            assertEquals(setOf("id", "projectId"), issueDetail.inputSchema.required?.toSet())
            assertTrue(issueDetail.outputSchema?.properties?.get("status").toString().contains("invalid_argument"))
            assertTrue(issueDetail.outputSchema?.properties?.get("status").toString().contains("burp_error"))
            val issueSummarySchema = issueDetail.outputSchema?.properties?.get("summary")!!.jsonObject
            val issueSummaryObject = issueSummarySchema.takeIf { it.containsKey("properties") }
                ?: issueSummarySchema.getValue("anyOf").jsonArray.first { it.jsonObject["type"]?.jsonPrimitive?.content == "object" }.jsonObject
            assertTrue(
                setOf("nameTruncated", "baseUrlTruncated", "hostTruncated").all {
                    it in issueSummaryObject.getValue("required").jsonArray.map { value -> value.jsonPrimitive.content }
                }
            )

            val generator = tools.single { it.name == "generate_collaborator_payload" }
            assertEquals(false, generator.annotations?.readOnlyHint)

            val interactions = tools.single { it.name == "get_collaborator_interactions" }
            assertTrue(interactions.description.orEmpty().contains("has no continuation cursor"))
            assertNotNull(interactions.inputSchema.properties?.get("waitSeconds"))
            assertTrue(interactions.inputSchema.properties?.get("detailEncoding").toString().contains("base64"))
            assertNotNull(interactions.outputSchema?.properties?.get("detailsTruncated"))
            assertTrue(interactions.outputSchema?.properties?.get("hasMore").toString().contains("no continuation cursor"))
            val interactionSchema = interactions.outputSchema?.properties?.get("interactions")!!.jsonObject
                .getValue("items").jsonObject
            assertTrue("customDataTruncated" in interactionSchema.getValue("required").jsonArray.map { it.jsonPrimitive.content })
            assertEquals(false, interactions.annotations?.idempotentHint)
            setOf(
                "generate_collaborator_payload",
                "get_collaborator_interactions",
                "get_scanner_issues",
                "get_scanner_issue_by_id",
                "get_websocket_message_by_id",
            ).forEach { toolName ->
                val errorSchema = tools.single { it.name == toolName }.outputSchema
                    ?.properties?.get("error")?.jsonObject
                assertEquals(
                    MAX_STRUCTURED_TOOL_ERROR_CHARS,
                    errorSchema?.get("maxLength")?.jsonPrimitive?.int,
                    "$toolName.error must advertise its runtime bound",
                )
            }

            val invalidStart = client.callTool(
                "start_scanner_audit_from_ids",
                mapOf("projectId" to "project", "mode" to "active", "targets" to emptyList<Any>()),
            )
            assertEquals(
                "invalid_argument",
                invalidStart?.structuredContent?.get("status")?.jsonPrimitive?.content,
            )
            assertEquals(true, invalidStart?.isError)
            assertEquals(JsonNull, invalidStart?.structuredContent?.get("projectId"))
            assertEquals(
                "not_started",
                invalidStart?.structuredContent?.get("actionState")?.jsonPrimitive?.content,
            )
            assertEquals(emptyList<JsonElement>(), invalidStart?.structuredContent?.get("targets")?.jsonArray)
            assertEquals(0, invalidStart?.structuredContent?.get("targetCount")?.jsonPrimitive?.int)
            assertEquals(emptyList<JsonElement>(), invalidStart?.structuredContent?.get("issues")?.jsonArray)
            assertEquals(false, invalidStart?.structuredContent?.get("issuesUnavailable")?.jsonPrimitive?.boolean)

            listOf("get_scanner_audit", "cancel_scanner_audit").forEach { toolName ->
                val invalidTask = client.callTool(
                    toolName,
                    mapOf("projectId" to "caller-forged", "taskId" to "not-a-task-id"),
                )
                assertEquals(true, invalidTask?.isError, toolName)
                assertEquals(
                    "invalid_id",
                    invalidTask?.structuredContent?.get("status")?.jsonPrimitive?.content,
                    toolName,
                )
                assertEquals(JsonNull, invalidTask?.structuredContent?.get("projectId"), toolName)
            }
        }

        @Test
        fun `Collaborator correction and pre-execution Burp failures set MCP isError`() = runBlocking {
            val invalidPayload = client.callTool(
                "generate_collaborator_payload",
                mapOf("projectId" to collaboratorProjectId, "customData" to "not-valid"),
            )
            assertEquals(true, invalidPayload?.isError)
            assertEquals("invalid_argument", invalidPayload?.structuredContent?.get("status")?.jsonPrimitive?.content)

            val invalidInteractions = client.callTool(
                "get_collaborator_interactions",
                mapOf("projectId" to collaboratorProjectId, "waitSeconds" to 121),
            )
            assertEquals(true, invalidInteractions?.isError)
            assertEquals("invalid_argument", invalidInteractions?.structuredContent?.get("status")?.jsonPrimitive?.content)

            val failingProject = mockk<burp.api.montoya.project.Project>()
            every { failingProject.id() } throws IllegalStateException("PRIVATE_SENTINEL")
            every { api.project() } returns failingProject

            val payloadFailure = client.callTool(
                "generate_collaborator_payload",
                mapOf("projectId" to collaboratorProjectId),
            )
            assertEquals(true, payloadFailure?.isError)
            assertEquals("burp_error", payloadFailure?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals(JsonNull, payloadFailure?.structuredContent?.get("projectId"))
            assertFalse(payloadFailure?.structuredContent.toString().contains("PRIVATE_SENTINEL"))

            val interactionFailure = client.callTool(
                "get_collaborator_interactions",
                mapOf("projectId" to collaboratorProjectId),
            )
            assertEquals(true, interactionFailure?.isError)
            assertEquals("burp_error", interactionFailure?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals(JsonNull, interactionFailure?.structuredContent?.get("projectId"))
            assertFalse(interactionFailure?.structuredContent.toString().contains("PRIVATE_SENTINEL"))
        }

        @Test
        fun `uncertain Collaborator generation preserves service MCP error classification`() = runBlocking {
            val transitioningProject = mockk<burp.api.montoya.project.Project>()
            every { api.project() } returns transitioningProject
            every { transitioningProject.id() } returnsMany listOf(
                collaboratorProjectId,
                "replacement-project",
            )
            val payload = mockk<CollaboratorPayload>()
            val payloadId = mockk<InteractionId>()
            every { payload.toString() } returns "allocated.burpcollaborator.net"
            every { payload.id() } returns payloadId
            every { payloadId.toString() } returns "allocated"
            every { collaboratorClient.generatePayload() } returns payload

            val result = client.callTool(
                "generate_collaborator_payload",
                mapOf("projectId" to collaboratorProjectId),
            )

            assertEquals(true, result?.isError)
            assertEquals(
                "execution_uncertain",
                result?.structuredContent?.get("status")?.jsonPrimitive?.content,
            )
            assertEquals("uncertain", result?.structuredContent?.get("executionState")?.jsonPrimitive?.content)
            assertEquals("do_not_retry", result?.structuredContent?.get("retry")?.jsonPrimitive?.content)
            verify(exactly = 1) { collaboratorClient.generatePayload() }
        }

        @Test
        fun `Scanner search and detail expose bounded MCP error outcomes`() = runBlocking {
            val siteMap = mockk<SiteMap>()
            every { api.siteMap() } returns siteMap
            every { siteMap.issues() } throws IllegalStateException("synthetic Scanner source failure")

            val invalidSearch = client.callTool("get_scanner_issues", mapOf("count" to 0))
            assertEquals(true, invalidSearch?.isError)
            assertEquals("invalid_argument", invalidSearch?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals(JsonNull, invalidSearch?.structuredContent?.get("projectId"))

            val search = client.callTool("get_scanner_issues", emptyMap())
            assertEquals(true, search?.isError)
            assertEquals("burp_error", search?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals(collaboratorProjectId, search?.structuredContent?.get("projectId")?.jsonPrimitive?.content)

            val detail = client.callTool(
                "get_scanner_issue_by_id",
                mapOf(
                    "projectId" to collaboratorProjectId,
                    "id" to "issue_v2_0_${"0".repeat(32)}",
                ),
            )
            assertEquals(true, detail?.isError)
            assertEquals("burp_error", detail?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals(collaboratorProjectId, detail?.structuredContent?.get("projectId")?.jsonPrimitive?.content)
        }

        @Test
        fun `legacy Scanner empty page keeps exact sentinel and complete structured flags`() = runBlocking {
            val siteMap = mockk<SiteMap>()
            every { api.siteMap() } returns siteMap
            every { siteMap.issues() } returns emptyList()

            val result = client.callTool("get_scanner_issues", emptyMap())

            result.expectTextContent("Reached end of items")
            assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals(emptyList<JsonElement>(), result?.structuredContent?.get("items")?.jsonArray)
            assertEquals(0, result?.structuredContent?.get("returned")?.jsonPrimitive?.int)
            assertEquals(false, result?.structuredContent?.get("hasMore")?.jsonPrimitive?.boolean)
            assertEquals(true, result?.structuredContent?.get("legacyMode")?.jsonPrimitive?.boolean)
            assertEquals(false, result?.structuredContent?.get("legacyTextTruncated")?.jsonPrimitive?.boolean)
        }

        @Test
        fun `Scanner issue lookup resolves a stable ID`() {
            val siteMap = mockk<SiteMap>()
            val issue = mockk<AuditIssue>()
            val service = mockk<burp.api.montoya.http.HttpService>()
            val definition = mockk<AuditIssueDefinition>()
            every { api.siteMap() } returns siteMap
            every { siteMap.issues() } returns listOf(issue)
            every { issue.definition() } returns definition
            every { definition.typeIndex() } returns 123
            every { issue.name() } returns "Example issue"
            every { issue.baseUrl() } returns "https://example.test/path"
            every { issue.httpService() } returns service
            every { service.host() } returns "example.test"
            every { service.port() } returns 443
            every { service.secure() } returns true
            every { issue.severity() } returns AuditIssueSeverity.HIGH
            every { issue.confidence() } returns AuditIssueConfidence.CERTAIN
            every { issue.detail() } returns "Issue detail"
            every { issue.requestResponses() } returns emptyList()
            val id = issue.stableHistoryId()

            runBlocking {
                val result = client.callTool(
                    "get_scanner_issue_by_id",
                    mapOf("id" to id, "projectId" to collaboratorProjectId),
                )
                assertEquals("ok", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
                assertEquals(id, result?.structuredContent?.get("id")?.jsonPrimitive?.content)
                assertEquals(
                    collaboratorProjectId,
                    result?.structuredContent?.get("projectId")?.jsonPrimitive?.content,
                )
                val summary = result?.structuredContent?.get("summary")!!.jsonObject
                assertEquals(false, summary.getValue("nameTruncated").jsonPrimitive.boolean)
                assertEquals(false, summary.getValue("baseUrlTruncated").jsonPrimitive.boolean)
                assertEquals(false, summary.getValue("hostTruncated").jsonPrimitive.boolean)
                val wrongProject = client.callTool(
                    "get_scanner_issue_by_id",
                    mapOf("id" to id, "projectId" to "different-project"),
                )
                assertEquals(
                    "project_mismatch",
                    wrongProject?.structuredContent?.get("status")?.jsonPrimitive?.content,
                )
                assertEquals(true, wrongProject?.isError)
                val invalidId = client.callTool(
                    "get_scanner_issue_by_id",
                    mapOf("id" to "not-a-stable-id", "projectId" to collaboratorProjectId),
                )
                assertEquals(true, invalidId?.isError)
            }
            verify(exactly = 1) { siteMap.issues() }
        }

        @Test
        fun `Scanner issue lookup discards bounded content after a project transition`() = runBlocking {
            val project = mockk<burp.api.montoya.project.Project>()
            val siteMap = mockk<SiteMap>()
            val issue = mockk<AuditIssue>()
            val service = mockk<burp.api.montoya.http.HttpService>()
            val definition = mockk<AuditIssueDefinition>()
            every { api.project() } returns project
            every { project.id() } returnsMany listOf(
                "project-before",
                "project-before",
                "project-before",
                "project-before",
                "project-after",
            )
            every { api.siteMap() } returns siteMap
            every { siteMap.issues() } returns listOf(issue)
            every { issue.definition() } returns definition
            every { definition.typeIndex() } returns 321
            every { issue.name() } returns "Transition issue"
            every { issue.baseUrl() } returns "https://example.test/race"
            every { issue.httpService() } returns service
            every { service.host() } returns "example.test"
            every { service.port() } returns 443
            every { service.secure() } returns true
            every { issue.severity() } returns AuditIssueSeverity.MEDIUM
            every { issue.confidence() } returns AuditIssueConfidence.FIRM
            every { issue.detail() } returns "sensitive detail"
            every { issue.remediation() } returns null
            every { issue.requestResponses() } returns emptyList()
            val id = issue.stableHistoryId()

            val result = client.callTool(
                "get_scanner_issue_by_id",
                mapOf("id" to id, "projectId" to "project-before", "field" to "detail"),
            )

            assertEquals("project_mismatch", result?.structuredContent?.get("status")?.jsonPrimitive?.content)
            assertEquals("project-after", result?.structuredContent?.get("projectId")?.jsonPrimitive?.content)
            assertEquals(null, result?.structuredContent?.get("content"))
            verify(atLeast = 1) { issue.detail() }
        }

        @Test
        fun `generate payload should return payload and server info`() {
            val payload = mockk<CollaboratorPayload>()
            val payloadId = mockk<InteractionId>()
            every { payload.toString() } returns "abc123.burpcollaborator.net"
            every { payload.id() } returns payloadId
            every { payloadId.toString() } returns "abc123"
            every { collaboratorClient.generatePayload() } returns payload

            runBlocking {
                val result = client.callTool(
                    "generate_collaborator_payload",
                    mapOf("projectId" to collaboratorProjectId),
                )
                delay(100)
                result.expectTextContent(
                    "Payload: abc123.burpcollaborator.net\n" +
                    "Payload ID: abc123\n" +
                    "Collaborator server: burpcollaborator.net"
                )
            }

            verify(exactly = 1) { collaboratorClient.generatePayload() }
        }

        @Test
        fun `generate payload with custom data should pass custom data`() {
            val payload = mockk<CollaboratorPayload>()
            val payloadId = mockk<InteractionId>()
            every { payload.toString() } returns "custom123.burpcollaborator.net"
            every { payload.id() } returns payloadId
            every { payloadId.toString() } returns "custom123"
            every { collaboratorClient.generatePayload(any<String>()) } returns payload

            runBlocking {
                val result = client.callTool(
                    "generate_collaborator_payload", mapOf(
                        "projectId" to collaboratorProjectId,
                        "customData" to "mydata",
                    )
                )
                delay(100)
                result.expectTextContent(
                    "Payload: custom123.burpcollaborator.net\n" +
                    "Payload ID: custom123\n" +
                    "Collaborator server: burpcollaborator.net"
                )
            }

            verify(exactly = 1) { collaboratorClient.generatePayload("mydata") }
        }

        @Test
        fun `get interactions should return dns interaction details`() {
            val dnsDetails = mockk<DnsDetails>().also {
                every { it.queryType() } returns DnsQueryType.A
            }
            val interaction = mockInteraction("int-001", InteractionType.DNS, dnsDetails = dnsDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool(
                    "get_collaborator_interactions",
                    mapOf("projectId" to collaboratorProjectId),
                )
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"id\":\"int-001\""))
                assertTrue(text.contains("\"type\":\"DNS\""))
                assertTrue(text.contains("\"queryType\":\"A\""))
                assertTrue(text.contains("\"clientIp\":\"10.0.0.1\""))
                assertTrue(text.contains("\"customDataTruncated\":false"))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions should return http interaction details`() {
            val mockRequest = mockk<burp.api.montoya.http.message.requests.HttpRequest>()
            every { mockRequest.toString() } returns "GET / HTTP/1.1"
            val mockResponse = mockk<burp.api.montoya.http.message.responses.HttpResponse>()
            every { mockResponse.toString() } returns "HTTP/1.1 200 OK"
            val mockRequestResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            every { mockRequestResponse.request() } returns mockRequest
            every { mockRequestResponse.response() } returns mockResponse

            val httpDetails = mockk<HttpDetails>().also {
                every { it.protocol() } returns HttpProtocol.HTTP
                every { it.requestResponse() } returns mockRequestResponse
            }
            val interaction = mockInteraction("int-002", InteractionType.HTTP, httpDetails = httpDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool(
                    "get_collaborator_interactions",
                    mapOf("projectId" to collaboratorProjectId),
                )
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"type\":\"HTTP\""))
                assertTrue(text.contains("\"protocol\":\"HTTP\""))
                assertTrue(text.contains("GET / HTTP/1.1"))
                assertTrue(text.contains("HTTP/1.1 200 OK"))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions should return smtp interaction details`() {
            val smtpDetails = mockk<SmtpDetails>().also {
                every { it.protocol() } returns SmtpProtocol.SMTP
                every { it.conversation() } returns "EHLO test\r\n250 OK"
            }
            val interaction = mockInteraction("int-003", InteractionType.SMTP, smtpDetails = smtpDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool(
                    "get_collaborator_interactions",
                    mapOf("projectId" to collaboratorProjectId),
                )
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"type\":\"SMTP\""))
                assertTrue(text.contains("\"protocol\":\"SMTP\""))
                assertTrue(text.contains("EHLO test"))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions with payloadId should use filter`() {
            val mockFilter = mockk<InteractionFilter>()
            every { InteractionFilter.interactionIdFilter("abc123") } returns mockFilter
            every { collaboratorClient.getInteractions(mockFilter) } returns emptyList()

            runBlocking {
                val result = client.callTool(
                    "get_collaborator_interactions", mapOf(
                        "projectId" to collaboratorProjectId,
                        "payloadId" to "abc123",
                    )
                )
                delay(100)
                result.expectTextContent("No interactions detected")
            }

            verify(exactly = 1) { collaboratorClient.getInteractions(mockFilter) }
        }

        @Test
        fun `get interactions should return no interactions message when empty`() {
            every { collaboratorClient.getAllInteractions() } returns emptyList()

            runBlocking {
                val result = client.callTool(
                    "get_collaborator_interactions",
                    mapOf("projectId" to collaboratorProjectId),
                )
                delay(100)
                result.expectTextContent("No interactions detected")
            }
        }
    }

    @Test
    fun `tool name conversion should work properly`() {
        assertEquals("send_raw_http_request", "SendRawHttpRequest".toLowerSnakeCase())
        assertEquals("test_case_conversion", "TestCaseConversion".toLowerSnakeCase())
        assertEquals("multiple_upper_case_letters", "MultipleUpperCaseLetters".toLowerSnakeCase())
    }
    
    @Test
    fun `edition specific tools should only register in professional edition`() {
        val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
        val version = mockk<burp.api.montoya.core.Version>()
        
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.version() } returns version
        
        every { version.edition() } returns BurpSuiteEdition.COMMUNITY_EDITION
        runBlocking {
            val tools = client.listTools()
            assertTrue(tools.all { it.annotations?.readOnlyHint != null })
            assertFalse(tools.any { it.name == "get_scanner_issues" })
            assertFalse(tools.any { it.name == "generate_collaborator_payload" })
            assertFalse(tools.any { it.name == "get_collaborator_interactions" })
        }

        every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL

        serverManager.stop {}
        serverStarted = false
        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")

            client.connectToServer("http://127.0.0.1:${testPort}/mcp")

            val tools = client.listTools()
            assertTrue(tools.all { it.annotations?.readOnlyHint != null })
            assertTrue(tools.all { it.outputSchema != null })
            assertTrue(tools.any { it.name == "get_scanner_issues" })
            assertTrue(tools.any { it.name == "generate_collaborator_payload" })
            assertTrue(tools.any { it.name == "get_collaborator_interactions" })
        }
    }
}