package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.filterConfigCredentials
import java.awt.KeyboardFocusManager
import java.util.regex.Pattern
import javax.swing.JTextArea

private suspend fun checkDataAccessOrDeny(
    accessType: DataAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = DataAccessSecurity.checkDataAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun String?.matchesCurrentProject(api: MontoyaApi): Boolean =
    this == null || this == api.project().id()

private fun truncateIfNeeded(serialized: String): String {
    return if (serialized.length > 5000) {
        serialized.substring(0, 5000) + "... (truncated)"
    } else {
        serialized
    }
}

private fun buildHttp2HeaderList(
    pseudoHeaders: Map<String, String>, headers: Map<String, String>
): List<HttpHeader> {
    val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

    val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
        orderedPseudoHeaderNames.forEach { name ->
            val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
            if (value != null) {
                put(name, value)
            }
        }

        pseudoHeaders.forEach { (key, value) ->
            val properKey = if (key.startsWith(":")) key else ":$key"
            if (!containsKey(properKey)) {
                put(properKey, value)
            }
        }
    }

    headers.forEach { (name, value) -> fixedPseudoHeaders[name] = value }
    return fixedPseudoHeaders.map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }
}

/**
 * Normalizes HTTP request line endings from MCP clients.
 *
 * MCP clients (e.g. Claude Code) often emit `\r\n` as the 4-character literal
 * sequence backslash-r-backslash-n in JSON tool parameters rather than actual
 * CR (0x0D) + LF (0x0A) bytes. The resulting text parses as a single line,
 * which strict servers (e.g. Apache-Coyote) reject with 400 Bad Request and
 * which Burp/Montoya may "repair" by injecting headers after the body
 * separator.
 *
 * Normalization is applied only to the request prelude (request line and
 * headers, up to and including the first blank line). The body is preserved
 * verbatim so that legitimate escape sequences in bodies — e.g. `\n` inside a
 * JSON string literal — and binary payloads remain byte-exact. If no blank
 * line is present, the entire content is treated as prelude.
 */
internal fun normalizeHttpContent(content: String): String {
    val preludeEnd = findPreludeEnd(content) ?: content.length
    return buildString(content.length + 16) {
        appendNormalizedPrelude(content, preludeEnd)
        if (preludeEnd < content.length) append(content, preludeEnd, content.length)
    }
}

private val BLANK_LINE_MARKERS = listOf(
    "\r\n\r\n",         // actual CRLF blank line
    "\n\n",              // actual LF blank line
    "\\r\\n\\r\\n",     // literal CRLF blank line
    "\\n\\n",            // literal LF blank line
)

private fun findPreludeEnd(content: String): Int? {
    var bestStart = -1
    var bestLen = 0
    for (marker in BLANK_LINE_MARKERS) {
        val idx = content.indexOf(marker)
        if (idx >= 0 && (bestStart < 0 || idx < bestStart)) {
            bestStart = idx
            bestLen = marker.length
        }
    }
    return if (bestStart < 0) null else bestStart + bestLen
}

private fun StringBuilder.appendNormalizedPrelude(content: String, endExclusive: Int) {
    var index = 0
    while (index < endExclusive) {
        when (content[index]) {
            '\\' -> when {
                index + 3 < endExclusive && content[index + 1] == 'r' &&
                    content[index + 2] == '\\' && content[index + 3] == 'n' -> {
                    append("\r\n")
                    index += 4
                }

                index + 1 < endExclusive && content[index + 1] == 'n' -> {
                    append("\r\n")
                    index += 2
                }

                index + 1 < endExclusive && content[index + 1] == 'r' -> index += 2
                else -> append(content[index++])
            }

            '\r' -> index++
            '\n' -> {
                append("\r\n")
                index++
            }

            else -> append(content[index++])
        }
    }
}

internal fun Server.registerTools(api: MontoyaApi, config: McpConfig, services: ToolServices) {
    val httpMessageSearchService = HttpMessageSearchService(api, config)
    val httpMessageActionService = HttpMessageActionService(api, config)
    val scopeToolService = ScopeToolService(api, config)
    val httpMessageComparisonService = HttpMessageComparisonService(api, config)

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val fixedContent = normalizeHttpContent(content)
        val allowed = HttpRequestSecurity.checkHttpRequestPermission(
            targetHostname,
            targetPort,
            config,
            fixedContent,
            api,
        )
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)
        recordHttpResponseInSiteMap(api, response)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)
        val http2RequestDisplay = buildString {
            headerList.forEach { header -> appendLine("${header.name()}: ${header.value()}") }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = HttpRequestSecurity.checkHttpRequestPermission(
            targetHostname,
            targetPort,
            config,
            http2RequestDisplay,
            api
        )
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)
        recordHttpResponseInSiteMap(api, response)

        response?.toString() ?: "<no response>"
    }

    mcpTool<CreateRepeaterTab>("Creates an HTTP/1.1 Repeater tab with the specified raw HTTP request and optional tab name. Make sure to use carriage returns appropriately. Prefer create_repeater_tab_http2 for modern web targets that speak HTTP/2.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        if (tabName == null) api.repeater().sendToRepeater(request)
        else api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<CreateRepeaterTabHttp2>("Creates an HTTP/2 Repeater tab with the specified HTTP/2 request and optional tab name. Use this by default for modern web targets. Do NOT pass headers to the body parameter.") {
        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)
        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        if (tabName == null) api.repeater().sendToRepeater(request)
        else api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        if (tabName == null) api.intruder().sendToIntruder(request)
        else api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportProjectOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportUserOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Export the current project options first to confirm the schema. The JSON must have a top-level 'project_options' object.") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Applying project-level configuration through MCP")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Export the current user options first to confirm the schema. The JSON must have a top-level 'user_options' object.") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Applying user-level configuration through MCP")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        val scannerIssueSearchService = ScannerIssueSearchService(api, config)
        val collaboratorToolService = services.collaborator
        mcpStructuredToolWithContext<GetScannerIssues, ScannerIssuePageResult>(
            description = "Reads Scanner issues. Existing offset/count calls retain their legacy text format with a 512 KiB safety cap. Set cursorMode=true, or supply severity/confidence/host/name filters, for bounded compact summaries with a signed project-bound snapshot cursor; cursor mode never serializes complete evidence messages.",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) { input ->
            scannerIssueSearchService.get(input)
        }

        mcpStructuredTool<GetScannerIssueById, ScannerIssueReadResult>(
            description = "Reads one Scanner issue by its stable issue ID. Pass projectId when it is available to reject cross-project IDs. Select metadata, detail, remediation, evidence_request, or evidence_response. Evidence content is byte-paginated and can be returned as text or base64.",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) {
            val normalizedField = normalizeScannerIssueField(field)
            val normalizedOffset = normalizeHistoryOffset(offset)
            val normalizedLimit = normalizeHistoryLimit(limit)
            val normalizedEncoding = normalizeHistoryEncoding(encoding)
            if (!checkDataAccessOrDeny(DataAccessType.SCANNER_ISSUES, config, api, "Scanner issue $id")) {
                return@mcpStructuredTool ScannerIssueReadResult(
                    status = HistoryReadStatus.ACCESS_DENIED,
                    id = id,
                    field = normalizedField,
                    error = "Scanner issue access denied by Burp Suite",
                )
            }
            if (!projectId.matchesCurrentProject(api)) {
                return@mcpStructuredTool ScannerIssueReadResult(
                    status = HistoryReadStatus.PROJECT_MISMATCH,
                    id = id,
                    field = normalizedField,
                    error = "Scanner issue ID belongs to a different Burp project",
                )
            }
            val issue = api.siteMap().issues().firstOrNull { it.stableHistoryId() == id }
                ?: return@mcpStructuredTool ScannerIssueReadResult(
                    status = HistoryReadStatus.NOT_FOUND,
                    id = id,
                    field = normalizedField,
                    error = "Scanner issue $id was not found",
                )
            issue.readField(normalizedField, evidenceIndex, normalizedOffset, normalizedLimit, normalizedEncoding)
        }

        mcpStructuredTool<StartScannerAuditFromIds, ScannerAuditResult>(
            description = "Starts a focused Professional Scanner audit from existing project-scoped HTTP references. Passive mode requires responses and sends no target traffic. Active mode requires explicit semantic insertionPoints for every target and rejects out-of-scope requests. This operation always requires Burp approval. actionState=uncertain means a task may exist and must not be started again automatically.",
            annotations = SCANNER_START_TOOL_ANNOTATIONS,
        ) {
            services.scannerAudits.start(this, config)
        }

        mcpStructuredTool<GetScannerAudit, ScannerAuditResult>(
            description = "Returns status, insertion-point/request/error counts, and bounded stable issue summaries for a Scanner audit started by this extension instance. Burp exposes a textual task status, so taskState is a conservative normalized interpretation and statusMessage remains authoritative. issuesUnavailable=true is a nonfatal warning when the current Burp runtime cannot expose live task issues.",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) {
            services.scannerAudits.get(this, config)
        }

        mcpStructuredTool<CancelScannerAudit, ScannerAuditResult>(
            description = "Cancels only a Scanner audit previously started by this extension instance. Cancellation always requires Burp approval. actionState=uncertain means the task may already have been deleted and cancellation must not be retried automatically.",
            annotations = SCANNER_CANCEL_TOOL_ANNOTATIONS,
        ) {
            services.scannerAudits.cancel(this)
        }

        mcpStructuredToolWithContext<GenerateCollaboratorPayload, GenerateCollaboratorPayloadResult>(
            description = "Generates a bounded Burp Collaborator payload for out-of-band testing and returns its payloadId. Optional customData must contain 1–16 ASCII alphanumeric characters, matching Burp's native limit. Use get_collaborator_interactions with that payloadId; generation does not inject or send the payload.",
            annotations = COLLABORATOR_GENERATE_TOOL_ANNOTATIONS,
        ) { input ->
            collaboratorToolService.generate(input)
        }

        mcpStructuredToolWithContext<GetCollaboratorInteractions, GetCollaboratorInteractionsResult>(
            description = "Polls Burp Collaborator for bounded DNS, HTTP, or SMTP interactions. payloadId is the interaction ID returned by generate_collaborator_payload and is matched with Burp's interaction-ID filter. Optional since, waitSeconds (maximum 120), maxResults, detail slicing, progress, and cancellation avoid model-side polling and unbounded output.",
            annotations = COLLABORATOR_READ_TOOL_ANNOTATIONS,
        ) { input ->
            collaboratorToolService.interactions(input, config) { progress, total, message ->
                reportProgress(progress, total, message)
            }
        }
    }

    mcpStructuredTool<SearchHttpMessages, SearchHttpMessagesResult>(
        description = "Searches compact HTTP metadata in Proxy history by default, or explicitly selected Proxy, Site Map, and Organizer sources. Filters support exact host, literal path/content, method, status, MIME type, scope, and response presence. Results are bounded to 50 items. Use nextCursor by itself to continue the same signed snapshot. Read a result with the source-specific get-by-ID tool, or copy projectId and ref into the *_from_id replay and routing tools.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) {
        httpMessageSearchService.search(this)
    }

    mcpStructuredTool<CheckScope, CheckScopeResult>(
        description = "Checks whether up to 32 explicit URLs or project-scoped HTTP message references are currently in Burp Target scope. This tool never changes scope. Each target must contain exactly one of url or ref.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) {
        scopeToolService.check(this)
    }

    mcpStructuredTool<UpdateScope, UpdateScopeResult>(
        description = "Includes or excludes up to 16 normalized URLs or project-scoped HTTP message references in Burp Target scope. All targets are validated before an always-required Burp approval. executionState=uncertain means some scope changes may already exist and the call must not be retried automatically.",
        annotations = SCOPE_MUTATION_TOOL_ANNOTATIONS,
    ) {
        scopeToolService.update(this)
    }

    mcpStructuredTool<CompareHttpMessages, CompareHttpMessagesResult>(
        description = "Compares 2 to 8 project-scoped Proxy, Site Map, or Organizer references without copying complete messages into the model. Returns bounded hashes, header differences, a two-message content excerpt, and optional Burp-native response variation attributes. allEqual=null means inspected prefixes matched but one or more selected parts were truncated.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) {
        httpMessageComparisonService.compare(this)
    }

    mcpStructuredTool<GetSitemapMessageById, SiteMapMessageReadResult>(
        description = "Reads one Site Map message returned by search_http_messages. projectId and id must be copied from the search result. Select metadata, request, request_headers, request_body, response, response_headers, or response_body. Content is byte-paginated and supports text or base64.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) {
        httpMessageSearchService.readSiteMapMessage(this)
    }

    mcpStructuredTool<SendHttpRequestFromId, HttpMessageActionResult>(
        description = "Replays a Proxy, Site Map, or Organizer request returned by search_http_messages. Applies only bounded structured method, path, header, parameter, or body patches; never asks the model to reconstruct raw HTTP. Requires the matching projectId and approvals. The response preview, timeout, redirects, and HTTP mode are bounded and explicit. Successful Site Map recording returns recordedRef for the exact replay result when Burp can locate it. executionState=uncertain means the request must not be retried automatically.",
        annotations = HTTP_REQUEST_ACTION_ANNOTATIONS,
    ) {
        httpMessageActionService.send(this)
    }

    mcpStructuredTool<CreateRepeaterTabFromId, HttpMessageActionResult>(
        description = "Creates a Repeater tab from an existing Proxy, Site Map, or Organizer request, optionally after a bounded structured patch. Requires the matching projectId and approvals. executionState=uncertain means a tab may already exist and the action must not be retried automatically.",
        annotations = REQUEST_ROUTING_TOOL_ANNOTATIONS,
    ) {
        httpMessageActionService.createRepeaterTab(this)
    }

    mcpStructuredTool<SendToIntruderFromId, HttpMessageActionResult>(
        description = "Sends an existing Proxy, Site Map, or Organizer request to Intruder, optionally after a bounded structured patch. Optional semantic insertionPoints select parameter values, header values, or the request body without model-supplied byte offsets. Requires the matching projectId and approvals. This creates an Intruder tab but does not start an attack. executionState=uncertain means a tab may already exist and the action must not be retried automatically.",
        annotations = REQUEST_ROUTING_TOOL_ANNOTATIONS,
    ) {
        httpMessageActionService.sendToIntruder(this)
    }

    mcpStructuredTool<SendToOrganizerFromId, HttpMessageActionResult>(
        description = "Sends an existing Proxy, Site Map, or Organizer request to Organizer, optionally after a bounded structured patch. An unmodified source response is preserved when the Montoya source supports it; patched requests never attach a mismatched response. executionState=uncertain means an item may already exist and the action must not be retried automatically.",
        annotations = REQUEST_ROUTING_TOOL_ANNOTATIONS,
    ) {
        httpMessageActionService.sendToOrganizer(this)
    }

    mcpPaginatedSequenceTool<GetProxyHttpHistory, ProxyHttpRequestResponse>(
        "Displays items within the proxy HTTP history. Set summariesOnly to true for compact metadata and stable IDs.",
        mapper = {
            if (summariesOnly == true) Json.encodeToString(it.toHistorySummary())
            else truncateIfNeeded(Json.encodeToString(it.toSerializableForm()))
        }
    ) {
        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        if (!allowed) {
            return@mcpPaginatedSequenceTool PaginatedSource.Message("HTTP history access denied by Burp Suite")
        }

        PaginatedSource.Items(api.proxy().history().asSequence())
    }

    mcpPaginatedSequenceTool<GetProxyHttpHistoryRegex, ProxyHttpRequestResponse>(
        "Displays items matching a specified regex within the proxy HTTP history. Set summariesOnly to true for compact metadata and stable IDs.",
        mapper = {
            if (summariesOnly == true) Json.encodeToString(it.toHistorySummary())
            else truncateIfNeeded(Json.encodeToString(it.toSerializableForm()))
        }
    ) {
        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        if (!allowed) {
            return@mcpPaginatedSequenceTool PaginatedSource.Message("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        PaginatedSource.Items(api.proxy().history { it.contains(compiledRegex) }.asSequence())
    }

    mcpPaginatedSequenceTool<GetOrganizerItems, OrganizerItem>(
        "Displays items within the Organizer tab. Set summariesOnly to true for compact metadata and stable IDs.",
        mapper = {
            if (summariesOnly == true) Json.encodeToString(it.toHistorySummary())
            else truncateIfNeeded(Json.encodeToString(it.toSerializableForm()))
        }
    ) {
        val allowed = checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        if (!allowed) {
            return@mcpPaginatedSequenceTool PaginatedSource.Message("Organizer access denied by Burp Suite")
        }

        PaginatedSource.Items(api.organizer().items().asSequence())
    }

    mcpPaginatedSequenceTool<GetOrganizerItemsRegex, OrganizerItem>(
        "Displays items matching a specified regex within the Organizer tab. Set summariesOnly to true for compact metadata and stable IDs.",
        mapper = {
            if (summariesOnly == true) Json.encodeToString(it.toHistorySummary())
            else truncateIfNeeded(Json.encodeToString(it.toSerializableForm()))
        }
    ) {
        val allowed = checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        if (!allowed) {
            return@mcpPaginatedSequenceTool PaginatedSource.Message("Organizer access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        PaginatedSource.Items(api.organizer().items { it.contains(compiledRegex) }.asSequence())
    }

    mcpStructuredTool<GetOrganizerItemById, HttpMessageReadResult>(
        description = "Reads one Organizer item by its stable Burp ID. Pass projectId from search_http_messages to reject cross-project IDs. Select metadata, request, request_headers, request_body, response, response_headers, or response_body. Content is byte-paginated and can be returned as text or base64.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) {
        val normalizedPart = normalizeHttpPart(part)
        val normalizedOffset = normalizeHistoryOffset(offset)
        val normalizedLimit = normalizeHistoryLimit(limit)
        val normalizedEncoding = normalizeHistoryEncoding(encoding)
        if (!checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer item $id")) {
            return@mcpStructuredTool HttpMessageReadResult(
                status = HistoryReadStatus.ACCESS_DENIED,
                id = id,
                part = normalizedPart,
                error = "Organizer access denied by Burp Suite",
            )
        }
        if (!projectId.matchesCurrentProject(api)) {
            return@mcpStructuredTool HttpMessageReadResult(
                status = HistoryReadStatus.PROJECT_MISMATCH,
                id = id,
                part = normalizedPart,
                error = "Organizer item ID belongs to a different Burp project",
            )
        }

        val item = api.organizer().items { it.id() == id }.firstOrNull()
            ?: return@mcpStructuredTool HttpMessageReadResult(
                status = HistoryReadStatus.NOT_FOUND,
                id = id,
                part = normalizedPart,
                error = "Organizer item $id was not found",
            )
        item.readPart(normalizedPart, normalizedOffset, normalizedLimit, normalizedEncoding)
    }

    mcpPaginatedSequenceTool<GetProxyWebsocketHistory, ProxyWebSocketMessage>(
        "Displays items within the proxy WebSocket history. Set summariesOnly to true for compact metadata and stable IDs.",
        mapper = {
            if (summariesOnly == true) Json.encodeToString(it.toHistorySummary())
            else truncateIfNeeded(Json.encodeToString(it.toSerializableForm()))
        }
    ) {
        val allowed = checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        if (!allowed) {
            return@mcpPaginatedSequenceTool PaginatedSource.Message("WebSocket history access denied by Burp Suite")
        }

        PaginatedSource.Items(api.proxy().webSocketHistory().asSequence())
    }

    mcpPaginatedSequenceTool<GetProxyWebsocketHistoryRegex, ProxyWebSocketMessage>(
        "Displays items matching a specified regex within the proxy WebSocket history. Set summariesOnly to true for compact metadata and stable IDs.",
        mapper = {
            if (summariesOnly == true) Json.encodeToString(it.toHistorySummary())
            else truncateIfNeeded(Json.encodeToString(it.toSerializableForm()))
        }
    ) {
        val allowed = checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        if (!allowed) {
            return@mcpPaginatedSequenceTool PaginatedSource.Message("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        PaginatedSource.Items(api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence())
    }

    mcpStructuredTool<GetHttpMessageById, HttpMessageReadResult>(
        description = "Reads one proxy HTTP history item by its stable Burp ID. Pass projectId from search_http_messages to reject cross-project IDs. Select metadata, request, request_headers, request_body, response, response_headers, or response_body. Content is byte-paginated and can be returned as text or base64.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) {
        val normalizedPart = normalizeHttpPart(part)
        val normalizedOffset = normalizeHistoryOffset(offset)
        val normalizedLimit = normalizeHistoryLimit(limit)
        val normalizedEncoding = normalizeHistoryEncoding(encoding)
        if (!checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history item $id")) {
            return@mcpStructuredTool HttpMessageReadResult(
                status = HistoryReadStatus.ACCESS_DENIED,
                id = id,
                part = normalizedPart,
                error = "HTTP history access denied by Burp Suite",
            )
        }
        if (!projectId.matchesCurrentProject(api)) {
            return@mcpStructuredTool HttpMessageReadResult(
                status = HistoryReadStatus.PROJECT_MISMATCH,
                id = id,
                part = normalizedPart,
                error = "HTTP history ID belongs to a different Burp project",
            )
        }

        val item = api.proxy().history { it.id() == id }.firstOrNull()
            ?: return@mcpStructuredTool HttpMessageReadResult(
                status = HistoryReadStatus.NOT_FOUND,
                id = id,
                part = normalizedPart,
                error = "Proxy HTTP history item $id was not found",
            )
        item.readPart(normalizedPart, normalizedOffset, normalizedLimit, normalizedEncoding)
    }

    mcpStructuredTool<GetWebsocketMessageById, WebSocketMessageReadResult>(
        description = "Reads one proxy WebSocket payload by its stable Burp ID. Pass projectId when it is available to reject cross-project IDs. Content is byte-paginated and can be returned as text or base64.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) {
        val normalizedOffset = normalizeHistoryOffset(offset)
        val normalizedLimit = normalizeHistoryLimit(limit)
        val normalizedEncoding = normalizeHistoryEncoding(encoding)
        if (!checkDataAccessOrDeny(
                DataAccessType.WEBSOCKET_HISTORY,
                config,
                api,
                "WebSocket history item $id",
            )
        ) {
            return@mcpStructuredTool WebSocketMessageReadResult(
                status = HistoryReadStatus.ACCESS_DENIED,
                id = id,
                error = "WebSocket history access denied by Burp Suite",
            )
        }

        if (!projectId.matchesCurrentProject(api)) {
            return@mcpStructuredTool WebSocketMessageReadResult(
                status = HistoryReadStatus.PROJECT_MISMATCH,
                id = id,
                error = "WebSocket history ID belongs to a different Burp project",
            )
        }

        val item = api.proxy().webSocketHistory { it.id() == id }.firstOrNull()
            ?: return@mcpStructuredTool WebSocketMessageReadResult(
                status = HistoryReadStatus.NOT_FOUND,
                id = id,
                error = "Proxy WebSocket history item $id was not found",
            )
        item.readPayload(edited == true, normalizedOffset, normalizedLimit, normalizedEncoding)
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }
}

private const val MAX_SITE_MAP_RECORD_LOOKBACK = 10_000

internal data class SiteMapRecordResult(
    val recorded: Boolean,
    val ref: HttpMessageReference? = null,
    val warning: String? = null,
)

internal fun recordHttpResponseInSiteMap(api: MontoyaApi, response: HttpRequestResponse?): Boolean =
    recordHttpResponseInSiteMap(api, response, projectId = null).recorded

internal fun recordHttpResponseInSiteMap(
    api: MontoyaApi,
    response: HttpRequestResponse?,
    projectId: String?,
): SiteMapRecordResult {
    if (response == null) return SiteMapRecordResult(recorded = false)
    try {
        api.siteMap().add(response)
    } catch (_: Exception) {
        // The request may already have changed server state. Never turn a local recording failure into a retryable tool error.
        runCatching {
            api.logging().logToError("MCP request completed, but its response could not be added to Site Map")
        }
        return SiteMapRecordResult(recorded = false)
    }

    if (projectId == null) return SiteMapRecordResult(recorded = true)
    return try {
        if (api.project().id() != projectId) {
            val warning = "request was recorded, but the Burp project changed before a stable Site Map reference could be created"
            runCatching { api.logging().logToError("MCP $warning") }
            SiteMapRecordResult(recorded = true, warning = warning)
        } else {
            // Montoya's SiteMap.add API does not return an index. Take one post-add snapshot and search from the append end.
            // Identity is normally preserved; the bounded anchor is a fallback for Burp implementations that wrap the object.
            val items = api.siteMap().requestResponses()
            val firstCandidate = (items.size - MAX_SITE_MAP_RECORD_LOOKBACK).coerceAtLeast(0)
            val identityIndex = (items.lastIndex downTo firstCandidate).firstOrNull { items[it] === response } ?: -1
            val index = if (identityIndex >= 0) identityIndex else {
                val anchor = siteMapBoundaryAnchor(response)
                (items.lastIndex downTo firstCandidate).firstOrNull { candidateIndex ->
                    siteMapBoundaryAnchor(items[candidateIndex]) == anchor
                } ?: -1
            }
            if (index < 0) {
                val warning = "request was recorded, but its stable Site Map reference could not be located"
                runCatching { api.logging().logToError("MCP $warning") }
                SiteMapRecordResult(recorded = true, warning = warning)
            } else {
                SiteMapRecordResult(
                    recorded = true,
                    ref = HttpMessageReference(
                        source = HttpMessageSource.SITE_MAP,
                        id = stableSiteMapId(projectId, index, items[index]),
                    ),
                )
            }
        }
    } catch (_: Exception) {
        val warning = "request was recorded, but its stable Site Map reference could not be created"
        runCatching { api.logging().logToError("MCP $warning") }
        SiteMapRecordResult(recorded = true, warning = warning)
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String? = null,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTabHttp2(
    val tabName: String? = null,
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String? = null,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetProxyHttpHistory(
    override val count: Int,
    override val offset: Int,
    val summariesOnly: Boolean? = null,
) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(
    val regex: String,
    override val count: Int,
    override val offset: Int,
    val summariesOnly: Boolean? = null,
) : Paginated

@Serializable
data class GetOrganizerItems(
    override val count: Int,
    override val offset: Int,
    val summariesOnly: Boolean? = null,
) : Paginated

@Serializable
data class GetOrganizerItemsRegex(
    val regex: String,
    override val count: Int,
    override val offset: Int,
    val summariesOnly: Boolean? = null,
) : Paginated

@Serializable
data class GetProxyWebsocketHistory(
    override val count: Int,
    override val offset: Int,
    val summariesOnly: Boolean? = null,
) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(
    val regex: String,
    override val count: Int,
    override val offset: Int,
    val summariesOnly: Boolean? = null,
) : Paginated

@Serializable
data class GetHttpMessageById(
    val id: Int,
    val projectId: String? = null,
    val part: String? = null,
    val offset: Int? = null,
    val limit: Int? = null,
    val encoding: String? = null,
)

@Serializable
data class GetWebsocketMessageById(
    val id: Int,
    val projectId: String? = null,
    val edited: Boolean? = null,
    val offset: Int? = null,
    val limit: Int? = null,
    val encoding: String? = null,
)

@Serializable
data class GetOrganizerItemById(
    val id: Int,
    val projectId: String? = null,
    val part: String? = null,
    val offset: Int? = null,
    val limit: Int? = null,
    val encoding: String? = null,
)

@Serializable
data class GetScannerIssueById(
    val id: String,
    val projectId: String? = null,
    val field: String? = null,
    val evidenceIndex: Int? = null,
    val offset: Int? = null,
    val limit: Int? = null,
    val encoding: String? = null,
)

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)
