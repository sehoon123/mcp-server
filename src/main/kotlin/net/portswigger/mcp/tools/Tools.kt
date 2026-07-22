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
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.config.TargetValidation
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.RequestActionSecurity
import net.portswigger.mcp.security.SensitiveActionSecurity
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

private const val MAX_LEGACY_RAW_REQUEST_CHARS = 2 * 1024 * 1024
private const val MAX_LEGACY_HTTP2_BODY_CHARS = 1024 * 1024
private const val MAX_LEGACY_HTTP_HEADERS = 128
private const val MAX_LEGACY_HEADER_NAME_CHARS = 256
private const val MAX_LEGACY_HEADER_VALUE_CHARS = 16 * 1024
private const val MAX_LEGACY_RESPONSE_PREVIEW_BYTES = 256 * 1024
private const val MAX_UTILITY_INPUT_CHARS = 256 * 1024
private const val MAX_RANDOM_STRING_CHARS = 64 * 1024
private const val MAX_RANDOM_CHARACTER_SET_CHARS = 256
private const val MAX_CONFIGURATION_JSON_CHARS = 1024 * 1024
private const val MAX_EDITOR_CONTENT_CHARS = 1024 * 1024
private const val MAX_EDITOR_PREVIEW_CHARS = 32 * 1024
private const val DEFAULT_LEGACY_PREVIEW_BYTES = 8 * 1024
private const val MAX_LEGACY_PREVIEW_BYTES = 32 * 1024
private const val MAX_LEGACY_REGEX_CHARS = 512

private fun validateLegacyTarget(hostname: String, port: Int) {
    require(TargetValidation.normalizeTarget(TargetValidation.formatTarget(hostname, port)) != null) {
        "targetHostname or targetPort is invalid"
    }
}

private fun validateLegacyHttp2Input(
    pseudoHeaders: Map<String, String>,
    headers: Map<String, String>,
    body: String,
) {
    require(body.length <= MAX_LEGACY_HTTP2_BODY_CHARS) { "requestBody is too large" }
    require(pseudoHeaders.size + headers.size <= MAX_LEGACY_HTTP_HEADERS) { "too many HTTP headers" }
    val allHeaders = pseudoHeaders.asSequence() + headers.asSequence()
    val totalChars = body.length.toLong() + allHeaders.sumOf { (name, value) -> name.length.toLong() + value.length + 4 }
    require(totalChars <= MAX_LEGACY_RAW_REQUEST_CHARS) { "combined HTTP/2 request content is too large" }
    (pseudoHeaders.asSequence() + headers.asSequence()).forEach { (name, value) ->
        require(name.length in 1..MAX_LEGACY_HEADER_NAME_CHARS && name.none(Char::isISOControl)) {
            "HTTP header name is invalid"
        }
        require(value.length <= MAX_LEGACY_HEADER_VALUE_CHARS && value.none { it == '\u0000' }) {
            "HTTP header value is invalid"
        }
    }
}

private fun HttpResponse?.boundedLegacyResponse(): String {
    val bytes = this?.toByteArray() ?: return "<no response>"
    val total = bytes.length()
    val returned = minOf(total, MAX_LEGACY_RESPONSE_PREVIEW_BYTES)
    val text = if (returned == 0) "" else bytes.subArray(0, returned).toString()
    return if (returned == total) text else buildString(text.length + 128) {
        append(text)
        append("\n\n[responseTruncated=true returnedBytes=")
        append(returned)
        append(" totalBytes=")
        append(total)
        append(" nextOffsetBytes=")
        append(returned)
        append(']')
    }
}

private fun normalizeLegacyPreviewLimit(limit: Int?): Int {
    val normalized = limit ?: DEFAULT_LEGACY_PREVIEW_BYTES
    require(normalized in 1..MAX_LEGACY_PREVIEW_BYTES) {
        "contentLimit must be between 1 and $MAX_LEGACY_PREVIEW_BYTES bytes"
    }
    return normalized
}

/** Conservatively rejects Java-regex constructs that can create unbounded backtracking. */
internal fun validateLegacyRegex(regex: String): Pattern {
    require(regex.isNotEmpty() && regex.length <= MAX_LEGACY_REGEX_CHARS) {
        "regex must contain 1 to $MAX_LEGACY_REGEX_CHARS characters"
    }
    require(regex.none(Char::isISOControl)) { "regex must not contain control characters" }
    require(!Regex("\\\\[1-9]").containsMatchIn(regex)) { "regex backreferences are not supported" }
    require("(?" !in regex) { "regex lookarounds, flags, and special groups are not supported" }
    require('{' !in regex && '}' !in regex) { "regex counted quantifiers are not supported" }

    var escaped = false
    var inClass = false
    var unboundedQuantifiers = 0
    var previousWasQuantifier = false
    var previousClosedGroup = false
    for (character in regex) {
        if (escaped) {
            escaped = false
            previousWasQuantifier = false
            previousClosedGroup = false
            continue
        }
        if (character == '\\') {
            escaped = true
            continue
        }
        if (character == '[') inClass = true
        if (character == ']' && inClass) inClass = false
        if (inClass) continue
        when (character) {
            ')' -> {
                previousClosedGroup = true
                previousWasQuantifier = false
            }
            '*', '+' -> {
                require(!previousWasQuantifier && !previousClosedGroup) {
                    "nested, repeated, or group quantifiers are not supported"
                }
                unboundedQuantifiers++
                require(unboundedQuantifiers <= 1) { "at most one unbounded regex quantifier is supported" }
                previousWasQuantifier = true
                previousClosedGroup = false
            }
            '?' -> {
                require(!previousWasQuantifier && !previousClosedGroup) {
                    "nested, repeated, or group quantifiers are not supported"
                }
                previousWasQuantifier = true
                previousClosedGroup = false
            }
            else -> {
                previousWasQuantifier = false
                previousClosedGroup = false
            }
        }
    }
    require(!escaped && !inClass) { "regex has an incomplete escape or character class" }
    return Pattern.compile(regex)
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

    mcpTool<SendHttp1Request>(
        "Issues an HTTP/1.1 request and returns a bounded response preview.",
        HTTP_REQUEST_ACTION_ANNOTATIONS,
    ) {
        validateLegacyTarget(targetHostname, targetPort)
        require(content.length <= MAX_LEGACY_RAW_REQUEST_CHARS) { "content is too large" }
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

        response?.response().boundedLegacyResponse()
    }

    mcpTool<SendHttp2Request>(
        "Issues an HTTP/2 request and returns a bounded response preview. Do not pass headers in requestBody.",
        HTTP_REQUEST_ACTION_ANNOTATIONS,
    ) {
        validateLegacyTarget(targetHostname, targetPort)
        validateLegacyHttp2Input(pseudoHeaders, headers, requestBody)
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

        response?.response().boundedLegacyResponse()
    }

    mcpTool<CreateRepeaterTab>(
        "Creates a Repeater tab from a bounded raw HTTP/1.1 request after request-routing approval.",
        REQUEST_ROUTING_TOOL_ANNOTATIONS,
    ) {
        validateLegacyTarget(targetHostname, targetPort)
        require(content.length <= MAX_LEGACY_RAW_REQUEST_CHARS) { "content is too large" }
        require(tabName == null || tabName.length <= 128) { "tabName is too long" }
        val fixedContent = normalizeHttpContent(content)
        val target = TargetValidation.formatTarget(targetHostname, targetPort)
        val approved = RequestActionSecurity.checkPermission(
            "create a Repeater tab",
            "raw MCP request",
            target,
            "no structured patch",
            fixedContent,
            config,
            api,
        )
        if (!approved) return@mcpTool
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        if (tabName == null) api.repeater().sendToRepeater(request)
        else api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<CreateRepeaterTabHttp2>(
        "Creates a Repeater tab from a bounded HTTP/2 request after request-routing approval.",
        REQUEST_ROUTING_TOOL_ANNOTATIONS,
    ) {
        validateLegacyTarget(targetHostname, targetPort)
        validateLegacyHttp2Input(pseudoHeaders, headers, requestBody)
        require(tabName == null || tabName.length <= 128) { "tabName is too long" }
        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)
        val review = buildString {
            headerList.forEach { appendLine("${it.name()}: ${it.value()}") }
            if (requestBody.isNotEmpty()) append("\n$requestBody")
        }
        val approved = RequestActionSecurity.checkPermission(
            "create a Repeater tab",
            "raw MCP request",
            TargetValidation.formatTarget(targetHostname, targetPort),
            "no structured patch",
            review,
            config,
            api,
        )
        if (!approved) return@mcpTool
        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        if (tabName == null) api.repeater().sendToRepeater(request)
        else api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<SendToIntruder>(
        "Creates an Intruder tab from a bounded raw request after request-routing approval; it does not start an attack.",
        REQUEST_ROUTING_TOOL_ANNOTATIONS,
    ) {
        validateLegacyTarget(targetHostname, targetPort)
        require(content.length <= MAX_LEGACY_RAW_REQUEST_CHARS) { "content is too large" }
        require(tabName == null || tabName.length <= 128) { "tabName is too long" }
        val fixedContent = normalizeHttpContent(content)
        val approved = RequestActionSecurity.checkPermission(
            "create an Intruder tab",
            "raw MCP request",
            TargetValidation.formatTarget(targetHostname, targetPort),
            "no insertion points and no attack start",
            fixedContent,
            config,
            api,
        )
        if (!approved) return@mcpTool
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        if (tabName == null) api.intruder().sendToIntruder(request)
        else api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes bounded input.", LOCAL_TRANSFORM_TOOL_ANNOTATIONS) {
        require(content.length <= MAX_UTILITY_INPUT_CHARS) { "content is too large" }
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes bounded input.", LOCAL_TRANSFORM_TOOL_ANNOTATIONS) {
        require(content.length <= MAX_UTILITY_INPUT_CHARS) { "content is too large" }
        api.utilities().urlUtils().decode(content).also {
            require(it.length <= MAX_UTILITY_INPUT_CHARS) { "decoded content is too large" }
        }
    }

    mcpTool<Base64Encode>("Base64 encodes bounded input.", LOCAL_TRANSFORM_TOOL_ANNOTATIONS) {
        require(content.length <= MAX_UTILITY_INPUT_CHARS) { "content is too large" }
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes bounded input.", LOCAL_TRANSFORM_TOOL_ANNOTATIONS) {
        require(content.length <= MAX_UTILITY_INPUT_CHARS) { "content is too large" }
        api.utilities().base64Utils().decode(content).also {
            require(it.length() <= MAX_UTILITY_INPUT_CHARS) { "decoded content is too large" }
        }.toString()
    }

    mcpTool<GenerateRandomString>(
        "Generates a bounded random string from a non-empty character set.",
        LOCAL_TRANSFORM_TOOL_ANNOTATIONS,
    ) {
        require(length in 0..MAX_RANDOM_STRING_CHARS) { "length must be between 0 and $MAX_RANDOM_STRING_CHARS" }
        require(characterSet.length in 1..MAX_RANDOM_CHARACTER_SET_CHARS && characterSet.none(Char::isISOControl)) {
            "characterSet is invalid"
        }
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs bounded current project-level configuration after explicit approval.",
        READ_ONLY_TOOL_ANNOTATIONS,
    ) {
        if (!SensitiveActionSecurity.checkPermission(
                "read project configuration",
                "Export project-level Burp configuration to the MCP client",
                api = api,
            )
        ) return@mcpTool "Project configuration access denied by Burp Suite"
        val json = api.burpSuite().exportProjectOptionsAsJson()
        require(json.length <= MAX_CONFIGURATION_JSON_CHARS) { "project configuration exceeds the output limit" }
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    mcpTool(
        "output_user_options",
        "Outputs bounded current user-level configuration after explicit approval.",
        READ_ONLY_TOOL_ANNOTATIONS,
    ) {
        if (!SensitiveActionSecurity.checkPermission(
                "read user configuration",
                "Export user-level Burp configuration to the MCP client",
                api = api,
            )
        ) return@mcpTool "User configuration access denied by Burp Suite"
        val json = api.burpSuite().exportUserOptionsAsJson()
        require(json.length <= MAX_CONFIGURATION_JSON_CHARS) { "user configuration exceeds the output limit" }
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>(
        "Imports bounded project configuration JSON after explicit approval. The JSON must have a top-level 'project_options' object.",
        PROJECT_MUTATION_TOOL_ANNOTATIONS,
    ) {
        require(json.length <= MAX_CONFIGURATION_JSON_CHARS) { "json is too large" }
        if (!config.configEditingTooling) return@mcpTool toolingDisabledMessage
        val approved = SensitiveActionSecurity.checkPermission(
            "change project configuration",
            "Merge supplied JSON into Burp project configuration",
            json,
            api = api,
        )
        if (!approved) return@mcpTool "Project configuration change denied by Burp Suite"
        api.logging().logToOutput("Applying project-level configuration through MCP")
        api.burpSuite().importProjectOptionsFromJson(json)
        "Project configuration has been applied"
    }


    mcpTool<SetUserOptions>(
        "Imports bounded user configuration JSON after explicit approval. The JSON must have a top-level 'user_options' object.",
        PROJECT_MUTATION_TOOL_ANNOTATIONS,
    ) {
        require(json.length <= MAX_CONFIGURATION_JSON_CHARS) { "json is too large" }
        if (!config.configEditingTooling) return@mcpTool toolingDisabledMessage
        val approved = SensitiveActionSecurity.checkPermission(
            "change user configuration",
            "Merge supplied JSON into Burp user configuration",
            json,
            api = api,
        )
        if (!approved) return@mcpTool "User configuration change denied by Burp Suite"
        api.logging().logToOutput("Applying user-level configuration through MCP")
        api.burpSuite().importUserOptionsFromJson(json)
        "User configuration has been applied"
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
            description = "Generates a project-bound, bounded Burp Collaborator payload for out-of-band testing and returns its payloadId. Optional customData must contain 1–16 ASCII alphanumeric characters, matching Burp's native limit. Use get_collaborator_interactions with that payloadId; generation does not inject or send the payload.",
            annotations = COLLABORATOR_GENERATE_TOOL_ANNOTATIONS,
        ) { input ->
            collaboratorToolService.generate(input)
        }

        mcpStructuredToolWithContext<GetCollaboratorInteractions, GetCollaboratorInteractionsResult>(
            description = "Polls the current project-bound Burp Collaborator client for bounded DNS, HTTP, or SMTP interactions. payloadId is the interaction ID returned by generate_collaborator_payload and is matched with Burp's interaction-ID filter. Optional since, waitSeconds (maximum 120), maxResults, detail slicing, progress, and cancellation avoid model-side polling and unbounded output.",
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
        description = "Replays a Proxy, Site Map, or Organizer request returned by search_http_messages. Applies only bounded structured method, path, header, parameter, or body patches; never asks the model to reconstruct raw HTTP. Requires the matching projectId and approvals. The response preview, timeout, and HTTP mode are bounded and explicit; automatic redirects are rejected because each destination would require separate review. Successful Site Map recording returns recordedRef for the exact replay result when Burp can locate it. executionState=uncertain means the request must not be retried automatically.",
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
        "Displays bounded Proxy history summaries by default. Set summariesOnly=false and select one part for a byte-limited preview; use get_http_message_by_id for further byte pagination.",
        mapper = {
            if (summariesOnly != false && part == null) Json.encodeToString(it.toHistorySummary())
            else Json.encodeToString(
                it.readPart(
                    normalizeHttpPart(part ?: "request"),
                    0,
                    normalizeLegacyPreviewLimit(contentLimit),
                    normalizeHistoryEncoding(encoding),
                )
            )
        }
    ) {
        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        if (!allowed) {
            return@mcpPaginatedSequenceTool PaginatedSource.Message("HTTP history access denied by Burp Suite")
        }

        PaginatedSource.Items(api.proxy().history().asSequence())
    }

    mcpPaginatedSequenceTool<GetProxyHttpHistoryRegex, ProxyHttpRequestResponse>(
        "Displays bounded Proxy history summaries matching a conservatively safe regex. Set summariesOnly=false and select one byte-limited part; use get_http_message_by_id for further pagination.",
        mapper = {
            if (summariesOnly != false && part == null) Json.encodeToString(it.toHistorySummary())
            else Json.encodeToString(
                it.readPart(
                    normalizeHttpPart(part ?: "request"),
                    0,
                    normalizeLegacyPreviewLimit(contentLimit),
                    normalizeHistoryEncoding(encoding),
                )
            )
        }
    ) {
        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        if (!allowed) {
            return@mcpPaginatedSequenceTool PaginatedSource.Message("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = validateLegacyRegex(regex)
        PaginatedSource.Items(api.proxy().history { it.contains(compiledRegex) }.asSequence())
    }

    mcpPaginatedSequenceTool<GetOrganizerItems, OrganizerItem>(
        "Displays bounded Organizer summaries by default. Set summariesOnly=false and select one part for a byte-limited preview; use get_organizer_item_by_id for further pagination.",
        mapper = {
            if (summariesOnly != false && part == null) Json.encodeToString(it.toHistorySummary())
            else Json.encodeToString(
                it.readPart(
                    normalizeHttpPart(part ?: "request"),
                    0,
                    normalizeLegacyPreviewLimit(contentLimit),
                    normalizeHistoryEncoding(encoding),
                )
            )
        }
    ) {
        val allowed = checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        if (!allowed) {
            return@mcpPaginatedSequenceTool PaginatedSource.Message("Organizer access denied by Burp Suite")
        }

        PaginatedSource.Items(api.organizer().items().asSequence())
    }

    mcpPaginatedSequenceTool<GetOrganizerItemsRegex, OrganizerItem>(
        "Displays bounded Organizer summaries matching a conservatively safe regex. Set summariesOnly=false and select one byte-limited part; use get_organizer_item_by_id for further pagination.",
        mapper = {
            if (summariesOnly != false && part == null) Json.encodeToString(it.toHistorySummary())
            else Json.encodeToString(
                it.readPart(
                    normalizeHttpPart(part ?: "request"),
                    0,
                    normalizeLegacyPreviewLimit(contentLimit),
                    normalizeHistoryEncoding(encoding),
                )
            )
        }
    ) {
        val allowed = checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        if (!allowed) {
            return@mcpPaginatedSequenceTool PaginatedSource.Message("Organizer access denied by Burp Suite")
        }

        val compiledRegex = validateLegacyRegex(regex)
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
        "Displays bounded WebSocket history summaries by default. Set summariesOnly=false for one byte-limited payload preview; use get_websocket_message_by_id for further pagination.",
        mapper = {
            if (summariesOnly != false) Json.encodeToString(it.toHistorySummary())
            else Json.encodeToString(
                it.readPayload(
                    edited == true,
                    0,
                    normalizeLegacyPreviewLimit(contentLimit),
                    normalizeHistoryEncoding(encoding),
                )
            )
        }
    ) {
        val allowed = checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        if (!allowed) {
            return@mcpPaginatedSequenceTool PaginatedSource.Message("WebSocket history access denied by Burp Suite")
        }

        PaginatedSource.Items(api.proxy().webSocketHistory().asSequence())
    }

    mcpPaginatedSequenceTool<GetProxyWebsocketHistoryRegex, ProxyWebSocketMessage>(
        "Displays bounded WebSocket summaries matching a conservatively safe regex. Set summariesOnly=false for one byte-limited payload preview; use get_websocket_message_by_id for further pagination.",
        mapper = {
            if (summariesOnly != false) Json.encodeToString(it.toHistorySummary())
            else Json.encodeToString(
                it.readPayload(
                    edited == true,
                    0,
                    normalizeLegacyPreviewLimit(contentLimit),
                    normalizeHistoryEncoding(encoding),
                )
            )
        }
    ) {
        val allowed = checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        if (!allowed) {
            return@mcpPaginatedSequenceTool PaginatedSource.Message("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = validateLegacyRegex(regex)
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

    mcpTool<SetTaskExecutionEngineState>(
        "Changes Burp's global task execution engine state after explicit approval.",
        PROJECT_MUTATION_TOOL_ANNOTATIONS,
    ) {
        val approved = SensitiveActionSecurity.checkPermission(
            "change task execution engine state",
            "Set Burp task execution engine to ${if (running) "running" else "paused"}",
            api = api,
        )
        if (!approved) return@mcpTool "Task execution engine change denied by Burp Suite"
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED
        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>(
        "Changes Burp Proxy Intercept state after explicit approval.",
        PROJECT_MUTATION_TOOL_ANNOTATIONS,
    ) {
        val approved = SensitiveActionSecurity.checkPermission(
            "change Proxy Intercept state",
            "Set Burp Proxy Intercept to ${if (intercepting) "enabled" else "disabled"}",
            api = api,
        )
        if (!approved) return@mcpTool "Proxy Intercept change denied by Burp Suite"
        if (intercepting) api.proxy().enableIntercept() else api.proxy().disableIntercept()
        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool(
        "get_active_editor_contents",
        "Returns a bounded preview of the active editor after explicit approval.",
        READ_ONLY_TOOL_ANNOTATIONS,
    ) {
        val approved = SensitiveActionSecurity.checkPermission(
            "read active editor contents",
            "Return up to $MAX_EDITOR_PREVIEW_CHARS characters from the active message editor",
            api = api,
        )
        if (!approved) return@mcpTool "Active editor access denied by Burp Suite"
        val value = getActiveEditor(api)?.text ?: return@mcpTool "<No active editor>"
        Json.encodeToString(
            ActiveEditorPreview(
                text = value.take(MAX_EDITOR_PREVIEW_CHARS),
                totalChars = value.length,
                truncated = value.length > MAX_EDITOR_PREVIEW_CHARS,
            )
        )
    }

    mcpTool<SetActiveEditorContents>(
        "Sets bounded active-editor text after explicit approval.",
        PROJECT_MUTATION_TOOL_ANNOTATIONS,
    ) {
        require(text.length <= MAX_EDITOR_CONTENT_CHARS) { "text is too large" }
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"
        if (!editor.isEditable) return@mcpTool "<Current editor is not editable>"
        val approved = SensitiveActionSecurity.checkPermission(
            "change active editor contents",
            "Replace editable message text with ${text.length} characters",
            text,
            api = api,
        )
        if (!approved) return@mcpTool "Active editor change denied by Burp Suite"
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
    @JsonSchemaMetadata(description = "Raw HTTP/1.1 request.", minLength = 1, maxLength = 2097152)
    val content: String,
    @JsonSchemaMetadata(description = "Exact DNS or IP destination host.", minLength = 1, maxLength = 253)
    override val targetHostname: String,
    @JsonSchemaMetadata(description = "Destination port.", minimum = 1, maximum = 65535)
    override val targetPort: Int,
    @JsonSchemaMetadata(description = "Use TLS for the destination.")
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    @JsonSchemaMetadata(description = "HTTP/2 pseudo-headers without or with leading colons.", maxProperties = 8)
    val pseudoHeaders: Map<String, String>,
    @JsonSchemaMetadata(description = "HTTP/2 regular headers; combined header count is at most 128.", maxProperties = 128)
    val headers: Map<String, String>,
    @JsonSchemaMetadata(description = "HTTP/2 request body.", maxLength = 1048576)
    val requestBody: String,
    @JsonSchemaMetadata(description = "Exact DNS or IP destination host.", minLength = 1, maxLength = 253)
    override val targetHostname: String,
    @JsonSchemaMetadata(description = "Destination port.", minimum = 1, maximum = 65535)
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    @JsonSchemaMetadata(description = "Optional Repeater tab caption.", maxLength = 128)
    val tabName: String? = null,
    @JsonSchemaMetadata(description = "Raw HTTP/1.1 request.", minLength = 1, maxLength = 2097152)
    val content: String,
    @JsonSchemaMetadata(description = "Exact DNS or IP destination host.", minLength = 1, maxLength = 253)
    override val targetHostname: String,
    @JsonSchemaMetadata(description = "Destination port.", minimum = 1, maximum = 65535)
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTabHttp2(
    @JsonSchemaMetadata(description = "Optional Repeater tab caption.", maxLength = 128)
    val tabName: String? = null,
    @JsonSchemaMetadata(description = "HTTP/2 pseudo-headers.", maxProperties = 8)
    val pseudoHeaders: Map<String, String>,
    @JsonSchemaMetadata(description = "Regular headers; combined header count is at most 128.", maxProperties = 128)
    val headers: Map<String, String>,
    @JsonSchemaMetadata(description = "HTTP/2 request body.", maxLength = 1048576)
    val requestBody: String,
    @JsonSchemaMetadata(description = "Exact DNS or IP destination host.", minLength = 1, maxLength = 253)
    override val targetHostname: String,
    @JsonSchemaMetadata(description = "Destination port.", minimum = 1, maximum = 65535)
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    @JsonSchemaMetadata(description = "Optional Intruder tab caption.", maxLength = 128)
    val tabName: String? = null,
    @JsonSchemaMetadata(description = "Raw HTTP request.", minLength = 1, maxLength = 2097152)
    val content: String,
    @JsonSchemaMetadata(description = "Exact DNS or IP destination host.", minLength = 1, maxLength = 253)
    override val targetHostname: String,
    @JsonSchemaMetadata(description = "Destination port.", minimum = 1, maximum = 65535)
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(@JsonSchemaMetadata(maxLength = 262144) val content: String)

@Serializable
data class UrlDecode(@JsonSchemaMetadata(maxLength = 262144) val content: String)

@Serializable
data class Base64Encode(@JsonSchemaMetadata(maxLength = 262144) val content: String)

@Serializable
data class Base64Decode(@JsonSchemaMetadata(maxLength = 262144) val content: String)

@Serializable
data class GenerateRandomString(
    @JsonSchemaMetadata(minimum = 0, maximum = 65536) val length: Int,
    @JsonSchemaMetadata(minLength = 1, maxLength = 256) val characterSet: String,
)

@Serializable
data class SetProjectOptions(@JsonSchemaMetadata(maxLength = 1048576) val json: String)

@Serializable
data class SetUserOptions(@JsonSchemaMetadata(maxLength = 1048576) val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(
    @JsonSchemaMetadata(description = "Replacement editor text.", maxLength = 1048576)
    val text: String,
)

@Serializable
private data class ActiveEditorPreview(
    val text: String,
    val totalChars: Int,
    val truncated: Boolean,
)

@Serializable
data class GetProxyHttpHistory(
    @JsonSchemaMetadata(description = "Maximum records returned.", minimum = 1, maximum = 50)
    override val count: Int,
    @JsonSchemaMetadata(description = "History offset.", minimum = 0, maximum = 1000000)
    override val offset: Int,
    @JsonSchemaMetadata(description = "Return compact stable-ID summaries.", defaultJson = "true")
    val summariesOnly: Boolean? = null,
    @JsonSchemaMetadata(description = "Optional selected message part when summariesOnly=false.", enumValues = ["request", "request_headers", "request_body", "response", "response_headers", "response_body"])
    val part: String? = null,
    @JsonSchemaMetadata(description = "Maximum selected-part bytes per record.", minimum = 1, maximum = 32768, defaultJson = "8192")
    val contentLimit: Int? = null,
    @JsonSchemaMetadata(description = "Selected-part encoding.", enumValues = ["text", "base64"], defaultJson = "\"text\"")
    val encoding: String? = null,
) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(
    @JsonSchemaMetadata(description = "Conservatively safe history regex.", minLength = 1, maxLength = 512)
    val regex: String,
    @JsonSchemaMetadata(description = "Maximum records returned.", minimum = 1, maximum = 50)
    override val count: Int,
    @JsonSchemaMetadata(description = "History offset.", minimum = 0, maximum = 1000000)
    override val offset: Int,
    @JsonSchemaMetadata(description = "Return compact stable-ID summaries.", defaultJson = "true")
    val summariesOnly: Boolean? = null,
    @JsonSchemaMetadata(description = "Optional selected message part when summariesOnly=false.", enumValues = ["request", "request_headers", "request_body", "response", "response_headers", "response_body"])
    val part: String? = null,
    @JsonSchemaMetadata(description = "Maximum selected-part bytes per record.", minimum = 1, maximum = 32768, defaultJson = "8192")
    val contentLimit: Int? = null,
    @JsonSchemaMetadata(description = "Selected-part encoding.", enumValues = ["text", "base64"], defaultJson = "\"text\"")
    val encoding: String? = null,
) : Paginated

@Serializable
data class GetOrganizerItems(
    @JsonSchemaMetadata(description = "Maximum records returned.", minimum = 1, maximum = 50)
    override val count: Int,
    @JsonSchemaMetadata(description = "Organizer offset.", minimum = 0, maximum = 1000000)
    override val offset: Int,
    @JsonSchemaMetadata(description = "Return compact stable-ID summaries.", defaultJson = "true")
    val summariesOnly: Boolean? = null,
    @JsonSchemaMetadata(description = "Optional selected message part when summariesOnly=false.", enumValues = ["request", "request_headers", "request_body", "response", "response_headers", "response_body"])
    val part: String? = null,
    @JsonSchemaMetadata(description = "Maximum selected-part bytes per record.", minimum = 1, maximum = 32768, defaultJson = "8192")
    val contentLimit: Int? = null,
    @JsonSchemaMetadata(description = "Selected-part encoding.", enumValues = ["text", "base64"], defaultJson = "\"text\"")
    val encoding: String? = null,
) : Paginated

@Serializable
data class GetOrganizerItemsRegex(
    @JsonSchemaMetadata(description = "Conservatively safe Organizer regex.", minLength = 1, maxLength = 512)
    val regex: String,
    @JsonSchemaMetadata(description = "Maximum records returned.", minimum = 1, maximum = 50)
    override val count: Int,
    @JsonSchemaMetadata(description = "Organizer offset.", minimum = 0, maximum = 1000000)
    override val offset: Int,
    @JsonSchemaMetadata(description = "Return compact stable-ID summaries.", defaultJson = "true")
    val summariesOnly: Boolean? = null,
    @JsonSchemaMetadata(description = "Optional selected message part when summariesOnly=false.", enumValues = ["request", "request_headers", "request_body", "response", "response_headers", "response_body"])
    val part: String? = null,
    @JsonSchemaMetadata(description = "Maximum selected-part bytes per record.", minimum = 1, maximum = 32768, defaultJson = "8192")
    val contentLimit: Int? = null,
    @JsonSchemaMetadata(description = "Selected-part encoding.", enumValues = ["text", "base64"], defaultJson = "\"text\"")
    val encoding: String? = null,
) : Paginated

@Serializable
data class GetProxyWebsocketHistory(
    @JsonSchemaMetadata(description = "Maximum records returned.", minimum = 1, maximum = 50)
    override val count: Int,
    @JsonSchemaMetadata(description = "History offset.", minimum = 0, maximum = 1000000)
    override val offset: Int,
    @JsonSchemaMetadata(description = "Return compact stable-ID summaries.", defaultJson = "true")
    val summariesOnly: Boolean? = null,
    @JsonSchemaMetadata(description = "Select the edited payload variant.", defaultJson = "false")
    val edited: Boolean? = null,
    @JsonSchemaMetadata(description = "Maximum payload bytes per record.", minimum = 1, maximum = 32768, defaultJson = "8192")
    val contentLimit: Int? = null,
    @JsonSchemaMetadata(description = "Payload encoding.", enumValues = ["text", "base64"], defaultJson = "\"text\"")
    val encoding: String? = null,
) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(
    @JsonSchemaMetadata(description = "Conservatively safe WebSocket regex.", minLength = 1, maxLength = 512)
    val regex: String,
    @JsonSchemaMetadata(description = "Maximum records returned.", minimum = 1, maximum = 50)
    override val count: Int,
    @JsonSchemaMetadata(description = "History offset.", minimum = 0, maximum = 1000000)
    override val offset: Int,
    @JsonSchemaMetadata(description = "Return compact stable-ID summaries.", defaultJson = "true")
    val summariesOnly: Boolean? = null,
    @JsonSchemaMetadata(description = "Select the edited payload variant.", defaultJson = "false")
    val edited: Boolean? = null,
    @JsonSchemaMetadata(description = "Maximum payload bytes per record.", minimum = 1, maximum = 32768, defaultJson = "8192")
    val contentLimit: Int? = null,
    @JsonSchemaMetadata(description = "Payload encoding.", enumValues = ["text", "base64"], defaultJson = "\"text\"")
    val encoding: String? = null,
) : Paginated

@Serializable
data class GetHttpMessageById(
    @JsonSchemaMetadata(description = "Stable Proxy history ID.", minimum = 0) val id: Int,
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256) val projectId: String? = null,
    @JsonSchemaMetadata(enumValues = ["metadata", "request", "request_headers", "request_body", "response", "response_headers", "response_body"], defaultJson = "\"metadata\"") val part: String? = null,
    @JsonSchemaMetadata(minimum = 0, defaultJson = "0") val offset: Int? = null,
    @JsonSchemaMetadata(minimum = 1, maximum = 262144, defaultJson = "32768") val limit: Int? = null,
    @JsonSchemaMetadata(enumValues = ["text", "base64"], defaultJson = "\"text\"") val encoding: String? = null,
)

@Serializable
data class GetWebsocketMessageById(
    @JsonSchemaMetadata(description = "Stable WebSocket history ID.", minimum = 0) val id: Int,
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256) val projectId: String? = null,
    @JsonSchemaMetadata(description = "Read the edited payload variant.", defaultJson = "false") val edited: Boolean? = null,
    @JsonSchemaMetadata(minimum = 0, defaultJson = "0") val offset: Int? = null,
    @JsonSchemaMetadata(minimum = 1, maximum = 262144, defaultJson = "32768") val limit: Int? = null,
    @JsonSchemaMetadata(enumValues = ["text", "base64"], defaultJson = "\"text\"") val encoding: String? = null,
)

@Serializable
data class GetOrganizerItemById(
    @JsonSchemaMetadata(description = "Stable Organizer item ID.", minimum = 0) val id: Int,
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256) val projectId: String? = null,
    @JsonSchemaMetadata(enumValues = ["metadata", "request", "request_headers", "request_body", "response", "response_headers", "response_body"], defaultJson = "\"metadata\"") val part: String? = null,
    @JsonSchemaMetadata(minimum = 0, defaultJson = "0") val offset: Int? = null,
    @JsonSchemaMetadata(minimum = 1, maximum = 262144, defaultJson = "32768") val limit: Int? = null,
    @JsonSchemaMetadata(enumValues = ["text", "base64"], defaultJson = "\"text\"") val encoding: String? = null,
)

@Serializable
data class GetScannerIssueById(
    @JsonSchemaMetadata(description = "Stable Scanner issue ID.", pattern = "^issue_[0-9a-f]{32}$", maxLength = 128) val id: String,
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256) val projectId: String? = null,
    @JsonSchemaMetadata(enumValues = ["metadata", "detail", "remediation", "evidence_request", "evidence_response"], defaultJson = "\"metadata\"") val field: String? = null,
    @JsonSchemaMetadata(minimum = 0) val evidenceIndex: Int? = null,
    @JsonSchemaMetadata(minimum = 0, defaultJson = "0") val offset: Int? = null,
    @JsonSchemaMetadata(minimum = 1, maximum = 262144, defaultJson = "32768") val limit: Int? = null,
    @JsonSchemaMetadata(enumValues = ["text", "base64"], defaultJson = "\"text\"") val encoding: String? = null,
)

@Serializable
data class GenerateCollaboratorPayload(
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Optional ASCII alphanumeric payload prefix.", minLength = 1, maxLength = 16, pattern = "^[A-Za-z0-9]{1,16}$")
    val customData: String? = null,
)
