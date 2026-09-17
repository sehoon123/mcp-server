package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.config.TargetValidation
import net.portswigger.mcp.presets.DeleteWorkflowPreset
import net.portswigger.mcp.presets.DeleteWorkflowPresetResult
import net.portswigger.mcp.presets.ExecuteWorkflowPreset
import net.portswigger.mcp.presets.ExecuteWorkflowPresetResult
import net.portswigger.mcp.presets.ListWorkflowPresets
import net.portswigger.mcp.presets.ListWorkflowPresetsResult
import net.portswigger.mcp.presets.SaveWorkflowPreset
import net.portswigger.mcp.presets.SaveWorkflowPresetResult
import net.portswigger.mcp.presets.WorkflowPresetStatus
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.McpAuditSink
import net.portswigger.mcp.security.McpSessionApprovalRegistry
import net.portswigger.mcp.security.NoOpMcpAuditSink
import net.portswigger.mcp.security.SensitiveActionAuditOperation
import net.portswigger.mcp.security.SensitiveActionSecurity
import java.util.regex.Pattern

internal suspend fun checkDataAccessOrDeny(
    accessType: DataAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    currentCoroutineContext().ensureActive()
    val allowed = DataAccessSecurity.checkDataAccessPermission(accessType, config)
    currentCoroutineContext().ensureActive()
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private const val MAX_RAW_REQUEST_CHARS = 2 * 1024 * 1024
private const val MAX_RAW_HTTP2_BODY_CHARS = 1024 * 1024
private const val MAX_RAW_HTTP_HEADERS = 128
private const val MAX_RAW_HEADER_NAME_CHARS = 256
private const val MAX_RAW_HEADER_VALUE_CHARS = 16 * 1024
private const val MAX_SAFE_REGEX_CHARS = 512

/**
 * Retained-tool MCP error classification. Approval/policy denials and unavailable data remain ordinary structured
 * outcomes for wire compatibility; correction-required, private-safe Burp, and uncertain outcomes are MCP errors.
 */
private fun HttpMessageActionStatus.isMcpError(): Boolean = when (this) {
    HttpMessageActionStatus.INVALID_ARGUMENT,
    HttpMessageActionStatus.INVALID_ID,
    HttpMessageActionStatus.PROJECT_MISMATCH,
    HttpMessageActionStatus.NOT_FOUND,
    HttpMessageActionStatus.BURP_ERROR,
    HttpMessageActionStatus.EXECUTION_UNCERTAIN -> true

    else -> false
}

private fun HttpMessageReadStatus.isMcpError(): Boolean = when (this) {
    HttpMessageReadStatus.INVALID_ARGUMENT,
    HttpMessageReadStatus.INVALID_ID,
    HttpMessageReadStatus.PROJECT_MISMATCH,
    HttpMessageReadStatus.NOT_FOUND,
    HttpMessageReadStatus.BURP_ERROR -> true

    else -> false
}

private fun HttpComparisonStatus.isMcpError(): Boolean = when (this) {
    HttpComparisonStatus.INVALID_ARGUMENT,
    HttpComparisonStatus.INVALID_ID,
    HttpComparisonStatus.PROJECT_MISMATCH,
    HttpComparisonStatus.NOT_FOUND,
    HttpComparisonStatus.BURP_ERROR -> true

    else -> false
}

private fun ScopeToolStatus.isMcpError(): Boolean = when (this) {
    ScopeToolStatus.INVALID_ARGUMENT,
    ScopeToolStatus.INVALID_ID,
    ScopeToolStatus.PROJECT_MISMATCH,
    ScopeToolStatus.NOT_FOUND,
    ScopeToolStatus.BURP_ERROR,
    ScopeToolStatus.EXECUTION_UNCERTAIN -> true

    else -> false
}

private fun ScannerAuditToolStatus.isMcpError(): Boolean = when (this) {
    ScannerAuditToolStatus.INVALID_ARGUMENT,
    ScannerAuditToolStatus.INVALID_ID,
    ScannerAuditToolStatus.PROJECT_MISMATCH,
    ScannerAuditToolStatus.NOT_FOUND,
    ScannerAuditToolStatus.BURP_ERROR,
    ScannerAuditToolStatus.EXECUTION_UNCERTAIN -> true

    else -> false
}

private fun HistoryReadStatus.isMcpError(): Boolean = when (this) {
    HistoryReadStatus.INVALID_ARGUMENT,
    HistoryReadStatus.NOT_FOUND,
    HistoryReadStatus.PROJECT_MISMATCH,
    HistoryReadStatus.BURP_ERROR -> true

    else -> false
}

private fun NativeToolStatus.isMcpError(): Boolean = when (this) {
    NativeToolStatus.INVALID_ARGUMENT,
    NativeToolStatus.INVALID_ID,
    NativeToolStatus.NOT_FOUND,
    NativeToolStatus.LIMIT_EXCEEDED,
    NativeToolStatus.PROJECT_MISMATCH,
    NativeToolStatus.STALE_STATE,
    NativeToolStatus.BURP_ERROR,
    NativeToolStatus.EXECUTION_UNCERTAIN -> true

    NativeToolStatus.OK,
    NativeToolStatus.ACCESS_DENIED,
    NativeToolStatus.DISABLED,
    NativeToolStatus.NOT_AVAILABLE -> false
}

private fun CollaboratorToolStatus.isMcpError(): Boolean = when (this) {
    CollaboratorToolStatus.INVALID_ARGUMENT,
    CollaboratorToolStatus.PROJECT_MISMATCH,
    CollaboratorToolStatus.BURP_ERROR,
    CollaboratorToolStatus.EXECUTION_UNCERTAIN -> true

    else -> false
}

private fun HttpMessageSearchStatus.isMcpError(): Boolean = when (this) {
    HttpMessageSearchStatus.INVALID_ARGUMENT,
    HttpMessageSearchStatus.INVALID_CURSOR,
    HttpMessageSearchStatus.STALE_CURSOR,
    HttpMessageSearchStatus.PROJECT_MISMATCH,
    HttpMessageSearchStatus.BURP_ERROR -> true

    else -> false
}

private fun WebSocketSearchStatus.isMcpError(): Boolean = when (this) {
    WebSocketSearchStatus.INVALID_ARGUMENT,
    WebSocketSearchStatus.INVALID_CURSOR,
    WebSocketSearchStatus.STALE_CURSOR,
    WebSocketSearchStatus.PROJECT_MISMATCH,
    WebSocketSearchStatus.BURP_ERROR -> true

    else -> false
}

private fun HttpAttackSurfaceStatus.isMcpError(): Boolean = when (this) {
    HttpAttackSurfaceStatus.INVALID_ARGUMENT,
    HttpAttackSurfaceStatus.PROJECT_MISMATCH,
    HttpAttackSurfaceStatus.BURP_ERROR -> true

    else -> false
}

private fun HttpActivityCorrelationStatus.isMcpError(): Boolean = when (this) {
    HttpActivityCorrelationStatus.INVALID_ARGUMENT,
    HttpActivityCorrelationStatus.INVALID_ID,
    HttpActivityCorrelationStatus.PROJECT_MISMATCH,
    HttpActivityCorrelationStatus.NOT_FOUND,
    HttpActivityCorrelationStatus.BURP_ERROR -> true

    else -> false
}

private fun HttpSessionAnalysisStatus.isMcpError(): Boolean = when (this) {
    HttpSessionAnalysisStatus.INVALID_ARGUMENT,
    HttpSessionAnalysisStatus.INVALID_ID,
    HttpSessionAnalysisStatus.PROJECT_MISMATCH,
    HttpSessionAnalysisStatus.NOT_FOUND,
    HttpSessionAnalysisStatus.BURP_ERROR -> true

    else -> false
}

internal fun validateRawTarget(hostname: String, port: Int) {
    require(TargetValidation.normalizeTarget(TargetValidation.formatTarget(hostname, port)) != null) {
        "targetHostname or targetPort is invalid"
    }
}

internal fun validateRawHttp2Input(
    pseudoHeaders: Map<String, String>,
    headers: Map<String, String>,
    body: String,
) {
    require(body.length <= MAX_RAW_HTTP2_BODY_CHARS) { "requestBody is too large" }
    require(pseudoHeaders.size + headers.size <= MAX_RAW_HTTP_HEADERS) { "too many HTTP headers" }
    val allHeaders = pseudoHeaders.asSequence() + headers.asSequence()
    val totalChars = body.length.toLong() + allHeaders.sumOf { (name, value) -> name.length.toLong() + value.length + 4 }
    require(totalChars <= MAX_RAW_REQUEST_CHARS) { "combined HTTP/2 request content is too large" }
    (pseudoHeaders.asSequence() + headers.asSequence()).forEach { (name, value) ->
        require(name.length in 1..MAX_RAW_HEADER_NAME_CHARS && name.none(Char::isISOControl)) {
            "HTTP header name is invalid"
        }
        require(value.length <= MAX_RAW_HEADER_VALUE_CHARS && value.none { it == '\u0000' }) {
            "HTTP header value is invalid"
        }
    }
}

/** Conservatively rejects Java-regex constructs that can create unbounded backtracking. */
internal fun validateSafeRegex(regex: String, caseSensitive: Boolean = true): Pattern {
    require(regex.isNotEmpty() && regex.length <= MAX_SAFE_REGEX_CHARS) {
        "regex must contain 1 to $MAX_SAFE_REGEX_CHARS characters"
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
    val flags = if (caseSensitive) 0 else Pattern.CASE_INSENSITIVE or Pattern.UNICODE_CASE
    return Pattern.compile(regex, flags)
}

internal fun buildHttp2HeaderList(
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

internal fun Server.registerTools(
    api: MontoyaApi,
    config: McpConfig,
    services: ToolServices,
    auditSink: McpAuditSink = NoOpMcpAuditSink,
    sessionApprovals: McpSessionApprovalRegistry = McpSessionApprovalRegistry(32),
) {
    bindToolRuntimePolicy(config, auditSink, sessionApprovals)
    val httpMessageSearchService = HttpMessageSearchService(
        api = api,
        config = config,
        metadataIndex = services.httpMetadataIndex,
        performanceDiagnostics = services.historyPerformanceDiagnostics,
    )
    val httpAttackSurfaceService = HttpAttackSurfaceService(api, config, services.httpMetadataIndex)
    val httpActivityCorrelationService = HttpActivityCorrelationService(
        api,
        config,
        httpMessageSearchService,
        services.historyPerformanceDiagnostics,
    )
    val httpMessageActionService = HttpMessageActionService(api, config, services::withOrganizerMutation)
    val rawHttpActionService = RawHttpActionService(api, config, services::withOrganizerMutation)
    val httpMessageReadService = HttpMessageReadService(api, config)
    val webSocketMessageSearchService = WebSocketMessageSearchService(
        api,
        config,
        performanceDiagnostics = services.historyPerformanceDiagnostics,
    )
    val webSocketMessageReadService = WebSocketMessageReadService(api, config)
    val scopeToolService = ScopeToolService(api, config, services.httpMetadataIndex)
    val httpMessageComparisonService = HttpMessageComparisonService(api, config)
    val workflowPresetService = WorkflowPresetService(
        api,
        services.workflowPresetStore,
        httpMessageSearchService,
        webSocketMessageSearchService,
        httpMessageComparisonService,
    )
    val burpOptionsService = BurpOptionsService(api, config, services.httpMetadataIndex)
    val nativeHttpRankingService = NativeHttpRankingService(api, config)
    val httpAnnotationService = HttpAnnotationService(api, config, services::withOrganizerMutation)
    val localCommandService = services.localCommands(config)

    mcpStructuredToolWithContext<SendRawHttpRequest, RawHttpActionResult>(
        title = "Send raw HTTP request",
        description = "Send one caller-supplied HTTP/1.1 or HTTP/2 request only if no stored ref exists; otherwise prefer send_http_request_from_id. The independent outbound-target policy applies, not stored-reference/request-action approval. Binds to the current project and returns projectId. Redirects are disabled, output is bounded, and no Site Map entry is added. If executionState is uncertain, the request may have been sent; do not retry automatically.",
        annotations = HTTP_REQUEST_ACTION_ANNOTATIONS,
    ) { input ->
        val output = rawHttpActionService.send(input)
        StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
    }

    mcpStructuredToolWithContext<RouteRawHttpRequest, RawHttpActionResult>(
        title = "Create Repeater tab or route raw HTTP request",
        description = "Create a new Repeater tab (destination=repeater), or route a caller-supplied request to Intruder, Organizer, Comparer, or Decoder; prefer route_http_message_from_id for stored traffic. Routing approval and current-project binding apply; no network traffic is sent. HTTP/2 Intruder is unsupported. Comparer/Decoder receive only request bytes. Never retry executionState=uncertain automatically.",
        annotations = REQUEST_ROUTING_TOOL_ANNOTATIONS,
    ) { input ->
        val output = rawHttpActionService.route(input)
        StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
    }

    mcpStructuredToolWithContext<RankHttpMessages, RankHttpMessagesResult>(
        title = "Rank HTTP messages",
        description = "Rank 1–32 explicit stored HTTP messages using Burp's native anomaly ranking. Source access and matching projectId apply; private request/response bounds are 2 MiB each and 16 MiB total. Ranks are relative ordinals for this set, not severity, confidence, or vulnerability evidence. No traffic or mutation occurs; the native call has no interruptible deadline.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        val output = nativeHttpRankingService.rank(input)
        StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
    }

    mcpStructuredToolWithContext<AnnotateHttpMessages, AnnotateHttpMessagesResult>(
        title = "Annotate HTTP messages",
        description = "Annotate 1–16 explicit stored HTTP records: replace/append/clear notes and set/clear highlights. Source access, sensitive-action approval and matching projectId apply; current annotations are rechecked before mutation. No traffic is sent. The batch is not atomic: uncertain execution may have changed a prefix or one field; reconcile manually and never retry automatically.",
        annotations = PROJECT_MUTATION_TOOL_ANNOTATIONS,
    ) { input ->
        val output = httpAnnotationService.annotate(input)
        StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
    }

    mcpStructuredToolWithContext<ExecuteLocalCommand, ExecuteLocalCommandResult>(
        title = "Execute local command",
        description = "Execute one direct argv or explicitly shell-interpreted local command via Burp. The separate code-execution toggle and sensitive approval apply; YOLO bypasses only the prompt. Emergency read-only blocks it. Native timeout options apply, but only the MCP preview is output-bounded; a started process is outside project fencing. Never retry an uncertain result.",
        annotations = CODE_EXECUTION_TOOL_ANNOTATIONS,
    ) { input ->
        val output = localCommandService.execute(input)
        StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
    }

    mcpStructuredToolWithContext<GetBurpOptions, GetBurpOptionsResult>(
        title = "Read Burp options",
        description = "Read bounded Burp configuration for level=project or level=user. Approval applies unless YOLO allows it. Project reads capture and recheck the current project without returning its ID; user reads are project-independent. Credentials are filtered by default; disabling filtering may expose secrets. No Burp state changes.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        burpOptionsService.get(input)
    }

    mcpStructuredToolWithContext<SetBurpOptions, SetBurpOptionsResult>(
        title = "Update Burp options",
        description = "Update Burp configuration by importing bounded JSON for level=project or level=user; editing tools must be enabled. Approval applies unless YOLO allows it. Project imports capture and recheck the current project without returning its ID; user imports are project-independent. If executionState is uncertain, configuration may be partially applied; reconcile manually and do not retry automatically.",
        annotations = PROJECT_MUTATION_TOOL_ANNOTATIONS,
    ) { input ->
        burpOptionsService.set(input)
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        val requestExecutionService = services.requestExecutions(config)
        val bambdaService = services.bambdas(config)

        mcpStructuredToolWithContext<StartHttpRequestExecution, HttpRequestExecutionActionResult>(
            title = "Start HTTP request execution",
            description = "Start one Professional Request Execution Engine with 1–16 stored or raw requests; sending begins immediately. Source, derived-request, outbound-target and batch approvals, project binding and aggregate limits apply. Returns an extension-owned executionId handle: add work with queue_http_request_execution, poll get_http_request_execution, and pause/cancel with control_http_request_execution. If executionState is uncertain, requests may have started; never retry automatically.",
            annotations = REQUEST_EXECUTION_TOOL_ANNOTATIONS,
        ) { input ->
            val output = requestExecutionService.start(input)
            StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
        }

        mcpStructuredToolWithContext<QueueHttpRequestExecution, HttpRequestExecutionActionResult>(
            title = "Queue HTTP request execution",
            description = "Queue 1–16 additional stored or raw requests into a running extension-owned Request Execution Engine, up to 64 total. Pass the executionId from start_http_request_execution; poll get_http_request_execution for progress. Source, derived-request, outbound-target, batch and project checks precede native queueing. Queueing is not atomic: an uncertain result may have queued a prefix; never retry automatically.",
            annotations = REQUEST_EXECUTION_TOOL_ANNOTATIONS,
        ) { input ->
            val output = requestExecutionService.queue(input)
            StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
        }

        mcpStructuredToolWithContext<GetHttpRequestExecution, HttpRequestExecutionStatusResult>(
            title = "Read HTTP request execution status",
            description = "Read live stats and bounded completion-order metadata for an executionId from start_http_request_execution; optionally wait up to 30 seconds. This extension never returns or retains request/response content; native results are dropped after metadata capture. No requests are sent or queued and no execution control is changed; use control_http_request_execution to pause, resume, or cancel.",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) { input ->
            val output = requestExecutionService.get(input)
            StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
        }

        mcpStructuredToolWithContext<ControlHttpRequestExecution, HttpRequestExecutionActionResult>(
            title = "Control HTTP request execution",
            description = "Control one extension-owned Request Execution Engine by executionId from start_http_request_execution: pause, resume, cancel, or cancel-and-delete. Confirm the effect with get_http_request_execution. Sensitive approval and project recheck apply. Emergency read-only blocks every control, including cancellation; project changes and extension unload independently attempt cleanup. If executionState is uncertain, the control may already have applied; do not retry automatically.",
            annotations = REQUEST_EXECUTION_TOOL_ANNOTATIONS,
        ) { input ->
            val output = requestExecutionService.control(input)
            StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
        }

        mcpStructuredToolWithContext<ImportBambda, BambdaImportResult>(
            title = "Import Repeater Bambda",
            description = "Import bounded bare Java source as a Professional Repeater CUSTOM_ACTION Bambda. The name determines a stable ID; reimport replaces it. At most 32 distinct MCP-imported IDs per extension lifetime. The code-execution toggle and sensitive approval apply. Imported code can later run outside MCP request, project, outbound, and emergency-read-only fences. Inspect the full local approval preview; never retry an uncertain import automatically.",
            annotations = CODE_EXECUTION_TOOL_ANNOTATIONS,
        ) { input ->
            val output = bambdaService.import(input)
            StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
        }

        mcpStructuredToolWithContext<GenerateBambdaChain, GenerateBambdaChainResult>(
            title = "Generate and import Repeater Bambda chain",
            description = "Generate and immediately import a Professional Repeater CUSTOM_ACTION Bambda for 1–8 fixed-target steps; not a preview. The code-execution toggle, replacement/approval rules and 32-distinct-ID lifetime cap from import_bambda apply. Running or auto-running it sends requests with value extraction and later-header injection outside MCP request, project, outbound and emergency-read-only fences.",
            annotations = CODE_EXECUTION_TOOL_ANNOTATIONS,
        ) { input ->
            val output = bambdaService.generateAndImport(input)
            StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
        }

        val scannerIssueSearchService = ScannerIssueSearchService(
            api,
            config,
            performanceDiagnostics = services.historyPerformanceDiagnostics,
        )
        val scannerIssueReadService = ScannerIssueReadService(api, config)
        val scannerIssueCreationService = ScannerIssueCreationService(api, config, services::withOrganizerMutation)
        val collaboratorToolService = services.collaborator
        mcpStructuredToolWithContext<CreateScannerIssue, CreateScannerIssueResult>(
            title = "Record Scanner issue",
            description = "Record one Professional Scanner issue from 1–8 existing HTTP references after human-reviewed attestation and local approval. This evidence-reporting tool sends nothing, starts no scan, and does not automatically verify the caller-authored finding or persistence. If executionState is uncertain, never retry automatically.",
            annotations = PROJECT_MUTATION_TOOL_ANNOTATIONS,
        ) { input ->
            val output = scannerIssueCreationService.create(input)
            StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
        }

        mcpStructuredToolWithContext<GetScannerIssues, ScannerIssuePageResult>(
            title = "Search Scanner issues",
            description = "Search Scanner issues (findings) in the captured, rechecked current project; no projectId input, but the result returns projectId. Access policy applies; no traffic/mutation. Legacy JSON mode advances offset by returned while hasMore=true (empty: 'Reached end of items'). Cursor mode: use nextCursor as cursor or nextDeltaCursor as sinceSnapshotCursor. A fully consumed snapshotCursor starts an append-stable range; this does not prove regression, removal, or in-place change. Detail: get_scanner_issue_by_id.",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) { input ->
            scannerIssueSearchService.get(input)
        }

        mcpStructuredToolWithContext<GetScannerIssueById, ScannerIssueReadResult>(
            title = "Read Scanner issue",
            description = "Read one Scanner issue by id in the specified project. Reuse projectId from a producing result or burp://project/summary; IDs are not portable across projects. Scanner-issue access approval applies. field selects bounded, byte-paginated content; evidenceIndex is required for evidence_request or evidence_response. No mutation occurs; burp_error is a read failure.",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) { input ->
            val output = scannerIssueReadService.read(input)
            StructuredToolResponse(
                output = output,
                text = null,
                isError = output.status.isMcpError(),
            )
        }

        mcpStructuredToolWithContext<StartScannerAuditFromIds, ScannerAuditResult>(
            title = "Start Scanner audit",
            description = "Start one passive or focused active Scanner audit (vulnerability scan) from stored HTTP refs after approval unless the local operator enabled YOLO mode. Both modes reject out-of-scope requests. Passive mode requires responses and sends no target traffic; active mode requires insertionPoints and can send requests. Passive accepts 1–16 targets, active 1–4. Poll get_scanner_audit with the returned taskId; stop it with cancel_scanner_audit. If actionState is uncertain, never start another audit automatically.",
            annotations = SCANNER_START_TOOL_ANNOTATIONS,
        ) { input ->
            val output = services.scannerAudits.start(input, config)
            StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
        }

        mcpStructuredToolWithContext<GetScannerAudit, ScannerAuditResult>(
            title = "Read Scanner audit status",
            description = "Read vulnerability-scan status and bounded issue summaries for a taskId from start_scanner_audit_from_ids. Reading status refreshes the 6-hour inactivity lease but not the 24-hour maximum lifetime; requesting issues is subject to Scanner-issue access approval. issuesAccessDenied identifies an operator denial, while issuesUnavailable identifies a skipped or technically failed issue read. Treat normalized actionState and taskState as authoritative; bounded Burp statusMessage text may lag.",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) { input ->
            val output = services.scannerAudits.get(input, config)
            StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
        }

        mcpStructuredToolWithContext<CancelScannerAudit, ScannerAuditResult>(
            title = "Cancel Scanner audit",
            description = "Cancel (stop) a retained Scanner audit vulnerability scan by taskId from start_scanner_audit_from_ids, after approval unless the local operator enabled YOLO mode. Confirm the outcome with get_scanner_audit. If actionState is uncertain, the task may already be deleted; do not retry automatically.",
            annotations = SCANNER_CANCEL_TOOL_ANNOTATIONS,
        ) { input ->
            val output = services.scannerAudits.cancel(input, config)
            StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
        }

        mcpStructuredToolWithContext<GenerateCollaboratorPayload, GenerateCollaboratorPayloadResult>(
            title = "Allocate Collaborator payload",
            description = "Allocate a project-bound out-of-band (OAST) Collaborator payload for DNS, HTTP, or SMTP callbacks. This returns a payload and identifier but does not inject or send it; poll get_collaborator_interactions for callbacks. If executionState is uncertain, it may already have been allocated; do not retry automatically.",
            annotations = COLLABORATOR_GENERATE_TOOL_ANNOTATIONS,
        ) { input ->
            val response = collaboratorToolService.generate(input)
            response.copy(
                isError = response.isError || response.output.status.isMcpError(),
            )
        }

        mcpStructuredToolWithContext<GetCollaboratorInteractions, GetCollaboratorInteractionsResult>(
            title = "Poll Collaborator interactions",
            description = "Poll bounded out-of-band DNS/HTTP/SMTP interactions (callbacks) for the current projectId under Collaborator-interaction access policy. Filter with the payload ID from generate_collaborator_payload. Long polling is capped at 120 seconds and scanning at 10,000 interactions. hasMore marks known matching records omitted inside that window and has no continuation cursor; scanLimitReached means unscanned interactions have unknown match status.",
            annotations = COLLABORATOR_READ_TOOL_ANNOTATIONS,
        ) { input ->
            val response = collaboratorToolService.interactions(input, config) { progress, total, message ->
                reportProgress(progress, total, message)
            }
            response.copy(isError = response.isError || response.output.status.isMcpError())
        }
    }

    mcpStructuredToolWithContext<SearchHttpMessages, SearchHttpMessagesResult>(
        title = "Search HTTP messages",
        description = "Search Proxy history (default), Site Map, or Organizer messages in the call-start project if no ref exists. Returns projectId and {source,id} refs. Source access applies; no traffic or mutation occurs. At most 50 results, 10,000 scanned records and 32 MiB inspected. items=[] with hasMore=true is not end-of-data; follow nextCursor with filters omitted or repeated exactly. MCP sends are absent unless Burp recorded them.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        val output = httpMessageSearchService.search(input) { progress, total, message ->
            reportProgress(progress, total, message)
        }
        StructuredToolResponse(
            output = output,
            text = null,
            isError = output.status.isMcpError(),
        )
    }

    mcpStructuredToolWithContext<SummarizeHttpAttackSurface, HttpAttackSurfaceResult>(
        title = "Summarize HTTP attack surface",
        description = "Summarize the endpoint inventory (services, methods, statuses, MIME types, extensions, and normalized paths) from stored HTTP metadata; the default is in-scope Proxy history. Source-access policy applies, and no traffic or mutation occurs. Query strings, bodies, header values, and notes are not retained. If burp_error reports changing HTTP metadata, retry the read.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        val output = httpAttackSurfaceService.summarize(input) { progress, total, message ->
            reportProgress(progress, total, message)
        }
        StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
    }

    mcpStructuredToolWithContext<CorrelateHttpActivity, CorrelateHttpActivityResult>(
        title = "Correlate HTTP activity",
        description = "Correlate two cohorts of 1–16 explicit HTTP refs each. Optionally append up to 16 ranked related events from 1–4 seeds; refs are revalidated and discovered events never change the explicit delta. Source policy applies; no traffic or mutation occurs. Results expose only Proxy times and establish no identity, chronology, causality, vulnerability evidence, or complete enumeration. Query strings, headers, bodies, notes, and raw bytes are omitted; Site Map ID checks may inspect bounded private samples.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        val result = httpActivityCorrelationService.correlate(input) { progress, total, message ->
            reportProgress(progress, total, message)
        }
        StructuredToolResponse(
            result,
            text = null,
            isError = result.status.isMcpError(),
        )
    }

    mcpStructuredToolWithContext<CheckScope, CheckScopeResult>(
        title = "Check Target scope",
        description = "Check whether up to 32 URLs or stored HTTP references are currently in Target scope. This never changes scope; stored references remain subject to their source-access approval.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        val output = scopeToolService.check(input)
        StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
    }

    mcpStructuredToolWithContext<UpdateScope, UpdateScopeResult>(
        title = "Update Target scope",
        description = "Update Target scope by including/excluding up to 16 URLs or stored HTTP references. All targets are validated before any approval prompt or policy bypass and before mutation. Scope changes require approval unless policy allows them. If executionState is uncertain, some changes may already exist; do not retry automatically.",
        annotations = SCOPE_MUTATION_TOOL_ANNOTATIONS,
    ) { input ->
        val output = scopeToolService.update(input)
        StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
    }

    mcpStructuredToolWithContext<CompareHttpMessages, CompareHttpMessagesResult>(
        title = "Compare HTTP messages",
        description = "Compare (diff) parts of 2–8 stored HTTP messages under source-access approval; no traffic or mutation occurs. request_json/response_json return paths without scalar values: allEqual is structural equality only when jsonComparison.status is ok. Other parts use byte equality; null means incomplete/unavailable. responseKeywords analyzes complete stored responses regardless of selected part or preview limit; runtime-only.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        val output = httpMessageComparisonService.compare(input)
        StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
    }

    mcpStructuredToolWithContext<AnalyzeHttpSessionSecurity, AnalyzeHttpSessionSecurityResult>(
        title = "Analyze HTTP session security",
        description = "Analyze authentication and session signals across 1–32 HTTP refs using stored evidence only. Source access applies; no traffic or mutation occurs. Returns value-free authentication, cookie, token, redirect, endpoint-role and cross-message observations, never raw bodies or sensitive values. Site Map identity checks may privately inspect bounded body and header samples. Input order is a proposed flow, not proof of chronology, browser behavior, severity, or a vulnerability.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        val output = services.httpSessionSecurityAnalyzer.analyze(input, config) { progress, total, message ->
            reportProgress(progress, total, message)
        }
        StructuredToolResponse(
            output = output,
            text = null,
            isError = output.status.isMcpError(),
        )
    }

    mcpStructuredToolWithContext<GetHttpMessage, GetHttpMessageResult>(
        title = "Read HTTP message",
        description = "Read a stored {source,id} from search_http_messages; source approval and matching projectId apply. Metadata by default; response_mime returns native MIME observations. Raw parts: 8 KiB default, 256 KiB cap; pass nextOffsetBytes as offset while hasMore. jsonPointer selects a complete RFC 6901 body value; headerName selects complete parsed header values. Use explicit body/header parts. Nothing is sent or changed; no read is required before from-ID actions.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        val output = httpMessageReadService.read(input)
        StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
    }

    mcpStructuredToolWithContext<SendHttpRequestFromId, HttpMessageActionResult>(
        title = "Send stored HTTP request",
        description = "Send one stored HTTP request again (replay), optionally with a bounded patch. Each call restarts from the stored source, so omitted fields inherit it and patches never accumulate; the destination service cannot change. Source access, derived-request/request-action policy and independent outbound-target policy apply. No redirects and no automatic Site Map entry. If executionState is uncertain, it may have been sent; never retry automatically.",
        annotations = HTTP_REQUEST_ACTION_ANNOTATIONS,
    ) { input ->
        val output = httpMessageActionService.send(input)
        StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
    }

    mcpStructuredToolWithContext<RouteHttpMessageFromId, HttpMessageActionResult>(
        title = "Create Repeater tab or route stored HTTP message",
        description = "Create a new Repeater tab (destination=repeater), or route a stored request to Intruder, Organizer, Comparer, or Decoder. Source and routing approvals apply; no network traffic or attack is started. Each call restarts from the stored source; patches never accumulate. Comparer/Decoder receive only request bytes. Unpatched Organizer routing may include the source response. Never retry executionState=uncertain automatically.",
        annotations = REQUEST_ROUTING_TOOL_ANNOTATIONS,
    ) { input ->
        val output = httpMessageActionService.route(input)
        StructuredToolResponse(output, isError = output.status.isMcpError(), text = null)
    }

    mcpStructuredToolWithContext<SearchWebsocketMessages, SearchWebsocketMessagesResult>(
        title = "Search WebSocket messages",
        description = "Search Proxy WebSocket metadata with projectId from burp://project/summary or a producing result. Use get_websocket_message_by_id for payloads. Access policy applies; no traffic or mutation occurs. At most 50 results, 10,000 records scanned and 32 MiB inspected. items=[] with hasMore=true is not end-of-data; pass nextCursor as cursor with only projectId and optional limit.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        val output = webSocketMessageSearchService.search(input) { progress, total, message ->
            reportProgress(progress, total, message)
        }
        StructuredToolResponse(
            output = output,
            text = null,
            isError = output.status.isMcpError(),
        )
    }

    mcpStructuredToolWithContext<SaveWorkflowPreset, SaveWorkflowPresetResult>(
        title = "Save workflow preset",
        description = "Save a project-scoped HTTP search, WebSocket search, or HTTP comparison preset. Creates by default; overwrite=true replaces a case-insensitive same-name preset. Names are trimmed; other caller-authored strings are stored verbatim, not secret-filtered. Do not store secrets. No traffic is sent. Never retry executionState=uncertain automatically.",
        annotations = WORKFLOW_PRESET_SAVE_ANNOTATIONS,
    ) { input ->
        val output = workflowPresetService.save(input)
        StructuredToolResponse(output, isError = output.status != WorkflowPresetStatus.OK, text = null)
    }

    mcpStructuredToolWithContext<ListWorkflowPresets, ListWorkflowPresetsResult>(
        title = "List workflow presets",
        description = "List stored workflow preset definitions for the current project, optionally filtered and paginated. This is read-only, sends no traffic, and the project can contain at most 64 presets.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        val output = workflowPresetService.list(input)
        StructuredToolResponse(output, isError = output.status != WorkflowPresetStatus.OK, text = null)
    }

    mcpStructuredToolWithContext<DeleteWorkflowPreset, DeleteWorkflowPresetResult>(
        title = "Delete workflow preset",
        description = "Delete one project-scoped workflow preset without affecting traffic or other Burp state. A missing preset succeeds with deleted=false. If executionState is uncertain, do not retry automatically.",
        annotations = WORKFLOW_PRESET_DELETE_ANNOTATIONS,
    ) { input ->
        val output = workflowPresetService.delete(input)
        StructuredToolResponse(output, isError = output.status != WorkflowPresetStatus.OK, text = null)
    }

    mcpStructuredToolWithContext<ExecuteWorkflowPreset, ExecuteWorkflowPresetResult>(
        title = "Run read-only workflow preset",
        description = "Run a stored read-only HTTP search, WebSocket search, or HTTP comparison preset. Search cursor is runtime-only; runtime limit overrides saved defaultLimit, otherwise saved/service defaults apply. Comparison refs are runtime-only and required. Check outer and selected nested status. Delegated approvals, bounds and continuation rules apply; no traffic is sent.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        val output = workflowPresetService.execute(input) { progress, total, message ->
            reportProgress(progress, total, message)
        }
        StructuredToolResponse(output, isError = !output.delegatedSuccess(), text = null)
    }

    mcpStructuredToolWithContext<GetWebsocketMessageById, WebSocketMessageReadResult>(
        title = "Read WebSocket message",
        description = "Read one original or edited Proxy WebSocket payload by id from search_websocket_messages, with matching projectId. WebSocket-history access approval applies; content is bounded and byte-paginated using offset/limit. IDs are not portable across projects. burp_error is a read failure and no mutation occurred.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        val output = webSocketMessageReadService.read(input)
        StructuredToolResponse(
            output = output,
            text = null,
            isError = output.status.isMcpError(),
        )
    }

    mcpStructuredToolWithContext<SetBurpControlState, SetBurpControlStateResult>(
        title = "Set Burp control state",
        description = "Set one Burp-wide control: task execution engine or Proxy Intercept. Approval applies unless YOLO allows it. This is intentionally not project-scoped: no projectId and not reverted by a project switch. If executionState is uncertain, the change may have occurred; do not retry automatically.",
        annotations = PROJECT_MUTATION_TOOL_ANNOTATIONS,
    ) { input ->
        val deniedMessage = when (input.control) {
            BurpControl.TASK_EXECUTION_ENGINE -> "Task execution engine change denied by Burp Suite"
            BurpControl.PROXY_INTERCEPT -> "Proxy Intercept change denied by Burp Suite"
        }
        val approved = try {
            when (input.control) {
                BurpControl.TASK_EXECUTION_ENGINE -> SensitiveActionSecurity.checkPermission(
                    "change task execution engine state",
                    "Set Burp task execution engine to ${if (input.enabled) "running" else "paused"}",
                    api = api,
                    config = config,
                    auditOperation = SensitiveActionAuditOperation.TASK_EXECUTION_ENGINE,
                )
                BurpControl.PROXY_INTERCEPT -> SensitiveActionSecurity.checkPermission(
                    "change Proxy Intercept state",
                    "Set Burp Proxy Intercept to ${if (input.enabled) "enabled" else "disabled"}",
                    api = api,
                    config = config,
                    auditOperation = SensitiveActionAuditOperation.PROXY_INTERCEPT,
                )
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not request control-change approval", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetBurpControlStateResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    StandardExecutionState.NOT_STARTED,
                    input.control,
                    input.enabled,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (!approved) {
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetBurpControlStateResult(
                    StandardToolStatus.ACCESS_DENIED,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    StandardExecutionState.NOT_STARTED,
                    input.control,
                    input.enabled,
                    deniedMessage,
                ),
                text = deniedMessage,
            )
        }
        val successMessage = when (input.control) {
            BurpControl.TASK_EXECUTION_ENGINE ->
                "Task execution engine is now ${if (input.enabled) "running" else "paused"}"
            BurpControl.PROXY_INTERCEPT ->
                "Intercept has been ${if (input.enabled) "enabled" else "disabled"}"
        }
        val callContext = currentCoroutineContext()
        callContext.ensureActive()
        try {
            when (input.control) {
                BurpControl.TASK_EXECUTION_ENGINE -> {
                    api.burpSuite().taskExecutionEngine().state = if (input.enabled) RUNNING else PAUSED
                }
                BurpControl.PROXY_INTERCEPT -> {
                    if (input.enabled) api.proxy().enableIntercept() else api.proxy().disableIntercept()
                }
            }
        } catch (e: CancellationException) {
            if (!callContext.isActive) throw e
            val error = uncertainExecutionError(
                "Burp control state may have changed",
                e,
                preserveCancellation = false,
                maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
            )
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetBurpControlStateResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.DO_NOT_RETRY,
                    StandardExecutionState.UNCERTAIN,
                    input.control,
                    input.enabled,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        } catch (e: Exception) {
            val error = uncertainExecutionError(
                "Burp control state may have changed",
                e,
                maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
            )
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetBurpControlStateResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.DO_NOT_RETRY,
                    StandardExecutionState.UNCERTAIN,
                    input.control,
                    input.enabled,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        StructuredToolResponse(
            SetBurpControlStateResult(
                StandardToolStatus.OK,
                ToolRetryGuidance.NOT_APPLICABLE,
                StandardExecutionState.COMPLETED,
                input.control,
                input.enabled,
            ),
            text = successMessage,
        )
    }

}

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
    val warning = if (projectId == null) {
        "automatic Site Map recording was skipped because no project boundary was available"
    } else {
        "automatic Site Map recording is disabled because Burp does not provide an atomic project-bound add"
    }
    runCatching { api.logging().logToOutput("MCP request completed; $warning") }
    return SiteMapRecordResult(recorded = false, warning = warning)
}

@Serializable
enum class BurpControl {
    @SerialName("task_execution_engine")
    TASK_EXECUTION_ENGINE,

    @SerialName("proxy_intercept")
    PROXY_INTERCEPT,
}

@Serializable
data class SetBurpControlState(
    @JsonSchemaMetadata(description = "Global Burp control to change.")
    val control: BurpControl,
    @JsonSchemaMetadata(description = "True starts/enables the selected control; false pauses/disables it.")
    val enabled: Boolean,
)

@Serializable
data class GetWebsocketMessageById(
    @JsonSchemaMetadata(description = "Numeric message id from search_websocket_messages, not a webSocketId connection id.", minimum = 0) val id: Int,
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256) val projectId: String,
    @JsonSchemaMetadata(description = "Read the edited payload variant.", defaultJson = "false") val edited: Boolean? = null,
    @JsonSchemaMetadata(description = "Zero-based byte offset within the selected content.", minimum = 0, defaultJson = "0") val offset: Int? = null,
    @JsonSchemaMetadata(description = "Maximum content bytes to return.", minimum = 1, maximum = 262144, defaultJson = "8192") val limit: Int? = null,
    @JsonSchemaMetadata(description = "Encoding used for returned content.", enumValues = ["text", "base64"], defaultJson = "\"text\"") val encoding: String? = null,
)

@Serializable
data class GetScannerIssueById(
    @JsonSchemaMetadata(
        description = "Versioned issue id from get_scanner_issues or get_scanner_audit; copy verbatim.",
        pattern = "^issue_v2_(x|[0-9a-z]{1,6})_[0-9a-f]{32}$",
        maxLength = 128,
    )
    val id: String,
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256) val projectId: String,
    @JsonSchemaMetadata(description = "Scanner issue section to return.", enumValues = ["metadata", "detail", "remediation", "evidence_request", "evidence_response"], defaultJson = "\"metadata\"") val field: String? = null,
    @JsonSchemaMetadata(description = "Required when `field` is `evidence_request` or `evidence_response`.", minimum = 0) val evidenceIndex: Int? = null,
    @JsonSchemaMetadata(description = "Zero-based byte offset within the selected content.", minimum = 0, defaultJson = "0") val offset: Int? = null,
    @JsonSchemaMetadata(description = "Maximum content bytes to return.", minimum = 1, maximum = 262144, defaultJson = "8192") val limit: Int? = null,
    @JsonSchemaMetadata(description = "Encoding used for returned content.", enumValues = ["text", "base64"], defaultJson = "\"text\"") val encoding: String? = null,
)

@Serializable
data class GenerateCollaboratorPayload(
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Optional ASCII alphanumeric custom data embedded in the generated Collaborator payload.", minLength = 1, maxLength = 16, pattern = "^[A-Za-z0-9]{1,16}$")
    val customData: String? = null,
)
