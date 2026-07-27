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
import kotlinx.serialization.json.Json
import net.portswigger.mcp.ProductIdentity
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
import net.portswigger.mcp.security.filterConfigCredentials
import java.awt.KeyboardFocusManager
import java.util.regex.Pattern
import javax.swing.JTextArea

internal suspend fun checkDataAccessOrDeny(
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

private const val MAX_RAW_REQUEST_CHARS = 2 * 1024 * 1024
private const val MAX_RAW_HTTP2_BODY_CHARS = 1024 * 1024
private const val MAX_RAW_HTTP_HEADERS = 128
private const val MAX_RAW_HEADER_NAME_CHARS = 256
private const val MAX_RAW_HEADER_VALUE_CHARS = 16 * 1024
private const val MAX_UTILITY_INPUT_CHARS = 256 * 1024
private const val MAX_RANDOM_STRING_CHARS = 64 * 1024
private const val MAX_RANDOM_CHARACTER_SET_CHARS = 256
private const val MAX_CONFIGURATION_JSON_CHARS = 1024 * 1024
private const val MAX_EDITOR_CONTENT_CHARS = 1024 * 1024
private const val MAX_EDITOR_PREVIEW_CHARS = 32 * 1024
private const val MAX_SAFE_REGEX_CHARS = 512

private fun MontoyaApi.isCurrentProject(expectedProjectId: String?): Boolean =
    expectedProjectId == null || project().id() == expectedProjectId

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
    )
    val httpAttackSurfaceService = HttpAttackSurfaceService(api, config, services.httpMetadataIndex)
    val httpMessageActionService = HttpMessageActionService(api, config)
    val rawHttpActionService = RawHttpActionService(api, config)
    val httpMessageReadService = HttpMessageReadService(api, config)
    val webSocketMessageSearchService = WebSocketMessageSearchService(api, config)
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

    mcpStructuredTool<SendRawHttpRequest, RawHttpActionResult>(
        description = "Send exactly one caller-supplied HTTP/1.1 or HTTP/2 request. Request-action approval applies; redirects are disabled, the response preview is bounded, and the exchange is not added to Site Map. If executionState is uncertain, the request may have been sent; do not retry automatically.",
        annotations = HTTP_REQUEST_ACTION_ANNOTATIONS,
    ) {
        rawHttpActionService.send(this)
    }

    mcpStructuredTool<RouteRawHttpRequest, RawHttpActionResult>(
        description = "Open exactly one caller-supplied HTTP/1.1 or HTTP/2 request in Repeater, Intruder, or Organizer without sending it. Routing approval applies, and no Proxy or Site Map history is added. HTTP/2 Intruder routing is unsupported. If executionState is uncertain, the destination item may already exist; do not retry automatically.",
        annotations = REQUEST_ROUTING_TOOL_ANNOTATIONS,
    ) {
        rawHttpActionService.route(this)
    }

    mcpStructuredToolWithContext<TransformData, TransformDataResult>(
        description = "URL-encode, URL-decode, Base64-encode, or Base64-decode bounded local content. This sends no traffic and changes no Burp state.",
        annotations = LOCAL_TRANSFORM_TOOL_ANNOTATIONS,
    ) { input ->
        if (input.content.length > MAX_UTILITY_INPUT_CHARS) {
            val error = "content is too large"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                TransformDataResult(
                    StandardToolStatus.INVALID_ARGUMENT,
                    ToolRetryGuidance.AFTER_CORRECTION,
                    input.operation,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        val transformed = try {
            when (input.operation) {
                DataTransformOperation.URL_ENCODE -> api.utilities().urlUtils().encode(input.content)
                DataTransformOperation.URL_DECODE -> api.utilities().urlUtils().decode(input.content)
                DataTransformOperation.BASE64_ENCODE -> api.utilities().base64Utils().encodeToString(input.content)
                DataTransformOperation.BASE64_DECODE -> api.utilities().base64Utils().decode(input.content).toString()
            }
        } catch (e: CancellationException) {
            throw e
        } catch (_: IllegalArgumentException) {
            val error = "content is invalid for the selected operation"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                TransformDataResult(
                    StandardToolStatus.INVALID_ARGUMENT,
                    ToolRetryGuidance.AFTER_CORRECTION,
                    input.operation,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        } catch (e: Exception) {
            val error = standardToolException("Burp could not transform the content", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                TransformDataResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    input.operation,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        val operationLimit = when (input.operation) {
            DataTransformOperation.URL_DECODE, DataTransformOperation.BASE64_DECODE -> MAX_UTILITY_INPUT_CHARS
            else -> MAX_UTILITY_OUTPUT_CHARS
        }
        if (transformed.length > operationLimit) {
            val error = "transformed content exceeds the output limit"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                TransformDataResult(
                    StandardToolStatus.LIMIT_EXCEEDED,
                    ToolRetryGuidance.AFTER_CORRECTION,
                    input.operation,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        StructuredToolResponse(
            TransformDataResult(
                StandardToolStatus.OK,
                ToolRetryGuidance.NOT_APPLICABLE,
                input.operation,
                content = transformed,
                contentChars = transformed.length,
            ),
            text = transformed,
        )
    }

    mcpStructuredToolWithContext<GenerateRandomString, GenerateRandomStringResult>(
        description = "Generate a bounded random string from the supplied character set. This sends no traffic and changes no Burp state.",
        annotations = LOCAL_TRANSFORM_TOOL_ANNOTATIONS,
    ) { input ->
        if (input.length !in 0..MAX_RANDOM_STRING_CHARS) {
            val error = "length must be between 0 and $MAX_RANDOM_STRING_CHARS"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GenerateRandomStringResult(
                    StandardToolStatus.INVALID_ARGUMENT,
                    ToolRetryGuidance.AFTER_CORRECTION,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (input.characterSet.length !in 1..MAX_RANDOM_CHARACTER_SET_CHARS ||
            input.characterSet.any(Char::isISOControl)
        ) {
            val error = "characterSet is invalid"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GenerateRandomStringResult(
                    StandardToolStatus.INVALID_ARGUMENT,
                    ToolRetryGuidance.AFTER_CORRECTION,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        val generated = try {
            api.utilities().randomUtils().randomString(input.length, input.characterSet)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not generate random data", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GenerateRandomStringResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (generated.length > MAX_RANDOM_STRING_CHARS) {
            val error = "generated content exceeds the output limit"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GenerateRandomStringResult(
                    StandardToolStatus.LIMIT_EXCEEDED,
                    ToolRetryGuidance.AFTER_CORRECTION,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        StructuredToolResponse(
            GenerateRandomStringResult(
                StandardToolStatus.OK,
                ToolRetryGuidance.NOT_APPLICABLE,
                content = generated,
                contentChars = generated.length,
            ),
            text = generated,
        )
    }

    mcpStructuredToolWithContext<GetBurpOptions, GetBurpOptionsResult>(
        description = "Return bounded project- or user-level Burp configuration after approval unless the local operator enabled YOLO mode. Credentials are filtered by default; if the operator disables credential filtering, the returned JSON may contain sensitive values. This changes no Burp state.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        val deniedMessage =
            "${if (input.level == BurpOptionsLevel.PROJECT) "Project" else "User"} configuration access denied by Burp Suite"
        val expectedProjectId = if (input.level == BurpOptionsLevel.PROJECT) {
            try {
                api.project().id()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                val error = standardToolException("Burp could not capture the project before configuration approval", e)
                return@mcpStructuredToolWithContext StructuredToolResponse(
                    GetBurpOptionsResult(
                        StandardToolStatus.BURP_ERROR,
                        ToolRetryGuidance.SAFE_TO_RETRY,
                        input.level,
                        error = error,
                    ),
                    text = "Error: $error",
                    isError = true,
                )
            }
        } else {
            null
        }
        val approved = try {
            when (input.level) {
                BurpOptionsLevel.PROJECT -> SensitiveActionSecurity.checkPermission(
                    "read project configuration",
                    "Export project-level Burp configuration to the MCP client",
                    api = api,
                    config = config,
                    auditOperation = SensitiveActionAuditOperation.PROJECT_OPTIONS_READ,
                )
                BurpOptionsLevel.USER -> SensitiveActionSecurity.checkPermission(
                    "read user configuration",
                    "Export user-level Burp configuration to the MCP client",
                    api = api,
                    config = config,
                    auditOperation = SensitiveActionAuditOperation.USER_OPTIONS_READ,
                )
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not request configuration approval", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetBurpOptionsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    input.level,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        val projectStableAfterApproval = try {
            api.isCurrentProject(expectedProjectId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not recheck the project after configuration approval", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetBurpOptionsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    input.level,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (!projectStableAfterApproval) {
            val error = "Burp project changed during project configuration approval"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetBurpOptionsResult(
                    StandardToolStatus.PROJECT_MISMATCH,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    input.level,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (!approved) {
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetBurpOptionsResult(
                    StandardToolStatus.ACCESS_DENIED,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    input.level,
                    error = deniedMessage,
                ),
                text = deniedMessage,
            )
        }
        val exported = try {
            when (input.level) {
                BurpOptionsLevel.PROJECT -> api.burpSuite().exportProjectOptionsAsJson()
                BurpOptionsLevel.USER -> api.burpSuite().exportUserOptionsAsJson()
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not export configuration", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetBurpOptionsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    input.level,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        val projectStableAfterExport = try {
            api.isCurrentProject(expectedProjectId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not recheck the project after configuration export", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetBurpOptionsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    input.level,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (!projectStableAfterExport) {
            val error = "Burp project changed while project configuration was exported"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetBurpOptionsResult(
                    StandardToolStatus.PROJECT_MISMATCH,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    input.level,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (exported.length > MAX_CONFIGURATION_JSON_CHARS) {
            val error = "configuration exceeds the output limit"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetBurpOptionsResult(
                    StandardToolStatus.LIMIT_EXCEEDED,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    input.level,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        val credentialsFiltered = config.filterConfigCredentials
        val configuration = try {
            if (credentialsFiltered) filterConfigCredentials(exported) else exported
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not filter exported configuration", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetBurpOptionsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    input.level,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        val projectStableAfterFiltering = try {
            api.isCurrentProject(expectedProjectId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not recheck the project after configuration filtering", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetBurpOptionsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    input.level,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (!projectStableAfterFiltering) {
            val error = "Burp project changed while project configuration was prepared"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetBurpOptionsResult(
                    StandardToolStatus.PROJECT_MISMATCH,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    input.level,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (configuration.length > MAX_CONFIGURATION_JSON_CHARS) {
            val error = "filtered configuration exceeds the output limit"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetBurpOptionsResult(
                    StandardToolStatus.LIMIT_EXCEEDED,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    input.level,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        StructuredToolResponse(
            GetBurpOptionsResult(
                StandardToolStatus.OK,
                ToolRetryGuidance.NOT_APPLICABLE,
                input.level,
                configuration = configuration,
                configurationChars = configuration.length,
                credentialsFiltered = credentialsFiltered,
            ),
            text = configuration,
        )
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in Burp's ${ProductIdentity.SUITE_TAB_NAME} tab by selecting 'Enable tools that can edit your config'"

    mcpStructuredToolWithContext<SetBurpOptions, SetBurpOptionsResult>(
        description = "Import bounded project- or user-level Burp configuration when configuration-editing tools are enabled. Approval is required unless the local operator enabled YOLO mode. If executionState is uncertain, configuration may be partially applied; reconcile manually and do not retry automatically.",
        annotations = PROJECT_MUTATION_TOOL_ANNOTATIONS,
    ) { input ->
        if (input.json.length > MAX_CONFIGURATION_JSON_CHARS) {
            val error = "json is too large"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetBurpOptionsResult(
                    StandardToolStatus.INVALID_ARGUMENT,
                    ToolRetryGuidance.AFTER_CORRECTION,
                    StandardExecutionState.NOT_STARTED,
                    input.level,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (!config.configEditingTooling) {
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetBurpOptionsResult(
                    StandardToolStatus.DISABLED,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    StandardExecutionState.NOT_STARTED,
                    input.level,
                    toolingDisabledMessage,
                ),
                text = toolingDisabledMessage,
            )
        }
        val deniedMessage =
            "${if (input.level == BurpOptionsLevel.PROJECT) "Project" else "User"} configuration change denied by Burp Suite"
        val expectedProjectId = if (input.level == BurpOptionsLevel.PROJECT) {
            try {
                api.project().id()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                val error = standardToolException("Burp could not capture the project before configuration-change approval", e)
                return@mcpStructuredToolWithContext StructuredToolResponse(
                    SetBurpOptionsResult(
                        StandardToolStatus.BURP_ERROR,
                        ToolRetryGuidance.SAFE_TO_RETRY,
                        StandardExecutionState.NOT_STARTED,
                        input.level,
                        error,
                    ),
                    text = "Error: $error",
                    isError = true,
                )
            }
        } else {
            null
        }
        val approved = try {
            when (input.level) {
                BurpOptionsLevel.PROJECT -> SensitiveActionSecurity.checkPermission(
                    "change project configuration",
                    "Merge supplied JSON into Burp project configuration",
                    input.json,
                    api = api,
                    config = config,
                    auditOperation = SensitiveActionAuditOperation.PROJECT_OPTIONS_WRITE,
                )
                BurpOptionsLevel.USER -> SensitiveActionSecurity.checkPermission(
                    "change user configuration",
                    "Merge supplied JSON into Burp user configuration",
                    input.json,
                    api = api,
                    config = config,
                    auditOperation = SensitiveActionAuditOperation.USER_OPTIONS_WRITE,
                )
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not request configuration-change approval", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetBurpOptionsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    StandardExecutionState.NOT_STARTED,
                    input.level,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        val projectStableAfterApproval = try {
            api.isCurrentProject(expectedProjectId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not recheck the project after configuration-change approval", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetBurpOptionsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    StandardExecutionState.NOT_STARTED,
                    input.level,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (!projectStableAfterApproval) {
            val error = "Burp project changed during project configuration approval"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetBurpOptionsResult(
                    StandardToolStatus.PROJECT_MISMATCH,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    StandardExecutionState.NOT_STARTED,
                    input.level,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (!approved) {
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetBurpOptionsResult(
                    StandardToolStatus.ACCESS_DENIED,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    StandardExecutionState.NOT_STARTED,
                    input.level,
                    deniedMessage,
                ),
                text = deniedMessage,
            )
        }
        val successMessage =
            "${if (input.level == BurpOptionsLevel.PROJECT) "Project" else "User"} configuration has been applied"
        val callContext = currentCoroutineContext()
        callContext.ensureActive()
        try {
            when (input.level) {
                BurpOptionsLevel.PROJECT -> {
                    api.logging().logToOutput("Applying project-level configuration through MCP")
                    services.httpMetadataIndex.withMutation {
                        api.burpSuite().importProjectOptionsFromJson(input.json)
                    }
                }
                BurpOptionsLevel.USER -> {
                    api.logging().logToOutput("Applying user-level configuration through MCP")
                    api.burpSuite().importUserOptionsFromJson(input.json)
                }
            }
        } catch (e: CancellationException) {
            if (!callContext.isActive) throw e
            val error = uncertainExecutionError(
                "Configuration may have been partially applied",
                e,
                preserveCancellation = false,
                maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
            )
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetBurpOptionsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.DO_NOT_RETRY,
                    StandardExecutionState.UNCERTAIN,
                    input.level,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        } catch (e: Exception) {
            val error = uncertainExecutionError(
                "Configuration may have been partially applied",
                e,
                maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
            )
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetBurpOptionsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.DO_NOT_RETRY,
                    StandardExecutionState.UNCERTAIN,
                    input.level,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        val projectStableAfterImport = try {
            api.isCurrentProject(expectedProjectId)
        } catch (e: CancellationException) {
            if (!callContext.isActive) throw e
            val error = uncertainExecutionError(
                "Configuration may have been applied but the project boundary could not be rechecked",
                e,
                preserveCancellation = false,
                maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
            )
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetBurpOptionsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.DO_NOT_RETRY,
                    StandardExecutionState.UNCERTAIN,
                    input.level,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        } catch (e: Exception) {
            val error = uncertainExecutionError(
                "Configuration may have been applied but the project boundary could not be rechecked",
                e,
                preserveCancellation = false,
                maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
            )
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetBurpOptionsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.DO_NOT_RETRY,
                    StandardExecutionState.UNCERTAIN,
                    input.level,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (!projectStableAfterImport) {
            val error = "Configuration may have been applied while the Burp project changed; reconcile manually and do not retry automatically"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetBurpOptionsResult(
                    StandardToolStatus.PROJECT_MISMATCH,
                    ToolRetryGuidance.DO_NOT_RETRY,
                    StandardExecutionState.UNCERTAIN,
                    input.level,
                    boundedStandardToolError(error),
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        StructuredToolResponse(
            SetBurpOptionsResult(
                StandardToolStatus.OK,
                ToolRetryGuidance.NOT_APPLICABLE,
                StandardExecutionState.COMPLETED,
                input.level,
            ),
            text = successMessage,
        )
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        val scannerIssueSearchService = ScannerIssueSearchService(api, config)
        val scannerIssueReadService = ScannerIssueReadService(api, config)
        val collaboratorToolService = services.collaborator
        mcpStructuredToolWithContext<GetScannerIssues, ScannerIssuePageResult>(
            description = "List or filter Scanner issues in the current project, subject to Scanner-issue access policy. Legacy offset mode returns newline-separated JSON records with a blank line between records: bounded details by default, or summaries when summariesOnly=true. Signed-cursor mode returns compact structured summaries; pass nextCursor as cursor to continue. Use get_scanner_issue_by_id for bounded detail or evidence from a known issue ID.",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) { input ->
            scannerIssueSearchService.get(input)
        }

        mcpStructuredTool<GetScannerIssueById, ScannerIssueReadResult>(
            description = "Read one Scanner issue by stable ID from the specified project after Scanner-issue access approval. Selected detail or evidence content is bounded and byte-paginated. For evidence_request or evidence_response, evidenceIndex is required.",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) {
            scannerIssueReadService.read(this)
        }

        mcpStructuredTool<StartScannerAuditFromIds, ScannerAuditResult>(
            description = "Start one passive or focused active Scanner audit from stored HTTP references after approval unless the local operator enabled YOLO mode. Both modes reject out-of-scope requests. Passive mode requires responses and sends no target traffic; active mode requires insertionPoints and can send requests. Passive mode accepts up to 16 targets and active mode up to 4. If actionState is uncertain, do not start another audit automatically.",
            annotations = SCANNER_START_TOOL_ANNOTATIONS,
        ) {
            services.scannerAudits.start(this, config)
        }

        mcpStructuredTool<GetScannerAudit, ScannerAuditResult>(
            description = "Read status and bounded issue summaries for a Scanner audit started by this MCP server. Reading status refreshes the 6-hour inactivity lease but not the 24-hour maximum lifetime; requesting issues is subject to Scanner-issue access approval. Treat statusMessage as authoritative when it differs from taskState.",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) {
            services.scannerAudits.get(this, config)
        }

        mcpStructuredTool<CancelScannerAudit, ScannerAuditResult>(
            description = "Cancel a retained Scanner audit started by this MCP server after approval unless the local operator enabled YOLO mode. If actionState is uncertain, the task may already be deleted; do not retry automatically.",
            annotations = SCANNER_CANCEL_TOOL_ANNOTATIONS,
        ) {
            services.scannerAudits.cancel(this, config)
        }

        mcpStructuredToolWithContext<GenerateCollaboratorPayload, GenerateCollaboratorPayloadResult>(
            description = "Generate a project-bound Collaborator payload for out-of-band testing. This allocates and returns a payload but does not inject or send it. If executionState is uncertain, a payload may already have been allocated; do not retry automatically.",
            annotations = COLLABORATOR_GENERATE_TOOL_ANNOTATIONS,
        ) { input ->
            collaboratorToolService.generate(input)
        }

        mcpStructuredToolWithContext<GetCollaboratorInteractions, GetCollaboratorInteractionsResult>(
            description = "Poll for bounded DNS, HTTP, or SMTP interactions received by the current project's Collaborator client, subject to Collaborator-interaction access policy. Long polling is limited to 120 seconds; use the payload ID returned by generate_collaborator_payload to filter one payload.",
            annotations = COLLABORATOR_READ_TOOL_ANNOTATIONS,
        ) { input ->
            collaboratorToolService.interactions(input, config) { progress, total, message ->
                reportProgress(progress, total, message)
            }
        }
    }

    mcpStructuredToolWithContext<SearchHttpMessages, SearchHttpMessagesResult>(
        description = "Search stored HTTP messages in Proxy history, Site Map, or Organizer; Proxy is the default. Supports metadata filters and bounded literal or regular-expression search over requests and responses. Source-access policy applies, and no traffic or mutation occurs. Results are limited to 50 and content inspection to 32 MiB. Pass nextCursor as cursor; omit filters and optionally change only limit, or repeat the same filters. Requests sent by MCP are absent unless Burp recorded them.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        StructuredToolResponse(
            httpMessageSearchService.search(input) { progress, total, message ->
                reportProgress(progress, total, message)
            }
        )
    }

    mcpStructuredToolWithContext<SummarizeHttpAttackSurface, HttpAttackSurfaceResult>(
        description = "Summarize services, methods, statuses, MIME types, extensions, and normalized paths from stored HTTP metadata; the default is in-scope Proxy records. Source-access policy applies, and no traffic or mutation occurs. Query strings, bodies, header values, and notes are not retained. If burp_error reports changing HTTP metadata, retry the read.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        StructuredToolResponse(
            httpAttackSurfaceService.summarize(input) { progress, total, message ->
                reportProgress(progress, total, message)
            }
        )
    }

    mcpStructuredTool<CheckScope, CheckScopeResult>(
        description = "Check whether up to 32 URLs or stored HTTP references are currently in Target scope. This never changes scope; stored references remain subject to their source-access approval.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) {
        scopeToolService.check(this)
    }

    mcpStructuredTool<UpdateScope, UpdateScopeResult>(
        description = "Include or exclude up to 16 URLs or stored HTTP references in Target scope. All targets are validated before any approval prompt or policy bypass and before mutation. The scope change requires approval unless an existing policy allows it. If executionState is uncertain, some changes may already exist; do not retry automatically.",
        annotations = SCOPE_MUTATION_TOOL_ANNOTATIONS,
    ) {
        scopeToolService.update(this)
    }

    mcpStructuredTool<CompareHttpMessages, CompareHttpMessagesResult>(
        description = "Compare selected parts of 2–8 stored HTTP messages without returning complete messages. Source-access approval applies, and no traffic or mutation occurs. If allEqual is null, inspected prefixes matched but at least one part was truncated.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) {
        httpMessageComparisonService.compare(this)
    }

    mcpStructuredToolWithContext<AnalyzeHttpSessionSecurity, AnalyzeHttpSessionSecurityResult>(
        description = "Passively analyze authentication and session signals across 1–32 HTTP references. Source-access policy applies; no traffic or mutation occurs. Returns value-free authentication, cookie, redirect, endpoint-role, and cross-message observations; raw bodies and sensitive values are never returned. Site Map identity checks may privately inspect bounded body and header samples. Input order is a proposed flow; results do not establish chronology, browser behavior, severity, or a vulnerability.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        val output = services.httpSessionSecurityAnalyzer.analyze(input, config) { progress, total, message ->
            reportProgress(progress, total, message)
        }
        StructuredToolResponse(
            output = output,
            text = null,
            isError = output.status != HttpSessionAnalysisStatus.OK,
        )
    }

    mcpStructuredTool<GetHttpMessage, GetHttpMessageResult>(
        description = "Read metadata or a selected request or response part from a stored Proxy, Site Map, or Organizer message. Source-access approval and matching project ID apply; content is bounded and byte-paginated.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) {
        httpMessageReadService.read(this)
    }

    mcpStructuredTool<SendHttpRequestFromId, HttpMessageActionResult>(
        description = "Send one stored HTTP request, optionally with bounded structured changes. Source-access and request-action approvals apply; redirects are rejected and direct MCP sends are not added to Site Map. If executionState is uncertain, the request may have been sent; do not retry automatically.",
        annotations = HTTP_REQUEST_ACTION_ANNOTATIONS,
    ) {
        httpMessageActionService.send(this)
    }

    mcpStructuredTool<RouteHttpMessageFromId, HttpMessageActionResult>(
        description = "Open one stored HTTP request in Repeater, Intruder, or Organizer, optionally after bounded structured changes. Source-access and routing approvals apply; no Intruder attack is started. Routing only opens the destination tab or Organizer item; it sends no network traffic. If executionState is uncertain, do not retry automatically.",
        annotations = REQUEST_ROUTING_TOOL_ANNOTATIONS,
    ) {
        httpMessageActionService.route(this)
    }

    mcpStructuredToolWithContext<SearchWebsocketMessages, SearchWebsocketMessagesResult>(
        description = "Search stored Proxy WebSocket payload metadata in the specified project. WebSocket-history access policy applies, and no traffic or mutation occurs. Results are limited to 50, scanning to 10,000 records and 32 MiB. Pass nextCursor as cursor to continue; only projectId and optional limit may also be supplied.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        StructuredToolResponse(
            webSocketMessageSearchService.search(input) { progress, total, message ->
                reportProgress(progress, total, message)
            }
        )
    }

    mcpStructuredToolWithContext<SaveWorkflowPreset, SaveWorkflowPresetResult>(
        description = "Create one project-scoped HTTP search, WebSocket search, or HTTP comparison preset. With overwrite=true, replace an existing case-insensitive same-name preset. Names are trimmed; other caller-authored strings are stored verbatim and are not secret-filtered, so do not include secrets. This sends no traffic. If executionState is uncertain, do not retry automatically.",
        annotations = WORKFLOW_PRESET_SAVE_ANNOTATIONS,
    ) { input ->
        val output = workflowPresetService.save(input)
        StructuredToolResponse(output, isError = output.status != WorkflowPresetStatus.OK, text = null)
    }

    mcpStructuredToolWithContext<ListWorkflowPresets, ListWorkflowPresetsResult>(
        description = "List stored workflow preset definitions for the current project, optionally filtered and paginated. This is read-only, sends no traffic, and the project can contain at most 64 presets.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        val output = workflowPresetService.list(input)
        StructuredToolResponse(output, isError = output.status != WorkflowPresetStatus.OK, text = null)
    }

    mcpStructuredToolWithContext<DeleteWorkflowPreset, DeleteWorkflowPresetResult>(
        description = "Delete one project-scoped workflow preset without affecting traffic or other Burp state. A missing preset succeeds with deleted=false. If executionState is uncertain, do not retry automatically.",
        annotations = WORKFLOW_PRESET_DELETE_ANNOTATIONS,
    ) { input ->
        val output = workflowPresetService.delete(input)
        StructuredToolResponse(output, isError = output.status != WorkflowPresetStatus.OK, text = null)
    }

    mcpStructuredToolWithContext<ExecuteWorkflowPreset, ExecuteWorkflowPresetResult>(
        description = "Run one stored HTTP search, WebSocket search, or HTTP comparison preset. For search presets, cursor is runtime-only; an optional runtime limit overrides the saved defaultLimit, otherwise the saved or service default is used. Comparison refs are runtime-only and required. Delegated approvals, bounds, cursors, and status remain authoritative; this sends no traffic.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        val output = workflowPresetService.execute(input) { progress, total, message ->
            reportProgress(progress, total, message)
        }
        StructuredToolResponse(output, isError = !output.delegatedSuccess(), text = null)
    }

    mcpStructuredTool<GetWebsocketMessageById, WebSocketMessageReadResult>(
        description = "Read one original or edited Proxy WebSocket payload by stable ID from the specified project. WebSocket-history access approval applies; content is bounded and byte-paginated.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) {
        webSocketMessageReadService.read(this)
    }

    mcpStructuredToolWithContext<SetBurpControlState, SetBurpControlStateResult>(
        description = "Change exactly one Burp global control—the task execution engine or Proxy Intercept state—after approval unless the local operator enabled YOLO mode. If executionState is uncertain, the change may have occurred; do not retry automatically.",
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

    mcpStructuredToolWithContext<GetActiveEditorContents, GetActiveEditorContentsResult>(
        description = "Read a bounded preview from the Burp text area that currently has keyboard focus, not from a fixed tool or selected tab. Approval is required unless the local operator enabled YOLO mode. Returns status=not_available with an explanatory error when no editor is focused.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { _ ->
        val deniedMessage = "Active editor access denied by Burp Suite"
        val expectedProjectId = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not capture the project before active-editor approval", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetActiveEditorContentsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        val approved = try {
            SensitiveActionSecurity.checkPermission(
                "read active editor contents",
                "Return up to $MAX_EDITOR_PREVIEW_CHARS characters from the active message editor",
                api = api,
                config = config,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not request active-editor approval", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetActiveEditorContentsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        val projectStableAfterApproval = try {
            api.isCurrentProject(expectedProjectId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not recheck the project after active-editor approval", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetActiveEditorContentsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (!projectStableAfterApproval) {
            val error = "Burp project changed during active-editor approval"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetActiveEditorContentsResult(
                    StandardToolStatus.PROJECT_MISMATCH,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (!approved) {
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetActiveEditorContentsResult(
                    StandardToolStatus.ACCESS_DENIED,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    error = deniedMessage,
                ),
                text = deniedMessage,
            )
        }
        val value = try {
            getActiveEditor(api)?.text
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not read the active editor", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetActiveEditorContentsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        val projectStableAfterRead = try {
            api.isCurrentProject(expectedProjectId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not recheck the project after active-editor read", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetActiveEditorContentsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (!projectStableAfterRead) {
            val error = "Burp project changed while active-editor content was read"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetActiveEditorContentsResult(
                    StandardToolStatus.PROJECT_MISMATCH,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (value == null) {
            val message = "<No active editor>"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                GetActiveEditorContentsResult(
                    StandardToolStatus.NOT_AVAILABLE,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    error = message,
                ),
                text = message,
            )
        }
        val preview = value.take(MAX_EDITOR_PREVIEW_CHARS)
        val legacyText = Json.encodeToString(
            ActiveEditorPreview(
                text = preview,
                totalChars = value.length,
                truncated = value.length > MAX_EDITOR_PREVIEW_CHARS,
            )
        )
        StructuredToolResponse(
            GetActiveEditorContentsResult(
                StandardToolStatus.OK,
                ToolRetryGuidance.NOT_APPLICABLE,
                content = preview,
                totalChars = value.length,
                truncated = value.length > MAX_EDITOR_PREVIEW_CHARS,
            ),
            text = legacyText,
        )
    }

    mcpStructuredToolWithContext<SetActiveEditorContents, SetActiveEditorContentsResult>(
        description = "Replace all text in the Burp text area that currently has keyboard focus. Approval is required unless the local operator enabled YOLO mode. Returns status=not_available if no editor is focused, or status=not_editable if the focused editor is read-only. If executionState is uncertain, the edit may have occurred; do not retry automatically.",
        annotations = PROJECT_MUTATION_TOOL_ANNOTATIONS,
    ) { input ->
        if (input.text.length > MAX_EDITOR_CONTENT_CHARS) {
            val error = "text is too large"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetActiveEditorContentsResult(
                    StandardToolStatus.INVALID_ARGUMENT,
                    ToolRetryGuidance.AFTER_CORRECTION,
                    StandardExecutionState.NOT_STARTED,
                    error = error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        val expectedProjectId = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not capture the project before resolving the active editor", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetActiveEditorContentsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    StandardExecutionState.NOT_STARTED,
                    input.text.length,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        val editor = try {
            getActiveEditor(api)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not resolve the active editor", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetActiveEditorContentsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    StandardExecutionState.NOT_STARTED,
                    input.text.length,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (editor == null) {
            val message = "<No active editor>"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetActiveEditorContentsResult(
                    StandardToolStatus.NOT_AVAILABLE,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    StandardExecutionState.NOT_STARTED,
                    input.text.length,
                    message,
                ),
                text = message,
            )
        }
        val editable = try {
            editor.isEditable
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not inspect the active editor", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetActiveEditorContentsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    StandardExecutionState.NOT_STARTED,
                    input.text.length,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (!editable) {
            val message = "<Current editor is not editable>"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetActiveEditorContentsResult(
                    StandardToolStatus.NOT_EDITABLE,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    StandardExecutionState.NOT_STARTED,
                    input.text.length,
                    message,
                ),
                text = message,
            )
        }
        val deniedMessage = "Active editor change denied by Burp Suite"
        val approved = try {
            SensitiveActionSecurity.checkPermission(
                "change active editor contents",
                "Replace editable message text with ${input.text.length} characters",
                input.text,
                api = api,
                config = config,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not request active-editor change approval", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetActiveEditorContentsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    StandardExecutionState.NOT_STARTED,
                    input.text.length,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        val projectStableAfterApproval = try {
            api.isCurrentProject(expectedProjectId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = standardToolException("Burp could not recheck the project after active-editor change approval", e)
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetActiveEditorContentsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    StandardExecutionState.NOT_STARTED,
                    input.text.length,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (!projectStableAfterApproval) {
            val error = "Burp project changed during active-editor change approval"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetActiveEditorContentsResult(
                    StandardToolStatus.PROJECT_MISMATCH,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    StandardExecutionState.NOT_STARTED,
                    input.text.length,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (!approved) {
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetActiveEditorContentsResult(
                    StandardToolStatus.ACCESS_DENIED,
                    ToolRetryGuidance.AFTER_USER_ACTION,
                    StandardExecutionState.NOT_STARTED,
                    input.text.length,
                    deniedMessage,
                ),
                text = deniedMessage,
            )
        }
        val callContext = currentCoroutineContext()
        callContext.ensureActive()
        try {
            editor.text = input.text
        } catch (e: CancellationException) {
            if (!callContext.isActive) throw e
            val error = uncertainExecutionError(
                "Active editor text may have changed",
                e,
                preserveCancellation = false,
                maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
            )
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetActiveEditorContentsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.DO_NOT_RETRY,
                    StandardExecutionState.UNCERTAIN,
                    input.text.length,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        } catch (e: Exception) {
            val error = uncertainExecutionError(
                "Active editor text may have changed",
                e,
                maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
            )
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetActiveEditorContentsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.DO_NOT_RETRY,
                    StandardExecutionState.UNCERTAIN,
                    input.text.length,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        val projectStableAfterWrite = try {
            api.isCurrentProject(expectedProjectId)
        } catch (e: CancellationException) {
            if (!callContext.isActive) throw e
            val error = uncertainExecutionError(
                "Active editor text may have changed but the project boundary could not be rechecked",
                e,
                preserveCancellation = false,
                maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
            )
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetActiveEditorContentsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.DO_NOT_RETRY,
                    StandardExecutionState.UNCERTAIN,
                    input.text.length,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        } catch (e: Exception) {
            val error = uncertainExecutionError(
                "Active editor text may have changed but the project boundary could not be rechecked",
                e,
                preserveCancellation = false,
                maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
            )
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetActiveEditorContentsResult(
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.DO_NOT_RETRY,
                    StandardExecutionState.UNCERTAIN,
                    input.text.length,
                    error,
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        if (!projectStableAfterWrite) {
            val error = "Active editor text may have changed while the Burp project changed; reconcile manually and do not retry automatically"
            return@mcpStructuredToolWithContext StructuredToolResponse(
                SetActiveEditorContentsResult(
                    StandardToolStatus.PROJECT_MISMATCH,
                    ToolRetryGuidance.DO_NOT_RETRY,
                    StandardExecutionState.UNCERTAIN,
                    input.text.length,
                    boundedStandardToolError(error),
                ),
                text = "Error: $error",
                isError = true,
            )
        }
        StructuredToolResponse(
            SetActiveEditorContentsResult(
                StandardToolStatus.OK,
                ToolRetryGuidance.NOT_APPLICABLE,
                StandardExecutionState.COMPLETED,
                input.text.length,
            ),
            text = "Editor text has been set",
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

@Serializable
enum class DataTransformOperation {
    @SerialName("url_encode")
    URL_ENCODE,

    @SerialName("url_decode")
    URL_DECODE,

    @SerialName("base64_encode")
    BASE64_ENCODE,

    @SerialName("base64_decode")
    BASE64_DECODE,
}

@Serializable
data class TransformData(
    @JsonSchemaMetadata(description = "Transformation to apply.")
    val operation: DataTransformOperation,
    @JsonSchemaMetadata(description = "Input text to transform.", maxLength = 262144)
    val content: String,
)

@Serializable
data class GenerateRandomString(
    @JsonSchemaMetadata(description = "Exact number of output characters.", minimum = 0, maximum = 65536)
    val length: Int,
    @JsonSchemaMetadata(description = "Characters available for each generated position.", minLength = 1, maxLength = 256)
    val characterSet: String,
)

@Serializable
enum class BurpOptionsLevel {
    @SerialName("project")
    PROJECT,

    @SerialName("user")
    USER,
}

@Serializable
data class GetBurpOptions(
    @JsonSchemaMetadata(description = "Configuration level to read: project or user.")
    val level: BurpOptionsLevel,
)

@Serializable
data class SetBurpOptions(
    @JsonSchemaMetadata(description = "Configuration level to change: project or user.")
    val level: BurpOptionsLevel,
    @JsonSchemaMetadata(
        description = "Complete configuration JSON to import; project input requires project_options, user input requires user_options.",
        maxLength = 1048576,
    )
    val json: String,
)

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
class GetActiveEditorContents

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
data class GetWebsocketMessageById(
    @JsonSchemaMetadata(description = "Stable WebSocket history ID.", minimum = 0) val id: Int,
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256) val projectId: String,
    @JsonSchemaMetadata(description = "Read the edited payload variant.", defaultJson = "false") val edited: Boolean? = null,
    @JsonSchemaMetadata(description = "Zero-based byte offset within the selected content.", minimum = 0, defaultJson = "0") val offset: Int? = null,
    @JsonSchemaMetadata(description = "Maximum content bytes to return.", minimum = 1, maximum = 262144, defaultJson = "32768") val limit: Int? = null,
    @JsonSchemaMetadata(description = "Encoding used for returned content.", enumValues = ["text", "base64"], defaultJson = "\"text\"") val encoding: String? = null,
)

@Serializable
data class GetScannerIssueById(
    @JsonSchemaMetadata(
        description = "Versioned Scanner issue ID returned by search or audit status.",
        pattern = "^issue_v2_(x|[0-9a-z]{1,6})_[0-9a-f]{32}$",
        maxLength = 128,
    )
    val id: String,
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256) val projectId: String,
    @JsonSchemaMetadata(description = "Scanner issue section to return.", enumValues = ["metadata", "detail", "remediation", "evidence_request", "evidence_response"], defaultJson = "\"metadata\"") val field: String? = null,
    @JsonSchemaMetadata(description = "Required when `field` is `evidence_request` or `evidence_response`.", minimum = 0) val evidenceIndex: Int? = null,
    @JsonSchemaMetadata(description = "Zero-based byte offset within the selected content.", minimum = 0, defaultJson = "0") val offset: Int? = null,
    @JsonSchemaMetadata(description = "Maximum content bytes to return.", minimum = 1, maximum = 262144, defaultJson = "32768") val limit: Int? = null,
    @JsonSchemaMetadata(description = "Encoding used for returned content.", enumValues = ["text", "base64"], defaultJson = "\"text\"") val encoding: String? = null,
)

@Serializable
data class GenerateCollaboratorPayload(
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Optional ASCII alphanumeric custom data embedded in the generated Collaborator payload.", minLength = 1, maxLength = 16, pattern = "^[A-Za-z0-9]{1,16}$")
    val customData: String? = null,
)
