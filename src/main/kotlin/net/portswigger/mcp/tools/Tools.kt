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

    mcpStructuredTool<SendRawHttpRequest, RawHttpActionResult>(
        description = "Issues exactly one bounded raw HTTP/1.1 or HTTP/2 request. Exactly the protocol-matching http1 or http2 object is required. Redirects are always disabled; timeout and response preview are bounded. The exchange is not automatically added to Site Map because Burp does not provide an atomic project-bound add; recordedInSiteMap remains false and recordedRef remains absent. executionState=uncertain means the request may have been sent and must not be retried automatically.",
        annotations = HTTP_REQUEST_ACTION_ANNOTATIONS,
    ) {
        rawHttpActionService.send(this)
    }

    mcpStructuredTool<RouteRawHttpRequest, RawHttpActionResult>(
        description = "Routes exactly one bounded raw HTTP/1.1 or HTTP/2 request to one Repeater, Intruder, or Organizer destination after request-routing approval. This only opens the tab or Organizer item; it does not send the request or record anything in Proxy history or Site Map. HTTP/2 Intruder routing is rejected until verified. executionState=uncertain means the tab or item may already exist and must not be retried automatically.",
        annotations = REQUEST_ROUTING_TOOL_ANNOTATIONS,
    ) {
        rawHttpActionService.route(this)
    }

    mcpStructuredToolWithContext<TransformData, TransformDataResult>(
        description = "URL-encodes, URL-decodes, Base64-encodes, or Base64-decodes bounded content according to operation. Returns a typed status, retry guidance, and bounded transformed content.",
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
        description = "Generates a bounded random string from a non-empty character set and returns typed status and retry guidance.",
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
        description = "Outputs bounded current project- or user-level Burp configuration after explicit approval. Returns typed approval, limit, and Burp-error states.",
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
                    auditOperation = SensitiveActionAuditOperation.PROJECT_OPTIONS_READ,
                )
                BurpOptionsLevel.USER -> SensitiveActionSecurity.checkPermission(
                    "read user configuration",
                    "Export user-level Burp configuration to the MCP client",
                    api = api,
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
        description = "Imports bounded project- or user-level configuration JSON after explicit approval. Project JSON must contain top-level 'project_options'; user JSON must contain top-level 'user_options'. Returns typed execution state; uncertain means the configuration may be partially applied and must not be retried automatically.",
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
                    auditOperation = SensitiveActionAuditOperation.PROJECT_OPTIONS_WRITE,
                )
                BurpOptionsLevel.USER -> SensitiveActionSecurity.checkPermission(
                    "change user configuration",
                    "Merge supplied JSON into Burp user configuration",
                    input.json,
                    api = api,
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
            description = "Reads Scanner issues for the current Burp project; unlike most other tools here, this call takes no projectId (the returned projectId field simply reports which project was read). Legacy mode (the default: no cursorMode and no severity/confidence/host/name filter) returns full-fidelity issues as a plain-text block in the tool result's text field, not as JSON, bounded to 512 KiB; when there are no matching issues that text is the literal string 'Reached end of items'. Set cursorMode=true, or supply severity/confidence/host/name filters, to switch to bounded compact JSON summaries with a signed project-bound snapshot cursor; cursor mode never serializes complete evidence messages. For a single known issue ID, use get_scanner_issue_by_id instead, which does require projectId.",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) { input ->
            scannerIssueSearchService.get(input)
        }

        mcpStructuredTool<GetScannerIssueById, ScannerIssueReadResult>(
            description = "Reads one Scanner issue by its stable issue ID and required projectId, rechecking the project after lookup and bounded content materialization. Select metadata, detail, remediation, evidence_request, or evidence_response. Evidence content is byte-paginated and can be returned as text or base64.",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) {
            scannerIssueReadService.read(this)
        }

        mcpStructuredTool<StartScannerAuditFromIds, ScannerAuditResult>(
            description = "Starts a focused Professional Scanner audit from existing project-scoped HTTP references. Passive mode requires responses, sends no target traffic, and accepts up to 16 targets. Active mode requires explicit semantic insertionPoints for every target, rejects out-of-scope requests, and accepts at most 4 targets even though the targets array schema allows up to 16; submitting 5-16 targets in active mode is rejected with invalid_argument. This operation always requires Burp approval. Retained tasks expire after 6 hours without a status/cancel call and after 24 hours overall. actionState=uncertain means a task may exist and must not be started again automatically.",
            annotations = SCANNER_START_TOOL_ANNOTATIONS,
        ) {
            services.scannerAudits.start(this, config)
        }

        mcpStructuredTool<GetScannerAudit, ScannerAuditResult>(
            description = "Returns status, insertion-point/request/error counts, and bounded stable issue summaries for a Scanner audit started by this extension instance. A retained-task status call refreshes its 6-hour inactivity lease; every task still has a 24-hour maximum lifetime. Burp exposes a textual task status, so taskState is a conservative normalized interpretation and statusMessage remains authoritative. issuesUnavailable=true is a nonfatal warning when the current Burp runtime cannot expose live task issues.",
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
            description = "Generates a project-bound, bounded Burp Collaborator payload for out-of-band testing and returns its payloadId. Optional customData must contain 1–16 ASCII alphanumeric characters, matching Burp's native limit. Use get_collaborator_interactions with that payloadId; generation does not inject or send the payload. executionState=uncertain means Burp may have allocated a payload and the call must not be retried automatically.",
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

    mcpStructuredToolWithContext<SearchHttpMessages, SearchHttpMessagesResult>(
        description = "Searches compact HTTP metadata in Proxy history by default, or explicitly selected Proxy, Site Map, and Organizer sources. Requests issued directly by send_raw_http_request or send_http_request_from_id are not automatically recorded because Burp does not expose an atomic project-bound Site Map add. Filters support exact host, literal or conservatively safe regex content, path, method, status, MIME type, scope, and response presence. Results are bounded to 50 items and content scans to 32 MiB. With a progress token, fixed stages cover validation, approval, snapshot preparation, bounded scanning, and finalization; coroutine cancellation is checked between scan batches. Use nextCursor by itself to continue the same signed snapshot. Copy projectId and ref into get_http_message, send_http_request_from_id, or route_http_message_from_id.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        StructuredToolResponse(
            httpMessageSearchService.search(input) { progress, total, message ->
                reportProgress(progress, total, message)
            }
        )
    }

    mcpStructuredToolWithContext<SummarizeHttpAttackSurface, HttpAttackSurfaceResult>(
        description = "Summarizes a bounded, project-scoped, body-free HTTP metadata index. It defaults to in-scope Proxy records only and does not include direct MCP sends, which are not automatically recorded; it strips query strings, normalizes likely identifier path segments, and returns aggregate services, methods, status classes, MIME types, file extensions, and path prefixes. The index retains no bodies, header values, notes, URLs with queries, or Montoya objects; source truncation and refresh state are explicit. status=burp_error with a message about HTTP metadata changing is a transient condition (e.g. immediately after update_scope or set_burp_options) and the call should simply be retried. With a progress token, fixed stages cover validation, approval, bounded index refresh, aggregation, and snapshot verification; coroutine cancellation is checked during refresh and aggregation.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        StructuredToolResponse(
            httpAttackSurfaceService.summarize(input) { progress, total, message ->
                reportProgress(progress, total, message)
            }
        )
    }

    mcpStructuredTool<CheckScope, CheckScopeResult>(
        description = "Checks whether up to 32 explicit URLs or project-scoped HTTP message references are currently in Burp Target scope. This tool never changes scope. Each target's schema requires exactly one of url or ref via a oneOf constraint; supplying both or neither is rejected before approval.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) {
        scopeToolService.check(this)
    }

    mcpStructuredTool<UpdateScope, UpdateScopeResult>(
        description = "Includes or excludes up to 16 normalized URLs or project-scoped HTTP message references in Burp Target scope. Each target's schema requires exactly one of url or ref via a oneOf constraint. All targets are validated before approval unless the user has explicitly selected Always Allow for Target scope changes. executionState=uncertain means some scope changes may already exist and the call must not be retried automatically.",
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

    mcpStructuredToolWithContext<AnalyzeHttpSessionSecurity, AnalyzeHttpSessionSecurityResult>(
        description = "Passively analyzes 1 to 32 distinct ordered project-scoped Proxy, Site Map, or Organizer references for bounded authentication/session header presence, value-free response-cookie classifications, heuristic login/logout/refresh/redirect roles, and cross-message cookie observations. Input order is only a proposed flow. Analyzer logic does not access message bodies or authentication values; preserving v4.8 Site Map stable IDs can privately inspect bounded identity body samples and header values during reference resolution. Cookie and Location values are privately inspected only for fixed classifications and are never returned, and no raw body, authentication, redirect, cookie scope/lifetime value, Scanner analysis, traffic, or mutation is returned or performed. Observations do not establish chronology, causality, browser behavior, severity, or a vulnerability.",
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
        description = "Reads one Proxy, Site Map, or Organizer message returned by search_http_messages. Copy projectId and the complete ref from the search result. Select metadata, request, request_headers, request_body, response, response_headers, or response_body. Content is byte-paginated and supports text or base64.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) {
        httpMessageReadService.read(this)
    }

    mcpStructuredTool<SendHttpRequestFromId, HttpMessageActionResult>(
        description = "Replays a Proxy, Site Map, or Organizer request returned by search_http_messages. Applies only bounded structured method, path, header, parameter, or body patches; never asks the model to reconstruct raw HTTP. Requires the matching projectId and approvals. The response preview, timeout, and HTTP mode are bounded and explicit; automatic redirects are rejected because each destination would require separate review. Results are not automatically added to Site Map because Burp does not expose an atomic project-bound add. executionState=uncertain means the request must not be retried automatically.",
        annotations = HTTP_REQUEST_ACTION_ANNOTATIONS,
    ) {
        httpMessageActionService.send(this)
    }

    mcpStructuredTool<RouteHttpMessageFromId, HttpMessageActionResult>(
        description = "Routes one existing Proxy, Site Map, or Organizer request to exactly one Repeater, Intruder, or Organizer destination, optionally after a bounded structured patch. tabName applies only to Repeater or Intruder; semantic insertionPoints apply only to Intruder, and no Intruder attack is started. The matching projectId and approvals are required. executionState=uncertain means an item or tab may already exist and the action must not be retried automatically.",
        annotations = REQUEST_ROUTING_TOOL_ANNOTATIONS,
    ) {
        httpMessageActionService.route(this)
    }

    mcpStructuredToolWithContext<SearchWebsocketMessages, SearchWebsocketMessagesResult>(
        description = "Searches project-bound Proxy WebSocket history with signed snapshot cursors. Filters include connection ID, direction, listener port, and one conservatively safe payload regex. Results are bounded to 50 summaries, 10,000 scanned records, and 32 MiB of regex-inspected payload data. With a progress token, fixed stages cover validation, approval, snapshot loading, bounded scanning, and finalization; coroutine cancellation is checked between scan batches. Continue with only projectId, cursor set to the returned nextCursor, and optional limit.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) { input ->
        StructuredToolResponse(
            webSocketMessageSearchService.search(input) { progress, total, message ->
                reportProgress(progress, total, message)
            }
        )
    }

    mcpStructuredTool<GetWebsocketMessageById, WebSocketMessageReadResult>(
        description = "Reads one Proxy WebSocket payload by its stable Burp ID and required projectId. The project is rechecked after lookup and bounded content materialization. Content is byte-paginated and can be returned as text or base64.",
        annotations = READ_ONLY_TOOL_ANNOTATIONS,
    ) {
        webSocketMessageReadService.read(this)
    }

    mcpStructuredToolWithContext<SetBurpControlState, SetBurpControlStateResult>(
        description = "Changes exactly one Burp global control: the task execution engine or Proxy Intercept state. Returns typed execution state; uncertain means the change may have occurred and must not be retried automatically.",
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
                    auditOperation = SensitiveActionAuditOperation.TASK_EXECUTION_ENGINE,
                )
                BurpControl.PROXY_INTERCEPT -> SensitiveActionSecurity.checkPermission(
                    "change Proxy Intercept state",
                    "Set Burp Proxy Intercept to ${if (input.enabled) "enabled" else "disabled"}",
                    api = api,
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
        description = "Returns a bounded preview of the 'active editor', defined as whichever Burp Suite text-area component currently holds keyboard focus in the Burp window (for example a Repeater request/response pane, an Intruder payload editor, or Decoder input the user last clicked into) - not a fixed tool or tab. Returns status=not_available with no error if no such editor is currently focused. Requires explicit approval with typed availability, approval, and retry state.",
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
        description = "Overwrites the text of the same 'active editor' described in get_active_editor_contents - whichever Burp Suite text-area component currently holds keyboard focus in the Burp window - after explicit approval. Returns status=not_available if no editor is currently focused, or if the focused editor is read-only. Returns typed execution state; uncertain means the edit may have occurred and must not be retried automatically.",
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
    val operation: DataTransformOperation,
    @JsonSchemaMetadata(maxLength = 262144)
    val content: String,
)

@Serializable
data class GenerateRandomString(
    @JsonSchemaMetadata(minimum = 0, maximum = 65536) val length: Int,
    @JsonSchemaMetadata(minLength = 1, maxLength = 256) val characterSet: String,
)

@Serializable
enum class BurpOptionsLevel {
    @SerialName("project")
    PROJECT,

    @SerialName("user")
    USER,
}

@Serializable
data class GetBurpOptions(val level: BurpOptionsLevel)

@Serializable
data class SetBurpOptions(
    val level: BurpOptionsLevel,
    @JsonSchemaMetadata(maxLength = 1048576)
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
    val control: BurpControl,
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
    @JsonSchemaMetadata(minimum = 0, defaultJson = "0") val offset: Int? = null,
    @JsonSchemaMetadata(minimum = 1, maximum = 262144, defaultJson = "32768") val limit: Int? = null,
    @JsonSchemaMetadata(enumValues = ["text", "base64"], defaultJson = "\"text\"") val encoding: String? = null,
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
