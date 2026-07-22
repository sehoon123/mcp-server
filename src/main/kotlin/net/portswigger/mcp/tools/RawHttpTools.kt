package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.RedirectionMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.requests.HttpRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.config.TargetValidation
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.RequestActionSecurity
import net.portswigger.mcp.security.RequestRoutingAuditOperation
import net.portswigger.mcp.security.safeExceptionSummary

private const val MAX_RAW_HTTP1_CHARS = 2 * 1024 * 1024
private const val MIN_RAW_TIMEOUT_MS = 100
private const val MAX_RAW_TIMEOUT_MS = 120_000
private const val DEFAULT_RAW_TIMEOUT_MS = 30_000
private const val DEFAULT_RAW_RESPONSE_BODY_BYTES = 8 * 1024
private const val MAX_RAW_RESPONSE_BODY_BYTES = 64 * 1024
private const val MAX_RAW_TAB_NAME_CHARS = 128

@Serializable
enum class RawHttpProtocol {
    @SerialName("http_1")
    HTTP_1,

    @SerialName("http_2")
    HTTP_2,
}

@Serializable
data class RawHttp1Input(
    @JsonSchemaMetadata(description = "Raw HTTP/1.1 request.", minLength = 1, maxLength = 2097152)
    val content: String,
)

@Serializable
data class RawHttp2Input(
    @JsonSchemaMetadata(description = "HTTP/2 pseudo-headers without or with leading colons.", maxProperties = 8)
    val pseudoHeaders: Map<String, String>,
    @JsonSchemaMetadata(description = "HTTP/2 regular headers; combined header count is at most 128.", maxProperties = 128)
    val headers: Map<String, String>,
    @JsonSchemaMetadata(description = "HTTP/2 request body.", maxLength = 1048576)
    val requestBody: String,
)

@Serializable
data class SendRawHttpRequest(
    val protocol: RawHttpProtocol,
    @JsonSchemaMetadata(description = "Required only for protocol=http_1; http2 must be absent.")
    val http1: RawHttp1Input? = null,
    @JsonSchemaMetadata(description = "Required only for protocol=http_2; http1 must be absent.")
    val http2: RawHttp2Input? = null,
    @JsonSchemaMetadata(description = "Exact DNS or IP destination host.", minLength = 1, maxLength = 253)
    val targetHostname: String,
    @JsonSchemaMetadata(description = "Destination port.", minimum = 1, maximum = 65535)
    val targetPort: Int,
    @JsonSchemaMetadata(description = "Use TLS for the destination.")
    val usesHttps: Boolean,
    @JsonSchemaMetadata(description = "Response timeout in milliseconds.", minimum = 100, maximum = 120000, defaultJson = "30000")
    val responseTimeoutMs: Int? = null,
    @JsonSchemaMetadata(description = "Maximum response body bytes returned.", minimum = 0, maximum = 65536, defaultJson = "8192")
    val responseBodyLimit: Int? = null,
    @JsonSchemaMetadata(description = "Response body encoding.", enumValues = ["text", "base64"], defaultJson = "\"text\"")
    val responseBodyEncoding: String? = null,
)

@Serializable
enum class RawHttpRouteDestination {
    @SerialName("repeater")
    REPEATER,

    @SerialName("intruder")
    INTRUDER,

    @SerialName("organizer")
    ORGANIZER,
}

@Serializable
data class RouteRawHttpRequest(
    val destination: RawHttpRouteDestination,
    val protocol: RawHttpProtocol,
    @JsonSchemaMetadata(description = "Required only for protocol=http_1; http2 must be absent.")
    val http1: RawHttp1Input? = null,
    @JsonSchemaMetadata(description = "Required only for protocol=http_2; http1 must be absent.")
    val http2: RawHttp2Input? = null,
    @JsonSchemaMetadata(description = "Exact DNS or IP destination host.", minLength = 1, maxLength = 253)
    val targetHostname: String,
    @JsonSchemaMetadata(description = "Destination port.", minimum = 1, maximum = 65535)
    val targetPort: Int,
    @JsonSchemaMetadata(description = "Use TLS for the destination.")
    val usesHttps: Boolean,
    @JsonSchemaMetadata(description = "Optional Repeater or Intruder tab caption; rejected for Organizer.", maxLength = 128)
    val tabName: String? = null,
)

@Serializable
data class RawHttpActionResult(
    val status: HttpMessageActionStatus,
    val executionState: HttpMessageExecutionState,
    val protocol: RawHttpProtocol,
    val destination: HttpMessageActionDestination,
    val target: HttpActionTarget,
    val projectId: String? = null,
    val requestBytes: Int? = null,
    val tabName: String? = null,
    val response: HttpActionResponseSummary? = null,
    val recordedInSiteMap: Boolean? = null,
    val recordedRef: HttpMessageReference? = null,
    val error: String? = null,
)

internal class RawHttpActionService(
    private val api: MontoyaApi,
    private val config: McpConfig,
) {
    suspend fun send(input: SendRawHttpRequest): RawHttpActionResult {
        val target = input.toTarget()
        val timeout = input.responseTimeoutMs ?: DEFAULT_RAW_TIMEOUT_MS
        if (timeout !in MIN_RAW_TIMEOUT_MS..MAX_RAW_TIMEOUT_MS) {
            return invalid(input.protocol, HttpMessageActionDestination.HTTP, target, "responseTimeoutMs is out of range")
        }
        val bodyLimit = input.responseBodyLimit ?: DEFAULT_RAW_RESPONSE_BODY_BYTES
        if (bodyLimit !in 0..MAX_RAW_RESPONSE_BODY_BYTES) {
            return invalid(input.protocol, HttpMessageActionDestination.HTTP, target, "responseBodyLimit is out of range")
        }
        val encoding = try {
            normalizeHistoryEncoding(input.responseBodyEncoding)
        } catch (e: IllegalArgumentException) {
            return invalid(input.protocol, HttpMessageActionDestination.HTTP, target, e.message.orEmpty())
        }
        val prepared = try {
            prepare(
                input.protocol,
                input.http1,
                input.http2,
                input.targetHostname,
                input.targetPort,
                input.usesHttps,
            )
        } catch (e: IllegalArgumentException) {
            return invalid(input.protocol, HttpMessageActionDestination.HTTP, target, e.message.orEmpty())
        } catch (e: Exception) {
            return burpError(input.protocol, HttpMessageActionDestination.HTTP, target, e)
        }

        val approved = try {
            HttpRequestSecurity.checkHttpRequestPermission(
                input.targetHostname,
                input.targetPort,
                config,
                prepared.review,
                api,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return burpError(input.protocol, HttpMessageActionDestination.HTTP, target, e)
        }
        if (!approved) {
            return denied(input.protocol, HttpMessageActionDestination.HTTP, target, prepared.requestBytes)
        }

        val options = try {
            RequestOptions.requestOptions()
                .withHttpMode(input.protocol.toHttpMode())
                .withRedirectionMode(RedirectionMode.NEVER)
                .withResponseTimeout(timeout.toLong())
        } catch (e: Exception) {
            return burpError(input.protocol, HttpMessageActionDestination.HTTP, target, e)
        }

        currentCoroutineContext().ensureActive()
        val recordingProjectId = runCatching { api.project().id() }.getOrNull()
        val exchange = try {
            api.http().sendRequest(prepared.request, options)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return uncertain(input.protocol, HttpMessageActionDestination.HTTP, target, prepared.requestBytes, null, e)
        }

        val recording = recordHttpResponseInSiteMap(api, exchange, recordingProjectId)
        var warning: String? = recording.warning
        val response = try {
            exchange?.response()?.toActionSummary(bodyLimit, encoding)
        } catch (e: Exception) {
            val previewWarning = "request completed but its response preview could not be created: ${safeExceptionSummary(e)}"
            warning = listOfNotNull(warning, previewWarning).joinToString("; ").take(512)
            null
        }
        return RawHttpActionResult(
            status = HttpMessageActionStatus.OK,
            executionState = HttpMessageExecutionState.COMPLETED,
            protocol = input.protocol,
            destination = HttpMessageActionDestination.HTTP,
            target = target,
            projectId = recordingProjectId?.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
            requestBytes = prepared.requestBytes,
            response = response,
            recordedInSiteMap = recording.recorded,
            recordedRef = recording.ref,
            error = warning,
        )
    }

    suspend fun route(input: RouteRawHttpRequest): RawHttpActionResult {
        val destination = input.destination.toActionDestination()
        val target = input.toTarget()
        val tabName = try {
            normalizeRawTabName(input.tabName)
        } catch (e: IllegalArgumentException) {
            return invalid(input.protocol, destination, target, e.message.orEmpty())
        }
        if (input.destination == RawHttpRouteDestination.ORGANIZER && tabName != null) {
            return invalid(input.protocol, destination, target, "tabName is not supported for Organizer")
        }
        if (input.destination == RawHttpRouteDestination.INTRUDER && input.protocol == RawHttpProtocol.HTTP_2) {
            return invalid(
                input.protocol,
                destination,
                target,
                "HTTP/2 Intruder routing is unavailable until verified by the current Burp runtime",
            )
        }
        val prepared = try {
            prepare(
                input.protocol,
                input.http1,
                input.http2,
                input.targetHostname,
                input.targetPort,
                input.usesHttps,
            )
        } catch (e: IllegalArgumentException) {
            return invalid(input.protocol, destination, target, e.message.orEmpty())
        } catch (e: Exception) {
            return burpError(input.protocol, destination, target, e)
        }

        val approved = try {
            RequestActionSecurity.checkPermission(
                action = input.destination.approvalLabel(),
                source = "raw MCP request",
                target = TargetValidation.formatTarget(input.targetHostname, input.targetPort),
                changes = "${input.protocol.serialName()} request with no structured patch",
                requestContent = prepared.review,
                config = config,
                api = api,
                auditOperation = input.destination.auditOperation(),
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return burpError(input.protocol, destination, target, e)
        }
        if (!approved) return denied(input.protocol, destination, target, prepared.requestBytes, tabName)

        currentCoroutineContext().ensureActive()
        try {
            when (input.destination) {
                RawHttpRouteDestination.REPEATER -> {
                    if (tabName == null) api.repeater().sendToRepeater(prepared.request)
                    else api.repeater().sendToRepeater(prepared.request, tabName)
                }
                RawHttpRouteDestination.INTRUDER -> {
                    if (tabName == null) api.intruder().sendToIntruder(prepared.request)
                    else api.intruder().sendToIntruder(prepared.request, tabName)
                }
                RawHttpRouteDestination.ORGANIZER -> api.organizer().sendToOrganizer(prepared.request)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return uncertain(input.protocol, destination, target, prepared.requestBytes, tabName, e)
        }

        return RawHttpActionResult(
            status = HttpMessageActionStatus.OK,
            executionState = HttpMessageExecutionState.COMPLETED,
            protocol = input.protocol,
            destination = destination,
            target = target,
            requestBytes = prepared.requestBytes,
            tabName = tabName,
        )
    }
}

private data class PreparedRawHttpRequest(
    val request: HttpRequest,
    val review: String,
    val requestBytes: Int,
)

private fun prepare(
    protocol: RawHttpProtocol,
    http1: RawHttp1Input?,
    http2: RawHttp2Input?,
    targetHostname: String,
    targetPort: Int,
    usesHttps: Boolean,
): PreparedRawHttpRequest {
    when (protocol) {
        RawHttpProtocol.HTTP_1 -> require(http1 != null && http2 == null) {
            "protocol=http_1 requires only the http1 object"
        }
        RawHttpProtocol.HTTP_2 -> require(http2 != null && http1 == null) {
            "protocol=http_2 requires only the http2 object"
        }
    }
    validateLegacyTarget(targetHostname, targetPort)
    val service = HttpService.httpService(targetHostname, targetPort, usesHttps)
    val request: HttpRequest
    val review: String
    when (protocol) {
        RawHttpProtocol.HTTP_1 -> {
            require(http1 != null && http2 == null) { "protocol=http_1 requires only the http1 object" }
            require(http1.content.isNotEmpty() && http1.content.length <= MAX_RAW_HTTP1_CHARS) {
                "HTTP/1 content must contain 1 to $MAX_RAW_HTTP1_CHARS characters"
            }
            review = normalizeHttpContent(http1.content)
            request = HttpRequest.httpRequest(service, review)
        }
        RawHttpProtocol.HTTP_2 -> {
            require(http2 != null && http1 == null) { "protocol=http_2 requires only the http2 object" }
            validateLegacyHttp2Input(http2.pseudoHeaders, http2.headers, http2.requestBody)
            val headerList = buildHttp2HeaderList(http2.pseudoHeaders, http2.headers)
            review = buildString {
                headerList.forEach { appendLine("${it.name()}: ${it.value()}") }
                if (http2.requestBody.isNotEmpty()) {
                    appendLine()
                    append(http2.requestBody)
                }
            }
            request = HttpRequest.http2Request(service, headerList, http2.requestBody)
        }
    }
    val requestBytes = requestByteLength(request)
    require(requestBytes <= MAX_ACTION_REQUEST_BYTES) {
        "request exceeds the $MAX_ACTION_REQUEST_BYTES-byte action limit"
    }
    return PreparedRawHttpRequest(request, review, requestBytes)
}

private fun RawHttpProtocol.toHttpMode(): HttpMode = when (this) {
    RawHttpProtocol.HTTP_1 -> HttpMode.HTTP_1
    RawHttpProtocol.HTTP_2 -> HttpMode.HTTP_2
}

private fun RawHttpProtocol.serialName(): String = when (this) {
    RawHttpProtocol.HTTP_1 -> "http_1"
    RawHttpProtocol.HTTP_2 -> "http_2"
}

private fun RawHttpRouteDestination.toActionDestination(): HttpMessageActionDestination = when (this) {
    RawHttpRouteDestination.REPEATER -> HttpMessageActionDestination.REPEATER
    RawHttpRouteDestination.INTRUDER -> HttpMessageActionDestination.INTRUDER
    RawHttpRouteDestination.ORGANIZER -> HttpMessageActionDestination.ORGANIZER
}

private fun RawHttpRouteDestination.approvalLabel(): String = when (this) {
    RawHttpRouteDestination.REPEATER -> "create a Repeater tab"
    RawHttpRouteDestination.INTRUDER -> "create an Intruder tab"
    RawHttpRouteDestination.ORGANIZER -> "send this request to Organizer"
}

private fun RawHttpRouteDestination.auditOperation(): RequestRoutingAuditOperation = when (this) {
    RawHttpRouteDestination.REPEATER -> RequestRoutingAuditOperation.REPEATER
    RawHttpRouteDestination.INTRUDER -> RequestRoutingAuditOperation.INTRUDER
    RawHttpRouteDestination.ORGANIZER -> RequestRoutingAuditOperation.ORGANIZER
}

private fun normalizeRawTabName(tabName: String?): String? = tabName?.also {
    require(it.length <= MAX_RAW_TAB_NAME_CHARS && it.none(Char::isISOControl)) { "tabName is invalid" }
}

private fun SendRawHttpRequest.toTarget() = HttpActionTarget(
    host = targetHostname.safeResultHost(),
    port = targetPort,
    secure = usesHttps,
)

private fun RouteRawHttpRequest.toTarget() = HttpActionTarget(
    host = targetHostname.safeResultHost(),
    port = targetPort,
    secure = usesHttps,
)

private fun String.safeResultHost(): String =
    take(MAX_HTTP_SEARCH_HOST_CHARS).filter {
        it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '.' || it == '-' || it == ':'
    }
        .ifEmpty { "<invalid>" }

private fun invalid(
    protocol: RawHttpProtocol,
    destination: HttpMessageActionDestination,
    target: HttpActionTarget,
    message: String,
) = RawHttpActionResult(
    status = HttpMessageActionStatus.INVALID_ARGUMENT,
    executionState = HttpMessageExecutionState.NOT_STARTED,
    protocol = protocol,
    destination = destination,
    target = target,
    error = message.take(512),
)

private fun denied(
    protocol: RawHttpProtocol,
    destination: HttpMessageActionDestination,
    target: HttpActionTarget,
    requestBytes: Int,
    tabName: String? = null,
) = RawHttpActionResult(
    status = HttpMessageActionStatus.ACTION_DENIED,
    executionState = HttpMessageExecutionState.NOT_STARTED,
    protocol = protocol,
    destination = destination,
    target = target,
    requestBytes = requestBytes,
    tabName = tabName,
    error = "request action denied by Burp Suite",
)

private fun burpError(
    protocol: RawHttpProtocol,
    destination: HttpMessageActionDestination,
    target: HttpActionTarget,
    error: Exception,
) = RawHttpActionResult(
    status = HttpMessageActionStatus.BURP_ERROR,
    executionState = HttpMessageExecutionState.NOT_STARTED,
    protocol = protocol,
    destination = destination,
    target = target,
    error = "Burp could not prepare the raw request action: ${safeExceptionSummary(error)}".take(512),
)

private fun uncertain(
    protocol: RawHttpProtocol,
    destination: HttpMessageActionDestination,
    target: HttpActionTarget,
    requestBytes: Int,
    tabName: String?,
    error: Exception,
) = RawHttpActionResult(
    status = HttpMessageActionStatus.EXECUTION_UNCERTAIN,
    executionState = HttpMessageExecutionState.UNCERTAIN,
    protocol = protocol,
    destination = destination,
    target = target,
    requestBytes = requestBytes,
    tabName = tabName,
    error = "Burp may have completed the raw request action; do not retry automatically: ${safeExceptionSummary(error)}".take(512),
)
