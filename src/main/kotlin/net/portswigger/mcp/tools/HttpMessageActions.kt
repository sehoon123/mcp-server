package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.RedirectionMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpRequestResponse as MontoyaHttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.intruder.HttpRequestTemplate
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.RequestActionSecurity
import net.portswigger.mcp.security.RequestRoutingAuditOperation
import net.portswigger.mcp.security.recordCurrentToolApproval
import net.portswigger.mcp.security.safeExceptionSummary
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.HexFormat

internal const val MAX_ACTION_REQUEST_BYTES = 2 * 1024 * 1024
internal const val DEFAULT_ACTION_RESPONSE_BODY_BYTES = 8 * 1024
internal const val MAX_ACTION_RESPONSE_BODY_BYTES = 64 * 1024
private const val MAX_ACTION_TAB_NAME_CHARS = 128
private const val MAX_ACTION_PATH_CHARS = 8 * 1024
private const val MAX_ACTION_HEADER_NAME_CHARS = 256
private const val MAX_ACTION_HEADER_VALUE_CHARS = 16 * 1024
private const val MAX_ACTION_PARAMETER_NAME_CHARS = 512
private const val MAX_ACTION_PARAMETER_VALUE_CHARS = 16 * 1024
private const val MAX_ACTION_MUTATIONS = 64
private const val MAX_ACTION_BODY_BYTES = 1024 * 1024
private const val MIN_ACTION_TIMEOUT_MS = 100
private const val MAX_ACTION_TIMEOUT_MS = 120_000
private const val DEFAULT_ACTION_TIMEOUT_MS = 30_000
private val HTTP_TOKEN_PATTERN = Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+")

@Serializable
data class SendHttpRequestFromId(
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Existing project-scoped HTTP message reference.")
    val ref: HttpMessageReference,
    @JsonSchemaMetadata(description = "Bounded immutable request mutations.")
    val patch: HttpRequestPatch? = null,
    @JsonSchemaMetadata(description = "HTTP protocol mode.", defaultJson = "\"original\"")
    val httpMode: HttpReplayMode? = null,
    @JsonSchemaMetadata(description = "Only never is accepted so every destination remains reviewable.", enumValues = ["never"], defaultJson = "\"never\"")
    val redirection: HttpRedirectionPolicy? = null,
    @JsonSchemaMetadata(description = "Response timeout in milliseconds.", minimum = 100, maximum = 120000, defaultJson = "30000")
    val responseTimeoutMs: Int? = null,
    @JsonSchemaMetadata(description = "Maximum response body bytes returned.", minimum = 0, maximum = 65536, defaultJson = "8192")
    val responseBodyLimit: Int? = null,
    @JsonSchemaMetadata(description = "Response body encoding.", pattern = "^(text|base64)$", defaultJson = "\"text\"")
    val responseBodyEncoding: String? = null,
)

@Serializable
enum class HttpMessageRouteDestination {
    @SerialName("repeater")
    REPEATER,

    @SerialName("intruder")
    INTRUDER,

    @SerialName("organizer")
    ORGANIZER,
}

@Serializable
data class RouteHttpMessageFromId(
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Existing project-scoped HTTP message reference.")
    val ref: HttpMessageReference,
    @JsonSchemaMetadata(description = "Single Burp tool destination for this action.")
    val destination: HttpMessageRouteDestination,
    val patch: HttpRequestPatch? = null,
    @JsonSchemaMetadata(description = "Optional Repeater or Intruder tab caption; rejected for Organizer.", maxLength = 128)
    val tabName: String? = null,
    @JsonSchemaMetadata(description = "Optional semantic Intruder insertion points; rejected for other destinations.", minItems = 1, maxItems = 32)
    val insertionPoints: List<HttpInsertionPointSelector>? = null,
)

@Serializable
data class CreateRepeaterTabFromId(
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256)
    val projectId: String,
    val ref: HttpMessageReference,
    val patch: HttpRequestPatch? = null,
    @JsonSchemaMetadata(description = "Optional Repeater tab caption.", maxLength = 128)
    val tabName: String? = null,
)

@Serializable
data class SendToIntruderFromId(
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256)
    val projectId: String,
    val ref: HttpMessageReference,
    val patch: HttpRequestPatch? = null,
    @JsonSchemaMetadata(description = "Optional Intruder tab caption.", maxLength = 128)
    val tabName: String? = null,
    @JsonSchemaMetadata(description = "Semantic Intruder insertion points.", minItems = 1, maxItems = 32)
    val insertionPoints: List<HttpInsertionPointSelector>? = null,
)

@Serializable
data class SendToOrganizerFromId(
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256)
    val projectId: String,
    val ref: HttpMessageReference,
    val patch: HttpRequestPatch? = null,
)

@Serializable
data class HttpRequestPatch(
    @JsonSchemaMetadata(description = "Replacement HTTP method token.", minLength = 1, maxLength = 32)
    val method: String? = null,
    @JsonSchemaMetadata(description = "Replacement origin-form request target.", minLength = 1, maxLength = 8192)
    val path: String? = null,
    @JsonSchemaMetadata(description = "Header names to remove.", maxItems = 64)
    val removeHeaders: List<String>? = null,
    @JsonSchemaMetadata(description = "Headers to replace.", maxItems = 64)
    val setHeaders: List<HttpHeaderMutation>? = null,
    @JsonSchemaMetadata(description = "Headers to append.", maxItems = 64)
    val addHeaders: List<HttpHeaderMutation>? = null,
    @JsonSchemaMetadata(description = "Parameters to remove.", maxItems = 64)
    val removeParameters: List<HttpParameterKey>? = null,
    @JsonSchemaMetadata(description = "Parameters to replace.", maxItems = 64)
    val setParameters: List<HttpParameterMutation>? = null,
    @JsonSchemaMetadata(description = "Parameters to append.", maxItems = 64)
    val addParameters: List<HttpParameterMutation>? = null,
    @JsonSchemaMetadata(description = "Replacement request body, limited to 1 MiB decoded.")
    val body: HttpBodyPatch? = null,
)

@Serializable
data class HttpHeaderMutation(val name: String, val value: String)

@Serializable
data class HttpParameterKey(val type: HttpActionParameterType, val name: String)

@Serializable
data class HttpParameterMutation(val type: HttpActionParameterType, val name: String, val value: String)

@Serializable
data class HttpBodyPatch(val encoding: HttpBodyPatchEncoding, val data: String)

@Serializable
enum class HttpBodyPatchEncoding {
    @SerialName("text")
    TEXT,

    @SerialName("base64")
    BASE64,
}

@Serializable
enum class HttpActionParameterType {
    @SerialName("url")
    URL,

    @SerialName("body")
    BODY,

    @SerialName("cookie")
    COOKIE,

    @SerialName("xml")
    XML,

    @SerialName("xml_attribute")
    XML_ATTRIBUTE,

    @SerialName("multipart_attribute")
    MULTIPART_ATTRIBUTE,

    @SerialName("json")
    JSON,
}

@Serializable
enum class HttpReplayMode {
    @SerialName("original")
    ORIGINAL,

    @SerialName("auto")
    AUTO,

    @SerialName("http_1")
    HTTP_1,

    @SerialName("http_2")
    HTTP_2,

    @SerialName("http_2_ignore_alpn")
    HTTP_2_IGNORE_ALPN,
}

@Serializable
enum class HttpRedirectionPolicy {
    @SerialName("never")
    NEVER,

    @SerialName("same_host")
    SAME_HOST,

    @SerialName("in_scope")
    IN_SCOPE,

    @SerialName("always")
    ALWAYS,
}

@Serializable
enum class HttpMessageActionStatus {
    @SerialName("ok")
    OK,

    @SerialName("access_denied")
    ACCESS_DENIED,

    @SerialName("action_denied")
    ACTION_DENIED,

    @SerialName("invalid_argument")
    INVALID_ARGUMENT,

    @SerialName("invalid_id")
    INVALID_ID,

    @SerialName("project_mismatch")
    PROJECT_MISMATCH,

    @SerialName("not_found")
    NOT_FOUND,

    @SerialName("request_unavailable")
    REQUEST_UNAVAILABLE,

    @SerialName("burp_error")
    BURP_ERROR,

    @SerialName("execution_uncertain")
    EXECUTION_UNCERTAIN,
}

@Serializable
enum class HttpMessageExecutionState {
    @SerialName("not_started")
    NOT_STARTED,

    @SerialName("completed")
    COMPLETED,

    @SerialName("uncertain")
    UNCERTAIN,
}

@Serializable
enum class HttpMessageActionDestination {
    @SerialName("http")
    HTTP,

    @SerialName("repeater")
    REPEATER,

    @SerialName("intruder")
    INTRUDER,

    @SerialName("organizer")
    ORGANIZER,
}

@Serializable
data class HttpActionTarget(val host: String, val port: Int, val secure: Boolean)

@Serializable
data class HttpActionResponseSummary(
    val statusCode: Int,
    val mimeType: String?,
    val httpVersion: String,
    val bodyBytes: Int,
    val body: HistoryContentSlice? = null,
)

@Serializable
data class HttpMessageActionResult(
    val status: HttpMessageActionStatus,
    val executionState: HttpMessageExecutionState,
    val projectId: String?,
    val ref: HttpMessageReference,
    val destination: HttpMessageActionDestination,
    val target: HttpActionTarget? = null,
    val patchApplied: Boolean = false,
    val changes: String? = null,
    val requestBytes: Int? = null,
    val tabName: String? = null,
    val insertionPointCount: Int? = null,
    val response: HttpActionResponseSummary? = null,
    val recordedInSiteMap: Boolean? = null,
    val recordedRef: HttpMessageReference? = null,
    val preservedResponseInOrganizer: Boolean? = null,
    val error: String? = null,
)

internal class HttpMessageActionService(
    private val api: MontoyaApi,
    private val config: McpConfig,
) {
    private val resolver = HttpMessageResolver(api, config)

    suspend fun send(input: SendHttpRequestFromId): HttpMessageActionResult {
        if (input.redirection != null && input.redirection != HttpRedirectionPolicy.NEVER) {
            return invalidArgument(
                input.projectId,
                input.ref,
                HttpMessageActionDestination.HTTP,
                "automatic redirects are disabled because redirected destinations cannot be reviewed and approved",
            )
        }
        val timeout = input.responseTimeoutMs ?: DEFAULT_ACTION_TIMEOUT_MS
        if (timeout !in MIN_ACTION_TIMEOUT_MS..MAX_ACTION_TIMEOUT_MS) {
            return invalidArgument(
                input.projectId,
                input.ref,
                HttpMessageActionDestination.HTTP,
                "responseTimeoutMs must be between $MIN_ACTION_TIMEOUT_MS and $MAX_ACTION_TIMEOUT_MS",
            )
        }
        val bodyLimit = input.responseBodyLimit ?: DEFAULT_ACTION_RESPONSE_BODY_BYTES
        if (bodyLimit !in 0..MAX_ACTION_RESPONSE_BODY_BYTES) {
            return invalidArgument(
                input.projectId,
                input.ref,
                HttpMessageActionDestination.HTTP,
                "responseBodyLimit must be between 0 and $MAX_ACTION_RESPONSE_BODY_BYTES bytes",
            )
        }
        val bodyEncoding = try {
            normalizeHistoryEncoding(input.responseBodyEncoding)
        } catch (e: IllegalArgumentException) {
            return invalidArgument(input.projectId, input.ref, HttpMessageActionDestination.HTTP, e.message.orEmpty())
        }

        val resolved = when (val outcome = resolveSafely(input.projectId, input.ref)) {
            is HttpMessageBatchResolution.Found -> outcome.messages.single()
            is HttpMessageBatchResolution.Failed -> return resolutionFailure(
                input.ref,
                HttpMessageActionDestination.HTTP,
                outcome,
            )
        }
        val patched = try {
            applyPatch(resolved.request, input.patch)
        } catch (e: IllegalArgumentException) {
            return invalidArgument(input.projectId, input.ref, HttpMessageActionDestination.HTTP, e.message.orEmpty())
        } catch (e: Exception) {
            return burpError(input.projectId, input.ref, HttpMessageActionDestination.HTTP, e)
        }
        val approved = try {
            approveNetworkAction(resolved, patched)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return burpError(input.projectId, input.ref, HttpMessageActionDestination.HTTP, e)
        }
        if (!approved) {
            return denied(input.projectId, input.ref, HttpMessageActionDestination.HTTP, patched)
        }

        val options = try {
            RequestOptions.requestOptions()
                .withHttpMode(input.httpMode.toMontoyaMode(patched.request))
                .withRedirectionMode(input.redirection.toMontoyaRedirectionMode())
                .withResponseTimeout(timeout.toLong())
        } catch (e: Exception) {
            return burpError(input.projectId, input.ref, HttpMessageActionDestination.HTTP, e)
        }

        currentCoroutineContext().ensureActive()
        recheckProject(input.projectId, input.ref, HttpMessageActionDestination.HTTP)?.let { return it }
        val response = try {
            api.http().sendRequest(patched.request, options)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            runCatching {
                api.logging().logToError(
                    auditLine(HttpMessageActionDestination.HTTP, resolved, patched, "execution uncertain")
                )
            }
            return uncertain(input.projectId, input.ref, HttpMessageActionDestination.HTTP, patched, e)
        }

        val recorded = recordHttpResponseInSiteMap(api, response, input.projectId)
        var summaryError: String? = recorded.warning
        val responseSummary = try {
            response?.response()?.toActionSummary(bodyLimit, bodyEncoding)
        } catch (e: Exception) {
            val message = "request completed but its response preview could not be created: ${safeException(e)}"
            summaryError = listOfNotNull(summaryError, message).joinToString("; ")
            runCatching { api.logging().logToError(message) }
            null
        }
        runCatching {
            api.logging().logToOutput(
                auditLine(HttpMessageActionDestination.HTTP, resolved, patched, "completed")
            )
        }
        return success(
            input.projectId,
            input.ref,
            HttpMessageActionDestination.HTTP,
            patched,
            response = responseSummary,
            recordedInSiteMap = recorded.recorded,
            recordedRef = recorded.ref,
            error = summaryError,
        )
    }

    suspend fun route(input: RouteHttpMessageFromId): HttpMessageActionResult = when (input.destination) {
        HttpMessageRouteDestination.REPEATER -> {
            if (input.insertionPoints != null) {
                invalidArgument(
                    input.projectId,
                    input.ref,
                    HttpMessageActionDestination.REPEATER,
                    "insertionPoints are supported only for the Intruder destination",
                )
            } else {
                createRepeaterTab(
                    CreateRepeaterTabFromId(input.projectId, input.ref, input.patch, input.tabName)
                )
            }
        }

        HttpMessageRouteDestination.INTRUDER -> sendToIntruder(
            SendToIntruderFromId(
                input.projectId,
                input.ref,
                input.patch,
                input.tabName,
                input.insertionPoints,
            )
        )

        HttpMessageRouteDestination.ORGANIZER -> {
            if (input.tabName != null || input.insertionPoints != null) {
                invalidArgument(
                    input.projectId,
                    input.ref,
                    HttpMessageActionDestination.ORGANIZER,
                    "tabName and insertionPoints are not supported for the Organizer destination",
                )
            } else {
                sendToOrganizer(SendToOrganizerFromId(input.projectId, input.ref, input.patch))
            }
        }
    }

    suspend fun createRepeaterTab(input: CreateRepeaterTabFromId): HttpMessageActionResult = route(
        projectId = input.projectId,
        ref = input.ref,
        patch = input.patch,
        destination = HttpMessageActionDestination.REPEATER,
        tabName = input.tabName,
    ) { _, patched, tabName, _ ->
        if (tabName == null) api.repeater().sendToRepeater(patched.request)
        else api.repeater().sendToRepeater(patched.request, tabName)
        false
    }

    suspend fun sendToIntruder(input: SendToIntruderFromId): HttpMessageActionResult = route(
        projectId = input.projectId,
        ref = input.ref,
        patch = input.patch,
        destination = HttpMessageActionDestination.INTRUDER,
        tabName = input.tabName,
        insertionPointSelectors = input.insertionPoints,
    ) { _, patched, tabName, preparedInsertionPoints ->
        if (preparedInsertionPoints == null) {
            if (tabName == null) api.intruder().sendToIntruder(patched.request)
            else api.intruder().sendToIntruder(patched.request, tabName)
        } else {
            val template = HttpRequestTemplate.httpRequestTemplate(patched.request, preparedInsertionPoints.ranges)
            if (tabName == null) {
                api.intruder().sendToIntruder(patched.service, template)
            } else {
                api.intruder().sendToIntruder(patched.service, template, tabName)
            }
        }
        false
    }

    suspend fun sendToOrganizer(input: SendToOrganizerFromId): HttpMessageActionResult = route(
        projectId = input.projectId,
        ref = input.ref,
        patch = input.patch,
        destination = HttpMessageActionDestination.ORGANIZER,
        tabName = null,
    ) { resolved, patched, _, _ ->
        val envelope = if (!patched.changed && resolved.response != null) {
            resolved.envelope ?: MontoyaHttpRequestResponse.httpRequestResponse(patched.request, resolved.response)
        } else {
            null
        }
        if (envelope != null) {
            api.organizer().sendToOrganizer(envelope)
        } else {
            api.organizer().sendToOrganizer(patched.request)
        }
        envelope != null
    }

    private suspend fun route(
        projectId: String,
        ref: HttpMessageReference,
        patch: HttpRequestPatch?,
        destination: HttpMessageActionDestination,
        tabName: String?,
        insertionPointSelectors: List<HttpInsertionPointSelector>? = null,
        execute: (ResolvedHttpMessage, PatchedRequest, String?, PreparedInsertionPoints?) -> Boolean,
    ): HttpMessageActionResult {
        val normalizedTabName = try {
            normalizeTabName(tabName)
        } catch (e: IllegalArgumentException) {
            return invalidArgument(projectId, ref, destination, e.message.orEmpty())
        }
        val resolved = when (val outcome = resolveSafely(projectId, ref)) {
            is HttpMessageBatchResolution.Found -> outcome.messages.single()
            is HttpMessageBatchResolution.Failed -> return resolutionFailure(ref, destination, outcome)
        }
        val patched = try {
            applyPatch(resolved.request, patch)
        } catch (e: IllegalArgumentException) {
            return invalidArgument(projectId, ref, destination, e.message.orEmpty())
        } catch (e: Exception) {
            return burpError(projectId, ref, destination, e)
        }
        val preparedInsertionPoints = try {
            insertionPointSelectors?.let { prepareInsertionPoints(patched.request, it) }
        } catch (e: IllegalArgumentException) {
            return invalidArgument(projectId, ref, destination, e.message.orEmpty())
        } catch (e: Exception) {
            return burpError(projectId, ref, destination, e)
        }
        val actionChanges = listOfNotNull(patched.summary, preparedInsertionPoints?.summary).joinToString("; ").take(2_048)
        val approved = try {
            approveRoutingAction(destination, resolved, patched, actionChanges)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return burpError(projectId, ref, destination, e)
        }
        if (!approved) {
            return denied(
                projectId,
                ref,
                destination,
                patched,
                normalizedTabName,
                changes = actionChanges,
                insertionPointCount = preparedInsertionPoints?.ranges?.size,
            )
        }

        currentCoroutineContext().ensureActive()
        recheckProject(projectId, ref, destination)?.let { return it }
        val preserved = try {
            execute(resolved, patched, normalizedTabName, preparedInsertionPoints)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            runCatching { api.logging().logToError(auditLine(destination, resolved, patched, "execution uncertain")) }
            return uncertain(
                projectId,
                ref,
                destination,
                patched,
                e,
                normalizedTabName,
                changes = actionChanges,
                insertionPointCount = preparedInsertionPoints?.ranges?.size,
            )
        }
        runCatching { api.logging().logToOutput(auditLine(destination, resolved, patched, "completed")) }
        return success(
            projectId,
            ref,
            destination,
            patched,
            tabName = normalizedTabName,
            changes = actionChanges,
            insertionPointCount = preparedInsertionPoints?.ranges?.size,
            preservedResponseInOrganizer = if (destination == HttpMessageActionDestination.ORGANIZER) preserved else null,
        )
    }

    private suspend fun resolveSafely(
        projectId: String,
        ref: HttpMessageReference,
    ): HttpMessageBatchResolution = resolver.resolve(projectId, ref)

    private fun recheckProject(
        expectedProjectId: String,
        ref: HttpMessageReference,
        destination: HttpMessageActionDestination,
    ): HttpMessageActionResult? {
        val currentProjectId = try {
            api.project().id()
        } catch (e: Exception) {
            return burpError(expectedProjectId, ref, destination, e)
        }
        if (currentProjectId == expectedProjectId) return null
        return HttpMessageActionResult(
            status = HttpMessageActionStatus.PROJECT_MISMATCH,
            executionState = HttpMessageExecutionState.NOT_STARTED,
            projectId = currentProjectId.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
            ref = HttpMessageReference(ref.source, ref.id.take(MAX_HTTP_REFERENCE_ID_CHARS)),
            destination = destination,
            error = "Burp project changed before the request action executed",
        )
    }

    private suspend fun approveNetworkAction(
        resolved: ResolvedHttpMessage,
        patched: PatchedRequest,
    ): Boolean {
        val service = patched.service
        if (config.requireRequestActionApproval) {
            return approveRoutingAction(HttpMessageActionDestination.HTTP, resolved, patched)
        }
        return HttpRequestSecurity.checkHttpRequestPermissionLazy(
            service.host(),
            service.port(),
            config,
            api,
        ) { patched.requestContent }
    }

    private suspend fun approveRoutingAction(
        destination: HttpMessageActionDestination,
        resolved: ResolvedHttpMessage,
        patched: PatchedRequest,
        changes: String = patched.summary,
    ): Boolean {
        val auditOperation = destination.routingAuditOperation()
        if (!config.requireRequestActionApproval) {
            recordCurrentToolApproval(auditOperation?.auditKind ?: "request_routing", "policy_allow")
            return true
        }
        val service = patched.service
        return RequestActionSecurity.checkPermission(
            action = destination.approvalLabel(),
            source = "${resolved.ref.source.serialName()}:${resolved.ref.id}",
            target = "${service.host()}:${service.port()} (${if (service.secure()) "HTTPS" else "HTTP"})",
            changes = changes,
            requestContent = patched.requestContent,
            config = config,
            api = api,
            auditOperation = auditOperation,
        )
    }
}

private class PatchedRequest(
    val request: HttpRequest,
    val service: HttpService,
    val target: HttpActionTarget,
    val changed: Boolean,
    val summary: String,
    val requestBytes: Int,
) {
    val requestContent: String by lazy(LazyThreadSafetyMode.NONE) { request.toString() }
}

private fun applyPatch(original: HttpRequest, patch: HttpRequestPatch?): PatchedRequest {
    val immutableTarget = original.httpService().toActionTarget()
    val originalBytes = requestByteLength(original)
    require(originalBytes <= MAX_ACTION_REQUEST_BYTES) {
        "source request exceeds the $MAX_ACTION_REQUEST_BYTES-byte action limit"
    }
    if (patch == null) {
        return finalizePatchedRequest(
            original,
            false,
            listOf("none (exact source request)"),
            expectedTarget = immutableTarget,
            knownBytes = originalBytes,
        )
    }

    val headerMutationCount = (patch.removeHeaders?.size ?: 0) + (patch.setHeaders?.size ?: 0) +
        (patch.addHeaders?.size ?: 0)
    require(headerMutationCount <= MAX_ACTION_MUTATIONS) { "at most $MAX_ACTION_MUTATIONS header mutations are allowed" }
    val parameterMutationCount = (patch.removeParameters?.size ?: 0) + (patch.setParameters?.size ?: 0) +
        (patch.addParameters?.size ?: 0)
    require(parameterMutationCount <= MAX_ACTION_MUTATIONS) {
        "at most $MAX_ACTION_MUTATIONS parameter mutations are allowed"
    }
    validateBodyParameterCombination(patch)

    var request = original
    val changes = ArrayList<String>(8)

    patch.method?.let { method ->
        require(method.length in 1..32 && method.matches(HTTP_TOKEN_PATTERN)) { "method must be a valid HTTP token" }
        if (method != request.method()) {
            changes += "method ${request.method()} -> $method"
            request = request.withMethod(method)
        }
    }
    patch.path?.let { path ->
        require(path.length in 1..MAX_ACTION_PATH_CHARS) { "path must contain 1 to $MAX_ACTION_PATH_CHARS characters" }
        require(path.startsWith('/') || path == "*") { "path must start with '/' or equal '*'" }
        require(path.none(Char::isISOControl)) { "path contains forbidden control characters" }
        if (path != request.path()) {
            changes += "path ${request.path().boundedDiff()} -> ${path.boundedDiff()}"
            request = request.withPath(path)
        }
    }

    patch.removeHeaders.orEmpty().forEach { name ->
        validateHeaderName(name)
        request = request.withRemovedHeader(name)
        changes += "remove header ${name.lowercase()}"
    }
    val setHeaders = patch.setHeaders.orEmpty()
    setHeaders.forEach(::validateHeader)
    val setHeaderNames = setHeaders.map { it.name.lowercase() }
    require(setHeaderNames.distinct().size == setHeaderNames.size) {
        "setHeaders contains duplicate header names"
    }
    setHeaders.forEach { header ->
        request = request.withRemovedHeader(header.name).withAddedHeader(header.name, header.value)
        changes += "set header ${header.name.lowercase()}"
    }
    patch.addHeaders.orEmpty().forEach { header ->
        validateHeader(header)
        request = request.withAddedHeader(header.name, header.value)
        changes += "add header ${header.name.lowercase()}"
    }

    val removeParameters = patch.removeParameters.orEmpty()
    val setParameters = patch.setParameters.orEmpty()
    val addParameters = patch.addParameters.orEmpty()
    removeParameters.forEach { validateParameter(it.name, null) }
    setParameters.forEach { validateParameter(it.name, it.value) }
    addParameters.forEach { validateParameter(it.name, it.value) }
    val setKeys = setParameters.map { it.type to it.name }
    require(setKeys.distinct().size == setKeys.size) { "setParameters contains duplicate type/name keys" }

    val keysToReplace = (removeParameters.map { it.type to it.name } + setKeys).toSet()
    if (keysToReplace.isNotEmpty()) {
        val existing = keysToReplace.groupBy({ it.first }, { it.second }).flatMap { (type, names) ->
            val nameSet = names.toHashSet()
            request.parameters(type.toMontoyaType()).filter { it.name() in nameSet }
        }
        if (existing.isNotEmpty()) request = request.withRemovedParameters(existing)
    }
    val parametersToAdd = (setParameters + addParameters).map { parameter ->
        HttpParameter.parameter(parameter.name, parameter.value, parameter.type.toMontoyaType())
    }
    if (parametersToAdd.isNotEmpty()) request = request.withAddedParameters(parametersToAdd)

    removeParameters.forEach { key ->
        changes += "remove ${key.type.serialName()} parameter ${key.name.boundedDiff()}"
    }
    setParameters.forEach { parameter ->
        changes += "set ${parameter.type.serialName()} parameter ${parameter.name.boundedDiff()}"
    }
    addParameters.forEach { parameter ->
        changes += "add ${parameter.type.serialName()} parameter ${parameter.name.boundedDiff()}"
    }

    patch.body?.let { body ->
        val bytes = body.decode()
        request = when (body.encoding) {
            HttpBodyPatchEncoding.TEXT -> request.withBody(body.data)
            HttpBodyPatchEncoding.BASE64 -> request.withBody(MontoyaByteArray.byteArray(*bytes))
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        changes += "replace body (${bytes.size} bytes, sha256:${HexFormat.of().formatHex(digest, 0, 8)})"
    }

    return finalizePatchedRequest(
        request,
        changes.isNotEmpty(),
        changes.ifEmpty { listOf("none (patch was a no-op)") },
        expectedTarget = immutableTarget,
    )
}

private fun finalizePatchedRequest(
    request: HttpRequest,
    changed: Boolean,
    changes: List<String>,
    expectedTarget: HttpActionTarget,
    knownBytes: Int? = null,
): PatchedRequest {
    val bytes = knownBytes ?: requestByteLength(request)
    require(bytes <= MAX_ACTION_REQUEST_BYTES) {
        "resulting request exceeds the $MAX_ACTION_REQUEST_BYTES-byte action limit"
    }
    val service = request.httpService()
    val target = service.toActionTarget()
    require(target == expectedTarget) { "structured patches must not change the destination service" }
    return PatchedRequest(
        request = request,
        service = service,
        target = target,
        changed = changed,
        summary = changes.joinToString("; ").take(2_048),
        requestBytes = bytes,
    )
}

internal fun requestByteLength(request: HttpRequest): Int {
    val headerBytes = request.bodyOffset()
    val bodyBytes = request.body().length()
    require(headerBytes >= 0 && bodyBytes >= 0) { "request reported an invalid byte length" }
    val total = headerBytes.toLong() + bodyBytes.toLong()
    require(total <= Int.MAX_VALUE) { "request is too large" }
    return total.toInt()
}

private fun validateHeader(header: HttpHeaderMutation) {
    validateHeaderName(header.name)
    require(header.value.length <= MAX_ACTION_HEADER_VALUE_CHARS) { "header value is too long" }
    require(header.value.none { it == '\r' || it == '\n' || it == '\u0000' }) {
        "header value contains forbidden control characters"
    }
}

private fun validateHeaderName(name: String) {
    require(name.length in 1..MAX_ACTION_HEADER_NAME_CHARS && name.matches(HTTP_TOKEN_PATTERN)) {
        "header name must be a valid HTTP token"
    }
}

private fun validateParameter(name: String, value: String?) {
    require(name.length in 1..MAX_ACTION_PARAMETER_NAME_CHARS) { "parameter name is empty or too long" }
    require(name.none { it == '\r' || it == '\n' || it == '\u0000' }) {
        "parameter name contains forbidden control characters"
    }
    if (value != null) {
        require(value.length <= MAX_ACTION_PARAMETER_VALUE_CHARS) { "parameter value is too long" }
        require(value.none { it == '\r' || it == '\n' || it == '\u0000' }) {
            "parameter value contains forbidden control characters"
        }
    }
}

private fun validateBodyParameterCombination(patch: HttpRequestPatch) {
    if (patch.body == null) return
    val bodyTypes = setOf(
        HttpActionParameterType.BODY,
        HttpActionParameterType.XML,
        HttpActionParameterType.XML_ATTRIBUTE,
        HttpActionParameterType.MULTIPART_ATTRIBUTE,
        HttpActionParameterType.JSON,
    )
    val hasBodyParameterMutation = patch.removeParameters.orEmpty().any { it.type in bodyTypes } ||
        patch.setParameters.orEmpty().any { it.type in bodyTypes } ||
        patch.addParameters.orEmpty().any { it.type in bodyTypes }
    require(!hasBodyParameterMutation) { "body replacement cannot be combined with body-backed parameter mutations" }
}

private fun HttpBodyPatch.decode(): ByteArray = when (encoding) {
    HttpBodyPatchEncoding.TEXT -> {
        require(data.length <= MAX_ACTION_BODY_BYTES) { "text body exceeds the $MAX_ACTION_BODY_BYTES-byte limit" }
        data.toByteArray(StandardCharsets.UTF_8).also {
            require(it.size <= MAX_ACTION_BODY_BYTES) { "UTF-8 body exceeds the $MAX_ACTION_BODY_BYTES-byte limit" }
        }
    }

    HttpBodyPatchEncoding.BASE64 -> {
        require(data.length <= ((MAX_ACTION_BODY_BYTES + 2) / 3) * 4 + 4) { "base64 body is too large" }
        try {
            Base64.getDecoder().decode(data)
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("body data is not valid base64")
        }.also {
            require(it.size <= MAX_ACTION_BODY_BYTES) { "decoded body exceeds the $MAX_ACTION_BODY_BYTES-byte limit" }
        }
    }
}

private fun normalizeTabName(tabName: String?): String? {
    if (tabName == null) return null
    require(tabName.length <= MAX_ACTION_TAB_NAME_CHARS) { "tabName is too long" }
    require(tabName.none(Char::isISOControl)) { "tabName contains control characters" }
    return tabName
}

private fun HttpReplayMode?.toMontoyaMode(request: HttpRequest): HttpMode = when (this ?: HttpReplayMode.ORIGINAL) {
    HttpReplayMode.ORIGINAL -> if (request.httpVersion().contains('2')) HttpMode.HTTP_2 else HttpMode.HTTP_1
    HttpReplayMode.AUTO -> HttpMode.AUTO
    HttpReplayMode.HTTP_1 -> HttpMode.HTTP_1
    HttpReplayMode.HTTP_2 -> HttpMode.HTTP_2
    HttpReplayMode.HTTP_2_IGNORE_ALPN -> HttpMode.HTTP_2_IGNORE_ALPN
}

private fun HttpRedirectionPolicy?.toMontoyaRedirectionMode(): RedirectionMode = when (this ?: HttpRedirectionPolicy.NEVER) {
    HttpRedirectionPolicy.NEVER -> RedirectionMode.NEVER
    HttpRedirectionPolicy.SAME_HOST -> RedirectionMode.SAME_HOST
    HttpRedirectionPolicy.IN_SCOPE -> RedirectionMode.IN_SCOPE
    HttpRedirectionPolicy.ALWAYS -> RedirectionMode.ALWAYS
}

private fun HttpActionParameterType.toMontoyaType(): HttpParameterType = when (this) {
    HttpActionParameterType.URL -> HttpParameterType.URL
    HttpActionParameterType.BODY -> HttpParameterType.BODY
    HttpActionParameterType.COOKIE -> HttpParameterType.COOKIE
    HttpActionParameterType.XML -> HttpParameterType.XML
    HttpActionParameterType.XML_ATTRIBUTE -> HttpParameterType.XML_ATTRIBUTE
    HttpActionParameterType.MULTIPART_ATTRIBUTE -> HttpParameterType.MULTIPART_ATTRIBUTE
    HttpActionParameterType.JSON -> HttpParameterType.JSON
}

private fun HttpActionParameterType.serialName(): String = name.lowercase()
private fun HttpMessageSource.serialName(): String = name.lowercase()
private fun String.boundedDiff(): String = replace("\r", "\\r").replace("\n", "\\n").take(256)

internal fun HttpResponse.toActionSummary(limit: Int, encoding: String): HttpActionResponseSummary {
    val responseBody = body()
    return HttpActionResponseSummary(
        statusCode = statusCode().toInt(),
        mimeType = mimeType()?.name,
        httpVersion = httpVersion().take(32),
        bodyBytes = responseBody.length(),
        body = if (limit == 0) null else responseBody.toHistorySlice(0, limit, encoding),
    )
}

private fun HttpMessageActionDestination.approvalLabel(): String = when (this) {
    HttpMessageActionDestination.HTTP -> "send this derived HTTP request"
    HttpMessageActionDestination.REPEATER -> "create a Repeater tab from this request"
    HttpMessageActionDestination.INTRUDER -> "send this request to Intruder"
    HttpMessageActionDestination.ORGANIZER -> "send this request to Organizer"
}

private fun HttpMessageActionDestination.routingAuditOperation(): RequestRoutingAuditOperation? = when (this) {
    HttpMessageActionDestination.HTTP -> null
    HttpMessageActionDestination.REPEATER -> RequestRoutingAuditOperation.REPEATER
    HttpMessageActionDestination.INTRUDER -> RequestRoutingAuditOperation.INTRUDER
    HttpMessageActionDestination.ORGANIZER -> RequestRoutingAuditOperation.ORGANIZER
}

private fun HttpMessageActionService.resolutionFailure(
    ref: HttpMessageReference,
    destination: HttpMessageActionDestination,
    failure: HttpMessageBatchResolution.Failed,
) = HttpMessageActionResult(
    status = failure.status.toActionStatus(),
    executionState = HttpMessageExecutionState.NOT_STARTED,
    projectId = failure.projectId,
    ref = ref,
    destination = destination,
    error = failure.error.take(512),
)

private fun HttpMessageResolutionStatus.toActionStatus(): HttpMessageActionStatus = when (this) {
    HttpMessageResolutionStatus.ACCESS_DENIED -> HttpMessageActionStatus.ACCESS_DENIED
    HttpMessageResolutionStatus.INVALID_ARGUMENT -> HttpMessageActionStatus.INVALID_ARGUMENT
    HttpMessageResolutionStatus.INVALID_ID -> HttpMessageActionStatus.INVALID_ID
    HttpMessageResolutionStatus.PROJECT_MISMATCH -> HttpMessageActionStatus.PROJECT_MISMATCH
    HttpMessageResolutionStatus.NOT_FOUND -> HttpMessageActionStatus.NOT_FOUND
    HttpMessageResolutionStatus.REQUEST_UNAVAILABLE -> HttpMessageActionStatus.REQUEST_UNAVAILABLE
    HttpMessageResolutionStatus.BURP_ERROR -> HttpMessageActionStatus.BURP_ERROR
}

private fun invalidArgument(
    projectId: String,
    ref: HttpMessageReference,
    destination: HttpMessageActionDestination,
    error: String,
) = HttpMessageActionResult(
    status = HttpMessageActionStatus.INVALID_ARGUMENT,
    executionState = HttpMessageExecutionState.NOT_STARTED,
    projectId = projectId.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
    ref = HttpMessageReference(ref.source, ref.id.take(MAX_HTTP_REFERENCE_ID_CHARS)),
    destination = destination,
    error = error.take(512),
)

private fun burpError(
    projectId: String,
    ref: HttpMessageReference,
    destination: HttpMessageActionDestination,
    error: Exception,
) = HttpMessageActionResult(
    status = HttpMessageActionStatus.BURP_ERROR,
    executionState = HttpMessageExecutionState.NOT_STARTED,
    projectId = projectId.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
    ref = HttpMessageReference(ref.source, ref.id.take(MAX_HTTP_REFERENCE_ID_CHARS)),
    destination = destination,
    error = "Burp could not prepare the request action: ${safeException(error)}",
)

private fun denied(
    projectId: String,
    ref: HttpMessageReference,
    destination: HttpMessageActionDestination,
    patched: PatchedRequest,
    tabName: String? = null,
    changes: String = patched.summary,
    insertionPointCount: Int? = null,
) = HttpMessageActionResult(
    status = HttpMessageActionStatus.ACTION_DENIED,
    executionState = HttpMessageExecutionState.NOT_STARTED,
    projectId = projectId,
    ref = ref,
    destination = destination,
    target = patched.target,
    patchApplied = patched.changed,
    changes = changes,
    requestBytes = patched.requestBytes,
    tabName = tabName,
    insertionPointCount = insertionPointCount,
    error = "action denied by Burp Suite",
)

private fun success(
    projectId: String,
    ref: HttpMessageReference,
    destination: HttpMessageActionDestination,
    patched: PatchedRequest,
    tabName: String? = null,
    changes: String = patched.summary,
    insertionPointCount: Int? = null,
    response: HttpActionResponseSummary? = null,
    recordedInSiteMap: Boolean? = null,
    recordedRef: HttpMessageReference? = null,
    preservedResponseInOrganizer: Boolean? = null,
    error: String? = null,
) = HttpMessageActionResult(
    status = HttpMessageActionStatus.OK,
    executionState = HttpMessageExecutionState.COMPLETED,
    projectId = projectId,
    ref = ref,
    destination = destination,
    target = patched.target,
    patchApplied = patched.changed,
    changes = changes,
    requestBytes = patched.requestBytes,
    tabName = tabName,
    insertionPointCount = insertionPointCount,
    response = response,
    recordedInSiteMap = recordedInSiteMap,
    recordedRef = recordedRef,
    preservedResponseInOrganizer = preservedResponseInOrganizer,
    error = error?.take(512),
)

private fun uncertain(
    projectId: String,
    ref: HttpMessageReference,
    destination: HttpMessageActionDestination,
    patched: PatchedRequest,
    error: Exception,
    tabName: String? = null,
    changes: String = patched.summary,
    insertionPointCount: Int? = null,
) = HttpMessageActionResult(
    status = HttpMessageActionStatus.EXECUTION_UNCERTAIN,
    executionState = HttpMessageExecutionState.UNCERTAIN,
    projectId = projectId,
    ref = ref,
    destination = destination,
    target = patched.target,
    patchApplied = patched.changed,
    changes = changes,
    requestBytes = patched.requestBytes,
    tabName = tabName,
    insertionPointCount = insertionPointCount,
    error = safeException(error),
)

private fun safeException(error: Exception): String = safeExceptionSummary(error)

private fun HttpService.toActionTarget() = HttpActionTarget(
    host().take(MAX_HTTP_SEARCH_HOST_CHARS),
    port(),
    secure(),
)

private fun auditLine(
    destination: HttpMessageActionDestination,
    resolved: ResolvedHttpMessage,
    patched: PatchedRequest,
    outcome: String,
): String {
    return "MCP request action: destination=${destination.name.lowercase()} source=${resolved.ref.source.name.lowercase()}:" +
        "${resolved.ref.id.take(MAX_HTTP_REFERENCE_ID_CHARS)} target=${patched.target.host}:" +
        "${patched.target.port} requestBytes=${patched.requestBytes} patchApplied=${patched.changed} outcome=$outcome"
}
