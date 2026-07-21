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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.RequestActionSecurity
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.HexFormat

internal const val MAX_ACTION_REQUEST_BYTES = 2 * 1024 * 1024
internal const val DEFAULT_ACTION_RESPONSE_BODY_BYTES = 8 * 1024
internal const val MAX_ACTION_RESPONSE_BODY_BYTES = 64 * 1024
private const val MAX_ACTION_PROJECT_ID_CHARS = 256
private const val MAX_ACTION_ID_CHARS = 128
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
    val projectId: String,
    val ref: HttpMessageReference,
    val patch: HttpRequestPatch? = null,
    val httpMode: HttpReplayMode? = null,
    val redirection: HttpRedirectionPolicy? = null,
    val responseTimeoutMs: Int? = null,
    val responseBodyLimit: Int? = null,
    val responseBodyEncoding: String? = null,
)

@Serializable
data class CreateRepeaterTabFromId(
    val projectId: String,
    val ref: HttpMessageReference,
    val patch: HttpRequestPatch? = null,
    val tabName: String? = null,
)

@Serializable
data class SendToIntruderFromId(
    val projectId: String,
    val ref: HttpMessageReference,
    val patch: HttpRequestPatch? = null,
    val tabName: String? = null,
)

@Serializable
data class SendToOrganizerFromId(
    val projectId: String,
    val ref: HttpMessageReference,
    val patch: HttpRequestPatch? = null,
)

@Serializable
data class HttpRequestPatch(
    val method: String? = null,
    val path: String? = null,
    val removeHeaders: List<String>? = null,
    val setHeaders: List<HttpHeaderMutation>? = null,
    val addHeaders: List<HttpHeaderMutation>? = null,
    val removeParameters: List<HttpParameterKey>? = null,
    val setParameters: List<HttpParameterMutation>? = null,
    val addParameters: List<HttpParameterMutation>? = null,
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
    val response: HttpActionResponseSummary? = null,
    val recordedInSiteMap: Boolean? = null,
    val preservedResponseInOrganizer: Boolean? = null,
    val error: String? = null,
)

internal class HttpMessageActionService(
    private val api: MontoyaApi,
    private val config: McpConfig,
) {
    suspend fun send(input: SendHttpRequestFromId): HttpMessageActionResult {
        val validated = validateCommon(input.projectId, input.ref)
            ?: return invalidArgument(input.projectId, input.ref, HttpMessageActionDestination.HTTP, "invalid reference")
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

        val resolved = when (val outcome = resolveSafely(validated)) {
            is Resolution.Found -> outcome.message
            is Resolution.Failed -> return resolutionFailure(input.ref, HttpMessageActionDestination.HTTP, outcome)
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

        val recorded = recordHttpResponseInSiteMap(api, response)
        var summaryError: String? = null
        val responseSummary = try {
            response?.response()?.toActionSummary(bodyLimit, bodyEncoding)
        } catch (e: Exception) {
            val message = "request completed but its response preview could not be created: ${safeException(e)}"
            summaryError = message
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
            recordedInSiteMap = recorded,
            error = summaryError,
        )
    }

    suspend fun createRepeaterTab(input: CreateRepeaterTabFromId): HttpMessageActionResult = route(
        projectId = input.projectId,
        ref = input.ref,
        patch = input.patch,
        destination = HttpMessageActionDestination.REPEATER,
        tabName = input.tabName,
    ) { _, patched, tabName ->
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
    ) { _, patched, tabName ->
        if (tabName == null) api.intruder().sendToIntruder(patched.request)
        else api.intruder().sendToIntruder(patched.request, tabName)
        false
    }

    suspend fun sendToOrganizer(input: SendToOrganizerFromId): HttpMessageActionResult = route(
        projectId = input.projectId,
        ref = input.ref,
        patch = input.patch,
        destination = HttpMessageActionDestination.ORGANIZER,
        tabName = null,
    ) { resolved, patched, _ ->
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
        execute: (ResolvedHttpMessage, PatchedRequest, String?) -> Boolean,
    ): HttpMessageActionResult {
        val validated = validateCommon(projectId, ref)
            ?: return invalidArgument(projectId, ref, destination, "invalid reference")
        val normalizedTabName = try {
            normalizeTabName(tabName)
        } catch (e: IllegalArgumentException) {
            return invalidArgument(projectId, ref, destination, e.message.orEmpty())
        }
        val resolved = when (val outcome = resolveSafely(validated)) {
            is Resolution.Found -> outcome.message
            is Resolution.Failed -> return resolutionFailure(ref, destination, outcome)
        }
        val patched = try {
            applyPatch(resolved.request, patch)
        } catch (e: IllegalArgumentException) {
            return invalidArgument(projectId, ref, destination, e.message.orEmpty())
        } catch (e: Exception) {
            return burpError(projectId, ref, destination, e)
        }
        val approved = try {
            approveRoutingAction(destination, resolved, patched)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return burpError(projectId, ref, destination, e)
        }
        if (!approved) {
            return denied(projectId, ref, destination, patched, normalizedTabName)
        }

        currentCoroutineContext().ensureActive()
        val preserved = try {
            execute(resolved, patched, normalizedTabName)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            runCatching { api.logging().logToError(auditLine(destination, resolved, patched, "execution uncertain")) }
            return uncertain(projectId, ref, destination, patched, e, normalizedTabName)
        }
        runCatching { api.logging().logToOutput(auditLine(destination, resolved, patched, "completed")) }
        return success(
            projectId,
            ref,
            destination,
            patched,
            tabName = normalizedTabName,
            preservedResponseInOrganizer = if (destination == HttpMessageActionDestination.ORGANIZER) preserved else null,
        )
    }

    private suspend fun resolveSafely(validated: ValidatedReference): Resolution = try {
        resolve(validated)
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        Resolution.Failed(
            HttpMessageActionStatus.BURP_ERROR,
            validated.projectId,
            "Burp could not resolve the HTTP message: ${safeException(e)}",
        )
    }

    private suspend fun resolve(validated: ValidatedReference): Resolution {
        val currentProjectId = api.project().id()
        if (validated.projectId != currentProjectId) {
            return Resolution.Failed(
                HttpMessageActionStatus.PROJECT_MISMATCH,
                currentProjectId,
                "reference belongs to a different Burp project",
            )
        }

        val parsedSiteMapId = if (validated.ref.source == HttpMessageSource.SITE_MAP) {
            parseSiteMapId(validated.ref.id) ?: return Resolution.Failed(
                HttpMessageActionStatus.INVALID_ID,
                currentProjectId,
                "Site Map reference ID must come from search_http_messages",
            )
        } else {
            null
        }
        if (validated.ref.source != HttpMessageSource.SITE_MAP && validated.numericId == null) {
            return Resolution.Failed(
                HttpMessageActionStatus.INVALID_ID,
                currentProjectId,
                "${validated.ref.source.displayNameForAction()} reference ID must be a non-negative integer",
            )
        }

        val accessType = when (validated.ref.source) {
            HttpMessageSource.PROXY -> DataAccessType.HTTP_HISTORY
            HttpMessageSource.SITE_MAP -> DataAccessType.SITE_MAP
            HttpMessageSource.ORGANIZER -> DataAccessType.ORGANIZER
        }
        if (!DataAccessSecurity.checkDataAccessPermission(accessType, config)) {
            api.logging().logToOutput("MCP request action source access denied: ${validated.ref.source.serialName()}")
            return Resolution.Failed(
                HttpMessageActionStatus.ACCESS_DENIED,
                currentProjectId,
                "${validated.ref.source.displayNameForAction()} access denied by Burp Suite",
            )
        }
        api.logging().logToOutput("MCP request action source access granted: ${validated.ref.source.serialName()}")

        return when (validated.ref.source) {
            HttpMessageSource.PROXY -> {
                val item = api.proxy().history { it.id() == validated.numericId }.firstOrNull()
                    ?: return notFound(currentProjectId)
                val request = item.request() ?: return requestUnavailable(currentProjectId)
                Resolution.Found(
                    ResolvedHttpMessage(validated.ref, request, item.response(), null),
                )
            }

            HttpMessageSource.ORGANIZER -> {
                val item = api.organizer().items { it.id() == validated.numericId }.firstOrNull()
                    ?: return notFound(currentProjectId)
                val request = item.request() ?: return requestUnavailable(currentProjectId)
                Resolution.Found(
                    ResolvedHttpMessage(validated.ref, request, item.response(), item),
                )
            }

            HttpMessageSource.SITE_MAP -> {
                val parsed = requireNotNull(parsedSiteMapId)
                val item = api.siteMap().requestResponses().getOrNull(parsed.index)
                    ?: return notFound(currentProjectId)
                if (stableSiteMapId(currentProjectId, parsed.index, item) != validated.ref.id) {
                    return notFound(currentProjectId)
                }
                val request = item.request() ?: return requestUnavailable(currentProjectId)
                Resolution.Found(
                    ResolvedHttpMessage(validated.ref, request, item.response(), item),
                )
            }
        }
    }

    private fun notFound(projectId: String) = Resolution.Failed(
        HttpMessageActionStatus.NOT_FOUND,
        projectId,
        "HTTP message reference was not found or changed after it was issued",
    )

    private fun requestUnavailable(projectId: String) = Resolution.Failed(
        HttpMessageActionStatus.REQUEST_UNAVAILABLE,
        projectId,
        "HTTP message exists but its request is unavailable",
    )

    private fun validateCommon(
        projectId: String,
        ref: HttpMessageReference,
    ): ValidatedReference? {
        if (projectId.isEmpty() || projectId.length > MAX_ACTION_PROJECT_ID_CHARS || projectId.any(Char::isISOControl)) {
            return null
        }
        if (ref.id.isEmpty() || ref.id.length > MAX_ACTION_ID_CHARS || ref.id.any(Char::isISOControl)) return null
        val numericId = if (ref.source == HttpMessageSource.SITE_MAP) null else ref.id.toIntOrNull()?.takeIf { it >= 0 }
        return ValidatedReference(projectId, ref, numericId)
    }

    private suspend fun approveNetworkAction(
        resolved: ResolvedHttpMessage,
        patched: PatchedRequest,
    ): Boolean {
        val service = patched.request.httpService()
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
    ): Boolean {
        if (!config.requireRequestActionApproval) return true
        val service = patched.request.httpService()
        return RequestActionSecurity.checkPermission(
            action = destination.approvalLabel(),
            source = "${resolved.ref.source.serialName()}:${resolved.ref.id}",
            target = "${service.host()}:${service.port()} (${if (service.secure()) "HTTPS" else "HTTP"})",
            changes = patched.summary,
            requestContent = patched.requestContent,
            config = config,
            api = api,
        )
    }
}

private data class ValidatedReference(
    val projectId: String,
    val ref: HttpMessageReference,
    val numericId: Int?,
)

private sealed interface Resolution {
    data class Found(val message: ResolvedHttpMessage) : Resolution
    data class Failed(
        val status: HttpMessageActionStatus,
        val projectId: String?,
        val error: String,
    ) : Resolution
}

private data class ResolvedHttpMessage(
    val ref: HttpMessageReference,
    val request: HttpRequest,
    val response: HttpResponse?,
    val envelope: MontoyaHttpRequestResponse?,
)

private class PatchedRequest(
    val request: HttpRequest,
    val changed: Boolean,
    val summary: String,
    val requestBytes: Int,
) {
    val requestContent: String by lazy(LazyThreadSafetyMode.NONE) { request.toString() }
}

private fun applyPatch(original: HttpRequest, patch: HttpRequestPatch?): PatchedRequest {
    val originalBytes = requestByteLength(original)
    require(originalBytes <= MAX_ACTION_REQUEST_BYTES) {
        "source request exceeds the $MAX_ACTION_REQUEST_BYTES-byte action limit"
    }
    if (patch == null) {
        return finalizePatchedRequest(
            original,
            false,
            listOf("none (exact source request)"),
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

    return finalizePatchedRequest(request, changes.isNotEmpty(), changes.ifEmpty { listOf("none (patch was a no-op)") })
}

private fun finalizePatchedRequest(
    request: HttpRequest,
    changed: Boolean,
    changes: List<String>,
    knownBytes: Int? = null,
): PatchedRequest {
    val bytes = knownBytes ?: requestByteLength(request)
    require(bytes <= MAX_ACTION_REQUEST_BYTES) {
        "resulting request exceeds the $MAX_ACTION_REQUEST_BYTES-byte action limit"
    }
    return PatchedRequest(
        request = request,
        changed = changed,
        summary = changes.joinToString("; ").take(2_048),
        requestBytes = bytes,
    )
}

private fun requestByteLength(request: HttpRequest): Int {
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

private fun HttpResponse.toActionSummary(limit: Int, encoding: String): HttpActionResponseSummary {
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

private fun HttpMessageSource.displayNameForAction(): String = when (this) {
    HttpMessageSource.PROXY -> "Proxy history"
    HttpMessageSource.SITE_MAP -> "Site Map"
    HttpMessageSource.ORGANIZER -> "Organizer"
}

private fun HttpMessageActionService.resolutionFailure(
    ref: HttpMessageReference,
    destination: HttpMessageActionDestination,
    failure: Resolution.Failed,
) = HttpMessageActionResult(
    status = failure.status,
    executionState = HttpMessageExecutionState.NOT_STARTED,
    projectId = failure.projectId,
    ref = ref,
    destination = destination,
    error = failure.error.take(512),
)

private fun invalidArgument(
    projectId: String,
    ref: HttpMessageReference,
    destination: HttpMessageActionDestination,
    error: String,
) = HttpMessageActionResult(
    status = HttpMessageActionStatus.INVALID_ARGUMENT,
    executionState = HttpMessageExecutionState.NOT_STARTED,
    projectId = projectId.take(MAX_ACTION_PROJECT_ID_CHARS),
    ref = HttpMessageReference(ref.source, ref.id.take(MAX_ACTION_ID_CHARS)),
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
    projectId = projectId.take(MAX_ACTION_PROJECT_ID_CHARS),
    ref = HttpMessageReference(ref.source, ref.id.take(MAX_ACTION_ID_CHARS)),
    destination = destination,
    error = "Burp could not prepare the request action: ${safeException(error)}",
)

private fun denied(
    projectId: String,
    ref: HttpMessageReference,
    destination: HttpMessageActionDestination,
    patched: PatchedRequest,
    tabName: String? = null,
) = HttpMessageActionResult(
    status = HttpMessageActionStatus.ACTION_DENIED,
    executionState = HttpMessageExecutionState.NOT_STARTED,
    projectId = projectId,
    ref = ref,
    destination = destination,
    target = patched.request.httpService().toActionTarget(),
    patchApplied = patched.changed,
    changes = patched.summary,
    requestBytes = patched.requestBytes,
    tabName = tabName,
    error = "action denied by Burp Suite",
)

private fun success(
    projectId: String,
    ref: HttpMessageReference,
    destination: HttpMessageActionDestination,
    patched: PatchedRequest,
    tabName: String? = null,
    response: HttpActionResponseSummary? = null,
    recordedInSiteMap: Boolean? = null,
    preservedResponseInOrganizer: Boolean? = null,
    error: String? = null,
) = HttpMessageActionResult(
    status = HttpMessageActionStatus.OK,
    executionState = HttpMessageExecutionState.COMPLETED,
    projectId = projectId,
    ref = ref,
    destination = destination,
    target = patched.request.httpService().toActionTarget(),
    patchApplied = patched.changed,
    changes = patched.summary,
    requestBytes = patched.requestBytes,
    tabName = tabName,
    response = response,
    recordedInSiteMap = recordedInSiteMap,
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
) = HttpMessageActionResult(
    status = HttpMessageActionStatus.EXECUTION_UNCERTAIN,
    executionState = HttpMessageExecutionState.UNCERTAIN,
    projectId = projectId,
    ref = ref,
    destination = destination,
    target = patched.request.httpService().toActionTarget(),
    patchApplied = patched.changed,
    changes = patched.summary,
    requestBytes = patched.requestBytes,
    tabName = tabName,
    error = safeException(error),
)

private fun safeException(error: Exception): String =
    "${error::class.simpleName ?: "Exception"}: ${error.message.orEmpty()}".take(512)

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
    val target = patched.request.httpService()
    return "MCP request action: destination=${destination.name.lowercase()} source=${resolved.ref.source.name.lowercase()}:" +
        "${resolved.ref.id.take(MAX_ACTION_ID_CHARS)} target=${target.host().take(MAX_HTTP_SEARCH_HOST_CHARS)}:" +
        "${target.port()} requestBytes=${patched.requestBytes} patchApplied=${patched.changed} outcome=$outcome"
}
