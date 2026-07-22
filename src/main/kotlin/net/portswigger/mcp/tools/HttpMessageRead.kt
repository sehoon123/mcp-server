package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.security.safeExceptionSummary

@Serializable
data class GetHttpMessage(
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Proxy, Site Map, or Organizer reference returned by search_http_messages.")
    val ref: HttpMessageReference,
    @JsonSchemaMetadata(
        enumValues = ["metadata", "request", "request_headers", "request_body", "response", "response_headers", "response_body"],
        defaultJson = "\"metadata\"",
    )
    val part: String? = null,
    @JsonSchemaMetadata(minimum = 0, defaultJson = "0")
    val offset: Int? = null,
    @JsonSchemaMetadata(minimum = 1, maximum = 262144, defaultJson = "32768")
    val limit: Int? = null,
    @JsonSchemaMetadata(enumValues = ["text", "base64"], defaultJson = "\"text\"")
    val encoding: String? = null,
)

@Serializable
enum class HttpMessageReadStatus {
    @SerialName("ok")
    OK,

    @SerialName("access_denied")
    ACCESS_DENIED,

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

    @SerialName("part_unavailable")
    PART_UNAVAILABLE,

    @SerialName("burp_error")
    BURP_ERROR,
}

@Serializable
data class UnifiedHttpMessageMetadata(
    val projectId: String,
    val ref: HttpMessageReference,
    val method: String,
    val url: String,
    val urlTruncated: Boolean,
    val host: String,
    val port: Int,
    val secure: Boolean,
    val statusCode: Int?,
    val mimeType: String?,
    val hasResponse: Boolean,
    val requestBodyBytes: Int,
    val responseBodyBytes: Int?,
    val time: String? = null,
    val listenerPort: Int? = null,
    val edited: Boolean? = null,
    val inScope: Boolean? = null,
    val notes: String? = null,
    val notesTruncated: Boolean = false,
)

@Serializable
data class GetHttpMessageResult(
    val status: HttpMessageReadStatus,
    val projectId: String?,
    val ref: HttpMessageReference,
    val part: String,
    val metadata: UnifiedHttpMessageMetadata? = null,
    val content: HistoryContentSlice? = null,
    val error: String? = null,
)

internal class HttpMessageReadService(
    private val api: MontoyaApi,
    config: McpConfig,
) {
    private val resolver = HttpMessageResolver(api, config)

    suspend fun read(input: GetHttpMessage): GetHttpMessageResult {
        val normalizedPart: String
        val normalizedOffset: Int
        val normalizedLimit: Int
        val normalizedEncoding: String
        try {
            normalizedPart = normalizeHttpPart(input.part)
            normalizedOffset = normalizeHistoryOffset(input.offset)
            normalizedLimit = normalizeHistoryLimit(input.limit)
            normalizedEncoding = normalizeHistoryEncoding(input.encoding)
        } catch (e: IllegalArgumentException) {
            return readError(
                status = HttpMessageReadStatus.INVALID_ARGUMENT,
                projectId = input.projectId.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
                ref = input.ref,
                part = input.part?.take(64) ?: "metadata",
                message = e.message.orEmpty(),
            )
        }

        val found = when (
            val resolution = resolver.resolve(input.projectId, input.ref, includeSourceMetadata = true)
        ) {
            is HttpMessageBatchResolution.Found -> resolution
            is HttpMessageBatchResolution.Failed -> return readError(
                status = resolution.status.toReadStatus(),
                projectId = resolution.projectId,
                ref = resolution.ref ?: input.ref,
                part = normalizedPart,
                message = resolution.error,
            )
        }

        val result = try {
            currentCoroutineContext().ensureActive()
            readResolved(
                projectId = found.projectId,
                resolved = found.messages.single(),
                part = normalizedPart,
                offset = normalizedOffset,
                limit = normalizedLimit,
                encoding = normalizedEncoding,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: IllegalArgumentException) {
            return readError(
                status = HttpMessageReadStatus.INVALID_ARGUMENT,
                projectId = found.projectId,
                ref = input.ref,
                part = normalizedPart,
                message = e.message.orEmpty(),
            )
        } catch (e: Exception) {
            return readError(
                status = HttpMessageReadStatus.BURP_ERROR,
                projectId = found.projectId,
                ref = input.ref,
                part = normalizedPart,
                message = "Burp could not read the HTTP message: ${safeExceptionSummary(e)}",
            )
        }

        val currentProjectId = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return readError(
                status = HttpMessageReadStatus.BURP_ERROR,
                projectId = found.projectId,
                ref = input.ref,
                part = normalizedPart,
                message = "Burp could not recheck the current project: ${safeExceptionSummary(e)}",
            )
        }
        if (currentProjectId != found.projectId) {
            return readError(
                status = HttpMessageReadStatus.PROJECT_MISMATCH,
                projectId = currentProjectId,
                ref = input.ref,
                part = normalizedPart,
                message = "reference belongs to a different Burp project",
            )
        }
        return result
    }
}

private fun readResolved(
    projectId: String,
    resolved: ResolvedHttpMessage,
    part: String,
    offset: Int,
    limit: Int,
    encoding: String,
): GetHttpMessageResult {
    val request = resolved.request
    val response = resolved.response
    val service = request.httpService()
    val rawUrl = request.url()
    val sourceMetadata = resolved.sourceMetadata
    val metadata = UnifiedHttpMessageMetadata(
        projectId = projectId,
        ref = resolved.ref,
        method = request.method().take(32),
        url = rawUrl.take(MAX_HTTP_SEARCH_URL_CHARS),
        urlTruncated = rawUrl.length > MAX_HTTP_SEARCH_URL_CHARS,
        host = service.host().take(MAX_HTTP_SEARCH_HOST_CHARS),
        port = service.port(),
        secure = service.secure(),
        statusCode = response?.statusCode()?.toInt(),
        mimeType = response?.mimeType()?.name,
        hasResponse = response != null,
        requestBodyBytes = request.body().length(),
        responseBodyBytes = response?.body()?.length(),
        time = sourceMetadata?.time,
        listenerPort = sourceMetadata?.listenerPort,
        edited = sourceMetadata?.edited,
        inScope = sourceMetadata?.inScope,
        notes = sourceMetadata?.notes,
        notesTruncated = sourceMetadata?.notesTruncated == true,
    )
    if (part == "metadata") {
        return GetHttpMessageResult(
            status = HttpMessageReadStatus.OK,
            projectId = projectId,
            ref = resolved.ref,
            part = part,
            metadata = metadata,
        )
    }

    val bytes: MontoyaByteArray? = when (part) {
        "request" -> request.toByteArray()
        "request_headers" -> request.toByteArray().subArray(0, request.bodyOffset())
        "request_body" -> request.body()
        "response" -> response?.toByteArray()
        "response_headers" -> response?.let { it.toByteArray().subArray(0, it.bodyOffset()) }
        "response_body" -> response?.body()
        else -> error("Unsupported HTTP message part: $part")
    }
    if (bytes == null) {
        return GetHttpMessageResult(
            status = HttpMessageReadStatus.PART_UNAVAILABLE,
            projectId = projectId,
            ref = resolved.ref,
            part = part,
            metadata = metadata,
            error = "$part is not available for ${resolved.ref.source.displayNameForResolution()} item",
        )
    }
    return GetHttpMessageResult(
        status = HttpMessageReadStatus.OK,
        projectId = projectId,
        ref = resolved.ref,
        part = part,
        metadata = metadata,
        content = bytes.toHistorySlice(offset, limit, encoding),
    )
}

private fun HttpMessageResolutionStatus.toReadStatus(): HttpMessageReadStatus = when (this) {
    HttpMessageResolutionStatus.ACCESS_DENIED -> HttpMessageReadStatus.ACCESS_DENIED
    HttpMessageResolutionStatus.INVALID_ARGUMENT -> HttpMessageReadStatus.INVALID_ARGUMENT
    HttpMessageResolutionStatus.INVALID_ID -> HttpMessageReadStatus.INVALID_ID
    HttpMessageResolutionStatus.PROJECT_MISMATCH -> HttpMessageReadStatus.PROJECT_MISMATCH
    HttpMessageResolutionStatus.NOT_FOUND -> HttpMessageReadStatus.NOT_FOUND
    HttpMessageResolutionStatus.REQUEST_UNAVAILABLE -> HttpMessageReadStatus.REQUEST_UNAVAILABLE
    HttpMessageResolutionStatus.BURP_ERROR -> HttpMessageReadStatus.BURP_ERROR
}

private fun readError(
    status: HttpMessageReadStatus,
    projectId: String?,
    ref: HttpMessageReference,
    part: String,
    message: String,
) = GetHttpMessageResult(
    status = status,
    projectId = projectId?.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
    ref = HttpMessageReference(ref.source, ref.id.take(MAX_HTTP_REFERENCE_ID_CHARS)),
    part = part.take(64),
    error = message.take(512),
)
