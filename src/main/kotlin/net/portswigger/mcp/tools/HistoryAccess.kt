package net.portswigger.mcp.tools

import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.websocket.Direction
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.schema.JsonSchemaMetadata
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.util.Base64
import java.util.HexFormat
import kotlin.math.min

internal const val DEFAULT_HISTORY_SLICE_BYTES = 32 * 1024
internal const val MAX_HISTORY_SLICE_BYTES = 256 * 1024
internal const val MAX_NOTES_CHARS = 2_000
internal const val MCP_PROJECT_ID_INPUT_DESCRIPTION =
    "Opaque ID from burp://project/summary or the producing search/list result; it must match the current project and every supplied reference or cursor."
private const val SCANNER_IDENTITY_CHUNK_CHARS = 8 * 1024
private const val SCANNER_TEXT_ENCODING_BUFFER_BYTES = 8 * 1024
private val HTTP_MESSAGE_PARTS = setOf(
    "metadata",
    "request",
    "request_headers",
    "request_body",
    "response",
    "response_headers",
    "response_body",
)
private val SCANNER_ISSUE_FIELDS = setOf(
    "metadata",
    "detail",
    "remediation",
    "evidence_request",
    "evidence_response",
)

@Serializable
data class ProxyHttpHistorySummary(
    val id: Int,
    val time: String,
    val method: String,
    val url: String,
    val host: String,
    val port: Int,
    val secure: Boolean,
    val statusCode: Int?,
    val mimeType: String?,
    val listenerPort: Int,
    val edited: Boolean,
    val requestBodyBytes: Int,
    val responseBodyBytes: Int?,
    @JsonSchemaMetadata(maxLength = MAX_NOTES_CHARS)
    val notes: String?,
    @JsonSchemaMetadata(description = "True when notes was truncated to its 2,000-character output bound.")
    val notesTruncated: Boolean,
)

@Serializable
data class WebSocketHistorySummary(
    val id: Int,
    val webSocketId: Int,
    val time: String,
    val direction: String,
    val payloadBytes: Int,
    val listenerPort: Int,
    @JsonSchemaMetadata(maxLength = MAX_NOTES_CHARS)
    val notes: String?,
    @JsonSchemaMetadata(description = "True when notes was truncated to its 2,000-character output bound.")
    val notesTruncated: Boolean,
)

@Serializable
data class OrganizerItemSummary(
    val id: Int,
    val status: String,
    val url: String,
    val statusCode: Int?,
    val requestBodyBytes: Int,
    val responseBodyBytes: Int?,
    @JsonSchemaMetadata(maxLength = MAX_NOTES_CHARS)
    val notes: String?,
    @JsonSchemaMetadata(description = "True when notes was truncated to its 2,000-character output bound.")
    val notesTruncated: Boolean,
)

@Serializable
data class ScannerIssueSummary(
    val id: String,
    @JsonSchemaMetadata(maxLength = 512)
    val name: String?,
    @JsonSchemaMetadata(description = "True when name was truncated to its 512-character output bound.")
    val nameTruncated: Boolean,
    @JsonSchemaMetadata(maxLength = MAX_HTTP_SEARCH_URL_CHARS)
    val baseUrl: String?,
    @JsonSchemaMetadata(description = "True when baseUrl was truncated to its 2,048-character output bound.")
    val baseUrlTruncated: Boolean,
    @JsonSchemaMetadata(maxLength = MAX_HTTP_SEARCH_HOST_CHARS)
    val host: String?,
    @JsonSchemaMetadata(description = "True when host was truncated to its 253-character output bound.")
    val hostTruncated: Boolean,
    val port: Int?,
    val secure: Boolean?,
    val severity: String,
    val confidence: String,
    val definitionTypeIndex: Int,
    /** Null because Montoya exposes evidence only as a potentially unbounded materialized list. */
    val evidenceCount: Int? = null,
)

@Serializable
enum class HistoryReadStatus {
    @SerialName("ok")
    OK,

    @SerialName("invalid_argument")
    INVALID_ARGUMENT,

    @SerialName("access_denied")
    ACCESS_DENIED,

    @SerialName("not_found")
    NOT_FOUND,

    @SerialName("scan_limit_reached")
    SCAN_LIMIT_REACHED,

    @SerialName("project_mismatch")
    PROJECT_MISMATCH,

    @SerialName("part_unavailable")
    PART_UNAVAILABLE,

    @SerialName("field_unavailable")
    FIELD_UNAVAILABLE,

    @SerialName("burp_error")
    BURP_ERROR,
}

@Serializable
data class HistoryContentSlice(
    val encoding: String,
    val data: String,
    val offsetBytes: Int,
    val returnedBytes: Int,
    val totalBytes: Int,
    val hasMore: Boolean,
    val nextOffsetBytes: Int?,
)

@Serializable
data class HttpMessageMetadata(
    val id: Int,
    val source: String,
    val method: String,
    val url: String,
    val host: String,
    val port: Int,
    val secure: Boolean,
    val time: String?,
    val statusCode: Int?,
    val mimeType: String?,
    val listenerPort: Int?,
    val edited: Boolean?,
    @JsonSchemaMetadata(maxLength = MAX_NOTES_CHARS)
    val notes: String?,
    @JsonSchemaMetadata(description = "True when notes was truncated to its 2,000-character output bound.")
    val notesTruncated: Boolean,
)

@Serializable
data class HttpMessageReadResult(
    val status: HistoryReadStatus,
    val id: Int,
    val part: String,
    val metadata: HttpMessageMetadata? = null,
    val content: HistoryContentSlice? = null,
    val error: String? = null,
)

@Serializable
data class WebSocketMessageMetadata(
    val id: Int,
    val webSocketId: Int,
    val time: String,
    val direction: String,
    val listenerPort: Int,
    val payloadVariant: String,
    @JsonSchemaMetadata(maxLength = MAX_NOTES_CHARS)
    val notes: String?,
    @JsonSchemaMetadata(description = "True when notes was truncated to its 2,000-character output bound.")
    val notesTruncated: Boolean,
)

@Serializable
data class WebSocketMessageReadResult(
    @JsonSchemaMetadata(description = "Outcome; invalid_argument and burp_error set MCP isError=true, and no mutation occurs.")
    val status: HistoryReadStatus,
    val id: Int,
    @JsonSchemaMetadata(description = "Effective project binding when safely known.")
    val projectId: String? = null,
    val metadata: WebSocketMessageMetadata? = null,
    val content: HistoryContentSlice? = null,
    @JsonSchemaMetadata(maxLength = MAX_STRUCTURED_TOOL_ERROR_CHARS)
    val error: String? = null,
)

@Serializable
data class ScannerIssueReadResult(
    @JsonSchemaMetadata(description = "Outcome; invalid_argument and burp_error set MCP isError=true, and no mutation occurs.")
    val status: HistoryReadStatus,
    val id: String,
    val field: String,
    @JsonSchemaMetadata(description = "Effective project binding when safely known.")
    val projectId: String? = null,
    val summary: ScannerIssueSummary? = null,
    val evidenceIndex: Int? = null,
    val content: HistoryContentSlice? = null,
    @JsonSchemaMetadata(maxLength = MAX_STRUCTURED_TOOL_ERROR_CHARS)
    val error: String? = null,
)

internal fun ProxyHttpRequestResponse.toHistorySummary(): ProxyHttpHistorySummary {
    val request = request()
    val response = response()
    val service = httpService()
    val notes = annotations().notes().boundedNotes()
    return ProxyHttpHistorySummary(
        id = id(),
        time = time().toString(),
        method = request?.method().orEmpty(),
        url = request?.url().orEmpty(),
        host = service.host(),
        port = service.port(),
        secure = service.secure(),
        statusCode = response?.statusCode()?.toInt(),
        mimeType = if (response != null) mimeType().name else null,
        listenerPort = listenerPort(),
        edited = edited(),
        requestBodyBytes = request?.body()?.length() ?: 0,
        responseBodyBytes = response?.body()?.length(),
        notes = notes.first,
        notesTruncated = notes.second,
    )
}

internal fun ProxyWebSocketMessage.toHistorySummary(): WebSocketHistorySummary {
    val notes = annotations().notes().boundedNotes()
    return WebSocketHistorySummary(
        id = id(),
        webSocketId = webSocketId(),
        time = time().toString(),
        direction = direction().name,
        payloadBytes = payload()?.length() ?: 0,
        listenerPort = listenerPort(),
        notes = notes.first,
        notesTruncated = notes.second,
    )
}

internal fun OrganizerItem.toHistorySummary(): OrganizerItemSummary {
    val request = request()
    val response = response()
    val notes = annotations().notes().boundedNotes()
    return OrganizerItemSummary(
        id = id(),
        status = status().displayName(),
        url = request?.url().orEmpty(),
        statusCode = response?.statusCode()?.toInt(),
        requestBodyBytes = request?.body()?.length() ?: 0,
        responseBodyBytes = response?.body()?.length(),
        notes = notes.first,
        notesTruncated = notes.second,
    )
}

internal fun AuditIssue.toHistorySummary(id: String = stableHistoryId()): ScannerIssueSummary {
    val service = httpService()
    val rawName = name()
    val rawBaseUrl = baseUrl()
    val rawHost = service?.host()
    return ScannerIssueSummary(
        id = id,
        name = rawName?.take(512),
        nameTruncated = (rawName?.length ?: 0) > 512,
        baseUrl = rawBaseUrl?.take(MAX_HTTP_SEARCH_URL_CHARS),
        baseUrlTruncated = (rawBaseUrl?.length ?: 0) > MAX_HTTP_SEARCH_URL_CHARS,
        host = rawHost?.take(MAX_HTTP_SEARCH_HOST_CHARS),
        hostTruncated = (rawHost?.length ?: 0) > MAX_HTTP_SEARCH_HOST_CHARS,
        port = service?.port(),
        secure = service?.secure(),
        severity = severity().name,
        confidence = confidence().name,
        definitionTypeIndex = definition().typeIndex(),
        evidenceCount = null,
    )
}

/**
 * A versioned project-scoped ID. Site Map search results include their bounded snapshot index so
 * they remain directly resolvable; other producers use the `x` locator and bounded lookup.
 * The fingerprint intentionally excludes detail, remediation, and evidence content.
 */
internal fun AuditIssue.stableHistoryId(index: Int? = null): String {
    require(index == null || index >= 0) { "Scanner issue index must be non-negative" }
    val locator = index?.toString(36) ?: "x"
    return "issue_v2_${locator}_${scannerIssueFingerprint()}"
}

internal fun AuditIssue.scannerIssueFingerprint(): String {
    val service = httpService()
    val values = listOf(
        definition().typeIndex().toString() to 32,
        name().orEmpty() to 512,
        baseUrl().orEmpty() to MAX_HTTP_SEARCH_URL_CHARS,
        service?.host().orEmpty() to MAX_HTTP_SEARCH_HOST_CHARS,
        service?.port()?.toString().orEmpty() to 16,
        service?.secure()?.toString().orEmpty() to 8,
        severity().name to 32,
        confidence().name to 32,
    )
    val digest = MessageDigest.getInstance("SHA-256")
    values.forEachIndexed { valueIndex, (value, maxChars) ->
        if (valueIndex > 0) digest.update(0)
        digest.updateScannerIdentityValue(value.take(maxChars))
    }
    val identity = digest.digest()
    return HexFormat.of().formatHex(identity, 0, 16)
}

private fun MessageDigest.updateScannerIdentityValue(value: String) {
    var start = 0
    while (start < value.length) {
        var end = minOf(value.length, start + SCANNER_IDENTITY_CHUNK_CHARS)
        if (end < value.length && end > start && value[end - 1].isHighSurrogate() && value[end].isLowSurrogate()) {
            end--
        }
        update(value.substring(start, end).toByteArray(Charsets.UTF_8))
        start = end
    }
}

internal fun ProxyHttpRequestResponse.readPart(
    part: String,
    offset: Int,
    limit: Int,
    encoding: String,
): HttpMessageReadResult {
    val normalizedPart = normalizeHttpPart(part)
    val request = request()
    val response = response()
    val service = httpService()
    val notes = annotations().notes().boundedNotes()
    val metadata = HttpMessageMetadata(
        id = id(),
        source = "proxy",
        method = request?.method().orEmpty(),
        url = request?.url().orEmpty(),
        host = service.host(),
        port = service.port(),
        secure = service.secure(),
        time = time().toString(),
        statusCode = response?.statusCode()?.toInt(),
        mimeType = if (response != null) mimeType().name else null,
        listenerPort = listenerPort(),
        edited = edited(),
        notes = notes.first,
        notesTruncated = notes.second,
    )

    if (normalizedPart == "metadata") {
        return HttpMessageReadResult(
            status = HistoryReadStatus.OK,
            id = id(),
            part = normalizedPart,
            metadata = metadata,
        )
    }

    val bytes = when (normalizedPart) {
        "request" -> request?.toByteArray()
        "request_headers" -> request?.let { it.toByteArray().subArray(0, it.bodyOffset()) }
        "request_body" -> request?.body()
        "response" -> response?.toByteArray()
        "response_headers" -> response?.let { it.toByteArray().subArray(0, it.bodyOffset()) }
        "response_body" -> response?.body()
        else -> error("Unsupported HTTP message part: $normalizedPart")
    }

    if (bytes == null) {
        return HttpMessageReadResult(
            status = HistoryReadStatus.PART_UNAVAILABLE,
            id = id(),
            part = normalizedPart,
            metadata = metadata,
            error = "$normalizedPart is not available for proxy history item ${id()}",
        )
    }

    return HttpMessageReadResult(
        status = HistoryReadStatus.OK,
        id = id(),
        part = normalizedPart,
        metadata = metadata,
        content = bytes.toHistorySlice(offset, limit, encoding),
    )
}

internal fun OrganizerItem.readPart(
    part: String,
    offset: Int,
    limit: Int,
    encoding: String,
): HttpMessageReadResult {
    val normalizedPart = normalizeHttpPart(part)
    val request = request()
    val response = response()
    val service = httpService()
    val notes = annotations().notes().boundedNotes()
    val metadata = HttpMessageMetadata(
        id = id(),
        source = "organizer",
        method = request?.method().orEmpty(),
        url = request?.url().orEmpty(),
        host = service.host(),
        port = service.port(),
        secure = service.secure(),
        time = null,
        statusCode = response?.statusCode()?.toInt(),
        mimeType = response?.mimeType()?.name,
        listenerPort = null,
        edited = null,
        notes = notes.first,
        notesTruncated = notes.second,
    )

    if (normalizedPart == "metadata") {
        return HttpMessageReadResult(
            status = HistoryReadStatus.OK,
            id = id(),
            part = normalizedPart,
            metadata = metadata,
        )
    }

    val bytes = when (normalizedPart) {
        "request" -> request?.toByteArray()
        "request_headers" -> request?.let { it.toByteArray().subArray(0, it.bodyOffset()) }
        "request_body" -> request?.body()
        "response" -> response?.toByteArray()
        "response_headers" -> response?.let { it.toByteArray().subArray(0, it.bodyOffset()) }
        "response_body" -> response?.body()
        else -> error("Unsupported HTTP message part: $normalizedPart")
    }
    if (bytes == null) {
        return HttpMessageReadResult(
            status = HistoryReadStatus.PART_UNAVAILABLE,
            id = id(),
            part = normalizedPart,
            metadata = metadata,
            error = "$normalizedPart is not available for Organizer item ${id()}",
        )
    }
    return HttpMessageReadResult(
        status = HistoryReadStatus.OK,
        id = id(),
        part = normalizedPart,
        metadata = metadata,
        content = bytes.toHistorySlice(offset, limit, encoding),
    )
}

internal fun AuditIssue.readField(
    field: String,
    evidenceIndex: Int?,
    offset: Int,
    limit: Int,
    encoding: String,
    resolvedId: String = stableHistoryId(),
): ScannerIssueReadResult {
    val normalizedField = normalizeScannerIssueField(field)
    val summary = toHistorySummary(resolvedId)
    val id = summary.id
    if (normalizedField == "metadata") {
        return ScannerIssueReadResult(
            status = HistoryReadStatus.OK,
            id = id,
            field = normalizedField,
            summary = summary,
        )
    }

    val textField = when (normalizedField) {
        "detail" -> detail()
        "remediation" -> remediation()
        else -> null
    }
    val content = when (normalizedField) {
        "detail", "remediation" -> textField?.toHistorySlice(offset, limit, encoding)
        "evidence_request", "evidence_response" -> {
            val index = evidenceIndex ?: return ScannerIssueReadResult(
                status = HistoryReadStatus.INVALID_ARGUMENT,
                id = id,
                field = normalizedField,
                summary = summary,
                evidenceIndex = null,
                error = "evidenceIndex is required for $normalizedField",
            )
            val evidence = requestResponses()
            if (index !in evidence.indices) {
                return ScannerIssueReadResult(
                    status = HistoryReadStatus.INVALID_ARGUMENT,
                    id = id,
                    field = normalizedField,
                    summary = summary,
                    evidenceIndex = index,
                    error = "evidenceIndex must be between 0 and ${evidence.lastIndex}",
                )
            }
            val message = if (normalizedField == "evidence_request") {
                evidence[index].request()?.toByteArray()
            } else {
                evidence[index].response()?.toByteArray()
            }
            message?.toHistorySlice(offset, limit, encoding)
        }
        else -> error("Unsupported Scanner issue field: $normalizedField")
    }
    if (content == null) {
        return ScannerIssueReadResult(
            status = HistoryReadStatus.FIELD_UNAVAILABLE,
            id = id,
            field = normalizedField,
            summary = summary,
            evidenceIndex = evidenceIndex,
            error = "$normalizedField is not available for Scanner issue $id",
        )
    }
    return ScannerIssueReadResult(
        status = HistoryReadStatus.OK,
        id = id,
        field = normalizedField,
        summary = summary,
        evidenceIndex = evidenceIndex,
        content = content,
    )
}

internal fun ProxyWebSocketMessage.readPayload(
    edited: Boolean,
    offset: Int,
    limit: Int,
    encoding: String,
): WebSocketMessageReadResult {
    val notes = annotations().notes().boundedNotes()
    val variant = if (edited) "edited" else "original"
    val metadata = WebSocketMessageMetadata(
        id = id(),
        webSocketId = webSocketId(),
        time = time().toString(),
        direction = if (direction() == Direction.CLIENT_TO_SERVER) "CLIENT_TO_SERVER" else "SERVER_TO_CLIENT",
        listenerPort = listenerPort(),
        payloadVariant = variant,
        notes = notes.first,
        notesTruncated = notes.second,
    )
    val payload = if (edited) editedPayload() else payload()
    if (payload == null) {
        return WebSocketMessageReadResult(
            status = HistoryReadStatus.PART_UNAVAILABLE,
            id = id(),
            metadata = metadata,
            error = "$variant payload is not available for WebSocket history item ${id()}",
        )
    }
    return WebSocketMessageReadResult(
        status = HistoryReadStatus.OK,
        id = id(),
        metadata = metadata,
        content = payload.toHistorySlice(offset, limit, encoding),
    )
}

internal fun normalizeHttpPart(part: String?): String {
    val normalized = part?.trim()?.lowercase()?.replace('-', '_') ?: "metadata"
    require(normalized in HTTP_MESSAGE_PARTS) {
        "part must be metadata, request, request_headers, request_body, response, response_headers, or response_body"
    }
    return normalized
}

internal fun normalizeScannerIssueField(field: String?): String {
    val normalized = field?.trim()?.lowercase()?.replace('-', '_') ?: "metadata"
    require(normalized in SCANNER_ISSUE_FIELDS) {
        "field must be metadata, detail, remediation, evidence_request, or evidence_response"
    }
    return normalized
}

internal fun normalizeHistoryEncoding(encoding: String?): String {
    val normalized = encoding?.trim()?.lowercase() ?: "text"
    require(normalized == "text" || normalized == "base64") { "encoding must be text or base64" }
    return normalized
}

internal fun normalizeHistoryOffset(offset: Int?): Int {
    val normalized = offset ?: 0
    require(normalized >= 0) { "offset must be non-negative" }
    return normalized
}

internal fun normalizeHistoryLimit(limit: Int?): Int {
    val normalized = limit ?: DEFAULT_HISTORY_SLICE_BYTES
    require(normalized in 1..MAX_HISTORY_SLICE_BYTES) {
        "limit must be between 1 and $MAX_HISTORY_SLICE_BYTES bytes"
    }
    return normalized
}

internal class HistoryOffsetOutOfRangeException(offset: Int, totalBytes: Long) :
    IllegalArgumentException("offset must not exceed totalBytes ($totalBytes); received $offset")

private fun requireHistoryOffsetInRange(offset: Int, totalBytes: Long) {
    if (offset.toLong() > totalBytes) throw HistoryOffsetOutOfRangeException(offset, totalBytes)
}

internal fun MontoyaByteArray.toHistorySlice(offset: Int, limit: Int, encoding: String): HistoryContentSlice {
    val totalBytes = length()
    requireHistoryOffsetInRange(offset, totalBytes.toLong())
    val end = min(totalBytes.toLong(), offset.toLong() + limit).toInt()
    val returnedBytes = end - offset
    val data = if (returnedBytes == 0) {
        ""
    } else {
        val selected = subArray(offset, end)
        when (encoding) {
            "text" -> selected.toString()
            "base64" -> Base64.getEncoder().encodeToString(selected.getBytes())
            else -> error("Unsupported encoding: $encoding")
        }
    }
    val hasMore = end < totalBytes
    return HistoryContentSlice(
        encoding = encoding,
        data = data,
        offsetBytes = offset,
        returnedBytes = returnedBytes,
        totalBytes = totalBytes,
        hasMore = hasMore,
        nextOffsetBytes = if (hasMore) end else null,
    )
}

private fun String.toHistorySlice(offset: Int, limit: Int, encoding: String): HistoryContentSlice {
    val encoder = Charsets.UTF_8.newEncoder()
        .onMalformedInput(CodingErrorAction.REPLACE)
        .onUnmappableCharacter(CodingErrorAction.REPLACE)
    val input = CharBuffer.wrap(this)
    val output = ByteBuffer.allocate(SCANNER_TEXT_ENCODING_BUFFER_BYTES)
    val selected = ByteArray(limit)
    var selectedBytes = 0
    var totalBytes = 0L
    val requestedEnd = offset.toLong() + limit.toLong()

    fun consumeOutput() {
        output.flip()
        val chunkBytes = output.remaining()
        val chunkStart = totalBytes
        val chunkEnd = chunkStart + chunkBytes
        val overlapStart = maxOf(offset.toLong(), chunkStart)
        val overlapEnd = minOf(requestedEnd, chunkEnd)
        if (overlapStart < overlapEnd) {
            output.position((overlapStart - chunkStart).toInt())
            val copyBytes = (overlapEnd - overlapStart).toInt()
            output.get(selected, selectedBytes, copyBytes)
            selectedBytes += copyBytes
        }
        totalBytes = chunkEnd
        output.clear()
    }

    while (true) {
        val result = encoder.encode(input, output, true)
        consumeOutput()
        if (result.isUnderflow) break
        if (result.isError) result.throwException()
    }
    while (true) {
        val result = encoder.flush(output)
        consumeOutput()
        if (result.isUnderflow) break
        if (result.isError) result.throwException()
    }

    require(totalBytes <= Int.MAX_VALUE) { "Scanner text field exceeds the supported byte length" }
    requireHistoryOffsetInRange(offset, totalBytes)
    val total = totalBytes.toInt()
    val end = min(total.toLong(), requestedEnd).toInt()
    val data = when (encoding) {
        "text" -> String(selected, 0, selectedBytes, Charsets.UTF_8)
        "base64" -> Base64.getEncoder().encodeToString(selected.copyOf(selectedBytes))
        else -> error("Unsupported encoding: $encoding")
    }
    val hasMore = end < total
    return HistoryContentSlice(
        encoding = encoding,
        data = data,
        offsetBytes = offset,
        returnedBytes = selectedBytes,
        totalBytes = total,
        hasMore = hasMore,
        nextOffsetBytes = if (hasMore) end else null,
    )
}

private fun kotlin.ByteArray.toHistorySlice(offset: Int, limit: Int, encoding: String): HistoryContentSlice {
    val totalBytes = size
    requireHistoryOffsetInRange(offset, totalBytes.toLong())
    val end = min(totalBytes.toLong(), offset.toLong() + limit).toInt()
    val selected = copyOfRange(offset, end)
    val data = when (encoding) {
        "text" -> selected.toString(Charsets.UTF_8)
        "base64" -> Base64.getEncoder().encodeToString(selected)
        else -> error("Unsupported encoding: $encoding")
    }
    val hasMore = end < totalBytes
    return HistoryContentSlice(
        encoding = encoding,
        data = data,
        offsetBytes = offset,
        returnedBytes = selected.size,
        totalBytes = totalBytes,
        hasMore = hasMore,
        nextOffsetBytes = if (hasMore) end else null,
    )
}

private fun String?.boundedNotes(): Pair<String?, Boolean> {
    if (this == null || length <= MAX_NOTES_CHARS) return this to false
    return take(MAX_NOTES_CHARS) to true
}
