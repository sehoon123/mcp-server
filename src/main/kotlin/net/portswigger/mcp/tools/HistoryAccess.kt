package net.portswigger.mcp.tools

import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.websocket.Direction
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.security.MessageDigest
import java.util.Base64
import java.util.HexFormat
import kotlin.math.min

internal const val DEFAULT_HISTORY_SLICE_BYTES = 32 * 1024
internal const val MAX_HISTORY_SLICE_BYTES = 256 * 1024
internal const val MAX_NOTES_CHARS = 2_000
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
    val notes: String?,
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
    val notes: String?,
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
    val notes: String?,
    val notesTruncated: Boolean,
)

@Serializable
data class ScannerIssueSummary(
    val id: String,
    val name: String?,
    val baseUrl: String?,
    val host: String?,
    val port: Int?,
    val secure: Boolean?,
    val severity: String,
    val confidence: String,
    val definitionTypeIndex: Int,
    val evidenceCount: Int,
)

@Serializable
enum class HistoryReadStatus {
    @SerialName("ok")
    OK,

    @SerialName("access_denied")
    ACCESS_DENIED,

    @SerialName("not_found")
    NOT_FOUND,

    @SerialName("project_mismatch")
    PROJECT_MISMATCH,

    @SerialName("part_unavailable")
    PART_UNAVAILABLE,

    @SerialName("field_unavailable")
    FIELD_UNAVAILABLE,
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
    val notes: String?,
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
    val notes: String?,
    val notesTruncated: Boolean,
)

@Serializable
data class WebSocketMessageReadResult(
    val status: HistoryReadStatus,
    val id: Int,
    val metadata: WebSocketMessageMetadata? = null,
    val content: HistoryContentSlice? = null,
    val error: String? = null,
)

@Serializable
data class ScannerIssueReadResult(
    val status: HistoryReadStatus,
    val id: String,
    val field: String,
    val summary: ScannerIssueSummary? = null,
    val evidenceIndex: Int? = null,
    val content: HistoryContentSlice? = null,
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

internal fun AuditIssue.toHistorySummary(): ScannerIssueSummary {
    val service = httpService()
    return ScannerIssueSummary(
        id = stableHistoryId(),
        name = name(),
        baseUrl = baseUrl(),
        host = service?.host(),
        port = service?.port(),
        secure = service?.secure(),
        severity = severity().name,
        confidence = confidence().name,
        definitionTypeIndex = definition().typeIndex(),
        evidenceCount = requestResponses().size,
    )
}

/** A deterministic ID scoped to the current Burp project and the issue's identity fields. */
internal fun AuditIssue.stableHistoryId(): String {
    val service = httpService()
    val canonicalIdentity = listOf(
        definition().typeIndex().toString(),
        name().orEmpty(),
        baseUrl().orEmpty(),
        service?.host().orEmpty(),
        service?.port()?.toString().orEmpty(),
        service?.secure()?.toString().orEmpty(),
        severity().name,
        confidence().name,
        detail().orEmpty(),
    ).joinToString(separator = "\u0000")
    val digest = MessageDigest.getInstance("SHA-256").digest(canonicalIdentity.toByteArray(Charsets.UTF_8))
    return "issue_" + HexFormat.of().formatHex(digest, 0, 16)
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
): ScannerIssueReadResult {
    val normalizedField = normalizeScannerIssueField(field)
    val summary = toHistorySummary()
    val id = summary.id
    if (normalizedField == "metadata") {
        return ScannerIssueReadResult(
            status = HistoryReadStatus.OK,
            id = id,
            field = normalizedField,
            summary = summary,
        )
    }

    val content = when (normalizedField) {
        "detail" -> detail()?.toByteArray(Charsets.UTF_8)?.toHistorySlice(offset, limit, encoding)
        "remediation" -> remediation()?.toByteArray(Charsets.UTF_8)?.toHistorySlice(offset, limit, encoding)
        "evidence_request", "evidence_response" -> {
            val index = requireNotNull(evidenceIndex) { "evidenceIndex is required for $normalizedField" }
            val evidence = requestResponses()
            require(index in evidence.indices) { "evidenceIndex must be between 0 and ${evidence.lastIndex}" }
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

internal fun MontoyaByteArray.toHistorySlice(offset: Int, limit: Int, encoding: String): HistoryContentSlice {
    val totalBytes = length()
    require(offset <= totalBytes) { "offset must not exceed totalBytes ($totalBytes)" }
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

private fun kotlin.ByteArray.toHistorySlice(offset: Int, limit: Int, encoding: String): HistoryContentSlice {
    val totalBytes = size
    require(offset <= totalBytes) { "offset must not exceed totalBytes ($totalBytes)" }
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
