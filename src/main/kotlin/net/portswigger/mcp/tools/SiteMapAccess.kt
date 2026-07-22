package net.portswigger.mcp.tools

import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpRequestResponse as MontoyaHttpRequestResponse
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.schema.JsonSchemaMetadata
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.HexFormat
import kotlin.math.min

private const val SITE_MAP_ID_PREFIX = "sitemap_"
private const val SITE_MAP_HASH_HEX_CHARS = 32
private const val SITE_MAP_HASH_SAMPLE_BYTES = 128
private val SITE_MAP_ID_PATTERN = Regex("^sitemap_([0-9]+)_([0-9a-f]{32})$")

@Serializable
data class GetSitemapMessageById(
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Stable Site Map ID.", pattern = "^sitemap_[0-9]+_[0-9a-f]{32}$", maxLength = 128)
    val id: String,
    @JsonSchemaMetadata(enumValues = ["metadata", "request", "request_headers", "request_body", "response", "response_headers", "response_body"], defaultJson = "\"metadata\"")
    val part: String? = null,
    @JsonSchemaMetadata(minimum = 0, defaultJson = "0") val offset: Int? = null,
    @JsonSchemaMetadata(minimum = 1, maximum = 262144, defaultJson = "32768") val limit: Int? = null,
    @JsonSchemaMetadata(enumValues = ["text", "base64"], defaultJson = "\"text\"") val encoding: String? = null,
)

@Serializable
enum class SiteMapReadStatus {
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

    @SerialName("part_unavailable")
    PART_UNAVAILABLE,
}

@Serializable
data class SiteMapHttpMessageMetadata(
    val projectId: String,
    val id: String,
    val method: String,
    val url: String,
    val urlTruncated: Boolean,
    val host: String,
    val port: Int,
    val secure: Boolean,
    val statusCode: Int?,
    val mimeType: String?,
    val hasResponse: Boolean,
    val inScope: Boolean,
    val requestBodyBytes: Int,
    val responseBodyBytes: Int?,
    val notes: String?,
    val notesTruncated: Boolean,
)

@Serializable
data class SiteMapMessageReadResult(
    val status: SiteMapReadStatus,
    val projectId: String,
    val id: String,
    val part: String,
    val metadata: SiteMapHttpMessageMetadata? = null,
    val content: HistoryContentSlice? = null,
    val error: String? = null,
)

internal data class ParsedSiteMapId(val index: Int)

internal fun parseSiteMapId(id: String): ParsedSiteMapId? {
    val match = SITE_MAP_ID_PATTERN.matchEntire(id) ?: return null
    val index = match.groupValues[1].toIntOrNull() ?: return null
    return ParsedSiteMapId(index)
}

internal fun stableSiteMapId(
    projectId: String,
    index: Int,
    item: MontoyaHttpRequestResponse,
): String {
    require(index >= 0) { "Site Map index must be non-negative" }
    val digest = MessageDigest.getInstance("SHA-256")
    digest.updateBounded(projectId)
    digest.updateInt(index)
    digest.updateSiteMapIdentity(item)
    return "$SITE_MAP_ID_PREFIX${index}_${HexFormat.of().formatHex(digest.digest()).take(SITE_MAP_HASH_HEX_CHARS)}"
}

internal fun siteMapBoundaryAnchor(item: MontoyaHttpRequestResponse): String {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.updateSiteMapIdentity(item)
    return HexFormat.of().formatHex(digest.digest()).take(SITE_MAP_HASH_HEX_CHARS)
}

private fun MessageDigest.updateSiteMapIdentity(item: MontoyaHttpRequestResponse) {
    val request = item.request()
    updateBounded(request.method())
    updateBounded(request.url())
    updateBounded(request.httpVersion())
    updateHeaders(request.headers())
    updateSample(request.body())
    val response = item.response()
    if (response == null) {
        update(0.toByte())
    } else {
        update(1.toByte())
        updateInt(response.statusCode().toInt())
        updateBounded(response.httpVersion())
        updateHeaders(response.headers())
        updateSample(response.body())
    }
}

internal fun MontoyaHttpRequestResponse.readSiteMapPart(
    projectId: String,
    id: String,
    part: String,
    offset: Int,
    limit: Int,
    encoding: String,
): SiteMapMessageReadResult {
    val request = request()
    val response = response()
    val service = httpService()
    val boundedNotes = annotations().notes().boundedSiteMetadata(MAX_NOTES_CHARS)
    val boundedUrl = request.url().boundedSiteMetadata(MAX_HTTP_SEARCH_URL_CHARS)
    val metadata = SiteMapHttpMessageMetadata(
        projectId = projectId,
        id = id,
        method = request.method().boundedSiteMetadata(32).first.orEmpty(),
        url = boundedUrl.first.orEmpty(),
        urlTruncated = boundedUrl.second,
        host = service.host().boundedSiteMetadata(MAX_HTTP_SEARCH_HOST_CHARS).first.orEmpty(),
        port = service.port(),
        secure = service.secure(),
        statusCode = response?.statusCode()?.toInt(),
        mimeType = response?.mimeType()?.name,
        hasResponse = response != null,
        inScope = request.isInScope(),
        requestBodyBytes = request.body().length(),
        responseBodyBytes = response?.body()?.length(),
        notes = boundedNotes.first,
        notesTruncated = boundedNotes.second,
    )
    if (part == "metadata") {
        return SiteMapMessageReadResult(SiteMapReadStatus.OK, projectId, id, part, metadata = metadata)
    }

    val bytes = when (part) {
        "request" -> request.toByteArray()
        "request_headers" -> request.toByteArray().subArray(0, request.bodyOffset())
        "request_body" -> request.body()
        "response" -> response?.toByteArray()
        "response_headers" -> response?.toByteArray()?.subArray(0, response.bodyOffset())
        "response_body" -> response?.body()
        else -> error("Unsupported HTTP message part: $part")
    }
    if (bytes == null) {
        return SiteMapMessageReadResult(
            status = SiteMapReadStatus.PART_UNAVAILABLE,
            projectId = projectId,
            id = id,
            part = part,
            metadata = metadata,
            error = "$part is not available for Site Map item $id",
        )
    }
    return SiteMapMessageReadResult(
        status = SiteMapReadStatus.OK,
        projectId = projectId,
        id = id,
        part = part,
        metadata = metadata,
        content = bytes.toHistorySlice(offset, limit, encoding),
    )
}

private fun String?.boundedSiteMetadata(maxChars: Int): Pair<String?, Boolean> {
    if (this == null || length <= maxChars) return this to false
    return take(maxChars) to true
}

private fun MessageDigest.updateInt(value: Int) {
    update((value ushr 24).toByte())
    update((value ushr 16).toByte())
    update((value ushr 8).toByte())
    update(value.toByte())
}

private fun MessageDigest.updateBounded(value: String) {
    updateInt(value.length)
    if (value.length <= 2_048) {
        update(value.toByteArray(StandardCharsets.UTF_8))
    } else {
        update(value.take(1_024).toByteArray(StandardCharsets.UTF_8))
        update(value.takeLast(1_024).toByteArray(StandardCharsets.UTF_8))
    }
}

private fun MessageDigest.updateHeaders(headers: List<HttpHeader>) {
    updateInt(headers.size)
    headers.take(128).forEach { header ->
        updateBounded(header.name())
        updateBounded(header.value())
    }
}

private fun MessageDigest.updateSample(bytes: MontoyaByteArray) {
    val length = bytes.length()
    updateInt(length)
    if (length == 0) return
    val ranges = buildList {
        add(0 until min(length, SITE_MAP_HASH_SAMPLE_BYTES))
        if (length > SITE_MAP_HASH_SAMPLE_BYTES * 2) {
            val middleStart = (length / 2 - SITE_MAP_HASH_SAMPLE_BYTES / 2).coerceAtLeast(0)
            add(middleStart until min(length, middleStart + SITE_MAP_HASH_SAMPLE_BYTES))
        }
        if (length > SITE_MAP_HASH_SAMPLE_BYTES) {
            val endStart = (length - SITE_MAP_HASH_SAMPLE_BYTES).coerceAtLeast(0)
            add(endStart until length)
        }
    }
    ranges.distinct().forEach { range ->
        range.forEach { index -> update(bytes.getByte(index)) }
    }
}
