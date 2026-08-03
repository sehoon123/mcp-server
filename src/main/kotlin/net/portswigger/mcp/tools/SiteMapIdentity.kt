package net.portswigger.mcp.tools

import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpRequestResponse as MontoyaHttpRequestResponse
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.HexFormat
import kotlin.math.min

private const val SITE_MAP_ID_PREFIX = "sitemap_"
private const val SITE_MAP_HASH_HEX_CHARS = 32
private const val SITE_MAP_HASH_SAMPLE_BYTES = 128
private val SITE_MAP_ID_PATTERN = Regex("^sitemap_([0-9]+)_([0-9a-f]{32})$")

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
