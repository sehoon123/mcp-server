package net.portswigger.mcp.tools

import burp.api.montoya.http.message.MimeType

internal const val MAX_INDEXED_HTTP_PATH_CHARS = 512
internal const val MAX_ATTACK_SURFACE_PATH_DEPTH = 4
internal const val MAX_ATTACK_SURFACE_SEGMENT_CHARS = 128
internal const val MAX_ATTACK_SURFACE_PREFIX_CHARS = 512

internal data class NormalizedHttpPath(
    val value: String,
    val truncated: Boolean,
)

internal fun normalizeHttpPath(value: String): NormalizedHttpPath {
    if (
        value.isNotEmpty() && value.startsWith('/') && value.length <= MAX_INDEXED_HTTP_PATH_CHARS &&
        '?' !in value && '#' !in value && value.none(Char::isISOControl)
    ) {
        return NormalizedHttpPath(value, false)
    }
    val withoutQuery = value.substringBefore('?').substringBefore('#').ifEmpty { "/" }
    val normalized = buildString(minOf(withoutQuery.length, MAX_INDEXED_HTTP_PATH_CHARS)) {
        for (character in withoutQuery) {
            if (length >= MAX_INDEXED_HTTP_PATH_CHARS) break
            append(if (character.isISOControl()) '_' else character)
        }
    }.let { if (it.startsWith('/')) it else "/$it" }
    return NormalizedHttpPath(
        value = normalized.take(MAX_INDEXED_HTTP_PATH_CHARS),
        truncated = withoutQuery.length > MAX_INDEXED_HTTP_PATH_CHARS ||
            normalized.length > MAX_INDEXED_HTTP_PATH_CHARS,
    )
}

internal fun normalizedHttpPathPrefix(path: String, depth: Int): String {
    require(depth in 1..MAX_ATTACK_SURFACE_PATH_DEPTH) { "path depth is out of range" }
    val queryStart = path.indexOf('?').takeIf { it >= 0 } ?: path.length
    val fragmentStart = path.indexOf('#').takeIf { it >= 0 } ?: path.length
    val pathEnd = minOf(queryStart, fragmentStart)
    val prefix = StringBuilder(minOf(pathEnd, MAX_ATTACK_SURFACE_PREFIX_CHARS))
    var cursor = 0
    var segments = 0
    while (cursor < pathEnd && segments < depth) {
        while (cursor < pathEnd && path[cursor] == '/') cursor++
        if (cursor >= pathEnd) break
        val nextSlash = path.indexOf('/', cursor).let { if (it < 0 || it > pathEnd) pathEnd else it }
        if (nextSlash > cursor) {
            prefix.append('/').append(normalizeHttpPathSegment(path.substring(cursor, nextSlash)))
            segments++
        }
        cursor = nextSlash + 1
    }
    if (segments == 0) return "/"
    return prefix.toString().take(MAX_ATTACK_SURFACE_PREFIX_CHARS)
}

internal fun httpFileExtension(path: String, pathTruncated: Boolean): String? {
    if (pathTruncated) return null
    val fileName = path.substringAfterLast('/')
    if (fileName.startsWith('.') || '.' !in fileName) return null
    return fileName.substringAfterLast('.')
        .takeIf { it.length in 1..16 && it.all(Char::isAsciiAlphanumeric) }
        ?.lowercase()
}

internal fun httpStatusClass(statusCode: Int): String = when (statusCode) {
    in 100..199 -> "1xx"
    in 200..299 -> "2xx"
    in 300..399 -> "3xx"
    in 400..499 -> "4xx"
    in 500..599 -> "5xx"
    else -> "other"
}

internal fun normalizeHttpMimeType(mimeType: MimeType?): String? = mimeType?.name?.take(64)?.lowercase()

private fun normalizeHttpPathSegment(raw: String): String {
    val segment = raw.take(MAX_ATTACK_SURFACE_SEGMENT_CHARS)
    return when {
        segment.isAsciiNumber() -> "{number}"
        segment.isUuid() -> "{uuid}"
        segment.isLongHex() || segment.isLongToken() -> "{id}"
        else -> segment
    }
}

private fun String.isAsciiNumber(): Boolean = isNotEmpty() && all { it in '0'..'9' }

private fun String.isUuid(): Boolean {
    if (length != 36) return false
    for (index in indices) {
        val character = this[index]
        when (index) {
            8, 13, 18, 23 -> if (character != '-') return false
            14 -> if (character !in '1'..'5') return false
            19 -> if (character.lowercaseChar() !in "89ab") return false
            else -> if (!character.isAsciiHex()) return false
        }
    }
    return true
}

private fun String.isLongHex(): Boolean = length >= 16 && all(Char::isAsciiHex)

private fun String.isLongToken(): Boolean = length >= 24 && all {
    it.isAsciiAlphanumeric() || it == '_' || it == '-'
}

private fun Char.isAsciiHex(): Boolean = this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'
private fun Char.isAsciiAlphanumeric(): Boolean = this in '0'..'9' || this in 'a'..'z' || this in 'A'..'Z'
