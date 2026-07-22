package net.portswigger.mcp.security

private const val MAX_SAFE_EXCEPTION_CHARS = 384
private val CONTROL_CHARACTERS = Regex("[\\r\\n\\t\\u0000-\\u001f\\u007f]+")
private val BEARER_CREDENTIAL = Regex("(?i)\\bBearer\\s+[A-Za-z0-9._~+/=-]{1,8192}")
private val NAMED_CREDENTIAL = Regex(
    "(?i)\\b(authorization|proxy-authorization|password|passwd|secret|token|api[_-]?key|private[_-]?key)" +
        "\\s*[:=]\\s*[^,;\\s]{1,8192}"
)
private val WINDOWS_ABSOLUTE_PATH = Regex("(?i)\\b[A-Z]:[\\\\/](?:[^\\s:;]+[\\\\/])+[^\\s:;]*")
private val UNIX_ABSOLUTE_PATH = Regex("(?<![A-Za-z0-9])/(?:[^/\\s:;]+/)+[^\\s:;]*")

/** Produces one bounded, single-line, credential- and path-redacted exception summary. */
@PublishedApi
internal fun safeExceptionSummary(error: Throwable): String {
    val message = error.message.orEmpty()
        .replace(BEARER_CREDENTIAL, "Bearer <redacted>")
        .replace(NAMED_CREDENTIAL) { match -> "${match.groupValues[1]}=<redacted>" }
        .replace(WINDOWS_ABSOLUTE_PATH, "<path>")
        .replace(UNIX_ABSOLUTE_PATH, "<path>")
        .replace(CONTROL_CHARACTERS, " ")
        .trim()
        .take(MAX_SAFE_EXCEPTION_CHARS)
    val type = error::class.simpleName ?: "Exception"
    return if (message.isEmpty()) type else "$type: $message"
}

internal fun safeSingleLine(value: String, limit: Int = MAX_SAFE_EXCEPTION_CHARS): String = value
    .replace(BEARER_CREDENTIAL, "Bearer <redacted>")
    .replace(NAMED_CREDENTIAL) { match -> "${match.groupValues[1]}=<redacted>" }
    .replace(CONTROL_CHARACTERS, " ")
    .trim()
    .take(limit.coerceIn(1, MAX_SAFE_EXCEPTION_CHARS))
