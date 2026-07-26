package net.portswigger.mcp.security

private const val MAX_SAFE_EXCEPTION_CHARS = 384
private const val MAX_SAFE_INPUT_CHARS = 8 * 1024
private val CONTROL_CHARACTERS = Regex("[\\r\\n\\t\\u0000-\\u001f\\u007f]+")
private val AUTHORIZATION_HEADER = Regex(
    "(?i)\\b(authorization|proxy-authorization)[\\\"']?\\s*[:=]\\s*[^\\r\\n]{0,$MAX_SAFE_INPUT_CHARS}"
)
private val COOKIE_HEADER = Regex(
    "(?i)\\b(cookie|set-cookie)[\\\"']?\\s*[:=]\\s*[^\\r\\n]{0,$MAX_SAFE_INPUT_CHARS}"
)
private val BEARER_CREDENTIAL = Regex("(?i)\\bBearer\\s+[A-Za-z0-9._~+/=-]{1,$MAX_SAFE_INPUT_CHARS}")
private val NAMED_CREDENTIAL = Regex(
    "(?i)\\b(password|passwd|secret|token|access[_-]?token|refresh[_-]?token|id[_-]?token|" +
        "client[_-]?secret|api[_-]?key|private[_-]?key|session[_-]?(?:id|token))[\\\"']?\\s*[:=]\\s*" +
        "(?:\"[^\"\\r\\n]{0,$MAX_SAFE_INPUT_CHARS}\"|'[^'\\r\\n]{0,$MAX_SAFE_INPUT_CHARS}'|" +
        "[^,;\\r\\n]{1,$MAX_SAFE_INPUT_CHARS})"
)
private val WINDOWS_ABSOLUTE_PATH = Regex("(?i)\\b[A-Z]:[\\\\/](?:[^\\s:;]+[\\\\/])*[^\\s:;]*")
private val UNIX_ABSOLUTE_PATH = Regex("(?<![A-Za-z0-9:/])/(?:[^/\\s:;]+/)*[^/\\s:;]+")

/** Produces one bounded, single-line, credential- and path-redacted exception summary. */
@PublishedApi
internal fun safeExceptionSummary(error: Throwable): String {
    val message = sanitizeForExternalOutput(error.message.orEmpty(), MAX_SAFE_EXCEPTION_CHARS)
    val type = error::class.simpleName ?: "Exception"
    return (if (message.isEmpty()) type else "$type: $message").take(MAX_SAFE_EXCEPTION_CHARS)
}

internal fun safeSingleLine(value: String, limit: Int = MAX_SAFE_EXCEPTION_CHARS): String =
    sanitizeForExternalOutput(value, limit.coerceIn(1, MAX_SAFE_EXCEPTION_CHARS))

private fun sanitizeForExternalOutput(value: String, limit: Int): String = value
    .take(MAX_SAFE_INPUT_CHARS)
    .replace(AUTHORIZATION_HEADER) { match -> "${match.groupValues[1]}=<redacted>" }
    .replace(COOKIE_HEADER) { match -> "${match.groupValues[1]}=<redacted>" }
    .replace(BEARER_CREDENTIAL, "Bearer <redacted>")
    .replace(NAMED_CREDENTIAL) { match -> "${match.groupValues[1]}=<redacted>" }
    .replace(WINDOWS_ABSOLUTE_PATH, "<path>")
    .replace(UNIX_ABSOLUTE_PATH, "<path>")
    .replace(CONTROL_CHARACTERS, " ")
    .trim()
    .take(limit)
