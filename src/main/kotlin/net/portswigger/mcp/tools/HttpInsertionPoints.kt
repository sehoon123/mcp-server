package net.portswigger.mcp.tools

import burp.api.montoya.core.Range
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.requests.HttpRequest
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.nio.charset.StandardCharsets

internal const val MAX_HTTP_INSERTION_POINTS = 32
private const val MAX_INSERTION_POINT_NAME_CHARS = 512
private const val MAX_INSERTION_POINT_OCCURRENCE = 31
private val INSERTION_HEADER_NAME_PATTERN = Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+")

@Serializable
data class HttpInsertionPointSelector(
    val kind: HttpInsertionPointKind,
    val name: String? = null,
    val parameterType: HttpActionParameterType? = null,
    val occurrence: Int? = null,
)

@Serializable
enum class HttpInsertionPointKind {
    @SerialName("parameter")
    PARAMETER,

    @SerialName("header")
    HEADER,

    @SerialName("body")
    BODY,
}

internal data class PreparedInsertionPoints(
    val ranges: List<Range>,
    val summary: String,
)

/** Resolves semantic selectors to byte ranges without exposing raw offsets to the MCP client. */
internal fun prepareInsertionPoints(
    request: HttpRequest,
    selectors: List<HttpInsertionPointSelector>,
): PreparedInsertionPoints {
    require(selectors.isNotEmpty()) { "insertionPoints must not be empty when provided" }
    require(selectors.size <= MAX_HTTP_INSERTION_POINTS) {
        "insertionPoints can contain at most $MAX_HTTP_INSERTION_POINTS selectors"
    }
    val bodyOffset = request.bodyOffset()
    val bodyLength = request.body().length()
    require(bodyOffset >= 0 && bodyLength >= 0) { "request reported an invalid byte length" }
    val totalLong = bodyOffset.toLong() + bodyLength.toLong()
    require(totalLong <= MAX_ACTION_REQUEST_BYTES && totalLong <= Int.MAX_VALUE) {
        "request exceeds the $MAX_ACTION_REQUEST_BYTES-byte insertion-point limit"
    }
    val totalBytes = totalLong.toInt()

    val requestedHeaderNames = selectors.asSequence()
        .filter { it.kind == HttpInsertionPointKind.HEADER }
        .mapNotNull { it.name?.lowercase() }
        .toSet()
    val rawHeaderRanges by lazy(LazyThreadSafetyMode.NONE) {
        val prelude = if (bodyOffset == 0) ByteArray(0) else request.toByteArray().subArray(0, bodyOffset).getBytes()
        require(prelude.size == bodyOffset) { "Burp returned an inconsistent request prelude" }
        parseHeaderValueRanges(prelude, requestedHeaderNames)
    }

    val offsets = ArrayList<ResolvedInsertionOffset>(selectors.size)
    selectors.forEachIndexed { selectorIndex, selector ->
        val occurrence = selector.occurrence ?: 0
        require(occurrence in 0..MAX_INSERTION_POINT_OCCURRENCE) {
            "insertionPoints[$selectorIndex].occurrence must be between 0 and $MAX_INSERTION_POINT_OCCURRENCE"
        }
        val resolved = when (selector.kind) {
            HttpInsertionPointKind.PARAMETER -> {
                val name = requireSelectorName(selector, selectorIndex)
                val type = requireNotNull(selector.parameterType) {
                    "insertionPoints[$selectorIndex].parameterType is required for a parameter selector"
                }
                val matches = request.parameters(type.toMontoyaInsertionType()).filter { it.name() == name }
                val parameter = matches.getOrNull(occurrence) ?: throw IllegalArgumentException(
                    "insertionPoints[$selectorIndex] did not match ${type.name.lowercase()} parameter " +
                        "${name.safeInsertionName()} occurrence $occurrence"
                )
                val range = parameter.valueOffsets()
                ResolvedInsertionOffset(
                    range.startIndexInclusive(),
                    range.endIndexExclusive(),
                    "${type.name.lowercase()} parameter ${name.safeInsertionName()}[$occurrence]",
                )
            }

            HttpInsertionPointKind.HEADER -> {
                require(selector.parameterType == null) {
                    "insertionPoints[$selectorIndex].parameterType is only valid for parameter selectors"
                }
                val name = requireSelectorName(selector, selectorIndex)
                require(name.matches(INSERTION_HEADER_NAME_PATTERN)) {
                    "insertionPoints[$selectorIndex].name must be a valid HTTP header name"
                }
                val matches = rawHeaderRanges[name.lowercase()].orEmpty()
                val range = matches.getOrNull(occurrence) ?: throw IllegalArgumentException(
                    "insertionPoints[$selectorIndex] did not match header ${name.safeInsertionName()} occurrence $occurrence"
                )
                ResolvedInsertionOffset(
                    range.first,
                    range.last + 1,
                    "header ${name.lowercase().safeInsertionName()}[$occurrence]",
                )
            }

            HttpInsertionPointKind.BODY -> {
                require(selector.name == null && selector.parameterType == null && occurrence == 0) {
                    "body insertion-point selectors cannot specify name, parameterType, or a non-zero occurrence"
                }
                require(bodyLength > 0) { "request body is empty" }
                ResolvedInsertionOffset(bodyOffset, totalBytes, "entire request body")
            }
        }
        require(resolved.start in 0 until totalBytes && resolved.end in 1..totalBytes && resolved.start < resolved.end) {
            "insertionPoints[$selectorIndex] resolved outside the request or to an empty range"
        }
        offsets += resolved
    }

    val sorted = offsets.sortedWith(compareBy<ResolvedInsertionOffset> { it.start }.thenBy { it.end })
    sorted.zipWithNext().forEach { (left, right) ->
        require(left.end <= right.start) { "insertionPoints must not duplicate or overlap" }
    }
    return PreparedInsertionPoints(
        ranges = sorted.map { Range.range(it.start, it.end) },
        summary = sorted.joinToString(prefix = "insertion points: ", separator = ", ") { it.label }.take(2_048),
    )
}

private data class ResolvedInsertionOffset(
    val start: Int,
    val end: Int,
    val label: String,
)

private fun requireSelectorName(selector: HttpInsertionPointSelector, index: Int): String {
    val name = selector.name ?: throw IllegalArgumentException("insertionPoints[$index].name is required")
    require(name.length in 1..MAX_INSERTION_POINT_NAME_CHARS && name.none(Char::isISOControl)) {
        "insertionPoints[$index].name is empty, too long, or contains control characters"
    }
    return name
}

/** Returns inclusive IntRanges keyed by lowercase header name. Char indexes equal byte indexes under ISO-8859-1. */
internal fun parseHeaderValueRanges(
    prelude: ByteArray,
    requestedNames: Set<String>? = null,
): Map<String, List<IntRange>> {
    if (prelude.isEmpty()) return emptyMap()
    val text = prelude.toString(StandardCharsets.ISO_8859_1)
    val result = LinkedHashMap<String, MutableList<IntRange>>()
    var lineStart = 0
    var lineNumber = 0
    while (lineStart < text.length) {
        val newline = text.indexOf('\n', lineStart).let { if (it < 0) text.length else it }
        val contentEnd = if (newline > lineStart && text[newline - 1] == '\r') newline - 1 else newline
        if (contentEnd == lineStart) break
        if (lineNumber > 0 && text[lineStart] != ' ' && text[lineStart] != '\t') {
            val colon = text.indexOf(':', lineStart).takeIf { it in lineStart until contentEnd }
            if (colon != null && colon > lineStart) {
                val name = text.substring(lineStart, colon).lowercase()
                if (requestedNames != null && name !in requestedNames) {
                    lineNumber++
                    if (newline == text.length) break
                    lineStart = newline + 1
                    continue
                }
                var valueStart = colon + 1
                while (valueStart < contentEnd && (text[valueStart] == ' ' || text[valueStart] == '\t')) valueStart++
                var valueEnd = contentEnd
                while (valueEnd > valueStart && (text[valueEnd - 1] == ' ' || text[valueEnd - 1] == '\t')) valueEnd--
                if (valueStart < valueEnd) {
                    result.getOrPut(name) { ArrayList(1) }.add(valueStart until valueEnd)
                }
            }
        }
        lineNumber++
        if (newline == text.length) break
        lineStart = newline + 1
    }
    return result
}

private fun HttpActionParameterType.toMontoyaInsertionType(): HttpParameterType = when (this) {
    HttpActionParameterType.URL -> HttpParameterType.URL
    HttpActionParameterType.BODY -> HttpParameterType.BODY
    HttpActionParameterType.COOKIE -> HttpParameterType.COOKIE
    HttpActionParameterType.XML -> HttpParameterType.XML
    HttpActionParameterType.XML_ATTRIBUTE -> HttpParameterType.XML_ATTRIBUTE
    HttpActionParameterType.MULTIPART_ATTRIBUTE -> HttpParameterType.MULTIPART_ATTRIBUTE
    HttpActionParameterType.JSON -> HttpParameterType.JSON
}

private fun String.safeInsertionName(): String = replace("\r", "\\r").replace("\n", "\\n").take(256)
