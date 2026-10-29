package net.portswigger.mcp.tools

import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.schema.JsonSchemaMetadata

internal const val MAX_REFLECTION_RESPONSE_BYTES = 1024 * 1024
internal const val MAX_REFLECTION_VALUE_BYTES = 1024
internal const val MAX_REFLECTION_OFFSETS = 16
private const val MAX_REFLECTION_COMPARISONS = 8 * 1024 * 1024
private val reflectionJson = Json { encodeDefaults = true }

@Serializable
enum class HttpReflectionStatus {
    @SerialName("ok") OK,
    @SerialName("parameter_unavailable") PARAMETER_UNAVAILABLE,
    @SerialName("input_limit_exceeded") INPUT_LIMIT_EXCEEDED,
    @SerialName("work_limit_exceeded") WORK_LIMIT_EXCEEDED,
    @SerialName("output_limit_exceeded") OUTPUT_LIMIT_EXCEEDED,
}

@Serializable
data class HttpParameterReflection(
    val status: HttpReflectionStatus,
    @JsonSchemaMetadata(description = "Complete overlapping raw-byte match count in response_headers, including the status line; null unless ok.", minimum = 0)
    val headerCount: Int? = null,
    @JsonSchemaMetadata(description = "Complete overlapping raw-byte match count in the stored, not decoded, response body; null unless ok.", minimum = 0)
    val bodyCount: Int? = null,
    @JsonSchemaMetadata(description = "First 16 matches as zero-based byte offsets within response_headers.", maxItems = MAX_REFLECTION_OFFSETS)
    val headerOffsets: List<Int>,
    @JsonSchemaMetadata(description = "First 16 matches as zero-based byte offsets within response_body. Reflection is not XSS evidence.", maxItems = MAX_REFLECTION_OFFSETS)
    val bodyOffsets: List<Int>,
) {
    constructor(status: HttpReflectionStatus) : this(status, null, null, emptyList(), emptyList())
}

internal fun validateReflectionParameter(selector: HttpInsertionPointSelector) {
    require(selector.kind == HttpInsertionPointKind.PARAMETER) { "reflectionParameter requires kind=parameter" }
    require(selector.name?.let(::isValidInsertionPointName) == true) { "reflectionParameter requires a valid name" }
    require(selector.parameterType != null) { "reflectionParameter requires parameterType" }
    require((selector.occurrence ?: 0) in 0..MAX_INSERTION_POINT_OCCURRENCE) {
        "reflectionParameter occurrence must be between 0 and $MAX_INSERTION_POINT_OCCURRENCE"
    }
}

internal suspend fun inspectParameterReflection(
    request: HttpRequest,
    response: HttpResponse,
    selector: HttpInsertionPointSelector,
    limit: Int,
): HttpParameterReflection {
    currentCoroutineContext().ensureActive()
    validateReflectionParameter(selector)
    fun failure(status: HttpReflectionStatus) = HttpParameterReflection(status)
    val requestHeader = request.bodyOffset()
    val requestBody = request.body().length()
    val responseHeader = response.bodyOffset()
    val responseBody = response.body().length()
    require(requestHeader >= 0 && requestBody >= 0 && responseHeader >= 0 && responseBody >= 0)
    val requestLength = requestHeader.toLong() + requestBody
    val responseLength = responseHeader.toLong() + responseBody
    if (requestLength > MAX_ACTION_REQUEST_BYTES || responseLength > MAX_REFLECTION_RESPONSE_BYTES) {
        return failure(HttpReflectionStatus.INPUT_LIMIT_EXCEEDED)
    }
    currentCoroutineContext().ensureActive()
    val parameters = request.parameters()
    val count = parameters.size
    require(count >= 0)
    if (count > MAX_PARAMETER_INVENTORY_ITEMS) return failure(HttpReflectionStatus.INPUT_LIMIT_EXCEEDED)
    var nameChars = 0
    var occurrence = 0
    var selected: ParsedHttpParameter? = null
    for (index in 0 until count) {
        currentCoroutineContext().ensureActive()
        val parameter = parameters[index]
        val name = parameter.name()
        if (name.length > 64 * 1024 - nameChars) return failure(HttpReflectionStatus.INPUT_LIMIT_EXCEEDED)
        nameChars += name.length
        if (parameter.type().name == selector.parameterType!!.name && name == selector.name) {
            if (occurrence++ == (selector.occurrence ?: 0)) selected = parameter
        }
    }
    check(parameters.size == count) { "Burp parameter inventory changed during inspection" }
    val range = selected?.valueOffsets() ?: return failure(HttpReflectionStatus.PARAMETER_UNAVAILABLE)
    val start = range.startIndexInclusive()
    val end = range.endIndexExclusive()
    if (start < 0 || end <= start || end > requestLength) return failure(HttpReflectionStatus.PARAMETER_UNAVAILABLE)
    if (end - start > MAX_REFLECTION_VALUE_BYTES) return failure(HttpReflectionStatus.INPUT_LIMIT_EXCEEDED)
    currentCoroutineContext().ensureActive()
    val requestBytes = request.toByteArray()
    require(requestBytes.length().toLong() == requestLength) { "Inconsistent request length" }
    val rawRequest = requestBytes.getBytes()
    require(rawRequest.size.toLong() == requestLength) { "Inconsistent request bytes" }
    val needle = rawRequest.copyOfRange(start, end)
    currentCoroutineContext().ensureActive()
    val responseBytes = response.toByteArray()
    require(responseBytes.length().toLong() == responseLength) { "Inconsistent response length" }
    val rawResponse = responseBytes.getBytes()
    require(rawResponse.size.toLong() == responseLength) { "Inconsistent response bytes" }
    var comparisons = 0
    suspend fun matches(from: Int, until: Int): Pair<Int, List<Int>>? {
        var hits = 0
        val offsets = ArrayList<Int>()
        for (position in from..until - needle.size) {
            var matched = true
            for (index in needle.indices) {
                if (comparisons and 4095 == 0) currentCoroutineContext().ensureActive()
                if (++comparisons > MAX_REFLECTION_COMPARISONS) return null
                if (rawResponse[position + index] != needle[index]) {
                    matched = false
                    break
                }
            }
            if (matched) {
                hits++
                if (offsets.size < MAX_REFLECTION_OFFSETS) offsets += position - from
            }
        }
        return hits to offsets
    }
    val headers = matches(0, responseHeader) ?: return failure(HttpReflectionStatus.WORK_LIMIT_EXCEEDED)
    val body = matches(responseHeader, rawResponse.size) ?: return failure(HttpReflectionStatus.WORK_LIMIT_EXCEEDED)
    currentCoroutineContext().ensureActive()
    val result = HttpParameterReflection(HttpReflectionStatus.OK, headers.first, body.first, headers.second, body.second)
    if (reflectionJson.encodeToString(result).toByteArray(Charsets.UTF_8).size > limit) {
        return failure(HttpReflectionStatus.OUTPUT_LIMIT_EXCEEDED)
    }
    return result
}
