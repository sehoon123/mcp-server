package net.portswigger.mcp.tools

import burp.api.montoya.http.handler.TimingData
import burp.api.montoya.http.message.requests.HttpRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.schema.JsonSchemaMetadata
import java.time.Duration

internal const val MAX_PARAMETER_INVENTORY_ITEMS = 128
private const val MAX_PARAMETER_NAME_INPUT_CHARS = 64 * 1024
private val observationJson = Json { encodeDefaults = true }

@Serializable
enum class HttpParameterInventoryStatus {
    @SerialName("ok") OK,
    @SerialName("input_limit_exceeded") INPUT_LIMIT_EXCEEDED,
    @SerialName("output_limit_exceeded") OUTPUT_LIMIT_EXCEEDED,
}

@Serializable
enum class HttpParameterUnavailableReason {
    @SerialName("invalid_name") INVALID_NAME,
    @SerialName("occurrence_limit") OCCURRENCE_LIMIT,
    @SerialName("invalid_range") INVALID_RANGE,
    @SerialName("empty_value") EMPTY_VALUE,
}

@Serializable
data class HttpParameterObservation(
    @JsonSchemaMetadata(description = "Exact name, or null if invalid for an insertion selector.", maxLength = MAX_INSERTION_POINT_NAME_CHARS)
    val name: String?,
    val parameterType: HttpActionParameterType,
    @JsonSchemaMetadata(description = "Zero-based occurrence within this exact type/name.", minimum = 0, maximum = MAX_PARAMETER_INVENTORY_ITEMS - 1L)
    val occurrence: Int,
    @JsonSchemaMetadata(description = "Null permits a kind=parameter selector with these fields; selection is revalidated on use.")
    val unavailableReason: HttpParameterUnavailableReason?,
)

@Serializable
data class HttpParameterInventory(
    val status: HttpParameterInventoryStatus,
    @JsonSchemaMetadata(maxItems = MAX_PARAMETER_INVENTORY_ITEMS)
    val parameters: List<HttpParameterObservation>,
) {
    constructor(status: HttpParameterInventoryStatus) : this(status, emptyList())
}

internal suspend fun inspectHttpParameters(request: HttpRequest, limit: Int): HttpParameterInventory {
    currentCoroutineContext().ensureActive()
    val headerBytes = request.bodyOffset()
    val bodyBytes = request.body().length()
    require(headerBytes >= 0 && bodyBytes >= 0) { "Burp reported a negative request length" }
    val requestBytes = headerBytes.toLong() + bodyBytes
    if (requestBytes > MAX_ACTION_REQUEST_BYTES) return HttpParameterInventory(HttpParameterInventoryStatus.INPUT_LIMIT_EXCEEDED)
    currentCoroutineContext().ensureActive()
    val parameters = request.parameters()
    val count = parameters.size
    require(count >= 0) { "Burp reported a negative parameter count" }
    if (count > MAX_PARAMETER_INVENTORY_ITEMS) return HttpParameterInventory(HttpParameterInventoryStatus.INPUT_LIMIT_EXCEEDED)
    val occurrences = HashMap<Pair<HttpActionParameterType, String>, Int>()
    val observations = ArrayList<HttpParameterObservation>(count)
    var nameChars = 0
    for (index in 0 until count) {
        currentCoroutineContext().ensureActive()
        val parameter = parameters[index]
        val type = HttpActionParameterType.valueOf(parameter.type().name)
        val name = parameter.name()
        if (name.length > MAX_PARAMETER_NAME_INPUT_CHARS - nameChars) {
            return HttpParameterInventory(HttpParameterInventoryStatus.INPUT_LIMIT_EXCEEDED)
        }
        nameChars += name.length
        val key = type to name
        val occurrence = occurrences.getOrDefault(key, 0)
        occurrences[key] = occurrence + 1
        val validName = isValidInsertionPointName(name)
        val reason = when {
            !validName -> HttpParameterUnavailableReason.INVALID_NAME
            occurrence > MAX_INSERTION_POINT_OCCURRENCE -> HttpParameterUnavailableReason.OCCURRENCE_LIMIT
            else -> {
                val range = parameter.valueOffsets()
                val start = range.startIndexInclusive().toLong()
                val end = range.endIndexExclusive().toLong()
                when {
                    start < 0 || end < start || end > requestBytes -> HttpParameterUnavailableReason.INVALID_RANGE
                    start == end -> HttpParameterUnavailableReason.EMPTY_VALUE
                    else -> null
                }
            }
        }
        observations += HttpParameterObservation(name.takeIf { validName }, type, occurrence, reason)
    }
    currentCoroutineContext().ensureActive()
    check(parameters.size == count) { "Burp parameter inventory changed during inspection" }
    val result = HttpParameterInventory(HttpParameterInventoryStatus.OK, observations)
    // Budget the complete object, including nulls and escaping, not just the names.
    if (observationJson.encodeToString(result).toByteArray(Charsets.UTF_8).size > limit) {
        return HttpParameterInventory(HttpParameterInventoryStatus.OUTPUT_LIMIT_EXCEEDED)
    }
    return result
}

@Serializable
data class HttpTimingSummary(
    @JsonSchemaMetadata(description = "Native request-sent time in UTC, when available.", maxLength = 64)
    val requestSentAt: String?,
    @JsonSchemaMetadata(description = "Native milliseconds from request sent to response start; null if unavailable.", minimum = 0)
    val responseStartMillis: Long?,
    @JsonSchemaMetadata(description = "Native milliseconds from request sent to response completion; null if unavailable.", minimum = 0)
    val responseEndMillis: Long?,
)

/** Optional telemetry must never discard a completed send's response or encourage a retry. */
internal suspend fun readHttpTiming(provider: () -> TimingData?): HttpTimingSummary? {
    currentCoroutineContext().ensureActive()
    return try {
        val timing = provider()
        currentCoroutineContext().ensureActive()
        if (timing == null) return null
        val sent = timing.timeRequestSent()?.toInstant()?.toString()
        currentCoroutineContext().ensureActive()
        val start = timing.timeBetweenRequestSentAndStartOfResponse().nonnegativeMillis()
        currentCoroutineContext().ensureActive()
        val end = timing.timeBetweenRequestSentAndEndOfResponse().nonnegativeMillis()
            ?.takeIf { start == null || it >= start }
        currentCoroutineContext().ensureActive()
        if (sent == null && start == null && end == null) null else HttpTimingSummary(sent, start, end)
    } catch (e: CancellationException) {
        throw e
    } catch (_: Exception) {
        currentCoroutineContext().ensureActive()
        null
    }
}

private fun Duration?.nonnegativeMillis(): Long? = if (this == null || isNegative) null else {
    try { toMillis() } catch (_: ArithmeticException) { null }
}
