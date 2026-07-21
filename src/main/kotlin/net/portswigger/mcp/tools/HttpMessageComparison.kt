package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.responses.analysis.AttributeType
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.McpConfig
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.HexFormat

private const val MIN_COMPARE_REFS = 2
private const val MAX_COMPARE_REFS = 8
private const val DEFAULT_COMPARE_BYTES_PER_MESSAGE = 256 * 1024
private const val MAX_COMPARE_BYTES_PER_MESSAGE = 1024 * 1024
private const val MAX_COMPARE_IGNORE_HEADERS = 32
private const val MAX_COMPARE_HEADER_NAME_CHARS = 256
private const val MAX_COMPARE_HEADER_VALUE_CHARS = 2_048
private const val MAX_COMPARE_HEADERS = 128
private const val COMPARE_EXCERPT_CONTEXT_BYTES = 256
private const val MAX_COMPARE_EXCERPT_BYTES = 1_024
private const val MAX_NATIVE_VARIATION_MESSAGE_BYTES = 1024 * 1024
private const val MAX_NATIVE_VARIATION_TOTAL_BYTES = 4 * 1024 * 1024

@Serializable
data class CompareHttpMessages(
    val projectId: String,
    val refs: List<HttpMessageReference>,
    val part: HttpComparisonPart? = null,
    val limitBytesPerMessage: Int? = null,
    val excerptEncoding: HttpComparisonEncoding? = null,
    val ignoreHeaders: List<String>? = null,
    val includeResponseVariations: Boolean? = null,
)

@Serializable
enum class HttpComparisonEncoding {
    @SerialName("text")
    TEXT,

    @SerialName("base64")
    BASE64,
}

@Serializable
enum class HttpComparisonPart {
    @SerialName("request")
    REQUEST,

    @SerialName("request_headers")
    REQUEST_HEADERS,

    @SerialName("request_body")
    REQUEST_BODY,

    @SerialName("response")
    RESPONSE,

    @SerialName("response_headers")
    RESPONSE_HEADERS,

    @SerialName("response_body")
    RESPONSE_BODY,
}

@Serializable
enum class HttpComparisonStatus {
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

    @SerialName("request_unavailable")
    REQUEST_UNAVAILABLE,

    @SerialName("part_unavailable")
    PART_UNAVAILABLE,

    @SerialName("burp_error")
    BURP_ERROR,
}

@Serializable
data class HttpComparisonItem(
    val ref: HttpMessageReference,
    val startLine: String?,
    val totalBytes: Int,
    val inspectedBytes: Int,
    val truncated: Boolean,
    val inspectedSha256: String,
)

@Serializable
data class HttpHeaderDifference(
    val name: String,
    val leftValues: List<String>,
    val rightValues: List<String>,
    val valuesTruncated: Boolean,
)

@Serializable
data class HttpHeaderComparison(
    val equal: Boolean?,
    val differences: List<HttpHeaderDifference>,
    val differencesTruncated: Boolean,
    val invariantNames: List<String>,
    val variantNames: List<String>,
)

@Serializable
data class HttpComparisonExcerpt(
    val encoding: String,
    val offsetBytes: Int,
    val returnedBytes: Int,
    val data: String,
)

@Serializable
data class HttpContentDifference(
    val equal: Boolean?,
    val firstDifferenceOffsetBytes: Int?,
    val commonPrefixBytes: Int,
    val commonSuffixBytes: Int,
    val left: HttpComparisonExcerpt?,
    val right: HttpComparisonExcerpt?,
)

@Serializable
data class HttpResponseVariationSummary(
    val variantAttributes: List<String>,
    val invariantAttributes: List<String>,
    val skipped: Boolean,
    val reason: String? = null,
)

@Serializable
data class CompareHttpMessagesResult(
    val status: HttpComparisonStatus,
    val projectId: String?,
    val part: HttpComparisonPart,
    val refs: List<HttpMessageReference>,
    val items: List<HttpComparisonItem>,
    val allEqual: Boolean?,
    val inspectedBytes: Long,
    val headerComparison: HttpHeaderComparison? = null,
    val contentDifference: HttpContentDifference? = null,
    val responseVariations: HttpResponseVariationSummary? = null,
    val errorRefIndex: Int? = null,
    val error: String? = null,
)

internal class HttpMessageComparisonService(
    private val api: MontoyaApi,
    config: McpConfig,
) {
    private val resolver = HttpMessageResolver(api, config)

    suspend fun compare(input: CompareHttpMessages): CompareHttpMessagesResult {
        val part = input.part ?: HttpComparisonPart.RESPONSE
        val limit = input.limitBytesPerMessage ?: DEFAULT_COMPARE_BYTES_PER_MESSAGE
        if (input.refs.size !in MIN_COMPARE_REFS..MAX_COMPARE_REFS) {
            return comparisonError(
                HttpComparisonStatus.INVALID_ARGUMENT,
                input.projectId,
                part,
                input.refs,
                "refs must contain between $MIN_COMPARE_REFS and $MAX_COMPARE_REFS items",
            )
        }
        if (input.refs.distinct().size != input.refs.size) {
            return comparisonError(
                HttpComparisonStatus.INVALID_ARGUMENT,
                input.projectId,
                part,
                input.refs,
                "refs must not contain duplicates",
            )
        }
        if (limit !in 1..MAX_COMPARE_BYTES_PER_MESSAGE) {
            return comparisonError(
                HttpComparisonStatus.INVALID_ARGUMENT,
                input.projectId,
                part,
                input.refs,
                "limitBytesPerMessage must be between 1 and $MAX_COMPARE_BYTES_PER_MESSAGE",
            )
        }
        val encoding = when (input.excerptEncoding ?: HttpComparisonEncoding.TEXT) {
            HttpComparisonEncoding.TEXT -> "text"
            HttpComparisonEncoding.BASE64 -> "base64"
        }
        val ignoredHeaders = try {
            normalizeIgnoredHeaders(input.ignoreHeaders)
        } catch (e: IllegalArgumentException) {
            return comparisonError(
                HttpComparisonStatus.INVALID_ARGUMENT,
                input.projectId,
                part,
                input.refs,
                e.message ?: "invalid ignoreHeaders",
            )
        }

        val messages = when (val resolution = resolver.resolveAll(input.projectId, input.refs, MAX_COMPARE_REFS)) {
            is HttpMessageBatchResolution.Failed -> return comparisonError(
                resolution.status.toComparisonStatus(),
                resolution.projectId,
                part,
                input.refs,
                resolution.error,
                resolution.refIndex,
            )

            is HttpMessageBatchResolution.Found -> resolution.messages
        }

        val projectBeforeComparison = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return comparisonError(
                HttpComparisonStatus.BURP_ERROR,
                input.projectId,
                part,
                input.refs,
                "Burp could not recheck the project before comparison: ${safeComparisonException(e)}",
            )
        }
        if (projectBeforeComparison != input.projectId) {
            return comparisonError(
                HttpComparisonStatus.PROJECT_MISMATCH,
                projectBeforeComparison,
                part,
                input.refs,
                "Burp project changed before the comparison",
            )
        }

        val materials = ArrayList<ComparisonMaterial>(messages.size)
        try {
            messages.forEachIndexed { index, message ->
                currentCoroutineContext().ensureActive()
                val material = message.material(part, limit, ignoredHeaders)
                    ?: return comparisonError(
                        HttpComparisonStatus.PART_UNAVAILABLE,
                        input.projectId,
                        part,
                        input.refs,
                        "${part.serialName()} is unavailable for reference at index $index",
                        index,
                    )
                materials += material
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return comparisonError(
                HttpComparisonStatus.BURP_ERROR,
                input.projectId,
                part,
                input.refs,
                "Burp could not prepare the comparison: ${safeComparisonException(e)}",
            )
        }

        val itemResults = materials.mapIndexed { index, material ->
            HttpComparisonItem(
                ref = messages[index].ref,
                startLine = material.startLine,
                totalBytes = material.totalBytes,
                inspectedBytes = material.bytes.size,
                truncated = material.truncated,
                inspectedSha256 = sha256(material.bytes),
            )
        }
        val allEqual = materials.knownEquality()
        val headerComparison = if (part.includesHeaders()) compareHeaders(materials) else null
        val contentDifference = if (materials.size == 2) compareContent(materials[0], materials[1], encoding) else null
        val variations = if ((input.includeResponseVariations ?: true) && part.isResponsePart()) {
            responseVariations(messages)
        } else {
            null
        }

        return CompareHttpMessagesResult(
            status = HttpComparisonStatus.OK,
            projectId = input.projectId,
            part = part,
            refs = input.refs,
            items = itemResults,
            allEqual = allEqual,
            inspectedBytes = materials.sumOf { it.bytes.size.toLong() },
            headerComparison = headerComparison,
            contentDifference = contentDifference,
            responseVariations = variations,
        )
    }

    private suspend fun responseVariations(messages: List<ResolvedHttpMessage>): HttpResponseVariationSummary {
        val responses = messages.map { it.response }
        if (responses.any { it == null }) {
            return HttpResponseVariationSummary(
                variantAttributes = emptyList(),
                invariantAttributes = emptyList(),
                skipped = true,
                reason = "one or more references do not have a response",
            )
        }
        val nonNullResponses = responses.filterNotNull()
        var total = 0L
        for (response in nonNullResponses) {
            val size = response.bodyOffset().toLong().coerceAtLeast(0) + response.body().length().toLong().coerceAtLeast(0)
            if (size > MAX_NATIVE_VARIATION_MESSAGE_BYTES) {
                return HttpResponseVariationSummary(
                    variantAttributes = emptyList(),
                    invariantAttributes = emptyList(),
                    skipped = true,
                    reason = "a response exceeds the $MAX_NATIVE_VARIATION_MESSAGE_BYTES-byte variation-analysis limit",
                )
            }
            total += size
            if (total > MAX_NATIVE_VARIATION_TOTAL_BYTES) {
                return HttpResponseVariationSummary(
                    variantAttributes = emptyList(),
                    invariantAttributes = emptyList(),
                    skipped = true,
                    reason = "responses exceed the $MAX_NATIVE_VARIATION_TOTAL_BYTES-byte total variation-analysis limit",
                )
            }
        }

        return try {
            val analyzer = api.http().createResponseVariationsAnalyzer()
            nonNullResponses.forEach {
                currentCoroutineContext().ensureActive()
                analyzer.updateWith(it)
            }
            HttpResponseVariationSummary(
                variantAttributes = analyzer.variantAttributes().map(AttributeType::name).map(::enumToSerialName).sorted(),
                invariantAttributes = analyzer.invariantAttributes().map(AttributeType::name).map(::enumToSerialName).sorted(),
                skipped = false,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            HttpResponseVariationSummary(
                variantAttributes = emptyList(),
                invariantAttributes = emptyList(),
                skipped = true,
                reason = "Burp response variation analysis was unavailable: ${safeComparisonException(e)}",
            )
        }
    }
}

private data class ComparisonMaterial(
    val totalBytes: Int,
    val bytes: ByteArray,
    val truncated: Boolean,
    val startLine: String?,
    val headers: Map<String, List<String>>?,
    val headersTruncated: Boolean,
)

private fun ResolvedHttpMessage.material(
    part: HttpComparisonPart,
    limit: Int,
    ignoredHeaders: Set<String>,
): ComparisonMaterial? {
    val selected: MontoyaByteArray
    val startLine: String?
    val headers: List<HttpHeader>?
    when (part) {
        HttpComparisonPart.REQUEST -> {
            selected = request.toByteArray()
            startLine = "${request.method().take(32)} ${request.path().take(1_960)} ${request.httpVersion().take(32)}"
            headers = request.headers()
        }

        HttpComparisonPart.REQUEST_HEADERS -> {
            selected = request.toByteArray().subArray(0, request.bodyOffset())
            startLine = "${request.method().take(32)} ${request.path().take(1_960)} ${request.httpVersion().take(32)}"
            headers = request.headers()
        }

        HttpComparisonPart.REQUEST_BODY -> {
            selected = request.body()
            startLine = null
            headers = null
        }

        HttpComparisonPart.RESPONSE -> {
            val value = response ?: return null
            selected = value.toByteArray()
            startLine = "${value.httpVersion().take(64)} ${value.statusCode()}"
            headers = value.headers()
        }

        HttpComparisonPart.RESPONSE_HEADERS -> {
            val value = response ?: return null
            selected = value.toByteArray().subArray(0, value.bodyOffset())
            startLine = "${value.httpVersion().take(64)} ${value.statusCode()}"
            headers = value.headers()
        }

        HttpComparisonPart.RESPONSE_BODY -> {
            val value = response ?: return null
            selected = value.body()
            startLine = null
            headers = null
        }
    }
    val total = selected.length()
    require(total >= 0) { "Burp reported a negative message length" }
    val inspected = minOf(total, limit)
    val bytes = if (inspected == 0) ByteArray(0) else selected.subArray(0, inspected).getBytes()
    require(bytes.size == inspected) { "Burp returned an inconsistent message slice" }
    val boundedHeaders = headers?.toBoundedHeaderData(ignoredHeaders)
    return ComparisonMaterial(
        totalBytes = total,
        bytes = bytes,
        truncated = total > inspected,
        startLine = startLine,
        headers = boundedHeaders?.values,
        headersTruncated = boundedHeaders?.truncated ?: false,
    )
}

private data class BoundedHeaderData(
    val values: Map<String, List<String>>,
    val truncated: Boolean,
)

private fun List<HttpHeader>.toBoundedHeaderData(ignored: Set<String>): BoundedHeaderData {
    val result = LinkedHashMap<String, MutableList<String>>()
    var truncated = size > MAX_COMPARE_HEADERS
    take(MAX_COMPARE_HEADERS).forEach { header ->
        val rawName = header.name()
        val rawValue = header.value()
        if (rawName.length > MAX_COMPARE_HEADER_NAME_CHARS || rawValue.length > MAX_COMPARE_HEADER_VALUE_CHARS) {
            truncated = true
        }
        val name = rawName.take(MAX_COMPARE_HEADER_NAME_CHARS).lowercase()
        if (name !in ignored) {
            result.getOrPut(name) { ArrayList(1) }.add(rawValue.take(MAX_COMPARE_HEADER_VALUE_CHARS))
        }
    }
    return BoundedHeaderData(result, truncated)
}

private fun normalizeIgnoredHeaders(values: List<String>?): Set<String> {
    require((values?.size ?: 0) <= MAX_COMPARE_IGNORE_HEADERS) {
        "ignoreHeaders can contain at most $MAX_COMPARE_IGNORE_HEADERS names"
    }
    return values.orEmpty().map { value ->
        require(value.length in 1..MAX_COMPARE_HEADER_NAME_CHARS) { "ignored header name is empty or too long" }
        require(value.all { it.isLetterOrDigit() || it in "!#$%&'*+-.^_`|~" }) { "ignored header name is invalid" }
        value.lowercase()
    }.toSet()
}

private fun compareHeaders(materials: List<ComparisonMaterial>): HttpHeaderComparison? {
    val maps = materials.map { it.headers ?: return null }
    val allNames = maps.asSequence().flatMap { it.keys.asSequence() }.toSortedSet()
    val invariant = ArrayList<String>()
    val variant = ArrayList<String>()
    allNames.forEach { name ->
        val first = maps.first()[name].orEmpty()
        if (maps.drop(1).all { it[name].orEmpty() == first }) invariant += name else variant += name
    }

    val differences = if (maps.size == 2) {
        variant.take(MAX_COMPARE_HEADERS).map { name ->
            val left = maps[0][name].orEmpty()
            val right = maps[1][name].orEmpty()
            HttpHeaderDifference(
                name = name,
                leftValues = left,
                rightValues = right,
                valuesTruncated = left.any { it.length >= MAX_COMPARE_HEADER_VALUE_CHARS } ||
                    right.any { it.length >= MAX_COMPARE_HEADER_VALUE_CHARS },
            )
        }
    } else {
        emptyList()
    }
    val inputTruncated = materials.any { it.headersTruncated }
    return HttpHeaderComparison(
        equal = if (variant.isNotEmpty()) false else if (inputTruncated) null else true,
        differences = differences,
        differencesTruncated = inputTruncated || maps.size == 2 && variant.size > differences.size,
        invariantNames = invariant.take(MAX_COMPARE_HEADERS),
        variantNames = variant.take(MAX_COMPARE_HEADERS),
    )
}

private fun compareContent(
    left: ComparisonMaterial,
    right: ComparisonMaterial,
    encoding: String,
): HttpContentDifference {
    val maxPrefix = minOf(left.bytes.size, right.bytes.size)
    var prefix = 0
    while (prefix < maxPrefix && left.bytes[prefix] == right.bytes[prefix]) prefix++

    val knownEqual = when {
        prefix < maxPrefix -> false
        left.totalBytes != right.totalBytes -> false
        !left.truncated && !right.truncated -> true
        else -> null
    }
    if (knownEqual == true) {
        return HttpContentDifference(true, null, left.totalBytes, 0, null, null)
    }

    var suffix = 0
    val leftAvailable = left.bytes.size - prefix
    val rightAvailable = right.bytes.size - prefix
    while (suffix < minOf(leftAvailable, rightAvailable) &&
        left.bytes[left.bytes.lastIndex - suffix] == right.bytes[right.bytes.lastIndex - suffix]
    ) {
        suffix++
    }
    val firstDifference = when {
        prefix < maxPrefix -> prefix
        left.totalBytes != right.totalBytes && prefix >= minOf(left.totalBytes, right.totalBytes) ->
            minOf(left.totalBytes, right.totalBytes)
        else -> null
    }
    val excerptStart = (firstDifference ?: prefix).minus(COMPARE_EXCERPT_CONTEXT_BYTES).coerceAtLeast(0)
    return HttpContentDifference(
        equal = knownEqual,
        firstDifferenceOffsetBytes = firstDifference,
        commonPrefixBytes = prefix,
        commonSuffixBytes = suffix,
        left = left.bytes.toExcerpt(excerptStart, encoding),
        right = right.bytes.toExcerpt(excerptStart, encoding),
    )
}

private fun ByteArray.toExcerpt(offset: Int, encoding: String): HttpComparisonExcerpt? {
    if (offset >= size) return null
    val end = minOf(size, offset + MAX_COMPARE_EXCERPT_BYTES)
    val slice = copyOfRange(offset, end)
    val data = when (encoding) {
        "base64" -> Base64.getEncoder().encodeToString(slice)
        else -> slice.toString(StandardCharsets.UTF_8)
    }
    return HttpComparisonExcerpt(encoding, offset, slice.size, data)
}

private fun List<ComparisonMaterial>.knownEquality(): Boolean? {
    val first = first()
    var unknown = false
    drop(1).forEach { material ->
        if (!first.bytes.contentEquals(material.bytes) || first.totalBytes != material.totalBytes) return false
        if (first.truncated || material.truncated) unknown = true
    }
    return if (unknown) null else true
}

private fun HttpComparisonPart.includesHeaders(): Boolean = when (this) {
    HttpComparisonPart.REQUEST, HttpComparisonPart.REQUEST_HEADERS,
    HttpComparisonPart.RESPONSE, HttpComparisonPart.RESPONSE_HEADERS -> true
    HttpComparisonPart.REQUEST_BODY, HttpComparisonPart.RESPONSE_BODY -> false
}

private fun HttpComparisonPart.isResponsePart(): Boolean = when (this) {
    HttpComparisonPart.RESPONSE, HttpComparisonPart.RESPONSE_HEADERS, HttpComparisonPart.RESPONSE_BODY -> true
    else -> false
}

private fun HttpComparisonPart.serialName(): String = name.lowercase()
private fun enumToSerialName(value: String): String = value.lowercase()
private fun sha256(bytes: ByteArray): String = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes))

private fun HttpMessageResolutionStatus.toComparisonStatus(): HttpComparisonStatus = when (this) {
    HttpMessageResolutionStatus.ACCESS_DENIED -> HttpComparisonStatus.ACCESS_DENIED
    HttpMessageResolutionStatus.INVALID_ARGUMENT -> HttpComparisonStatus.INVALID_ARGUMENT
    HttpMessageResolutionStatus.INVALID_ID -> HttpComparisonStatus.INVALID_ID
    HttpMessageResolutionStatus.PROJECT_MISMATCH -> HttpComparisonStatus.PROJECT_MISMATCH
    HttpMessageResolutionStatus.NOT_FOUND -> HttpComparisonStatus.NOT_FOUND
    HttpMessageResolutionStatus.REQUEST_UNAVAILABLE -> HttpComparisonStatus.REQUEST_UNAVAILABLE
    HttpMessageResolutionStatus.BURP_ERROR -> HttpComparisonStatus.BURP_ERROR
}

private fun comparisonError(
    status: HttpComparisonStatus,
    projectId: String?,
    part: HttpComparisonPart,
    refs: List<HttpMessageReference>,
    error: String,
    errorRefIndex: Int? = null,
) = CompareHttpMessagesResult(
    status = status,
    projectId = projectId?.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
    part = part,
    refs = refs.take(MAX_COMPARE_REFS).map {
        HttpMessageReference(it.source, it.id.take(MAX_HTTP_REFERENCE_ID_CHARS))
    },
    items = emptyList(),
    allEqual = null,
    inspectedBytes = 0,
    errorRefIndex = errorRefIndex,
    error = error.take(512),
)

private fun safeComparisonException(error: Exception): String =
    "${error::class.simpleName ?: "Exception"}: ${error.message.orEmpty()}".take(512)
