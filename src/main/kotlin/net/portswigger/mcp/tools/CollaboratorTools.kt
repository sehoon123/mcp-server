package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.collaborator.Interaction
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.time.format.DateTimeParseException
import java.util.Base64
import kotlin.math.min

private const val MAX_COLLABORATOR_CUSTOM_DATA_CHARS = 16
private const val MAX_COLLABORATOR_PAYLOAD_ID_CHARS = 256
private const val MAX_COLLABORATOR_SINCE_CHARS = 64
private const val DEFAULT_COLLABORATOR_RESULTS = 20
private const val MAX_COLLABORATOR_RESULTS = 50
private const val MAX_COLLABORATOR_WAIT_SECONDS = 120
private const val DEFAULT_COLLABORATOR_DETAIL_BYTES = 4 * 1024
private const val MAX_COLLABORATOR_DETAIL_BYTES = 16 * 1024
private const val MAX_COLLABORATOR_TOTAL_DETAIL_BYTES = 256 * 1024
private const val MAX_COLLABORATOR_SCANNED_INTERACTIONS = 10_000
private const val MAX_COLLABORATOR_METADATA_CHARS = 1_024
private const val MAX_CONCURRENT_COLLABORATOR_WAITS = 4
private const val COLLABORATOR_POLL_INTERVAL_MS = 1_000L

@Serializable
data class GenerateCollaboratorPayloadResult(
    val status: CollaboratorToolStatus,
    val payload: String? = null,
    val payloadId: String? = null,
    val server: String? = null,
    val error: String? = null,
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null,
    val since: String? = null,
    val waitSeconds: Int? = null,
    val maxResults: Int? = null,
    val detailLimitBytes: Int? = null,
    val detailEncoding: CollaboratorDetailEncoding? = null,
    val newestFirst: Boolean? = null,
)

@Serializable
enum class CollaboratorDetailEncoding {
    @SerialName("text")
    TEXT,

    @SerialName("base64")
    BASE64,
}

@Serializable
enum class CollaboratorToolStatus {
    @SerialName("ok")
    OK,

    @SerialName("access_denied")
    ACCESS_DENIED,

    @SerialName("invalid_argument")
    INVALID_ARGUMENT,

    @SerialName("burp_error")
    BURP_ERROR,
}

@Serializable
data class CollaboratorDnsInteraction(
    val queryType: String,
    val query: HistoryContentSlice? = null,
)

@Serializable
data class CollaboratorHttpInteraction(
    val protocol: String,
    val request: HistoryContentSlice? = null,
    val response: HistoryContentSlice? = null,
)

@Serializable
data class CollaboratorSmtpInteraction(
    val protocol: String,
    val conversation: HistoryContentSlice? = null,
)

@Serializable
data class CollaboratorInteractionResult(
    val id: String,
    val type: String,
    val timestamp: String,
    val clientIp: String,
    val clientPort: Int,
    val customData: String? = null,
    val customDataTruncated: Boolean = false,
    val dnsDetails: CollaboratorDnsInteraction? = null,
    val httpDetails: CollaboratorHttpInteraction? = null,
    val smtpDetails: CollaboratorSmtpInteraction? = null,
)

@Serializable
data class GetCollaboratorInteractionsResult(
    val status: CollaboratorToolStatus,
    val interactions: List<CollaboratorInteractionResult>,
    val returned: Int,
    val matched: Int,
    val scanned: Int,
    val scanLimitReached: Boolean,
    val hasMore: Boolean,
    val waitedMillis: Long,
    val timedOut: Boolean,
    val detailBytesReturned: Int,
    val detailsTruncated: Boolean,
    val detailsUnavailable: Boolean,
    val error: String? = null,
)

internal class CollaboratorToolService(
    private val api: MontoyaApi,
    private val pollIntervalMs: Long = COLLABORATOR_POLL_INTERVAL_MS,
) {
    init {
        require(pollIntervalMs in 1..COLLABORATOR_POLL_INTERVAL_MS) { "pollIntervalMs is out of range" }
    }
    private val client: CollaboratorClient by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        api.collaborator().createClient()
    }
    private val clientMutex = Mutex()
    private val waitAdmission = Semaphore(MAX_CONCURRENT_COLLABORATOR_WAITS)

    suspend fun generate(input: GenerateCollaboratorPayload): StructuredToolResponse<GenerateCollaboratorPayloadResult> {
        val customData = input.customData
        if (customData != null &&
            (customData.length !in 1..MAX_COLLABORATOR_CUSTOM_DATA_CHARS ||
                customData.any { !it.isAsciiLetterOrDigit() })
        ) {
            val result = GenerateCollaboratorPayloadResult(
                status = CollaboratorToolStatus.INVALID_ARGUMENT,
                error = "customData must contain 1 to $MAX_COLLABORATOR_CUSTOM_DATA_CHARS ASCII alphanumeric characters",
            )
            return StructuredToolResponse(result)
        }

        return try {
            val payload = clientMutex.withLock {
                if (customData == null) client.generatePayload() else client.generatePayload(customData)
            }
            val result = GenerateCollaboratorPayloadResult(
                status = CollaboratorToolStatus.OK,
                payload = payload.toString().take(2_048),
                payloadId = payload.id().toString().take(MAX_COLLABORATOR_PAYLOAD_ID_CHARS),
                server = client.server().address().take(MAX_HTTP_SEARCH_HOST_CHARS),
            )
            StructuredToolResponse(
                output = result,
                text = "Payload: ${result.payload}\nPayload ID: ${result.payloadId}\nCollaborator server: ${result.server}",
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            StructuredToolResponse(
                GenerateCollaboratorPayloadResult(
                    status = CollaboratorToolStatus.BURP_ERROR,
                    error = "Burp could not generate a Collaborator payload: ${safeCollaboratorException(e)}",
                )
            )
        }
    }

    suspend fun interactions(
        input: GetCollaboratorInteractions,
        config: McpConfig,
        reportProgress: suspend (Double, Double?, String?) -> Unit,
    ): StructuredToolResponse<GetCollaboratorInteractionsResult> {
        val normalized = try {
            normalizeInteractionInput(input)
        } catch (e: IllegalArgumentException) {
            return StructuredToolResponse(interactionError(CollaboratorToolStatus.INVALID_ARGUMENT, e.message.orEmpty()))
        }

        val allowed = try {
            DataAccessSecurity.checkDataAccessPermission(DataAccessType.COLLABORATOR_INTERACTIONS, config)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return StructuredToolResponse(
                interactionError(
                    CollaboratorToolStatus.BURP_ERROR,
                    "Burp could not check Collaborator data access: ${safeCollaboratorException(e)}",
                )
            )
        }
        if (!allowed) {
            runCatching { api.logging().logToOutput("MCP Collaborator interaction access denied") }
            return StructuredToolResponse(
                interactionError(
                    CollaboratorToolStatus.ACCESS_DENIED,
                    "Collaborator interaction access denied by Burp Suite",
                )
            )
        }
        runCatching { api.logging().logToOutput("MCP Collaborator interaction access granted") }

        return waitAdmission.withPermit {
            val started = System.nanoTime()
            val waitNanos = normalized.waitSeconds * 1_000_000_000L
            var selected: SelectedInteractions? = null
            var timedOut = false
            var poll = 0
            while (selected == null) {
                val elapsedNanos = (System.nanoTime() - started).coerceAtLeast(0)
                reportProgress(
                    min(elapsedNanos, waitNanos).toDouble() / 1_000_000_000.0,
                    normalized.waitSeconds.toDouble().takeIf { normalized.waitSeconds > 0 },
                    "Polling Burp Collaborator (attempt ${poll + 1})",
                )
                val interactions = try {
                    fetchInteractions(normalized.payloadId)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    return@withPermit StructuredToolResponse(
                        interactionError(
                            CollaboratorToolStatus.BURP_ERROR,
                            "Burp could not poll Collaborator interactions: ${safeCollaboratorException(e)}",
                            waitedMillis(started),
                        )
                    )
                }
                val candidate = try {
                    selectInteractions(interactions, normalized)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    return@withPermit StructuredToolResponse(
                        interactionError(
                            CollaboratorToolStatus.BURP_ERROR,
                            "Burp returned invalid Collaborator interaction metadata: ${safeCollaboratorException(e)}",
                            waitedMillis(started),
                        )
                    )
                }
                if (candidate.items.isNotEmpty() || normalized.waitSeconds == 0) {
                    selected = candidate
                    break
                }

                val nowElapsed = (System.nanoTime() - started).coerceAtLeast(0)
                if (nowElapsed >= waitNanos) {
                    selected = candidate
                    timedOut = true
                    break
                }
                val remainingMs = ((waitNanos - nowElapsed) / 1_000_000L).coerceAtLeast(1)
                delay(min(pollIntervalMs, remainingMs))
                poll++
            }

            val finalSelection = requireNotNull(selected)
            val detailBudget = CollaboratorDetailBudget(normalized.detailLimitBytes, normalized.detailEncoding)
            val outputItems = try {
                finalSelection.items.map { it.toBoundedResult(detailBudget) }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return@withPermit StructuredToolResponse(
                    interactionError(
                        CollaboratorToolStatus.BURP_ERROR,
                        "Burp returned an invalid Collaborator interaction: ${safeCollaboratorException(e)}",
                        waitedMillis(started),
                    )
                )
            }
            val waited = waitedMillis(started)
            reportProgress(
                normalized.waitSeconds.toDouble(),
                normalized.waitSeconds.toDouble().takeIf { normalized.waitSeconds > 0 },
                "Collaborator polling completed with ${outputItems.size} interaction(s)",
            )
            val result = GetCollaboratorInteractionsResult(
                status = CollaboratorToolStatus.OK,
                interactions = outputItems,
                returned = outputItems.size,
                matched = finalSelection.matched,
                scanned = finalSelection.scanned,
                scanLimitReached = finalSelection.scanLimitReached,
                hasMore = finalSelection.scanLimitReached || finalSelection.matched > outputItems.size,
                waitedMillis = waited,
                timedOut = timedOut && outputItems.isEmpty(),
                detailBytesReturned = detailBudget.returned,
                detailsTruncated = detailBudget.truncated,
                detailsUnavailable = detailBudget.unavailable,
            )
            val text = if (outputItems.isEmpty()) {
                "No interactions detected"
            } else {
                outputItems.joinToString("\n\n") { Json.encodeToString(it) }
            }
            StructuredToolResponse(result, text)
        }
    }

    private suspend fun fetchInteractions(payloadId: String?): List<Interaction> = clientMutex.withLock {
        if (payloadId == null) {
            client.getAllInteractions()
        } else {
            client.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
        }
    }
}

private data class NormalizedCollaboratorInput(
    val payloadId: String?,
    val since: Instant?,
    val waitSeconds: Int,
    val maxResults: Int,
    val detailLimitBytes: Int,
    val detailEncoding: String,
    val newestFirst: Boolean,
)

private data class SelectedInteractions(
    val items: List<Interaction>,
    val matched: Int,
    val scanned: Int,
    val scanLimitReached: Boolean,
)

private fun normalizeInteractionInput(input: GetCollaboratorInteractions): NormalizedCollaboratorInput {
    val payloadId = input.payloadId?.also {
        require(it.length in 1..MAX_COLLABORATOR_PAYLOAD_ID_CHARS && it.none(Char::isISOControl) && it.none(Char::isWhitespace)) {
            "payloadId is empty, too long, or contains whitespace/control characters"
        }
    }
    val since = input.since?.let { value ->
        require(value.length in 1..MAX_COLLABORATOR_SINCE_CHARS) { "since is empty or too long" }
        try {
            Instant.parse(value)
        } catch (_: DateTimeParseException) {
            throw IllegalArgumentException("since must be an ISO-8601 UTC instant such as 2025-01-01T12:00:00Z")
        }
    }
    val wait = input.waitSeconds ?: 0
    require(wait in 0..MAX_COLLABORATOR_WAIT_SECONDS) {
        "waitSeconds must be between 0 and $MAX_COLLABORATOR_WAIT_SECONDS"
    }
    val maxResults = input.maxResults ?: DEFAULT_COLLABORATOR_RESULTS
    require(maxResults in 1..MAX_COLLABORATOR_RESULTS) {
        "maxResults must be between 1 and $MAX_COLLABORATOR_RESULTS"
    }
    val detailLimit = input.detailLimitBytes ?: DEFAULT_COLLABORATOR_DETAIL_BYTES
    require(detailLimit in 0..MAX_COLLABORATOR_DETAIL_BYTES) {
        "detailLimitBytes must be between 0 and $MAX_COLLABORATOR_DETAIL_BYTES"
    }
    val encoding = when (input.detailEncoding ?: CollaboratorDetailEncoding.TEXT) {
        CollaboratorDetailEncoding.TEXT -> "text"
        CollaboratorDetailEncoding.BASE64 -> "base64"
    }
    return NormalizedCollaboratorInput(
        payloadId = payloadId,
        since = since,
        waitSeconds = wait,
        maxResults = maxResults,
        detailLimitBytes = detailLimit,
        detailEncoding = encoding,
        newestFirst = input.newestFirst ?: true,
    )
}

private suspend fun selectInteractions(
    interactions: List<Interaction>,
    input: NormalizedCollaboratorInput,
): SelectedInteractions {
    val scanLimitReached = interactions.size > MAX_COLLABORATOR_SCANNED_INTERACTIONS
    val scannedWindow = if (input.newestFirst) {
        interactions.takeLast(MAX_COLLABORATOR_SCANNED_INTERACTIONS).asReversed()
    } else {
        interactions.take(MAX_COLLABORATOR_SCANNED_INTERACTIONS)
    }
    var matched = 0
    val selected = ArrayList<Interaction>(input.maxResults)
    scannedWindow.forEachIndexed { index, interaction ->
        if (index and 63 == 0) currentCoroutineContext().ensureActive()
        if (input.since == null || interaction.timeStamp().toInstant().isAfter(input.since)) {
            matched++
            if (selected.size < input.maxResults) selected += interaction
        }
    }
    return SelectedInteractions(selected, matched, scannedWindow.size, scanLimitReached)
}

private class CollaboratorDetailBudget(
    private val perFieldLimit: Int,
    private val encoding: String,
) {
    private var remaining = MAX_COLLABORATOR_TOTAL_DETAIL_BYTES
    var returned: Int = 0
        private set
    var truncated: Boolean = false
        private set
    var unavailable: Boolean = false
        private set

    fun markUnavailable() {
        unavailable = true
    }

    fun slice(bytes: MontoyaByteArray?): HistoryContentSlice? {
        if (bytes == null || perFieldLimit == 0 || remaining == 0) {
            if (bytes != null && bytes.length() > 0) truncated = true
            return null
        }
        val allowed = min(perFieldLimit, remaining)
        val result = bytes.toHistorySlice(0, allowed, encoding)
        returned += result.returnedBytes
        remaining -= result.returnedBytes
        if (result.hasMore || remaining == 0 && bytes.length() > result.returnedBytes) truncated = true
        return result
    }

    fun slice(text: String?): HistoryContentSlice? {
        if (text == null) return null
        if (perFieldLimit == 0 || remaining == 0) {
            if (text.isNotEmpty()) truncated = true
            return null
        }
        val allowed = minOf(perFieldLimit, remaining)
        val measured = text.measureUtf8Prefix(allowed)
        val selected = measured.prefix.toByteArray(StandardCharsets.UTF_8).let {
            if (it.size <= allowed) it else it.copyOf(allowed)
        }
        returned += selected.size
        remaining -= selected.size
        if (selected.size < measured.totalBytes) truncated = true
        return HistoryContentSlice(
            encoding = encoding,
            data = if (encoding == "base64") Base64.getEncoder().encodeToString(selected)
            else selected.toString(StandardCharsets.UTF_8),
            offsetBytes = 0,
            returnedBytes = selected.size,
            totalBytes = measured.totalBytes,
            hasMore = selected.size < measured.totalBytes,
            nextOffsetBytes = selected.size.takeIf { selected.size < measured.totalBytes },
        )
    }
}

private data class Utf8PrefixMeasurement(
    val totalBytes: Int,
    val prefix: String,
)

/** Computes exact Java UTF-8 replacement semantics while allocating only the requested prefix. */
private fun String.measureUtf8Prefix(limitBytes: Int): Utf8PrefixMeasurement {
    var index = 0
    var total = 0L
    var prefixEnd = 0
    while (index < length) {
        val character = this[index]
        val charCount: Int
        val encodedBytes: Int
        when {
            character.code <= 0x7f -> {
                charCount = 1
                encodedBytes = 1
            }
            character.code <= 0x7ff -> {
                charCount = 1
                encodedBytes = 2
            }
            Character.isHighSurrogate(character) && index + 1 < length && Character.isLowSurrogate(this[index + 1]) -> {
                charCount = 2
                encodedBytes = 4
            }
            Character.isSurrogate(character) -> {
                charCount = 1
                encodedBytes = 1
            }
            else -> {
                charCount = 1
                encodedBytes = 3
            }
        }
        if (total < limitBytes) prefixEnd = index + charCount
        total += encodedBytes
        require(total <= Int.MAX_VALUE) { "Collaborator text detail is too large" }
        index += charCount
    }
    return Utf8PrefixMeasurement(total.toInt(), substring(0, prefixEnd))
}

private fun CollaboratorDetailBudget.sliceWithFallback(
    bytes: () -> MontoyaByteArray?,
    text: () -> String?,
): HistoryContentSlice? = try {
    slice(bytes())
} catch (_: Exception) {
    try {
        slice(text())
    } catch (_: Exception) {
        markUnavailable()
        null
    }
}

private fun Interaction.toBoundedResult(budget: CollaboratorDetailBudget): CollaboratorInteractionResult {
    val custom = customData().orElse(null)
    val customBounded = custom?.take(MAX_COLLABORATOR_METADATA_CHARS)
    val dns = dnsDetails().orElse(null)?.let {
        CollaboratorDnsInteraction(
            queryType = it.queryType().name,
            query = runCatching { budget.slice(it.query()) }.getOrElse {
                budget.markUnavailable()
                null
            },
        )
    }
    val http = httpDetails().orElse(null)?.let {
        val requestResponse = it.requestResponse()
        val request = requestResponse?.request()
        val response = requestResponse?.response()
        CollaboratorHttpInteraction(
            protocol = it.protocol().name,
            request = budget.sliceWithFallback(
                bytes = { request?.toByteArray() },
                text = { request?.toString() },
            ),
            response = budget.sliceWithFallback(
                bytes = { response?.toByteArray() },
                text = { response?.toString() },
            ),
        )
    }
    val smtp = smtpDetails().orElse(null)?.let {
        CollaboratorSmtpInteraction(
            protocol = it.protocol().name,
            conversation = runCatching { budget.slice(it.conversation()) }.getOrElse {
                budget.markUnavailable()
                null
            },
        )
    }
    return CollaboratorInteractionResult(
        id = id().toString().take(MAX_COLLABORATOR_PAYLOAD_ID_CHARS),
        type = type().name,
        timestamp = timeStamp().toString().take(64),
        clientIp = clientIp().hostAddress.take(64),
        clientPort = clientPort(),
        customData = customBounded,
        customDataTruncated = custom != null && custom.length > MAX_COLLABORATOR_METADATA_CHARS,
        dnsDetails = dns,
        httpDetails = http,
        smtpDetails = smtp,
    )
}

private fun interactionError(
    status: CollaboratorToolStatus,
    error: String,
    waitedMillis: Long = 0,
) = GetCollaboratorInteractionsResult(
    status = status,
    interactions = emptyList(),
    returned = 0,
    matched = 0,
    scanned = 0,
    scanLimitReached = false,
    hasMore = false,
    waitedMillis = waitedMillis,
    timedOut = false,
    detailBytesReturned = 0,
    detailsTruncated = false,
    detailsUnavailable = false,
    error = error.take(512),
)

private fun Char.isAsciiLetterOrDigit(): Boolean = this in 'a'..'z' || this in 'A'..'Z' || this in '0'..'9'

private fun waitedMillis(startedNanos: Long): Long =
    ((System.nanoTime() - startedNanos).coerceAtLeast(0) / 1_000_000L)

private fun safeCollaboratorException(error: Exception): String =
    "${error::class.simpleName ?: "Exception"}: ${error.message.orEmpty()}".take(512)
