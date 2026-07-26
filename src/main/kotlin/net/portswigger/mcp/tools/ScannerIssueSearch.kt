package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.scanner.audit.issues.AuditIssue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.AuditIssueConfidence as SerializableAuditIssueConfidence
import net.portswigger.mcp.schema.AuditIssueDefinition as SerializableAuditIssueDefinition
import net.portswigger.mcp.schema.AuditIssueSeverity as SerializableAuditIssueSeverity
import net.portswigger.mcp.schema.HttpRequestResponse as SerializableHttpRequestResponse
import net.portswigger.mcp.schema.HttpService as SerializableHttpService
import net.portswigger.mcp.schema.Interaction as SerializableInteraction
import net.portswigger.mcp.schema.IssueDetails
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.safeExceptionSummary
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private const val DEFAULT_SCANNER_ISSUE_LIMIT = 25
private const val MAX_SCANNER_ISSUE_LIMIT = 50
internal const val MAX_SCANNER_ISSUE_SCAN = 10_000
private const val MAX_SCANNER_FILTER_VALUES = 8
private const val MAX_SCANNER_HOST_CHARS = 253
private const val MAX_SCANNER_NAME_FILTER_CHARS = 256
private const val MAX_SCANNER_CURSOR_CHARS = 16_384
private const val MAX_LEGACY_SCANNER_TEXT_CHARS = 512 * 1024
private const val MAX_LEGACY_SCANNER_RECORD_INPUT_CHARS = 64 * 1024
private const val MAX_LEGACY_SCANNER_FIELD_CHARS = 8 * 1024
private const val MAX_LEGACY_SCANNER_MESSAGE_BYTES = 16 * 1024
private const val MAX_LEGACY_SCANNER_EVIDENCE = 8
private const val MAX_LEGACY_SCANNER_INTERACTIONS = 16
private const val SCANNER_CURSOR_VERSION = 1
private const val SCANNER_CURSOR_HMAC = "HmacSHA256"
private const val LEGACY_SCANNER_TRUNCATION_MARKER =
    "\n\n<Scanner issue output truncated; use summariesOnly or get_scanner_issue_by_id>"

@Serializable
data class GetScannerIssues(
    @JsonSchemaMetadata(description = "Maximum issues returned.", minimum = 1, maximum = 50, defaultJson = "25")
    override val count: Int = DEFAULT_SCANNER_ISSUE_LIMIT,
    @JsonSchemaMetadata(description = "Legacy-mode offset; cursor mode requires zero.", minimum = 0, defaultJson = "0")
    override val offset: Int = 0,
    @JsonSchemaMetadata(description = "Return compact issue summaries.", defaultJson = "false")
    val summariesOnly: Boolean? = null,
    @JsonSchemaMetadata(description = "Use snapshot-bound signed cursor pagination.", defaultJson = "false")
    val cursorMode: Boolean? = null,
    @JsonSchemaMetadata(description = "Opaque signed continuation cursor.", maxLength = 16384)
    val cursor: String? = null,
    @JsonSchemaMetadata(description = "Severity filters.", minItems = 1, maxItems = 8)
    val severities: List<ScannerIssueSeverityFilter>? = null,
    @JsonSchemaMetadata(description = "Confidence filters.", minItems = 1, maxItems = 8)
    val confidences: List<ScannerIssueConfidenceFilter>? = null,
    @JsonSchemaMetadata(description = "Exact canonical issue host.", minLength = 1, maxLength = 253)
    val host: String? = null,
    @JsonSchemaMetadata(description = "Issue-name substring filter.", minLength = 1, maxLength = 256)
    val nameContains: String? = null,
    @JsonSchemaMetadata(description = "Use case-sensitive name matching.", defaultJson = "false")
    val caseSensitive: Boolean? = null,
    @JsonSchemaMetadata(description = "Return newest issues first.", defaultJson = "true")
    val newestFirst: Boolean? = null,
) : Paginated

@Serializable
enum class ScannerIssueSeverityFilter {
    @SerialName("high")
    HIGH,

    @SerialName("medium")
    MEDIUM,

    @SerialName("low")
    LOW,

    @SerialName("information")
    INFORMATION,

    @SerialName("false_positive")
    FALSE_POSITIVE,
}

@Serializable
enum class ScannerIssueConfidenceFilter {
    @SerialName("certain")
    CERTAIN,

    @SerialName("firm")
    FIRM,

    @SerialName("tentative")
    TENTATIVE,
}

@Serializable
enum class ScannerIssuePageStatus {
    @SerialName("ok")
    OK,

    @SerialName("access_denied")
    ACCESS_DENIED,

    @SerialName("invalid_argument")
    INVALID_ARGUMENT,

    @SerialName("invalid_cursor")
    INVALID_CURSOR,

    @SerialName("stale_cursor")
    STALE_CURSOR,

    @SerialName("project_mismatch")
    PROJECT_MISMATCH,

    @SerialName("burp_error")
    BURP_ERROR,
}

@Serializable
data class ScannerIssuePageResult(
    val status: ScannerIssuePageStatus,
    val projectId: String?,
    val items: List<ScannerIssueSummary>,
    val returned: Int,
    val scanned: Int,
    val snapshotSize: Int?,
    val scanLimitReached: Boolean,
    val hasMore: Boolean,
    val nextCursor: String?,
    val legacyMode: Boolean,
    val legacyTextTruncated: Boolean = false,
    val error: String? = null,
)

@Serializable
private data class NormalizedScannerIssueQuery(
    val severities: List<ScannerIssueSeverityFilter>?,
    val confidences: List<ScannerIssueConfidenceFilter>?,
    val host: String?,
    val nameContains: String?,
    val caseSensitive: Boolean,
    val newestFirst: Boolean,
)

@Serializable
private data class ScannerIssueCursorSnapshot(
    val size: Int,
    val firstAnchor: String?,
    val lastAnchor: String?,
)

@Serializable
private data class ScannerIssueCursor(
    val version: Int,
    val projectId: String,
    val query: NormalizedScannerIssueQuery,
    val snapshot: ScannerIssueCursorSnapshot,
    val nextIndex: Int,
)

private data class PreparedScannerIssueCursor(
    val cursor: ScannerIssueCursor?,
    val query: NormalizedScannerIssueQuery,
)

private class ScannerIssueSearchError(
    val status: ScannerIssuePageStatus,
    override val message: String,
) : Exception(message)

internal class ScannerIssueSearchService(
    private val api: MontoyaApi,
    private val config: McpConfig,
    cursorSecret: ByteArray = ByteArray(32).also(SecureRandom()::nextBytes),
) {
    private val key = SecretKeySpec(
        cursorSecret.copyOf().also { require(it.size >= 32) { "cursorSecret must contain at least 32 bytes" } },
        SCANNER_CURSOR_HMAC,
    )
    private val cursorJson = Json { encodeDefaults = true }

    suspend fun get(input: GetScannerIssues): StructuredToolResponse<ScannerIssuePageResult> {
        if (input.count !in 1..MAX_SCANNER_ISSUE_LIMIT) {
            return responseError(
                ScannerIssuePageStatus.INVALID_ARGUMENT,
                "count must be between 1 and $MAX_SCANNER_ISSUE_LIMIT",
                legacyMode = !input.usesCursorMode(),
            )
        }
        if (input.offset < 0) {
            return responseError(
                ScannerIssuePageStatus.INVALID_ARGUMENT,
                "offset must be non-negative",
                legacyMode = !input.usesCursorMode(),
            )
        }

        val preparedCursor = if (input.usesCursorMode()) {
            try {
                val cursor = input.cursor?.let(::decodeCursor)
                val query = when {
                    cursor == null -> normalizeQuery(input)
                    input.hasExplicitCursorQuery() -> normalizeQuery(input).also {
                        if (it != cursor.query) {
                            throw ScannerIssueSearchError(
                                ScannerIssuePageStatus.INVALID_CURSOR,
                                "cursor does not match the supplied Scanner issue filters",
                            )
                        }
                    }
                    else -> cursor.query
                }
                PreparedScannerIssueCursor(cursor, query)
            } catch (e: IllegalArgumentException) {
                return responseError(
                    ScannerIssuePageStatus.INVALID_ARGUMENT,
                    e.message ?: "invalid Scanner issue filters",
                    legacyMode = false,
                )
            } catch (e: ScannerIssueSearchError) {
                return responseError(e.status, e.message, legacyMode = false)
            }
        } else {
            null
        }

        val projectId = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return responseError(
                ScannerIssuePageStatus.BURP_ERROR,
                "Burp could not read the current project: ${safeScannerSearchException(e)}",
                legacyMode = !input.usesCursorMode(),
            )
        }
        val allowed = try {
            DataAccessSecurity.checkDataAccessPermission(DataAccessType.SCANNER_ISSUES, config)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return responseError(
                ScannerIssuePageStatus.BURP_ERROR,
                "Burp could not check Scanner issue access: ${safeScannerSearchException(e)}",
                legacyMode = !input.usesCursorMode(),
            )
        }
        if (!allowed) {
            return StructuredToolResponse(
                output = scannerIssuePageError(
                    ScannerIssuePageStatus.ACCESS_DENIED,
                    "Scanner issue access denied by Burp Suite",
                    legacyMode = !input.usesCursorMode(),
                ),
                text = "Scanner issue access denied by Burp Suite",
            )
        }

        val projectAfterApproval = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return responseError(
                ScannerIssuePageStatus.BURP_ERROR,
                "Burp could not recheck the project after Scanner approval: ${safeScannerSearchException(e)}",
                projectId,
                legacyMode = preparedCursor == null,
            )
        }
        if (projectAfterApproval != projectId) {
            return responseError(
                ScannerIssuePageStatus.PROJECT_MISMATCH,
                "Burp project changed during Scanner issue approval",
                projectAfterApproval,
                legacyMode = preparedCursor == null,
            )
        }
        if (preparedCursor?.cursor != null && preparedCursor.cursor.projectId != projectId) {
            return responseError(
                ScannerIssuePageStatus.PROJECT_MISMATCH,
                "cursor belongs to a different Burp project",
                projectId,
                legacyMode = false,
            )
        }
        val issues = try {
            api.siteMap().issues()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return responseError(
                ScannerIssuePageStatus.BURP_ERROR,
                "Burp could not read Scanner issues: ${safeScannerSearchException(e)}",
                projectId,
                legacyMode = !input.usesCursorMode(),
            )
        }

        val projectAfterSnapshot = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return responseError(
                ScannerIssuePageStatus.BURP_ERROR,
                "Burp could not recheck the project after reading Scanner issues: ${safeScannerSearchException(e)}",
                projectId,
                legacyMode = preparedCursor == null,
            )
        }
        if (projectAfterSnapshot != projectId) {
            return responseError(
                ScannerIssuePageStatus.PROJECT_MISMATCH,
                "Burp project changed while reading Scanner issues",
                projectAfterSnapshot,
                legacyMode = preparedCursor == null,
            )
        }

        val response = try {
            if (preparedCursor != null) {
                cursorPage(input, projectId, issues, preparedCursor)
            } else {
                legacyPage(input, projectId, issues)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return responseError(
                ScannerIssuePageStatus.BURP_ERROR,
                "Burp returned an invalid Scanner issue: ${safeScannerSearchException(e)}",
                projectId,
                legacyMode = preparedCursor == null,
            )
        }
        val finalProjectId = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return responseError(
                ScannerIssuePageStatus.BURP_ERROR,
                "Burp could not recheck the project after materializing Scanner issues: ${safeScannerSearchException(e)}",
                projectId,
                legacyMode = preparedCursor == null,
            )
        }
        if (finalProjectId != projectId) {
            return responseError(
                ScannerIssuePageStatus.PROJECT_MISMATCH,
                "Burp project changed while Scanner issues were materialized",
                finalProjectId,
                legacyMode = preparedCursor == null,
            )
        }
        return response
    }

    private suspend fun legacyPage(
        input: GetScannerIssues,
        projectId: String,
        issues: List<AuditIssue>,
    ): StructuredToolResponse<ScannerIssuePageResult> {
        val selected = issues.withIndex().asSequence().drop(input.offset).take(input.count).toList()
        val page = selected.toBoundedLegacyPage(input.summariesOnly == true)
        return StructuredToolResponse(
            output = ScannerIssuePageResult(
                status = ScannerIssuePageStatus.OK,
                projectId = projectId,
                items = page.summaries,
                returned = page.summaries.size,
                scanned = page.scanned,
                snapshotSize = issues.size,
                scanLimitReached = false,
                hasMore = input.offset.toLong() + page.summaries.size.toLong() < issues.size.toLong(),
                nextCursor = null,
                legacyMode = true,
                legacyTextTruncated = page.truncated,
            ),
            text = page.text,
        )
    }

    private suspend fun cursorPage(
        input: GetScannerIssues,
        projectId: String,
        issues: List<AuditIssue>,
        prepared: PreparedScannerIssueCursor,
    ): StructuredToolResponse<ScannerIssuePageResult> {
        if (input.offset != 0) {
            return responseError(
                ScannerIssuePageStatus.INVALID_ARGUMENT,
                "offset is only supported in legacy mode; use cursor for cursor mode",
                projectId,
                legacyMode = false,
            )
        }
        if (input.summariesOnly == false) {
            return responseError(
                ScannerIssuePageStatus.INVALID_ARGUMENT,
                "cursor mode returns compact summaries; omit summariesOnly or set it to true",
                projectId,
                legacyMode = false,
            )
        }

        val cursor = prepared.cursor
        val query = prepared.query
        if (cursor != null && cursor.projectId != projectId) {
            return responseError(
                ScannerIssuePageStatus.PROJECT_MISMATCH,
                "cursor belongs to a different Burp project",
                projectId,
                legacyMode = false,
            )
        }
        val snapshot = if (cursor == null) {
            ScannerIssueCursorSnapshot(
                size = issues.size,
                firstAnchor = issues.firstOrNull()?.stableHistoryId(0),
                lastAnchor = issues.lastOrNull()?.stableHistoryId(issues.lastIndex),
            )
        } else {
            try {
                validateSnapshot(cursor, issues)
                cursor.snapshot
            } catch (e: ScannerIssueSearchError) {
                return responseError(e.status, e.message, projectId, legacyMode = false)
            }
        }

        var index = cursor?.nextIndex ?: if (query.newestFirst) snapshot.size - 1 else 0
        val direction = if (query.newestFirst) -1 else 1
        val compiledQuery = CompiledScannerIssueQuery(query)
        val results = ArrayList<ScannerIssueSummary>(input.count)
        var scanned = 0
        while (index in 0 until snapshot.size && results.size < input.count && scanned < MAX_SCANNER_ISSUE_SCAN) {
            if (scanned and 63 == 0) currentCoroutineContext().ensureActive()
            val issue = issues[index]
            scanned++
            if (issue.matches(compiledQuery)) results += issue.toHistorySummary(issue.stableHistoryId(index))
            index += direction
        }
        val scanLimitReached = scanned >= MAX_SCANNER_ISSUE_SCAN && index in 0 until snapshot.size
        val hasMore = index in 0 until snapshot.size
        val nextCursor = if (hasMore) {
            encodeCursor(
                ScannerIssueCursor(
                    version = SCANNER_CURSOR_VERSION,
                    projectId = projectId,
                    query = query,
                    snapshot = snapshot,
                    nextIndex = index,
                )
            )
        } else {
            null
        }
        val result = ScannerIssuePageResult(
            status = ScannerIssuePageStatus.OK,
            projectId = projectId,
            items = results,
            returned = results.size,
            scanned = scanned,
            snapshotSize = snapshot.size,
            scanLimitReached = scanLimitReached,
            hasMore = hasMore,
            nextCursor = nextCursor,
            legacyMode = false,
        )
        return StructuredToolResponse(result)
    }

    private fun validateSnapshot(cursor: ScannerIssueCursor, issues: List<AuditIssue>) {
        if (cursor.version != SCANNER_CURSOR_VERSION) {
            throw ScannerIssueSearchError(ScannerIssuePageStatus.INVALID_CURSOR, "unsupported cursor version")
        }
        if (cursor.snapshot.size < 0 || cursor.snapshot.size > issues.size) {
            throw ScannerIssueSearchError(
                ScannerIssuePageStatus.STALE_CURSOR,
                "Scanner issue list changed while paging; start a new query",
            )
        }
        if (cursor.nextIndex !in -1..cursor.snapshot.size) {
            throw ScannerIssueSearchError(ScannerIssuePageStatus.INVALID_CURSOR, "cursor position is invalid")
        }
        if (cursor.snapshot.size > 0 &&
            (issues.first().stableHistoryId(0) != cursor.snapshot.firstAnchor ||
                issues[cursor.snapshot.size - 1].stableHistoryId(cursor.snapshot.size - 1) != cursor.snapshot.lastAnchor)
        ) {
            throw ScannerIssueSearchError(
                ScannerIssuePageStatus.STALE_CURSOR,
                "Scanner issue ordering changed while paging; start a new query",
            )
        }
    }

    private fun encodeCursor(cursor: ScannerIssueCursor): String {
        val payload = cursorJson.encodeToString(cursor).toByteArray(StandardCharsets.UTF_8)
        val value = Base64.getUrlEncoder().withoutPadding().encodeToString(payload) + "." +
            Base64.getUrlEncoder().withoutPadding().encodeToString(hmac(payload))
        check(value.length <= MAX_SCANNER_CURSOR_CHARS) { "generated Scanner cursor exceeded its size bound" }
        return value
    }

    private fun decodeCursor(value: String): ScannerIssueCursor {
        if (value.length !in 1..MAX_SCANNER_CURSOR_CHARS) {
            throw ScannerIssueSearchError(ScannerIssuePageStatus.INVALID_CURSOR, "cursor is too large or empty")
        }
        val separator = value.indexOf('.')
        if (separator <= 0 || separator != value.lastIndexOf('.') || separator == value.lastIndex) {
            throw ScannerIssueSearchError(ScannerIssuePageStatus.INVALID_CURSOR, "cursor format is invalid")
        }
        val payload: ByteArray
        val signature: ByteArray
        try {
            payload = Base64.getUrlDecoder().decode(value.substring(0, separator))
            signature = Base64.getUrlDecoder().decode(value.substring(separator + 1))
        } catch (_: IllegalArgumentException) {
            throw ScannerIssueSearchError(ScannerIssuePageStatus.INVALID_CURSOR, "cursor encoding is invalid")
        }
        if (!MessageDigest.isEqual(hmac(payload), signature)) {
            throw ScannerIssueSearchError(ScannerIssuePageStatus.INVALID_CURSOR, "cursor signature is invalid")
        }
        return try {
            cursorJson.decodeFromString<ScannerIssueCursor>(payload.toString(StandardCharsets.UTF_8))
        } catch (_: Exception) {
            throw ScannerIssueSearchError(ScannerIssuePageStatus.INVALID_CURSOR, "cursor payload is invalid")
        }
    }

    private fun hmac(payload: ByteArray): ByteArray = Mac.getInstance(SCANNER_CURSOR_HMAC).run {
        init(key)
        doFinal(payload)
    }
}

private data class BoundedLegacyScannerPage(
    val summaries: List<ScannerIssueSummary>,
    val text: String,
    val truncated: Boolean,
    val scanned: Int,
)

private data class BoundedLegacyIssueDetails(
    val value: IssueDetails,
    val truncated: Boolean,
)

private suspend fun List<IndexedValue<AuditIssue>>.toBoundedLegacyPage(
    summariesOnly: Boolean,
): BoundedLegacyScannerPage {
    if (isEmpty()) return BoundedLegacyScannerPage(emptyList(), "Reached end of items", false, 0)
    val summaries = ArrayList<ScannerIssueSummary>(size)
    val contentLimit = MAX_LEGACY_SCANNER_TEXT_CHARS - LEGACY_SCANNER_TRUNCATION_MARKER.length
    val text = StringBuilder(minOf(contentLimit, size * 4_096))
    var truncated = false
    var scanned = 0
    for ((sourceIndex, issue) in this) {
        currentCoroutineContext().ensureActive()
        scanned++
        val summary = issue.toHistorySummary(issue.stableHistoryId(sourceIndex))
        val bounded = if (summariesOnly) null else issue.toBoundedLegacyDetails()
        val serialized = if (summariesOnly) {
            Json.encodeToString(summary)
        } else {
            Json.encodeToString(requireNotNull(bounded).value)
        }
        val separator = if (text.isEmpty()) "" else "\n\n"
        if (text.length + separator.length + serialized.length > contentLimit) {
            truncated = true
            break
        }
        text.append(separator).append(serialized)
        summaries += summary
        if (bounded?.truncated == true) {
            truncated = true
            break
        }
    }
    if (truncated) text.append(LEGACY_SCANNER_TRUNCATION_MARKER)
    return BoundedLegacyScannerPage(summaries, text.toString(), truncated, scanned)
}

private fun AuditIssue.toBoundedLegacyDetails(): BoundedLegacyIssueDetails {
    val budget = LegacyScannerIssueBudget()
    val service = httpService()
    val serializedService = service?.let {
        SerializableHttpService(
            host = budget.takeRequired(MAX_SCANNER_HOST_CHARS) { it.host() },
            port = it.port(),
            secure = it.secure(),
        )
    }
    val serializedSeverity = SerializableAuditIssueSeverity.valueOf(severity().name)
    val serializedConfidence = SerializableAuditIssueConfidence.valueOf(confidence().name)
    val issueDefinition = definition()
    val serializedDefinition = SerializableAuditIssueDefinition(
        id = budget.takeRequired(MAX_LEGACY_SCANNER_FIELD_CHARS) { issueDefinition.name() },
        background = budget.takeOptional(MAX_LEGACY_SCANNER_FIELD_CHARS) { issueDefinition.background() },
        remediation = budget.takeOptional(MAX_LEGACY_SCANNER_FIELD_CHARS) { issueDefinition.remediation() },
        typeIndex = issueDefinition.typeIndex(),
    )
    val name = budget.takeOptional(MAX_LEGACY_SCANNER_FIELD_CHARS) { name() }
    val baseUrl = budget.takeOptional(MAX_LEGACY_SCANNER_FIELD_CHARS) { baseUrl() }
    val detail = budget.takeOptional(MAX_LEGACY_SCANNER_FIELD_CHARS) { detail() }
    val remediation = budget.takeOptional(MAX_LEGACY_SCANNER_FIELD_CHARS) { remediation() }
    val requestResponses = ArrayList<SerializableHttpRequestResponse>()
    if (budget.canReadOptional()) {
        val evidence = requestResponses()
        if (evidence.size > MAX_LEGACY_SCANNER_EVIDENCE) budget.markTruncated()
        var index = 0
        while (index < evidence.size && index < MAX_LEGACY_SCANNER_EVIDENCE && budget.canReadOptional()) {
            val item = evidence[index]
            requestResponses += SerializableHttpRequestResponse(
                request = budget.takeMessage("<no request>") { item.request()?.toByteArray() },
                response = budget.takeMessage("<no response>") { item.response()?.toByteArray() },
                notes = budget.takeOptional(MAX_LEGACY_SCANNER_FIELD_CHARS) { item.annotations().notes() },
            )
            index++
        }
        if (index < evidence.size) budget.markTruncated()
    } else {
        budget.markTruncated()
    }
    val interactions = ArrayList<SerializableInteraction>()
    if (budget.canReadOptional()) {
        val sourceInteractions = collaboratorInteractions()
        if (sourceInteractions.size > MAX_LEGACY_SCANNER_INTERACTIONS) budget.markTruncated()
        var index = 0
        while (index < sourceInteractions.size && index < MAX_LEGACY_SCANNER_INTERACTIONS && budget.canReadOptional()) {
            val interaction = sourceInteractions[index]
            interactions += SerializableInteraction(
                interactionId = budget.takeRequired(512) { interaction.id().toString() },
                timestamp = budget.takeRequired(512) { interaction.timeStamp().toString() },
            )
            index++
        }
        if (index < sourceInteractions.size) budget.markTruncated()
    } else {
        budget.markTruncated()
    }
    return BoundedLegacyIssueDetails(
        value = IssueDetails(
            name = name,
            detail = detail,
            remediation = remediation,
            httpService = serializedService,
            baseUrl = baseUrl,
            severity = serializedSeverity,
            confidence = serializedConfidence,
            requestResponses = requestResponses,
            collaboratorInteractions = interactions,
            definition = serializedDefinition,
        ),
        truncated = budget.truncated,
    )
}

private class LegacyScannerIssueBudget {
    private var remainingChars = MAX_LEGACY_SCANNER_RECORD_INPUT_CHARS
    var truncated: Boolean = false
        private set

    fun canReadOptional(): Boolean = remainingChars > 0

    fun markTruncated() {
        truncated = true
    }

    fun takeRequired(maxChars: Int, value: () -> String?): String = takeOptional(maxChars, value).orEmpty()

    fun takeOptional(maxChars: Int, value: () -> String?): String? {
        if (!canReadOptional()) {
            truncated = true
            return null
        }
        val raw = value() ?: return null
        val allowed = minOf(maxChars, remainingChars)
        if (raw.length > allowed) truncated = true
        val selected = if (raw.length <= allowed) raw else raw.take(allowed)
        remainingChars -= selected.length
        return selected
    }

    fun takeMessage(absentValue: String, value: () -> MontoyaByteArray?): String? {
        if (!canReadOptional()) {
            truncated = true
            return null
        }
        val bytes = value() ?: return takeOptional(absentValue.length) { absentValue }
        val totalBytes = bytes.length()
        val selectedBytes = minOf(totalBytes, MAX_LEGACY_SCANNER_MESSAGE_BYTES, remainingChars)
        if (selectedBytes < totalBytes) truncated = true
        if (selectedBytes == 0) return ""
        val selected = bytes.subArray(0, selectedBytes).toString()
        return takeOptional(remainingChars) { selected }
    }
}

private fun GetScannerIssues.usesCursorMode(): Boolean =
    cursorMode == true || cursor != null || severities != null || confidences != null || host != null ||
        nameContains != null || caseSensitive != null || newestFirst != null

private fun GetScannerIssues.hasExplicitCursorQuery(): Boolean =
    severities != null || confidences != null || host != null || nameContains != null || caseSensitive != null ||
        newestFirst != null

private fun normalizeQuery(input: GetScannerIssues): NormalizedScannerIssueQuery {
    require((input.severities?.size ?: 0) <= MAX_SCANNER_FILTER_VALUES) { "too many severities" }
    require((input.confidences?.size ?: 0) <= MAX_SCANNER_FILTER_VALUES) { "too many confidences" }
    val severities = input.severities?.distinct()?.sortedBy { it.ordinal }?.also {
        require(it.isNotEmpty()) { "severities must not be empty" }
    }
    val confidences = input.confidences?.distinct()?.sortedBy { it.ordinal }?.also {
        require(it.isNotEmpty()) { "confidences must not be empty" }
    }
    val host = input.host?.trim()?.trimEnd('.')?.lowercase()?.also {
        require(it.length in 1..MAX_SCANNER_HOST_CHARS && it.none(Char::isISOControl)) {
            "host is empty, too long, or contains control characters"
        }
    }
    val name = input.nameContains?.also {
        require(it.length in 1..MAX_SCANNER_NAME_FILTER_CHARS && it.none { character -> character == '\u0000' }) {
            "nameContains is empty, too long, or contains a null character"
        }
    }
    return NormalizedScannerIssueQuery(
        severities = severities,
        confidences = confidences,
        host = host,
        nameContains = name,
        caseSensitive = input.caseSensitive ?: false,
        newestFirst = input.newestFirst ?: true,
    )
}

private data class CompiledScannerIssueQuery(
    val query: NormalizedScannerIssueQuery,
    val severities: Set<String>? = query.severities?.mapTo(HashSet()) { it.name },
    val confidences: Set<String>? = query.confidences?.mapTo(HashSet()) { it.name },
)

private fun AuditIssue.matches(compiled: CompiledScannerIssueQuery): Boolean {
    val query = compiled.query
    if (compiled.severities != null && severity().name !in compiled.severities) return false
    if (compiled.confidences != null && confidence().name !in compiled.confidences) return false
    if (query.host != null && httpService()?.host()?.trimEnd('.')?.equals(query.host, ignoreCase = true) != true) return false
    if (query.nameContains != null && name()?.contains(query.nameContains, ignoreCase = !query.caseSensitive) != true) {
        return false
    }
    return true
}

private fun ScannerIssueSearchService.responseError(
    status: ScannerIssuePageStatus,
    error: String,
    projectId: String? = null,
    legacyMode: Boolean,
): StructuredToolResponse<ScannerIssuePageResult> = StructuredToolResponse(
    scannerIssuePageError(status, error, projectId, legacyMode)
)

private fun scannerIssuePageError(
    status: ScannerIssuePageStatus,
    error: String,
    projectId: String? = null,
    legacyMode: Boolean,
) = ScannerIssuePageResult(
    status = status,
    projectId = projectId,
    items = emptyList(),
    returned = 0,
    scanned = 0,
    snapshotSize = null,
    scanLimitReached = false,
    hasMore = false,
    nextCursor = null,
    legacyMode = legacyMode,
    error = error.take(512),
)

private fun safeScannerSearchException(error: Exception): String = safeExceptionSummary(error)
