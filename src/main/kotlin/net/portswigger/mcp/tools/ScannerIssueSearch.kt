package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scanner.audit.issues.AuditIssue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private const val DEFAULT_SCANNER_ISSUE_LIMIT = 25
private const val MAX_SCANNER_ISSUE_LIMIT = 50
private const val MAX_SCANNER_ISSUE_SCAN = 10_000
private const val MAX_SCANNER_FILTER_VALUES = 8
private const val MAX_SCANNER_HOST_CHARS = 253
private const val MAX_SCANNER_NAME_FILTER_CHARS = 256
private const val MAX_SCANNER_CURSOR_CHARS = 16_384
private const val MAX_LEGACY_SCANNER_TEXT_CHARS = 512 * 1024
private const val SCANNER_CURSOR_VERSION = 1
private const val SCANNER_CURSOR_HMAC = "HmacSHA256"

@Serializable
data class GetScannerIssues(
    override val count: Int = DEFAULT_SCANNER_ISSUE_LIMIT,
    override val offset: Int = 0,
    val summariesOnly: Boolean? = null,
    val cursorMode: Boolean? = null,
    val cursor: String? = null,
    val severities: List<ScannerIssueSeverityFilter>? = null,
    val confidences: List<ScannerIssueConfidenceFilter>? = null,
    val host: String? = null,
    val nameContains: String? = null,
    val caseSensitive: Boolean? = null,
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

        return try {
            if (preparedCursor != null) {
                cursorPage(input, projectId, issues, preparedCursor)
            } else {
                legacyPage(input, projectId, issues)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            responseError(
                ScannerIssuePageStatus.BURP_ERROR,
                "Burp returned an invalid Scanner issue: ${safeScannerSearchException(e)}",
                projectId,
                legacyMode = preparedCursor == null,
            )
        }
    }

    private suspend fun legacyPage(
        input: GetScannerIssues,
        projectId: String,
        issues: List<AuditIssue>,
    ): StructuredToolResponse<ScannerIssuePageResult> {
        val selected = issues.asSequence().drop(input.offset).take(input.count).toList()
        val summaries = selected.map { it.toHistorySummary() }
        val legacyText = selected.toBoundedLegacyText(input.summariesOnly == true)
        return StructuredToolResponse(
            output = ScannerIssuePageResult(
                status = ScannerIssuePageStatus.OK,
                projectId = projectId,
                items = summaries,
                returned = summaries.size,
                scanned = summaries.size,
                snapshotSize = issues.size,
                scanLimitReached = false,
                hasMore = input.offset.toLong() + selected.size.toLong() < issues.size.toLong(),
                nextCursor = null,
                legacyMode = true,
                legacyTextTruncated = legacyText.second,
            ),
            text = legacyText.first,
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
                firstAnchor = issues.firstOrNull()?.stableHistoryId(),
                lastAnchor = issues.lastOrNull()?.stableHistoryId(),
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
            if (issue.matches(compiledQuery)) results += issue.toHistorySummary()
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
            (issues.first().stableHistoryId() != cursor.snapshot.firstAnchor ||
                issues[cursor.snapshot.size - 1].stableHistoryId() != cursor.snapshot.lastAnchor)
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

private suspend fun List<AuditIssue>.toBoundedLegacyText(summariesOnly: Boolean): Pair<String, Boolean> {
    if (isEmpty()) return "Reached end of items" to false
    val marker = "\n\n<Scanner issue output truncated; use summariesOnly or get_scanner_issue_by_id>"
    var truncated = false
    val text = buildString(minOf(MAX_LEGACY_SCANNER_TEXT_CHARS, size * 4_096)) {
        this@toBoundedLegacyText.forEachIndexed { index, issue ->
            currentCoroutineContext().ensureActive()
            val separator = if (index == 0) "" else "\n\n"
            val serialized = if (summariesOnly) {
                Json.encodeToString(issue.toHistorySummary())
            } else {
                Json.encodeToString(issue.toSerializableForm())
            }
            if (length + separator.length + serialized.length <= MAX_LEGACY_SCANNER_TEXT_CHARS) {
                append(separator)
                append(serialized)
            } else {
                val prefixLimit = MAX_LEGACY_SCANNER_TEXT_CHARS - marker.length
                if (length > prefixLimit) setLength(prefixLimit)
                var available = (prefixLimit - length).coerceAtLeast(0)
                if (available > 0) {
                    val separatorChars = minOf(available, separator.length)
                    append(separator, 0, separatorChars)
                    available -= separatorChars
                    if (available > 0) append(serialized, 0, minOf(available, serialized.length))
                }
                append(marker)
                truncated = true
                return@buildString
            }
        }
    }
    return text to truncated
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

private fun safeScannerSearchException(error: Exception): String =
    "${error::class.simpleName ?: "Exception"}: ${error.message.orEmpty()}".take(512)
