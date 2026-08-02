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
private const val SCANNER_SNAPSHOT_CURSOR_VERSION = 1
private const val SCANNER_CURSOR_HMAC = "HmacSHA256"
private const val LEGACY_SCANNER_TRUNCATION_MARKER =
    "\n\n<Scanner issue output truncated; use summariesOnly or get_scanner_issue_by_id>"

@Serializable
data class GetScannerIssues(
    @JsonSchemaMetadata(description = "Maximum issues returned.", minimum = 1, maximum = 50, defaultJson = "25")
    override val count: Int = DEFAULT_SCANNER_ISSUE_LIMIT,
    @JsonSchemaMetadata(description = "Legacy-mode offset; cursor mode requires zero.", minimum = 0, defaultJson = "0")
    override val offset: Int = 0,
    @JsonSchemaMetadata(description = "In legacy offset mode, return compact summary records instead of full details; does not enable cursor mode.", defaultJson = "false")
    val summariesOnly: Boolean? = null,
    @JsonSchemaMetadata(description = "Use signed snapshot cursor pagination; query filters also select this mode.", defaultJson = "false")
    val cursorMode: Boolean? = null,
    @JsonSchemaMetadata(description = "Returned nextCursor from the previous ordinary cursor page. Omit filters to reuse its query, or repeat the exact same filters. Cannot be combined with sinceSnapshotCursor.", maxLength = 16384)
    val cursor: String? = null,
    @JsonSchemaMetadata(description = "snapshotCursor or nextDeltaCursor from a prior response. Returns only the bounded append-stable range after that baseline; cannot be combined with cursor.", maxLength = 16384)
    val sinceSnapshotCursor: String? = null,
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
data class ScannerIssueDeltaEvidence(
    @JsonSchemaMetadata(description = "Fixed append-only visibility basis; not a full regression comparison.")
    val basis: String,
    @JsonSchemaMetadata(minimum = 0)
    val baselineSnapshotSize: Int,
    @JsonSchemaMetadata(minimum = 0)
    val currentSnapshotSize: Int,
    @JsonSchemaMetadata(minimum = 0)
    val appendedRangeSize: Int,
    @JsonSchemaMetadata(description = "Always false: this mode does not establish a vulnerability regression.")
    val regressionEstablished: Boolean,
    @JsonSchemaMetadata(description = "Always false: removal or in-place change is not established.")
    val removedOrChangedEstablished: Boolean,
    @JsonSchemaMetadata(description = "Always false: first/last anchors do not establish complete project history identity.")
    val completeHistoryEstablished: Boolean,
)

@Serializable
data class ScannerIssuePageResult(
    @JsonSchemaMetadata(description = READ_ONLY_TOOL_STATUS_DESCRIPTION)
    val status: ScannerIssuePageStatus,
    @JsonSchemaMetadata(description = "Captured current project ID; null only when capture did not complete safely.")
    val projectId: String?,
    @JsonSchemaMetadata(maxItems = MAX_SCANNER_ISSUE_LIMIT)
    val items: List<ScannerIssueSummary>,
    @JsonSchemaMetadata(minimum = 0, maximum = 50)
    val returned: Int,
    @JsonSchemaMetadata(minimum = 0, maximum = 10_000)
    val scanned: Int,
    @JsonSchemaMetadata(
        description = "Visible list size in legacy mode, frozen ordinary snapshot size in cursor mode, or frozen comparison size in delta mode; null on error.",
        minimum = 0,
    )
    val snapshotSize: Int?,
    val scanLimitReached: Boolean,
    @JsonSchemaMetadata(description = "True when more issues remain; continue even when items is empty using nextCursor in ordinary mode or nextDeltaCursor in delta mode.")
    val hasMore: Boolean,
    @JsonSchemaMetadata(
        description = "Opaque continuation cursor when hasMore is true in cursor mode; null otherwise.",
        maxLength = MAX_SCANNER_CURSOR_CHARS,
    )
    val nextCursor: String?,
    @JsonSchemaMetadata(
        description = "Signed process-local baseline for a later sinceSnapshotCursor call; present on successful ordinary cursor pages and only after a delta range is fully consumed.",
        maxLength = MAX_SCANNER_CURSOR_CHARS,
    )
    val snapshotCursor: String?,
    @JsonSchemaMetadata(
        description = "Signed continuation for the frozen append-stable range when hasMore is true in delta mode; pass it as sinceSnapshotCursor.",
        maxLength = MAX_SCANNER_CURSOR_CHARS,
    )
    val nextDeltaCursor: String?,
    val legacyMode: Boolean,
    val deltaMode: Boolean,
    val delta: ScannerIssueDeltaEvidence?,
    @JsonSchemaMetadata(description = "True when the compatibility text page was truncated; always present.")
    val legacyTextTruncated: Boolean,
    @JsonSchemaMetadata(maxLength = MAX_STRUCTURED_TOOL_ERROR_CHARS)
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
    val kind: ScannerIssueSnapshotCursorKind,
    val projectId: String,
    val query: NormalizedScannerIssueQuery,
    val snapshot: ScannerIssueCursorSnapshot,
    val nextIndex: Int,
)

private data class PreparedScannerIssueCursor(
    val cursor: ScannerIssueCursor?,
    val query: NormalizedScannerIssueQuery,
)

@Serializable
private enum class ScannerIssueSnapshotCursorKind {
    @SerialName("page")
    PAGE,

    @SerialName("snapshot")
    SNAPSHOT,

    @SerialName("delta")
    DELTA,
}

@Serializable
private data class ScannerIssueSnapshotCursor(
    val version: Int,
    val kind: ScannerIssueSnapshotCursorKind,
    val projectId: String,
    val query: NormalizedScannerIssueQuery,
    val snapshot: ScannerIssueCursorSnapshot,
)

@Serializable
private data class ScannerIssueDeltaCursor(
    val version: Int,
    val kind: ScannerIssueSnapshotCursorKind,
    val projectId: String,
    val query: NormalizedScannerIssueQuery,
    val baseline: ScannerIssueCursorSnapshot,
    val current: ScannerIssueCursorSnapshot,
    val nextIndex: Int,
)

private data class PreparedScannerIssueDelta(
    val projectId: String,
    val query: NormalizedScannerIssueQuery,
    val baseline: ScannerIssueCursorSnapshot,
    val current: ScannerIssueCursorSnapshot?,
    val nextIndex: Int?,
)

private class ScannerIssueSearchError(
    val status: ScannerIssuePageStatus,
    override val message: String,
) : Exception(message)

internal class ScannerIssueSearchService(
    private val api: MontoyaApi,
    private val config: McpConfig,
    cursorSecret: ByteArray = ByteArray(32).also(SecureRandom()::nextBytes),
    private val performanceDiagnostics: HistoryPerformanceDiagnostics = HistoryPerformanceDiagnostics.NO_OP,
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

        if (input.cursor != null && input.sinceSnapshotCursor != null) {
            return responseError(
                ScannerIssuePageStatus.INVALID_ARGUMENT,
                "cursor and sinceSnapshotCursor cannot be combined",
                legacyMode = false,
            )
        }

        val preparedModes = try {
            if (input.sinceSnapshotCursor != null) {
                val decoded = decodeSinceCursor(input.sinceSnapshotCursor)
                val query = if (input.hasExplicitCursorQuery()) {
                    normalizeQuery(input).also {
                        if (it != decoded.query) {
                            throw ScannerIssueSearchError(
                                ScannerIssuePageStatus.INVALID_CURSOR,
                                "snapshot cursor does not match the supplied Scanner issue filters",
                            )
                        }
                    }
                } else {
                    decoded.query
                }
                null to decoded.copy(query = query)
            } else if (input.usesCursorMode()) {
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
                PreparedScannerIssueCursor(cursor, query) to null
            } else {
                null to null
            }
        } catch (e: IllegalArgumentException) {
            return responseError(
                ScannerIssuePageStatus.INVALID_ARGUMENT,
                e.message ?: "invalid Scanner issue filters",
                legacyMode = false,
            )
        } catch (e: ScannerIssueSearchError) {
            return responseError(e.status, e.message, legacyMode = false)
        }
        val preparedCursor = preparedModes.first
        val preparedDelta = preparedModes.second
        if ((preparedCursor != null || preparedDelta != null) && input.offset != 0) {
            return responseError(
                ScannerIssuePageStatus.INVALID_ARGUMENT,
                if (preparedDelta == null) {
                    "offset is only supported in legacy mode; use cursor for cursor mode"
                } else {
                    "offset is not supported in Scanner delta mode"
                },
                legacyMode = false,
            )
        }
        if ((preparedCursor != null || preparedDelta != null) && input.summariesOnly == false) {
            return responseError(
                ScannerIssuePageStatus.INVALID_ARGUMENT,
                if (preparedDelta == null) {
                    "cursor mode returns compact summaries; omit summariesOnly or set it to true"
                } else {
                    "Scanner delta mode returns compact summaries; omit summariesOnly or set it to true"
                },
                legacyMode = false,
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
        if (preparedDelta != null && preparedDelta.projectId != projectId) {
            return responseError(
                ScannerIssuePageStatus.PROJECT_MISMATCH,
                "snapshot cursor belongs to a different Burp project",
                projectId,
                legacyMode = false,
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
                projectId,
                legacyMode = !input.usesCursorMode(),
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
                legacyMode = preparedCursor == null && preparedDelta == null,
            )
        }
        if (projectAfterApproval != projectId) {
            return responseError(
                ScannerIssuePageStatus.PROJECT_MISMATCH,
                "Burp project changed during Scanner issue approval",
                projectAfterApproval,
                legacyMode = preparedCursor == null && preparedDelta == null,
            )
        }
        if (!allowed) {
            return StructuredToolResponse(
                output = scannerIssuePageError(
                    ScannerIssuePageStatus.ACCESS_DENIED,
                    "Scanner issue access denied by Burp Suite",
                    projectId,
                    legacyMode = !input.usesCursorMode(),
                ),
                text = "Scanner issue access denied by Burp Suite",
            )
        }
        val issues = try {
            if (preparedDelta == null) {
                api.siteMap().issues()
            } else {
                performanceDiagnostics.measure(HistoryPerformanceMetric.SCANNER_DELTA_MONTOYA_ACQUISITION) {
                    api.siteMap().issues()
                }
            }
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
                legacyMode = preparedCursor == null && preparedDelta == null,
            )
        }
        if (projectAfterSnapshot != projectId) {
            return responseError(
                ScannerIssuePageStatus.PROJECT_MISMATCH,
                "Burp project changed while reading Scanner issues",
                projectAfterSnapshot,
                legacyMode = preparedCursor == null && preparedDelta == null,
            )
        }

        val response = try {
            when {
                preparedDelta != null -> performanceDiagnostics.measure(
                    metric = HistoryPerformanceMetric.SCANNER_DELTA_EXTENSION_PROCESSING,
                    outcomeForResult = { result ->
                        if (result.output.status == ScannerIssuePageStatus.OK) {
                            HistoryPerformanceOutcome.COMPLETED
                        } else {
                            HistoryPerformanceOutcome.FAILED
                        }
                    },
                ) {
                    deltaPage(input, projectId, issues, preparedDelta)
                }
                preparedCursor != null -> cursorPage(input, projectId, issues, preparedCursor)
                else -> legacyPage(input, projectId, issues)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return responseError(
                ScannerIssuePageStatus.BURP_ERROR,
                "Burp returned an invalid Scanner issue: ${safeScannerSearchException(e)}",
                projectId,
                legacyMode = preparedCursor == null && preparedDelta == null,
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
                legacyMode = preparedCursor == null && preparedDelta == null,
            )
        }
        if (finalProjectId != projectId) {
            return responseError(
                ScannerIssuePageStatus.PROJECT_MISMATCH,
                "Burp project changed while Scanner issues were materialized",
                finalProjectId,
                legacyMode = preparedCursor == null && preparedDelta == null,
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
                snapshotCursor = null,
                nextDeltaCursor = null,
                legacyMode = true,
                deltaMode = false,
                delta = null,
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
        val cursor = prepared.cursor
        val query = prepared.query
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
                    kind = ScannerIssueSnapshotCursorKind.PAGE,
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
            snapshotCursor = encodeSnapshotCursor(projectId, query, snapshot),
            nextDeltaCursor = null,
            legacyMode = false,
            deltaMode = false,
            delta = null,
            legacyTextTruncated = false,
        )
        return StructuredToolResponse(result)
    }

    private suspend fun deltaPage(
        input: GetScannerIssues,
        projectId: String,
        issues: List<AuditIssue>,
        prepared: PreparedScannerIssueDelta,
    ): StructuredToolResponse<ScannerIssuePageResult> {
        val baseline = prepared.baseline
        try {
            validateAppendStableSnapshot(
                snapshot = baseline,
                issues = issues,
                changedMessage = "Scanner issue list changed since the baseline; capture a new snapshot",
                orderingMessage = "Scanner issue ordering changed since the baseline; capture a new snapshot",
            )
        } catch (e: ScannerIssueSearchError) {
            return responseError(e.status, e.message, projectId, legacyMode = false)
        }
        val current = prepared.current ?: ScannerIssueCursorSnapshot(
            size = issues.size,
            firstAnchor = issues.firstOrNull()?.stableHistoryId(0),
            lastAnchor = issues.lastOrNull()?.stableHistoryId(issues.lastIndex),
        )
        if (prepared.current != null) {
            try {
                validateAppendStableSnapshot(
                    snapshot = current,
                    issues = issues,
                    changedMessage = "Scanner issue list changed while paging the delta; start a new delta read",
                    orderingMessage = "Scanner issue ordering changed while paging the delta; start a new delta read",
                )
            } catch (e: ScannerIssueSearchError) {
                return responseError(e.status, e.message, projectId, legacyMode = false)
            }
        }
        if (baseline.size > current.size) {
            return responseError(
                ScannerIssuePageStatus.STALE_CURSOR,
                "Scanner delta baseline is newer than its comparison snapshot",
                projectId,
                legacyMode = false,
            )
        }

        val query = prepared.query
        val direction = if (query.newestFirst) -1 else 1
        var index = prepared.nextIndex ?: if (query.newestFirst) current.size - 1 else baseline.size
        if (prepared.nextIndex != null && index !in baseline.size until current.size) {
            return responseError(
                ScannerIssuePageStatus.INVALID_CURSOR,
                "Scanner delta cursor position is invalid",
                projectId,
                legacyMode = false,
            )
        }
        val compiledQuery = CompiledScannerIssueQuery(query)
        val results = ArrayList<ScannerIssueSummary>(input.count)
        var scanned = 0
        while (index in baseline.size until current.size && results.size < input.count && scanned < MAX_SCANNER_ISSUE_SCAN) {
            if (scanned and 63 == 0) currentCoroutineContext().ensureActive()
            val issue = issues[index]
            scanned++
            if (issue.matches(compiledQuery)) results += issue.toHistorySummary(issue.stableHistoryId(index))
            index += direction
        }
        val hasMore = index in baseline.size until current.size
        val scanLimitReached = scanned >= MAX_SCANNER_ISSUE_SCAN && hasMore
        val nextDeltaCursor = if (hasMore) {
            encodeDeltaCursor(
                ScannerIssueDeltaCursor(
                    version = SCANNER_SNAPSHOT_CURSOR_VERSION,
                    kind = ScannerIssueSnapshotCursorKind.DELTA,
                    projectId = projectId,
                    query = query,
                    baseline = baseline,
                    current = current,
                    nextIndex = index,
                ),
            )
        } else {
            null
        }
        return StructuredToolResponse(
            ScannerIssuePageResult(
                status = ScannerIssuePageStatus.OK,
                projectId = projectId,
                items = results,
                returned = results.size,
                scanned = scanned,
                snapshotSize = current.size,
                scanLimitReached = scanLimitReached,
                hasMore = hasMore,
                nextCursor = null,
                snapshotCursor = if (hasMore) null else encodeSnapshotCursor(projectId, query, current),
                nextDeltaCursor = nextDeltaCursor,
                legacyMode = false,
                deltaMode = true,
                delta = ScannerIssueDeltaEvidence(
                    basis = "append_stable_currently_visible_range",
                    baselineSnapshotSize = baseline.size,
                    currentSnapshotSize = current.size,
                    appendedRangeSize = current.size - baseline.size,
                    regressionEstablished = false,
                    removedOrChangedEstablished = false,
                    completeHistoryEstablished = false,
                ),
                legacyTextTruncated = false,
            ),
        )
    }

    private fun validateSnapshot(cursor: ScannerIssueCursor, issues: List<AuditIssue>) {
        if (cursor.version != SCANNER_CURSOR_VERSION) {
            throw ScannerIssueSearchError(ScannerIssuePageStatus.INVALID_CURSOR, "unsupported cursor version")
        }
        if (cursor.nextIndex !in -1..cursor.snapshot.size) {
            throw ScannerIssueSearchError(ScannerIssuePageStatus.INVALID_CURSOR, "cursor position is invalid")
        }
        validateAppendStableSnapshot(
            snapshot = cursor.snapshot,
            issues = issues,
            changedMessage = "Scanner issue list changed while paging; start a new query",
            orderingMessage = "Scanner issue ordering changed while paging; start a new query",
        )
    }

    private fun validateAppendStableSnapshot(
        snapshot: ScannerIssueCursorSnapshot,
        issues: List<AuditIssue>,
        changedMessage: String,
        orderingMessage: String,
    ) {
        if (snapshot.size < 0 || snapshot.size > issues.size) {
            throw ScannerIssueSearchError(ScannerIssuePageStatus.STALE_CURSOR, changedMessage)
        }
        if (snapshot.size > 0 &&
            (issues.first().stableHistoryId(0) != snapshot.firstAnchor ||
                issues[snapshot.size - 1].stableHistoryId(snapshot.size - 1) != snapshot.lastAnchor)
        ) {
            throw ScannerIssueSearchError(ScannerIssuePageStatus.STALE_CURSOR, orderingMessage)
        }
    }

    private fun encodeCursor(cursor: ScannerIssueCursor): String = encodeSignedCursor(
        cursorJson.encodeToString(cursor).toByteArray(StandardCharsets.UTF_8),
    )

    private fun encodeSnapshotCursor(
        projectId: String,
        query: NormalizedScannerIssueQuery,
        snapshot: ScannerIssueCursorSnapshot,
    ): String = encodeSignedCursor(
        cursorJson.encodeToString(
            ScannerIssueSnapshotCursor(
                version = SCANNER_SNAPSHOT_CURSOR_VERSION,
                kind = ScannerIssueSnapshotCursorKind.SNAPSHOT,
                projectId = projectId,
                query = query,
                snapshot = snapshot,
            ),
        ).toByteArray(StandardCharsets.UTF_8),
    )

    private fun encodeDeltaCursor(cursor: ScannerIssueDeltaCursor): String = encodeSignedCursor(
        cursorJson.encodeToString(cursor).toByteArray(StandardCharsets.UTF_8),
    )

    private fun encodeSignedCursor(payload: ByteArray): String {
        val value = Base64.getUrlEncoder().withoutPadding().encodeToString(payload) + "." +
            Base64.getUrlEncoder().withoutPadding().encodeToString(hmac(payload))
        check(value.length <= MAX_SCANNER_CURSOR_CHARS) { "generated Scanner cursor exceeded its size bound" }
        return value
    }

    private fun decodeCursor(value: String): ScannerIssueCursor {
        val payload = decodeSignedCursor(value)
        val cursor = try {
            cursorJson.decodeFromString<ScannerIssueCursor>(payload.toString(StandardCharsets.UTF_8))
        } catch (_: Exception) {
            throw ScannerIssueSearchError(ScannerIssuePageStatus.INVALID_CURSOR, "cursor payload is invalid")
        }
        if (cursor.version != SCANNER_CURSOR_VERSION || cursor.kind != ScannerIssueSnapshotCursorKind.PAGE) {
            throw ScannerIssueSearchError(ScannerIssuePageStatus.INVALID_CURSOR, "unsupported cursor kind or version")
        }
        return cursor
    }

    private fun decodeSinceCursor(value: String): PreparedScannerIssueDelta {
        val payload = decodeSignedCursor(value).toString(StandardCharsets.UTF_8)
        val snapshot = try {
            cursorJson.decodeFromString<ScannerIssueSnapshotCursor>(payload)
        } catch (_: Exception) {
            null
        }
        if (snapshot != null && snapshot.kind == ScannerIssueSnapshotCursorKind.SNAPSHOT) {
            if (snapshot.version != SCANNER_SNAPSHOT_CURSOR_VERSION) {
                throw ScannerIssueSearchError(ScannerIssuePageStatus.INVALID_CURSOR, "unsupported snapshot cursor version")
            }
            return PreparedScannerIssueDelta(
                projectId = snapshot.projectId,
                query = snapshot.query,
                baseline = snapshot.snapshot,
                current = null,
                nextIndex = null,
            )
        }
        val delta = try {
            cursorJson.decodeFromString<ScannerIssueDeltaCursor>(payload)
        } catch (_: Exception) {
            null
        }
        if (delta != null && delta.kind == ScannerIssueSnapshotCursorKind.DELTA) {
            if (delta.version != SCANNER_SNAPSHOT_CURSOR_VERSION) {
                throw ScannerIssueSearchError(ScannerIssuePageStatus.INVALID_CURSOR, "unsupported delta cursor version")
            }
            return PreparedScannerIssueDelta(
                projectId = delta.projectId,
                query = delta.query,
                baseline = delta.baseline,
                current = delta.current,
                nextIndex = delta.nextIndex,
            )
        }
        throw ScannerIssueSearchError(ScannerIssuePageStatus.INVALID_CURSOR, "snapshot cursor payload is invalid")
    }

    private fun decodeSignedCursor(value: String): ByteArray {
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
        return payload
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
    cursorMode == true || cursor != null || sinceSnapshotCursor != null || severities != null || confidences != null ||
        host != null || nameContains != null || caseSensitive != null || newestFirst != null

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

private fun ScannerIssuePageStatus.isMcpError(): Boolean = when (this) {
    ScannerIssuePageStatus.INVALID_ARGUMENT,
    ScannerIssuePageStatus.INVALID_CURSOR,
    ScannerIssuePageStatus.STALE_CURSOR,
    ScannerIssuePageStatus.PROJECT_MISMATCH,
    ScannerIssuePageStatus.BURP_ERROR -> true

    else -> false
}

private fun ScannerIssueSearchService.responseError(
    status: ScannerIssuePageStatus,
    error: String,
    projectId: String? = null,
    legacyMode: Boolean,
): StructuredToolResponse<ScannerIssuePageResult> = StructuredToolResponse(
    output = scannerIssuePageError(status, error, projectId, legacyMode),
    text = null,
    isError = status.isMcpError(),
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
    snapshotCursor = null,
    nextDeltaCursor = null,
    legacyMode = legacyMode,
    deltaMode = false,
    delta = null,
    legacyTextTruncated = false,
    error = error.take(MAX_STRUCTURED_TOOL_ERROR_CHARS),
)

private fun safeScannerSearchException(
    @Suppress("UNUSED_PARAMETER") error: Exception,
): String = "internal Burp API failure"
