package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scanner.audit.issues.AuditIssue
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import net.portswigger.mcp.ProductIdentity
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessType

internal val SCANNER_ISSUE_ID_REGEX = Regex("^issue_v2_(x|[0-9a-z]{1,6})_[0-9a-f]{32}$")

private data class ParsedScannerIssueId(
    val index: Int?,
    val fingerprint: String,
)

private fun parseScannerIssueId(value: String): ParsedScannerIssueId? {
    val match = SCANNER_ISSUE_ID_REGEX.matchEntire(value) ?: return null
    val locator = match.groupValues[1]
    val index = if (locator == "x") null else locator.toIntOrNull(36) ?: return null
    return ParsedScannerIssueId(index, value.substringAfterLast('_'))
}

/** Shared implementation for the tool and native resource forms of a project-bound Scanner issue read. */
internal class ScannerIssueReadService(
    private val api: MontoyaApi,
    private val config: McpConfig,
) {
    suspend fun read(input: GetScannerIssueById): ScannerIssueReadResult {
        val parsedId = requireNotNull(parseScannerIssueId(input.id)) {
            "id must be a versioned Scanner issue ID returned by ${ProductIdentity.PRODUCT_NAME}"
        }
        require(
            input.projectId.length in 1..MAX_HTTP_REFERENCE_PROJECT_ID_CHARS &&
                input.projectId.none(Char::isISOControl)
        ) {
            "projectId is invalid"
        }
        val normalizedField = normalizeScannerIssueField(input.field)
        val normalizedOffset = normalizeHistoryOffset(input.offset)
        val normalizedLimit = normalizeHistoryLimit(input.limit)
        val normalizedEncoding = normalizeHistoryEncoding(input.encoding)
        val expectedProjectId = api.project().id()
        if (input.projectId != expectedProjectId) {
            return mismatch(input, normalizedField, expectedProjectId, "Scanner issue ID belongs to a different Burp project")
        }

        val allowed = checkDataAccessOrDeny(
            DataAccessType.SCANNER_ISSUES,
            config,
            api,
            "Scanner issue ${input.id}",
        )
        val projectAfterApproval = api.project().id()
        if (projectAfterApproval != expectedProjectId) {
            return mismatch(
                input,
                normalizedField,
                projectAfterApproval,
                "Burp project changed during Scanner issue approval",
            )
        }
        if (!allowed) {
            return ScannerIssueReadResult(
                status = HistoryReadStatus.ACCESS_DENIED,
                id = input.id,
                field = normalizedField,
                projectId = expectedProjectId,
                error = "Scanner issue access denied by Burp Suite",
            )
        }

        val issues = api.siteMap().issues()
        val projectAfterSnapshot = api.project().id()
        if (projectAfterSnapshot != expectedProjectId) {
            return mismatch(
                input,
                normalizedField,
                projectAfterSnapshot,
                "Burp project changed while Scanner issues were listed",
            )
        }

        var scanned = 0
        var ambiguous = false
        val issue = if (parsedId.index != null) {
            val candidate = issues.getOrNull(parsedId.index)
            if (candidate != null && candidate.stableHistoryId(parsedId.index) == input.id) candidate else null
        } else {
            var match: AuditIssue? = null
            var index = issues.lastIndex
            while (index >= 0 && scanned < MAX_SCANNER_ISSUE_SCAN) {
                if (scanned and 63 == 0) currentCoroutineContext().ensureActive()
                val candidate = issues[index]
                scanned++
                if (candidate.scannerIssueFingerprint() == parsedId.fingerprint) {
                    if (match != null) ambiguous = true else match = candidate
                }
                index--
            }
            if (ambiguous || scanned < issues.size) null else match
        }

        val currentProjectId = api.project().id()
        if (currentProjectId != expectedProjectId) {
            return mismatch(
                input,
                normalizedField,
                currentProjectId,
                "Burp project changed while the Scanner issue was resolved",
            )
        }
        if (issue == null) {
            val scanLimitReached = parsedId.index == null && scanned >= MAX_SCANNER_ISSUE_SCAN && scanned < issues.size
            return ScannerIssueReadResult(
                status = if (scanLimitReached) HistoryReadStatus.SCAN_LIMIT_REACHED else HistoryReadStatus.NOT_FOUND,
                id = input.id,
                field = normalizedField,
                projectId = expectedProjectId,
                error = when {
                    scanLimitReached ->
                        "Scanner issue lookup reached the $MAX_SCANNER_ISSUE_SCAN-record scan limit; refresh the issue summary"
                    ambiguous ->
                        "Scanner issue ID is ambiguous because multiple issues share its bounded metadata; use a search ID"
                    else ->
                        "Scanner issue ${input.id} was not found or its bounded metadata changed"
                },
            )
        }

        val result = issue.readField(
            normalizedField,
            input.evidenceIndex,
            normalizedOffset,
            normalizedLimit,
            normalizedEncoding,
            resolvedId = input.id,
        )
        val finalProjectId = api.project().id()
        if (finalProjectId != expectedProjectId) {
            return mismatch(
                input,
                normalizedField,
                finalProjectId,
                "Burp project changed while the Scanner issue was read",
            )
        }
        return result.copy(projectId = expectedProjectId)
    }

    private fun mismatch(
        input: GetScannerIssueById,
        field: String,
        projectId: String,
        error: String,
    ) = ScannerIssueReadResult(
        status = HistoryReadStatus.PROJECT_MISMATCH,
        id = input.id,
        field = field,
        projectId = projectId,
        error = error,
    )
}
