package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessType

internal val SCANNER_ISSUE_ID_REGEX = Regex("^issue_[0-9a-f]{32}$")

/** Shared implementation for the tool and native resource forms of a project-bound Scanner issue read. */
internal class ScannerIssueReadService(
    private val api: MontoyaApi,
    private val config: McpConfig,
) {
    suspend fun read(input: GetScannerIssueById): ScannerIssueReadResult {
        require(input.id.matches(SCANNER_ISSUE_ID_REGEX)) {
            "id must be a stable Scanner issue ID returned by Burp MCP"
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
            return ScannerIssueReadResult(
                status = HistoryReadStatus.PROJECT_MISMATCH,
                id = input.id,
                field = normalizedField,
                projectId = expectedProjectId,
                error = "Scanner issue ID belongs to a different Burp project",
            )
        }
        if (!checkDataAccessOrDeny(
                DataAccessType.SCANNER_ISSUES,
                config,
                api,
                "Scanner issue ${input.id}",
            )
        ) {
            return ScannerIssueReadResult(
                status = HistoryReadStatus.ACCESS_DENIED,
                id = input.id,
                field = normalizedField,
                projectId = expectedProjectId,
                error = "Scanner issue access denied by Burp Suite",
            )
        }
        val issue = api.siteMap().issues().firstOrNull { it.stableHistoryId() == input.id }
        val currentProjectId = api.project().id()
        if (currentProjectId != expectedProjectId) {
            return ScannerIssueReadResult(
                status = HistoryReadStatus.PROJECT_MISMATCH,
                id = input.id,
                field = normalizedField,
                projectId = currentProjectId,
                error = "Burp project changed while the Scanner issue was resolved",
            )
        }
        if (issue == null) {
            return ScannerIssueReadResult(
                status = HistoryReadStatus.NOT_FOUND,
                id = input.id,
                field = normalizedField,
                projectId = expectedProjectId,
                error = "Scanner issue ${input.id} was not found",
            )
        }
        val result = issue.readField(
            normalizedField,
            input.evidenceIndex,
            normalizedOffset,
            normalizedLimit,
            normalizedEncoding,
        )
        val finalProjectId = api.project().id()
        if (finalProjectId != expectedProjectId) {
            return ScannerIssueReadResult(
                status = HistoryReadStatus.PROJECT_MISMATCH,
                id = input.id,
                field = normalizedField,
                projectId = finalProjectId,
                error = "Burp project changed while the Scanner issue was read",
            )
        }
        return result.copy(projectId = expectedProjectId)
    }
}
