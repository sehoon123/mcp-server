package net.portswigger.mcp.tools

/**
 * Approval and policy denials, bounded absence, and unavailable data remain ordinary structured outcomes for wire
 * compatibility. Every unlisted outcome, including a newly added enum value, fails closed as an MCP error until it is
 * explicitly reviewed and added here.
 */
private val ORDINARY_RETAINED_TOOL_OUTCOMES: Set<Enum<*>> = setOf(
    HttpMessageActionStatus.OK,
    HttpMessageActionStatus.ACCESS_DENIED,
    HttpMessageActionStatus.ACTION_DENIED,
    HttpMessageActionStatus.REQUEST_UNAVAILABLE,

    HttpMessageReadStatus.OK,
    HttpMessageReadStatus.ACCESS_DENIED,
    HttpMessageReadStatus.REQUEST_UNAVAILABLE,
    HttpMessageReadStatus.PART_UNAVAILABLE,

    HttpComparisonStatus.OK,
    HttpComparisonStatus.ACCESS_DENIED,
    HttpComparisonStatus.REQUEST_UNAVAILABLE,
    HttpComparisonStatus.PART_UNAVAILABLE,

    ScopeToolStatus.OK,
    ScopeToolStatus.ACCESS_DENIED,
    ScopeToolStatus.ACTION_DENIED,
    ScopeToolStatus.REQUEST_UNAVAILABLE,

    ScannerAuditToolStatus.OK,
    ScannerAuditToolStatus.ACCESS_DENIED,
    ScannerAuditToolStatus.ACTION_DENIED,
    ScannerAuditToolStatus.REQUEST_UNAVAILABLE,
    ScannerAuditToolStatus.OUT_OF_SCOPE,
    ScannerAuditToolStatus.CAPACITY_EXCEEDED,

    HistoryReadStatus.OK,
    HistoryReadStatus.ACCESS_DENIED,
    HistoryReadStatus.SCAN_LIMIT_REACHED,
    HistoryReadStatus.PART_UNAVAILABLE,
    HistoryReadStatus.FIELD_UNAVAILABLE,

    CollaboratorToolStatus.OK,
    CollaboratorToolStatus.ACCESS_DENIED,

    HttpMessageSearchStatus.OK,
    HttpMessageSearchStatus.ACCESS_DENIED,

    WebSocketSearchStatus.OK,
    WebSocketSearchStatus.ACCESS_DENIED,

    HttpAttackSurfaceStatus.OK,
    HttpAttackSurfaceStatus.ACCESS_DENIED,

    HttpActivityCorrelationStatus.OK,
    HttpActivityCorrelationStatus.ACCESS_DENIED,
    HttpActivityCorrelationStatus.REQUEST_UNAVAILABLE,

    HttpSessionAnalysisStatus.OK,
    HttpSessionAnalysisStatus.ACCESS_DENIED,
    HttpSessionAnalysisStatus.REQUEST_UNAVAILABLE,

    ScannerIssuePageStatus.OK,
    ScannerIssuePageStatus.ACCESS_DENIED,
)

private fun Enum<*>.isUnlistedMcpError(): Boolean = this !in ORDINARY_RETAINED_TOOL_OUTCOMES

internal fun HttpMessageActionStatus.isMcpError(): Boolean = isUnlistedMcpError()
internal fun HttpMessageReadStatus.isMcpError(): Boolean = isUnlistedMcpError()
internal fun HttpComparisonStatus.isMcpError(): Boolean = isUnlistedMcpError()
internal fun ScopeToolStatus.isMcpError(): Boolean = isUnlistedMcpError()
internal fun ScannerAuditToolStatus.isMcpError(): Boolean = isUnlistedMcpError()
internal fun HistoryReadStatus.isMcpError(): Boolean = isUnlistedMcpError()
internal fun CollaboratorToolStatus.isMcpError(): Boolean = isUnlistedMcpError()
internal fun HttpMessageSearchStatus.isMcpError(): Boolean = isUnlistedMcpError()
internal fun WebSocketSearchStatus.isMcpError(): Boolean = isUnlistedMcpError()
internal fun HttpAttackSurfaceStatus.isMcpError(): Boolean = isUnlistedMcpError()
internal fun HttpActivityCorrelationStatus.isMcpError(): Boolean = isUnlistedMcpError()
internal fun HttpSessionAnalysisStatus.isMcpError(): Boolean = isUnlistedMcpError()
internal fun ScannerIssuePageStatus.isMcpError(): Boolean = isUnlistedMcpError()
