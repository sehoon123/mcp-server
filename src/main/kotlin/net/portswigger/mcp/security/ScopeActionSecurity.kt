package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig

private const val MAX_SCOPE_ACTION_LABEL_CHARS = 128
private const val MAX_SCOPE_ACTION_SUMMARY_CHARS = 4_096
private const val MAX_SCOPE_ACTION_REVIEW_CHARS = 64 * 1024

internal interface ScopeActionApprovalHandler {
    suspend fun requestApproval(
        action: String,
        summary: String,
        reviewContent: String,
        config: McpConfig,
        api: MontoyaApi,
    ): Boolean
}

internal class SwingScopeActionApprovalHandler : ScopeActionApprovalHandler {
    override suspend fun requestApproval(
        action: String,
        summary: String,
        reviewContent: String,
        config: McpConfig,
        api: MontoyaApi,
    ): Boolean {
        val message = buildString {
            appendLine("An MCP client is requesting to $action.")
            appendLine()
            appendLine(summary)
            appendLine()
            appendLine("Review every normalized URL before allowing this Target scope change.")
            appendLine()
            appendLine(
                "Allow for This Session permits later include and exclude changes only until this MCP session ends " +
                    "or session approvals are reset."
            )
            append(
                "Always Allow disables future include and exclude prompts until " +
                    "Require approval for Target scope changes is re-enabled in MCP settings."
            )
        }
        val result = SwingApprovalGate.showOption {
            Dialogs.showOptionDialog(
                parent = findBurpFrame(),
                message = message,
                options = arrayOf("Allow Once", "Allow for This Session", "Always Allow", "Deny"),
                requestContent = reviewContent,
                api = null,
            )
        }
        return when (result) {
            0 -> true
            1 -> {
                grantCurrentSessionApproval(McpSessionApproval.SCOPE_CHANGES)
                true
            }
            2 -> {
                val persisted = runCatching { config.requireScopeChangeApproval = false }
                runCatching {
                    if (persisted.isSuccess) {
                        api.logging().logToOutput(
                            "MCP Target scope-change approval disabled by the user from an approval dialog"
                        )
                    } else {
                        api.logging().logToError(
                            "MCP could not persist Always Allow for Target scope changes"
                        )
                    }
                }
                true
            }
            else -> false
        }
    }
}

internal enum class ScopeChangeApprovalOperation(val auditKind: String) {
    INCLUDE("scope_change:include"),
    EXCLUDE("scope_change:exclude"),
}

internal object ScopeActionSecurity {
    var approvalHandler: ScopeActionApprovalHandler = SwingScopeActionApprovalHandler()

    suspend fun checkPermission(
        action: String,
        summary: String,
        reviewContent: String,
        config: McpConfig,
        api: MontoyaApi,
        operation: ScopeChangeApprovalOperation,
    ): Boolean {
        require(action.length in 1..MAX_SCOPE_ACTION_LABEL_CHARS && action.none(Char::isISOControl)) {
            "scope action label is invalid"
        }
        require(summary.length in 1..MAX_SCOPE_ACTION_SUMMARY_CHARS && summary.none { it == '\u0000' }) {
            "scope action summary is invalid"
        }
        require(reviewContent.length <= MAX_SCOPE_ACTION_REVIEW_CHARS && reviewContent.none { it == '\u0000' }) {
            "scope action review content is invalid"
        }
        if (!config.requireScopeChangeApproval) {
            recordCurrentToolApproval(operation.auditKind, "policy_allow")
            return true
        }
        if (isCurrentSessionApproved(McpSessionApproval.SCOPE_CHANGES)) {
            recordCurrentToolApproval(operation.auditKind, "session_allow")
            return true
        }
        val approved = approvalHandler.requestApproval(action, summary, reviewContent, config, api)
        recordCurrentToolApproval(operation.auditKind, if (approved) "user_allow" else "user_deny")
        return approved
    }
}
