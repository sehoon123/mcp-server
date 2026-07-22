package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.Dialogs

private const val MAX_SENSITIVE_ACTION_LABEL_CHARS = 128
private const val MAX_SENSITIVE_ACTION_SUMMARY_CHARS = 4_096
private const val MAX_SENSITIVE_ACTION_CONTENT_CHARS = 2 * 1024 * 1024

interface SensitiveActionApprovalHandler {
    suspend fun requestApproval(
        action: String,
        summary: String,
        reviewContent: String?,
        renderContentAsHttp: Boolean,
        api: MontoyaApi,
    ): Boolean
}

class SwingSensitiveActionApprovalHandler : SensitiveActionApprovalHandler {
    override suspend fun requestApproval(
        action: String,
        summary: String,
        reviewContent: String?,
        renderContentAsHttp: Boolean,
        api: MontoyaApi,
    ): Boolean {
        val message = buildString {
            appendLine("An MCP client is requesting to $action.")
            appendLine()
            appendLine(summary)
            appendLine()
            append("This operation always requires explicit approval and is not covered by request-routing Always Allow.")
        }
        return SwingApprovalGate.showOption {
            Dialogs.showOptionDialog(
                parent = findBurpFrame(),
                message = message,
                options = arrayOf("Allow Once", "Deny"),
                requestContent = reviewContent,
                api = if (renderContentAsHttp) api else null,
            )
        } == 0
    }
}

enum class SensitiveActionAuditOperation(val auditKind: String) {
    PROJECT_OPTIONS_READ("sensitive_action:project_options_read"),
    USER_OPTIONS_READ("sensitive_action:user_options_read"),
    PROJECT_OPTIONS_WRITE("sensitive_action:project_options_write"),
    USER_OPTIONS_WRITE("sensitive_action:user_options_write"),
    TASK_EXECUTION_ENGINE("sensitive_action:task_execution_engine"),
    PROXY_INTERCEPT("sensitive_action:proxy_intercept"),
}

/** Approval gate for scope changes, Scanner starts, and other sensitive Burp project mutations. */
object SensitiveActionSecurity {
    var approvalHandler: SensitiveActionApprovalHandler = SwingSensitiveActionApprovalHandler()

    suspend fun checkPermission(
        action: String,
        summary: String,
        reviewContent: String? = null,
        renderContentAsHttp: Boolean = false,
        api: MontoyaApi,
        auditOperation: SensitiveActionAuditOperation? = null,
    ): Boolean {
        require(action.length in 1..MAX_SENSITIVE_ACTION_LABEL_CHARS && action.none(Char::isISOControl)) {
            "sensitive action label is invalid"
        }
        require(summary.length in 1..MAX_SENSITIVE_ACTION_SUMMARY_CHARS && summary.none { it == '\u0000' }) {
            "sensitive action summary is invalid"
        }
        require((reviewContent?.length ?: 0) <= MAX_SENSITIVE_ACTION_CONTENT_CHARS) {
            "sensitive action review content is too large"
        }
        val approved = approvalHandler.requestApproval(action, summary, reviewContent, renderContentAsHttp, api)
        val auditKind = auditOperation?.auditKind ?: "sensitive_action"
        recordCurrentToolApproval(auditKind, if (approved) "user_allow" else "user_deny")
        return approved
    }
}
