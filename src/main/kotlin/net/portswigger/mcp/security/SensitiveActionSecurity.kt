package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import kotlinx.coroutines.suspendCancellableCoroutine
import net.portswigger.mcp.config.Dialogs
import javax.swing.SwingUtilities

private const val MAX_SENSITIVE_ACTION_LABEL_CHARS = 128
private const val MAX_SENSITIVE_ACTION_SUMMARY_CHARS = 4_096
private const val MAX_SENSITIVE_ACTION_CONTENT_CHARS = 1024 * 1024

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
    ): Boolean = suspendCancellableCoroutine { continuation ->
        SwingUtilities.invokeLater ui@{
            if (!continuation.isActive) return@ui

            val message = buildString {
                appendLine("An MCP client is requesting to $action.")
                appendLine()
                appendLine(summary)
                appendLine()
                append("This operation always requires explicit approval and is not covered by request-routing Always Allow.")
            }
            val result = Dialogs.showOptionDialog(
                parent = findBurpFrame(),
                message = message,
                options = arrayOf("Allow Once", "Deny"),
                requestContent = reviewContent,
                api = if (renderContentAsHttp) api else null,
            )
            if (continuation.isActive) continuation.resume(result == 0) { _, _, _ -> }
        }
    }
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
        return approvalHandler.requestApproval(action, summary, reviewContent, renderContentAsHttp, api)
    }
}
