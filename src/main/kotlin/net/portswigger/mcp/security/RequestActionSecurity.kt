package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig

interface RequestActionApprovalHandler {
    suspend fun requestApproval(
        action: String,
        source: String,
        target: String,
        changes: String,
        requestContent: String,
        config: McpConfig,
        api: MontoyaApi,
    ): Boolean
}

class SwingRequestActionApprovalHandler : RequestActionApprovalHandler {
    override suspend fun requestApproval(
        action: String,
        source: String,
        target: String,
        changes: String,
        requestContent: String,
        config: McpConfig,
        api: MontoyaApi,
    ): Boolean {
        val message = buildString {
            appendLine("An MCP client is requesting to $action.")
            appendLine()
            appendLine("Source: $source")
            appendLine("Target: $target")
            appendLine("Changes: $changes")
            appendLine()
            appendLine("Review the exact resulting request before allowing this action.")
            appendLine()
            appendLine(
                "Allow for This Session permits later request-routing actions only until this MCP session ends or " +
                    "session approvals are reset."
            )
            append("Always Allow disables future request-routing approval prompts until re-enabled in MCP settings.")
        }
        val result = SwingApprovalGate.showOption {
            Dialogs.showOptionDialog(
                findBurpFrame(),
                message,
                arrayOf("Allow Once", "Allow for This Session", "Always Allow", "Deny"),
                requestContent,
                api,
            )
        }
        return when (result) {
            0 -> true
            1 -> {
                grantCurrentSessionApproval(McpSessionApproval.REQUEST_ROUTING)
                true
            }
            2 -> {
                val persisted = runCatching { config.requireRequestActionApproval = false }
                runCatching {
                    if (persisted.isSuccess) {
                        api.logging().logToOutput(
                            "MCP request-routing approval disabled by the user from an approval dialog"
                        )
                    } else {
                        api.logging().logToError(
                            "MCP could not persist Always Allow for request-routing actions"
                        )
                    }
                }
                true
            }
            else -> false
        }
    }
}

enum class RequestRoutingAuditOperation(val auditKind: String) {
    REPEATER("request_routing:repeater"),
    INTRUDER("request_routing:intruder"),
    ORGANIZER("request_routing:organizer"),
}

object RequestActionSecurity {
    var approvalHandler: RequestActionApprovalHandler = SwingRequestActionApprovalHandler()

    suspend fun checkPermission(
        action: String,
        source: String,
        target: String,
        changes: String,
        requestContent: String,
        config: McpConfig,
        api: MontoyaApi,
        auditOperation: RequestRoutingAuditOperation? = null,
    ): Boolean {
        val auditKind = auditOperation?.auditKind ?: "request_routing"
        if (!config.requireRequestActionApproval) {
            recordCurrentToolApproval(auditKind, "policy_allow")
            return true
        }
        if (isCurrentSessionApproved(McpSessionApproval.REQUEST_ROUTING)) {
            recordCurrentToolApproval(auditKind, "session_allow")
            return true
        }
        val approved = approvalHandler.requestApproval(action, source, target, changes, requestContent, config, api)
        recordCurrentToolApproval(auditKind, if (approved) "user_allow" else "user_deny")
        return approved
    }
}
