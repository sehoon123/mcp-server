package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import kotlinx.coroutines.suspendCancellableCoroutine
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig
import javax.swing.SwingUtilities

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
    ): Boolean = suspendCancellableCoroutine { continuation ->
        SwingUtilities.invokeLater ui@{
            if (!continuation.isActive) return@ui

            val message = buildString {
                appendLine("An MCP client is requesting to $action.")
                appendLine()
                appendLine("Source: $source")
                appendLine("Target: $target")
                appendLine("Changes: $changes")
                appendLine()
                appendLine("Review the exact resulting request before allowing this action.")
                appendLine()
                append("Always Allow disables future request-routing approval prompts until re-enabled in MCP settings.")
            }
            val result = Dialogs.showOptionDialog(
                findBurpFrame(),
                message,
                arrayOf("Allow Once", "Always Allow", "Deny"),
                requestContent,
                api,
            )
            if (!continuation.isActive) return@ui
            val approved = when (result) {
                0 -> true
                1 -> {
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
            if (continuation.isActive) continuation.resume(approved) { _, _, _ -> }
        }
    }
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
    ): Boolean {
        if (!config.requireRequestActionApproval) return true
        return approvalHandler.requestApproval(action, source, target, changes, requestContent, config, api)
    }
}
