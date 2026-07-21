package net.portswigger.mcp.security

import kotlinx.coroutines.suspendCancellableCoroutine
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig
import javax.swing.SwingUtilities

enum class DataAccessType {
    HTTP_HISTORY,
    WEBSOCKET_HISTORY,
    ORGANIZER,
    SCANNER_ISSUES,
}

interface DataAccessApprovalHandler {
    suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean
}

class SwingDataAccessApprovalHandler : DataAccessApprovalHandler {
    override suspend fun requestDataAccess(
        accessType: DataAccessType, config: McpConfig
    ): Boolean {
        return suspendCancellableCoroutine { continuation ->
            SwingUtilities.invokeLater ui@{
                if (!continuation.isActive) return@ui

                val accessTypeName = when (accessType) {
                    DataAccessType.HTTP_HISTORY -> "HTTP history"
                    DataAccessType.WEBSOCKET_HISTORY -> "WebSocket history"
                    DataAccessType.ORGANIZER -> "Organizer items"
                    DataAccessType.SCANNER_ISSUES -> "Scanner issues"
                }

                val message = buildString {
                    appendLine("An MCP client is requesting access to your Burp Suite $accessTypeName.")
                    appendLine()
                    appendLine("This may include sensitive data from previous web sessions.")
                    appendLine("Choose how you would like to respond:")
                }

                val options = arrayOf(
                    "Allow Once", "Always Allow $accessTypeName", "Deny"
                )

                val burpFrame = findBurpFrame()

                val result = Dialogs.showOptionDialog(
                    burpFrame, message, options
                )

                val approved = when (result) {
                    0 -> true
                    1 -> {
                        when (accessType) {
                            DataAccessType.HTTP_HISTORY -> config.alwaysAllowHttpHistory = true
                            DataAccessType.WEBSOCKET_HISTORY -> config.alwaysAllowWebSocketHistory = true
                            DataAccessType.ORGANIZER -> config.alwaysAllowOrganizer = true
                            DataAccessType.SCANNER_ISSUES -> config.alwaysAllowScannerIssues = true
                        }
                        true
                    }
                    else -> false
                }
                if (continuation.isActive) continuation.resume(approved) { _, _, _ -> }
            }
        }
    }
}

object DataAccessSecurity {

    var approvalHandler: DataAccessApprovalHandler = SwingDataAccessApprovalHandler()

    suspend fun checkDataAccessPermission(
        accessType: DataAccessType, config: McpConfig
    ): Boolean {
        if (!config.requireDataAccessApproval) {
            return true
        }

        val isAlwaysAllowed = when (accessType) {
            DataAccessType.HTTP_HISTORY -> config.alwaysAllowHttpHistory
            DataAccessType.WEBSOCKET_HISTORY -> config.alwaysAllowWebSocketHistory
            DataAccessType.ORGANIZER -> config.alwaysAllowOrganizer
            DataAccessType.SCANNER_ISSUES -> config.alwaysAllowScannerIssues
        }

        if (isAlwaysAllowed) {
            return true
        }

        return approvalHandler.requestDataAccess(accessType, config)
    }
}