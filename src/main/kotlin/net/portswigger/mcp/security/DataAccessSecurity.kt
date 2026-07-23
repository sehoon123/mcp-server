package net.portswigger.mcp.security

import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig

enum class DataAccessType {
    HTTP_HISTORY,
    SITE_MAP,
    WEBSOCKET_HISTORY,
    ORGANIZER,
    SCANNER_ISSUES,
    COLLABORATOR_INTERACTIONS,
}

interface DataAccessApprovalHandler {
    suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean
}

class SwingDataAccessApprovalHandler : DataAccessApprovalHandler {
    override suspend fun requestDataAccess(
        accessType: DataAccessType, config: McpConfig
    ): Boolean {
        val accessTypeName = when (accessType) {
            DataAccessType.HTTP_HISTORY -> "HTTP history"
            DataAccessType.SITE_MAP -> "Site Map items"
            DataAccessType.WEBSOCKET_HISTORY -> "WebSocket history"
            DataAccessType.ORGANIZER -> "Organizer items"
            DataAccessType.SCANNER_ISSUES -> "Scanner issues"
            DataAccessType.COLLABORATOR_INTERACTIONS -> "Collaborator interactions"
        }
        val message = buildString {
            appendLine("An MCP client is requesting access to your Burp Suite $accessTypeName.")
            appendLine()
            appendLine("This may include sensitive data from previous web sessions.")
            appendLine(
                "Allow for This Session applies only to $accessTypeName and expires when this MCP session ends or " +
                    "session approvals are reset."
            )
            appendLine("Choose how you would like to respond:")
        }
        val result = SwingApprovalGate.showOption {
            Dialogs.showOptionDialog(
                findBurpFrame(),
                message,
                arrayOf(
                    "Allow Once",
                    "Allow $accessTypeName for This Session",
                    "Always Allow $accessTypeName",
                    "Deny",
                ),
            )
        }

        return when (result) {
            0 -> true
            1 -> {
                grantCurrentSessionApproval(accessType.sessionApproval())
                true
            }
            2 -> {
                when (accessType) {
                    DataAccessType.HTTP_HISTORY -> config.alwaysAllowHttpHistory = true
                    DataAccessType.SITE_MAP -> config.alwaysAllowSiteMap = true
                    DataAccessType.WEBSOCKET_HISTORY -> config.alwaysAllowWebSocketHistory = true
                    DataAccessType.ORGANIZER -> config.alwaysAllowOrganizer = true
                    DataAccessType.SCANNER_ISSUES -> config.alwaysAllowScannerIssues = true
                    DataAccessType.COLLABORATOR_INTERACTIONS -> config.alwaysAllowCollaboratorInteractions = true
                }
                true
            }
            else -> false
        }
    }
}

object DataAccessSecurity {

    var approvalHandler: DataAccessApprovalHandler = SwingDataAccessApprovalHandler()

    suspend fun checkDataAccessPermission(
        accessType: DataAccessType, config: McpConfig
    ): Boolean {
        if (!config.requireDataAccessApproval) {
            recordCurrentToolApproval("data_access:${accessType.name.lowercase()}", "policy_allow")
            return true
        }

        val isAlwaysAllowed = when (accessType) {
            DataAccessType.HTTP_HISTORY -> config.alwaysAllowHttpHistory
            DataAccessType.SITE_MAP -> config.alwaysAllowSiteMap
            DataAccessType.WEBSOCKET_HISTORY -> config.alwaysAllowWebSocketHistory
            DataAccessType.ORGANIZER -> config.alwaysAllowOrganizer
            DataAccessType.SCANNER_ISSUES -> config.alwaysAllowScannerIssues
            DataAccessType.COLLABORATOR_INTERACTIONS -> config.alwaysAllowCollaboratorInteractions
        }

        if (isAlwaysAllowed) {
            recordCurrentToolApproval("data_access:${accessType.name.lowercase()}", "persisted_allow")
            return true
        }
        if (isCurrentSessionApproved(accessType.sessionApproval())) {
            recordCurrentToolApproval("data_access:${accessType.name.lowercase()}", "session_allow")
            return true
        }

        val approved = approvalHandler.requestDataAccess(accessType, config)
        recordCurrentToolApproval(
            "data_access:${accessType.name.lowercase()}",
            if (approved) "user_allow" else "user_deny",
        )
        return approved
    }
}

private fun DataAccessType.sessionApproval(): McpSessionApproval = when (this) {
    DataAccessType.HTTP_HISTORY -> McpSessionApproval.HTTP_HISTORY
    DataAccessType.SITE_MAP -> McpSessionApproval.SITE_MAP
    DataAccessType.WEBSOCKET_HISTORY -> McpSessionApproval.WEBSOCKET_HISTORY
    DataAccessType.ORGANIZER -> McpSessionApproval.ORGANIZER
    DataAccessType.SCANNER_ISSUES -> McpSessionApproval.SCANNER_ISSUES
    DataAccessType.COLLABORATOR_INTERACTIONS -> McpSessionApproval.COLLABORATOR_INTERACTIONS
}
