package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.config.TargetValidation

interface UserApprovalHandler {
    suspend fun requestApproval(
        hostname: String, port: Int, config: McpConfig, requestContent: String? = null, api: MontoyaApi? = null
    ): Boolean
}

class SwingUserApprovalHandler : UserApprovalHandler {
    override suspend fun requestApproval(
        hostname: String, port: Int, config: McpConfig, requestContent: String?, api: MontoyaApi?
    ): Boolean {
        val message = buildString {
            appendLine("An MCP client is requesting to send an HTTP request to:")
            appendLine()
            appendLine("Target: ${TargetValidation.formatTarget(hostname, port)}")
            appendLine()
            appendLine(
                "Allow All for This Session permits requests to any syntactically valid destination until this " +
                    "MCP session ends or session approvals are reset."
            )
        }
        val result = SwingApprovalGate.showOption {
            Dialogs.showOptionDialog(
                findBurpFrame(),
                message,
                arrayOf(
                    "Allow Once",
                    "Allow All for This Session",
                    "Always Allow Host",
                    "Always Allow Host:Port",
                    "Deny",
                ),
                requestContent,
                api,
            )
        }
        return when (result) {
            0 -> true
            1 -> {
                grantCurrentSessionApproval(McpSessionApproval.OUTBOUND_HTTP)
                true
            }
            2 -> {
                config.addAutoApproveTarget(hostname)
                true
            }
            3 -> {
                config.addAutoApproveTarget(TargetValidation.formatTarget(hostname, port))
                true
            }
            else -> false
        }
    }
}

object HttpRequestSecurity {

    var approvalHandler: UserApprovalHandler = SwingUserApprovalHandler()

    private fun isAutoApproved(hostname: String, port: Int, config: McpConfig): Boolean =
        config.getAutoApproveTargetsList().any { TargetValidation.isApproved(it, hostname, port) }

    suspend fun checkHttpRequestPermission(
        hostname: String, port: Int, config: McpConfig, requestContent: String? = null, api: MontoyaApi? = null
    ): Boolean {
        if (!isValidRequestedTarget(hostname, port)) {
            recordCurrentToolApproval("http_request", "target_reject")
            return false
        }
        if (!config.requireHttpRequestApproval) {
            recordCurrentToolApproval("http_request", "policy_allow")
            return true
        }

        if (isAutoApproved(hostname, port, config)) {
            recordCurrentToolApproval("http_request", "persisted_allow")
            return true
        }
        if (isCurrentSessionApproved(McpSessionApproval.OUTBOUND_HTTP)) {
            recordCurrentToolApproval("http_request", "session_allow")
            return true
        }

        val approved = approvalHandler.requestApproval(hostname, port, config, requestContent, api)
        recordCurrentToolApproval("http_request", if (approved) "user_allow" else "user_deny")
        return approved
    }

    /** Avoids materializing a potentially large request unless interactive approval is actually required. */
    suspend fun checkHttpRequestPermissionLazy(
        hostname: String,
        port: Int,
        config: McpConfig,
        api: MontoyaApi? = null,
        requestContent: () -> String,
    ): Boolean {
        if (!isValidRequestedTarget(hostname, port)) {
            recordCurrentToolApproval("http_request", "target_reject")
            return false
        }
        if (!config.requireHttpRequestApproval) {
            recordCurrentToolApproval("http_request", "policy_allow")
            return true
        }
        if (isAutoApproved(hostname, port, config)) {
            recordCurrentToolApproval("http_request", "persisted_allow")
            return true
        }
        if (isCurrentSessionApproved(McpSessionApproval.OUTBOUND_HTTP)) {
            recordCurrentToolApproval("http_request", "session_allow")
            return true
        }
        val approved = approvalHandler.requestApproval(hostname, port, config, requestContent(), api)
        recordCurrentToolApproval("http_request", if (approved) "user_allow" else "user_deny")
        return approved
    }

    private fun isValidRequestedTarget(hostname: String, port: Int): Boolean = runCatching {
        TargetValidation.normalizeTarget(TargetValidation.formatTarget(hostname, port)) != null
    }.getOrDefault(false)
}