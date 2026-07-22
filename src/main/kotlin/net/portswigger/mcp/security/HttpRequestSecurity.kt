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
        }
        val result = SwingApprovalGate.showOption {
            Dialogs.showOptionDialog(
                findBurpFrame(),
                message,
                arrayOf("Allow Once", "Always Allow Host", "Always Allow Host:Port", "Deny"),
                requestContent,
                api,
            )
        }
        return when (result) {
            0 -> true
            1 -> {
                config.addAutoApproveTarget(hostname)
                true
            }
            2 -> {
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
        if (!isValidRequestedTarget(hostname, port)) return false
        if (!config.requireHttpRequestApproval) {
            return true
        }

        if (isAutoApproved(hostname, port, config)) {
            return true
        }

        return approvalHandler.requestApproval(hostname, port, config, requestContent, api)
    }

    /** Avoids materializing a potentially large request unless interactive approval is actually required. */
    suspend fun checkHttpRequestPermissionLazy(
        hostname: String,
        port: Int,
        config: McpConfig,
        api: MontoyaApi? = null,
        requestContent: () -> String,
    ): Boolean {
        if (!isValidRequestedTarget(hostname, port)) return false
        if (!config.requireHttpRequestApproval || isAutoApproved(hostname, port, config)) {
            return true
        }
        return approvalHandler.requestApproval(hostname, port, config, requestContent(), api)
    }

    private fun isValidRequestedTarget(hostname: String, port: Int): Boolean = runCatching {
        TargetValidation.normalizeTarget(TargetValidation.formatTarget(hostname, port)) != null
    }.getOrDefault(false)
}