package net.portswigger.mcp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.ConfigUi
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.providers.ClaudeDesktopProvider
import net.portswigger.mcp.providers.ManualProxyInstallerProvider
import net.portswigger.mcp.providers.ProxyJarManager
import net.portswigger.mcp.security.PersistentMcpAuditLog
import net.portswigger.mcp.security.safeExceptionSummary

@Suppress("unused")
class ExtensionBase : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Burp MCP Server")

        val extensionStorage = api.persistence().extensionData()
        val config = McpConfig(extensionStorage, api.logging())
        val auditLog = PersistentMcpAuditLog(extensionStorage, config, api.logging())
        val serverManager = KtorServerManager(api, auditLog)

        val proxyJarManager = ProxyJarManager(api.logging())
        val proxyVerified = runCatching { proxyJarManager.getProxyJar() }
            .onFailure {
                api.logging().logToError("Failed to refresh the packaged MCP proxy: ${safeExceptionSummary(it)}")
            }
            .isSuccess
        val proxyProvenance = runCatching { proxyJarManager.packagedProvenance() }
            .onFailure {
                api.logging().logToError("Failed to read packaged MCP proxy provenance: ${safeExceptionSummary(it)}")
            }
            .getOrNull()

        val configUi = ConfigUi(
            config = config,
            providers = listOf(
                ClaudeDesktopProvider(api.logging(), proxyJarManager),
                ManualProxyInstallerProvider(api.logging(), proxyJarManager),
            ),
            diagnosticsProvider = serverManager::diagnostics,
            auditLog = auditLog,
            proxyProvenance = proxyProvenance,
            proxyVerified = proxyVerified,
            clearSessionApprovals = serverManager::clearSessionApprovals,
        )

        configUi.onEnabledToggled { enabled ->
            configUi.getConfig()

            if (enabled) {
                serverManager.start(config) { state ->
                    configUi.updateServerState(state)
                }
            } else {
                serverManager.stop { state ->
                    configUi.updateServerState(state)
                }
            }
        }

        api.userInterface().registerSuiteTab("MCP", configUi.component)
        val referenceMenuProvider = McpReferenceContextMenuProvider(api)
        val referenceMenuRegistration = api.userInterface().registerContextMenuItemsProvider(referenceMenuProvider)

        api.extension().registerUnloadingHandler {
            runCatching { referenceMenuRegistration.deregister() }
            referenceMenuProvider.close()
            serverManager.shutdown()
            configUi.cleanup()
            auditLog.close()
            config.cleanup()
        }

        if (config.enabled) {
            serverManager.start(config) { state ->
                configUi.updateServerState(state)
            }
        }
    }
}