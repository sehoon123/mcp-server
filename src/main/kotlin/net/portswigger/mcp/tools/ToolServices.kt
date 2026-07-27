package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.persistence.PersistedObject
import net.portswigger.mcp.presets.WorkflowPresetStore

/** Extension-lifetime state that must survive MCP HTTP server restarts. */
internal class ToolServices(private val api: MontoyaApi, extensionStorage: PersistedObject) {
    val workflowPresetStore = WorkflowPresetStore(extensionStorage)
    private val collaboratorDelegate = lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        CollaboratorToolService(api)
    }
    private val scannerAuditsDelegate = lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        ScannerAuditService(api)
    }
    private val httpMetadataIndexDelegate = lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        HttpMetadataIndex(api)
    }
    private val httpSessionSecurityAnalyzerDelegate = lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        HttpSessionSecurityAnalyzerService(api)
    }

    val collaborator: CollaboratorToolService get() = collaboratorDelegate.value
    val scannerAudits: ScannerAuditService get() = scannerAuditsDelegate.value
    val httpMetadataIndex: HttpMetadataIndex get() = httpMetadataIndexDelegate.value
    val httpSessionSecurityAnalyzer: HttpSessionSecurityAnalyzerService
        get() = httpSessionSecurityAnalyzerDelegate.value

    suspend fun resetForProjectBoundary() {
        if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
            scannerAuditsDelegate.value.resetForProjectBoundary()
            collaboratorDelegate.value.resetForProjectBoundary()
        }
        httpMetadataIndexDelegate.value.resetForProjectBoundary()
    }

    fun close() {
        if (scannerAuditsDelegate.isInitialized()) scannerAuditsDelegate.value.close()
        if (collaboratorDelegate.isInitialized()) collaboratorDelegate.value.close()
        if (httpMetadataIndexDelegate.isInitialized()) httpMetadataIndexDelegate.value.close()
    }
}
