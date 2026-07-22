package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi

/** Extension-lifetime state that must survive MCP HTTP server restarts. */
internal class ToolServices(private val api: MontoyaApi) {
    private val collaboratorDelegate = lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        CollaboratorToolService(api)
    }
    private val scannerAuditsDelegate = lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        ScannerAuditService(api)
    }
    private val httpMetadataIndexDelegate = lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        HttpMetadataIndex(api)
    }

    val collaborator: CollaboratorToolService get() = collaboratorDelegate.value
    val scannerAudits: ScannerAuditService get() = scannerAuditsDelegate.value
    val httpMetadataIndex: HttpMetadataIndex get() = httpMetadataIndexDelegate.value

    fun close() {
        if (scannerAuditsDelegate.isInitialized()) scannerAuditsDelegate.value.close()
        if (collaboratorDelegate.isInitialized()) collaboratorDelegate.value.close()
        if (httpMetadataIndexDelegate.isInitialized()) httpMetadataIndexDelegate.value.close()
    }
}
