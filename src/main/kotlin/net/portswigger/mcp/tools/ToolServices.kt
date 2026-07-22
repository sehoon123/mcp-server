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

    val collaborator: CollaboratorToolService get() = collaboratorDelegate.value
    val scannerAudits: ScannerAuditService get() = scannerAuditsDelegate.value

    fun close() {
        if (scannerAuditsDelegate.isInitialized()) scannerAuditsDelegate.value.close()
        if (collaboratorDelegate.isInitialized()) collaboratorDelegate.value.close()
    }
}
