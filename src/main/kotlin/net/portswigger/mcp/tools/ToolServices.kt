package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi

/** Extension-lifetime state that must survive MCP HTTP server restarts. */
internal class ToolServices(private val api: MontoyaApi) {
    val collaborator: CollaboratorToolService by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        CollaboratorToolService(api)
    }
    val scannerAudits: ScannerAuditService by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        ScannerAuditService(api)
    }
}
