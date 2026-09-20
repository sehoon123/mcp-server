package net.portswigger.mcp.config

/** One validated, credential-free endpoint shared by listener startup and client configuration. */
@ConsistentCopyVisibility
internal data class McpEndpoint private constructor(
    val host: String,
    val port: Int,
) {
    val url: String
        get() {
            val authorityHost = if (':' in host) "[$host]" else host
            return "http://$authorityHost:$port/mcp"
        }

    companion object {
        fun from(host: String, port: Int): McpEndpoint {
            val error = ConfigValidation.validateServerConfig(host, port.toString())
            require(error == null) { error.orEmpty() }
            return McpEndpoint(requireNotNull(ConfigValidation.normalizeLoopbackHost(host)), port)
        }
    }
}
