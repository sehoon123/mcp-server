package net.portswigger.mcp.providers

import java.nio.charset.StandardCharsets

internal const val MAX_CLIENT_SETUP_PREVIEW_BYTES = 16 * 1024

@ConsistentCopyVisibility
internal data class ClientSetupEndpoint private constructor(
    val host: String,
    val port: Int,
) {
    companion object {
        fun from(host: String, port: Int): ClientSetupEndpoint {
            val normalized = requireNotNull(
                net.portswigger.mcp.config.ConfigValidation.normalizeLoopbackHost(host),
            ) { "MCP endpoint host must be 127.0.0.1 or ::1" }
            require(port in 1024..65535) { "MCP endpoint port is outside the valid range" }
            return ClientSetupEndpoint(normalized, port)
        }
    }
}

internal enum class ClientSetupId {
    CLAUDE_DESKTOP,
    CLAUDE_CODE,
    VS_CODE_COPILOT,
    CURSOR,
    CODEX,
}

internal enum class ClientSetupTransport {
    STDIO_PROXY,
    NATIVE_HTTP,
}

internal data class ClientSetupDefinition(
    val id: ClientSetupId,
    val displayName: String,
    val transport: ClientSetupTransport,
    val guidance: String,
    val automaticInstallAvailable: Boolean,
) {
    override fun toString(): String = displayName
}

internal object ClientSetupCatalog {
    val definitions: List<ClientSetupDefinition> = listOf(
        ClientSetupDefinition(
            id = ClientSetupId.CLAUDE_DESKTOP,
            displayName = "Claude Desktop",
            transport = ClientSetupTransport.STDIO_PROXY,
            guidance = "Use the verified built-in installer. It fills the executable, proxy jar, and token values represented by placeholders in this preview, writes the private local configuration, and creates a backup. Restart Claude Desktop afterward.",
            automaticInstallAvailable = true,
        ),
        ClientSetupDefinition(
            id = ClientSetupId.CLAUDE_CODE,
            displayName = "Claude Code",
            transport = ClientSetupTransport.NATIVE_HTTP,
            guidance = "Use a user or project .mcp.json and provide the bearer through the named environment variable. Review the project trust prompt before connecting.",
            automaticInstallAvailable = false,
        ),
        ClientSetupDefinition(
            id = ClientSetupId.VS_CODE_COPILOT,
            displayName = "VS Code / GitHub Copilot",
            transport = ClientSetupTransport.NATIVE_HTTP,
            guidance = "Use workspace or user MCP configuration. VS Code prompts for the bearer as a password input and does not store it in this preview.",
            automaticInstallAvailable = false,
        ),
        ClientSetupDefinition(
            id = ClientSetupId.CURSOR,
            displayName = "Cursor",
            transport = ClientSetupTransport.NATIVE_HTTP,
            guidance = "Use project or global MCP configuration and set the named environment variable in the process that launches Cursor. Reconnect after changes.",
            automaticInstallAvailable = false,
        ),
        ClientSetupDefinition(
            id = ClientSetupId.CODEX,
            displayName = "OpenAI Codex",
            transport = ClientSetupTransport.NATIVE_HTTP,
            guidance = "Use user or trusted-project Codex TOML configuration and set the named bearer environment variable before reconnecting.",
            automaticInstallAvailable = false,
        ),
    )

    fun render(id: ClientSetupId, endpoint: ClientSetupEndpoint): String {
        val url = streamableHttpEndpoint(endpoint.host, endpoint.port)
        val preview = when (id) {
            ClientSetupId.CLAUDE_DESKTOP -> claudeDesktopPreview(url)
            ClientSetupId.CLAUDE_CODE -> claudeCodePreview(url)
            ClientSetupId.VS_CODE_COPILOT -> vsCodePreview(url)
            ClientSetupId.CURSOR -> cursorPreview(url)
            ClientSetupId.CODEX -> codexPreview(url)
        }
        check(preview.toByteArray(StandardCharsets.UTF_8).size <= MAX_CLIENT_SETUP_PREVIEW_BYTES) {
            "Client setup preview exceeds its safety bound"
        }
        return preview
    }

    private fun claudeDesktopPreview(url: String): String =
        """
        {
          "mcpServers": {
            "burp-independent": {
              "command": "<BURP_JAVA_EXECUTABLE>",
              "args": [
                "-jar",
                "<VERIFIED_PROXY_JAR>",
                "--mcp-url",
                "$url",
                "--bearer-token-env",
                "$BEARER_TOKEN_ENVIRONMENT_VARIABLE"
              ],
              "env": {
                "$BEARER_TOKEN_ENVIRONMENT_VARIABLE": "<TOKEN_INSTALLED_ONLY_AFTER_CONFIRMATION>"
              }
            }
          }
        }
        """.trimIndent()

    private fun claudeCodePreview(url: String): String =
        """
        {
          "mcpServers": {
            "burp-independent": {
              "type": "http",
              "url": "$url",
              "headers": {
                "Authorization": "Bearer ${'$'}{$BEARER_TOKEN_ENVIRONMENT_VARIABLE}"
              }
            }
          }
        }
        """.trimIndent()

    private fun vsCodePreview(url: String): String =
        """
        {
          "inputs": [
            {
              "type": "promptString",
              "id": "independent-mcp-bridge-token",
              "description": "Independent MCP Bridge local bearer token",
              "password": true
            }
          ],
          "servers": {
            "burp-independent": {
              "type": "http",
              "url": "$url",
              "headers": {
                "Authorization": "Bearer ${'$'}{input:independent-mcp-bridge-token}"
              }
            }
          }
        }
        """.trimIndent()

    private fun cursorPreview(url: String): String =
        """
        {
          "mcpServers": {
            "burp-independent": {
              "url": "$url",
              "headers": {
                "Authorization": "Bearer ${'$'}{env:$BEARER_TOKEN_ENVIRONMENT_VARIABLE}"
              }
            }
          }
        }
        """.trimIndent()

    private fun codexPreview(url: String): String =
        """
        [mcp_servers.burp-independent]
        url = "$url"
        bearer_token_env_var = "$BEARER_TOKEN_ENVIRONMENT_VARIABLE"
        enabled = true
        """.trimIndent()
}
