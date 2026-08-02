package net.portswigger.mcp.providers

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.charset.StandardCharsets
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ClientSetupTest {
    @Test
    fun `catalog is the exact five-client no-write surface`() {
        assertEquals(
            listOf(
                ClientSetupId.CLAUDE_DESKTOP,
                ClientSetupId.CLAUDE_CODE,
                ClientSetupId.VS_CODE_COPILOT,
                ClientSetupId.CURSOR,
                ClientSetupId.CODEX,
            ),
            ClientSetupCatalog.definitions.map { it.id },
        )
        assertEquals(5, ClientSetupCatalog.definitions.size)
        assertEquals(
            listOf(
                "Claude Desktop",
                "Claude Code",
                "VS Code / GitHub Copilot",
                "Cursor",
                "OpenAI Codex",
            ),
            ClientSetupCatalog.definitions.map { it.displayName },
        )
        assertEquals(
            listOf(ClientSetupId.CLAUDE_DESKTOP),
            ClientSetupCatalog.definitions.filter { it.automaticInstallAvailable }.map { it.id },
        )
    }

    @Test
    fun `JSON previews preserve each client's exact top-level shape`() {
        val endpoint = ClientSetupEndpoint.from("127.0.0.1", 9876)

        val desktop = Json.parseToJsonElement(
            ClientSetupCatalog.render(ClientSetupId.CLAUDE_DESKTOP, endpoint),
        ).jsonObject
        val desktopEntry = desktop.getValue("mcpServers").jsonObject.getValue("burp-independent").jsonObject
        assertEquals("<BURP_JAVA_EXECUTABLE>", desktopEntry.getValue("command").jsonPrimitive.content)
        assertEquals(
            listOf(
                "-jar",
                "<VERIFIED_PROXY_JAR>",
                "--mcp-url",
                "http://127.0.0.1:9876/mcp",
                "--bearer-token-env",
                BEARER_TOKEN_ENVIRONMENT_VARIABLE,
            ),
            desktopEntry.getValue("args").jsonArray.map { it.jsonPrimitive.content },
        )
        assertEquals(
            "<TOKEN_INSTALLED_ONLY_AFTER_CONFIRMATION>",
            desktopEntry.getValue("env").jsonObject.getValue(BEARER_TOKEN_ENVIRONMENT_VARIABLE).jsonPrimitive.content,
        )

        val claudeCode = Json.parseToJsonElement(
            ClientSetupCatalog.render(ClientSetupId.CLAUDE_CODE, endpoint),
        ).jsonObject.getValue("mcpServers").jsonObject.getValue("burp-independent").jsonObject
        assertEquals("http", claudeCode.getValue("type").jsonPrimitive.content)
        assertEquals("http://127.0.0.1:9876/mcp", claudeCode.getValue("url").jsonPrimitive.content)
        assertEquals(
            "Bearer \${$BEARER_TOKEN_ENVIRONMENT_VARIABLE}",
            claudeCode.getValue("headers").jsonObject.getValue("Authorization").jsonPrimitive.content,
        )

        val vsCodeRoot = Json.parseToJsonElement(
            ClientSetupCatalog.render(ClientSetupId.VS_CODE_COPILOT, endpoint),
        ).jsonObject
        assertEquals(setOf("inputs", "servers"), vsCodeRoot.keys)
        assertTrue(vsCodeRoot.getValue("inputs").jsonArray.single().jsonObject.getValue("password").jsonPrimitive.boolean)
        val vsCode = vsCodeRoot.getValue("servers").jsonObject.getValue("burp-independent").jsonObject
        assertEquals(
            "Bearer \${input:independent-mcp-bridge-token}",
            vsCode.getValue("headers").jsonObject.getValue("Authorization").jsonPrimitive.content,
        )

        val cursor = Json.parseToJsonElement(
            ClientSetupCatalog.render(ClientSetupId.CURSOR, endpoint),
        ).jsonObject.getValue("mcpServers").jsonObject.getValue("burp-independent").jsonObject
        assertEquals(
            "Bearer \${env:$BEARER_TOKEN_ENVIRONMENT_VARIABLE}",
            cursor.getValue("headers").jsonObject.getValue("Authorization").jsonPrimitive.content,
        )
    }

    @Test
    fun `Codex preview is exact TOML and IPv6 previews use brackets`() {
        val endpoint = ClientSetupEndpoint.from("[::1]", 9876)
        assertEquals(
            """
            [mcp_servers.burp-independent]
            url = "http://[::1]:9876/mcp"
            bearer_token_env_var = "$BEARER_TOKEN_ENVIRONMENT_VARIABLE"
            enabled = true
            """.trimIndent(),
            ClientSetupCatalog.render(ClientSetupId.CODEX, endpoint),
        )
        ClientSetupId.entries.forEach { id ->
            assertTrue(ClientSetupCatalog.render(id, endpoint).contains("http://[::1]:9876/mcp"))
        }
    }

    @Test
    fun `previews are bounded and cannot include runtime secrets or resolved paths`() {
        val endpoint = ClientSetupEndpoint.from("127.0.0.1", 65535)
        val forbidden = listOf(
            "sentinel-current-bearer-credential",
            "/Users/example/private/java",
            "/home/example/proxy.jar",
            "C:\\Users\\example\\client.json",
        )
        ClientSetupId.entries.forEach { id ->
            val preview = ClientSetupCatalog.render(id, endpoint)
            assertTrue(preview.toByteArray(StandardCharsets.UTF_8).size <= MAX_CLIENT_SETUP_PREVIEW_BYTES)
            forbidden.forEach { value -> assertFalse(preview.contains(value), "$id disclosed $value") }
        }
    }

    @Test
    fun `endpoint accepts only bounded numeric loopback values`() {
        assertEquals("127.0.0.1", ClientSetupEndpoint.from("127.0.0.1", 1024).host)
        assertEquals("::1", ClientSetupEndpoint.from("[::1]", 65535).host)
        listOf("localhost", "0.0.0.0", "::", "192.0.2.1").forEach { host ->
            assertThrows<IllegalArgumentException> { ClientSetupEndpoint.from(host, 9876) }
        }
        assertThrows<IllegalArgumentException> { ClientSetupEndpoint.from("127.0.0.1", 1023) }
        assertThrows<IllegalArgumentException> { ClientSetupEndpoint.from("127.0.0.1", 65536) }
        assertThrows<IllegalArgumentException> { streamableHttpEndpoint("127.0.0.1", 1) }
    }
}
