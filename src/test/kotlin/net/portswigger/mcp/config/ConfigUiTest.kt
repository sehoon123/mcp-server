package net.portswigger.mcp.config

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.*
import net.portswigger.mcp.unavailableMcpDiagnosticsSnapshot
import net.portswigger.mcp.security.NoOpMcpAuditSink
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.awt.Container
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JOptionPane
import javax.swing.SwingUtilities

class ConfigUiTest {
    @Test
    fun `version label is conspicuous and bounded`() {
        assertEquals("Extension version: 4.0.1", formatMcpVersionLabel("4.0.1"))
        val sanitized = formatMcpVersionLabel("4.0.1\nBearer secret-value /home/user/file")
        assertFalse(sanitized.contains('\n'))
        assertFalse(sanitized.contains("secret-value"))
        assertFalse(sanitized.contains("/home/"))
        assertEquals("Extension version: unknown", formatMcpVersionLabel(""))
    }

    @Test
    fun `allow all HTTP requests checkbox inversely controls the secure approval policy`() {
        val booleans = mutableMapOf("requireHttpRequestApproval" to true)
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers { booleans[firstArg()] }
        every { storage.setBoolean(any(), any()) } answers { booleans[firstArg()] = secondArg() }
        every { storage.getString(any()) } returns null
        every { storage.getInteger(any()) } returns null
        val config = McpConfig(storage, mockk<Logging>(relaxed = true))
        val ui = ConfigUi(config, emptyList())

        try {
            val checkbox = ui.component.descendants()
                .filterIsInstance<JCheckBox>()
                .single { it.text == "Always allow all outbound HTTP requests" }
            assertFalse(checkbox.isSelected)
            assertTrue(config.requireHttpRequestApproval)

            SwingUtilities.invokeAndWait { checkbox.doClick() }
            assertTrue(checkbox.isSelected)
            assertFalse(config.requireHttpRequestApproval)

            SwingUtilities.invokeAndWait { checkbox.doClick() }
            assertFalse(checkbox.isSelected)
            assertTrue(config.requireHttpRequestApproval)
        } finally {
            ui.cleanup()
        }
    }

    @Test
    fun `MCP tab exposes bounded session and persistent approval reset controls`() {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns null
        every { storage.getString(any()) } returns null
        every { storage.getInteger(any()) } returns null
        val config = McpConfig(storage, mockk<Logging>(relaxed = true))
        var sessionResetCalls = 0
        val ui = ConfigUi(
            config = config,
            providers = emptyList(),
            diagnosticsProvider = ::unavailableMcpDiagnosticsSnapshot,
            auditLog = NoOpMcpAuditSink,
            proxyProvenance = null,
            proxyVerified = false,
            clearSessionApprovals = {
                sessionResetCalls++
                3
            },
        )

        try {
            val buttons = ui.component.descendants().filterIsInstance<JButton>().associateBy { it.text }
            assertTrue(buttons.containsKey("Reset active session approvals"))
            assertTrue(buttons.containsKey("Reset all persistent approvals..."))

            SwingUtilities.invokeAndWait { buttons.getValue("Reset active session approvals").doClick() }
            assertEquals(1, sessionResetCalls)
        } finally {
            ui.cleanup()
        }
    }

    @Test
    fun `persistent approval reset button restores secure config and visible controls`() {
        val booleans = mutableMapOf(
            "requireHttpRequestApproval" to false,
            "requireRequestActionApproval" to false,
            "requireScopeChangeApproval" to false,
            "requireDataAccessApproval" to false,
            "_alwaysAllowHttpHistory" to true,
            "_alwaysAllowSiteMap" to true,
            "_alwaysAllowWebSocketHistory" to true,
            "_alwaysAllowOrganizer" to true,
            "_alwaysAllowScannerIssues" to true,
            "_alwaysAllowCollaboratorInteractions" to true,
        )
        val strings = mutableMapOf("_autoApproveTargets" to "example.com")
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers { booleans[firstArg()] }
        every { storage.setBoolean(any(), any()) } answers { booleans[firstArg()] = secondArg() }
        every { storage.getString(any()) } answers { strings[firstArg()] }
        every { storage.setString(any(), any()) } answers { strings[firstArg()] = secondArg() }
        every { storage.getInteger(any()) } returns null
        val config = McpConfig(storage, mockk<Logging>(relaxed = true))
        val ui = ConfigUi(config, emptyList())
        mockkStatic(JOptionPane::class)
        try {
            every {
                JOptionPane.showConfirmDialog(any(), any(), any(), any(), any())
            } returns JOptionPane.OK_OPTION
            val button = ui.component.descendants()
                .filterIsInstance<JButton>()
                .single { it.text == "Reset all persistent approvals..." }

            SwingUtilities.invokeAndWait { button.doClick() }
            SwingUtilities.invokeAndWait { }

            assertTrue(config.requireHttpRequestApproval)
            assertTrue(config.requireRequestActionApproval)
            assertTrue(config.requireScopeChangeApproval)
            assertTrue(config.requireDataAccessApproval)
            assertTrue(config.getAutoApproveTargetsList().isEmpty())
            assertFalse(config.alwaysAllowHttpHistory)
            assertFalse(config.alwaysAllowSiteMap)
            assertFalse(config.alwaysAllowWebSocketHistory)
            assertFalse(config.alwaysAllowOrganizer)
            assertFalse(config.alwaysAllowScannerIssues)
            assertFalse(config.alwaysAllowCollaboratorInteractions)
            val checkboxes = ui.component.descendants().filterIsInstance<JCheckBox>().associateBy { it.text }
            assertFalse(checkboxes.getValue("Always allow all outbound HTTP requests").isSelected)
            assertTrue(checkboxes.getValue("Require approval for request routing actions").isSelected)
            assertTrue(checkboxes.getValue("Require approval for Target scope changes").isSelected)
            assertTrue(checkboxes.getValue("Require approval for project data access").isSelected)
        } finally {
            unmockkStatic(JOptionPane::class)
            ui.cleanup()
        }
    }

    @Test
    fun `scope approval checkbox tracks Always Allow and can re-enable prompts`() {
        val booleans = mutableMapOf("requireScopeChangeApproval" to true)
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers { booleans[firstArg()] }
        every { storage.setBoolean(any(), any()) } answers { booleans[firstArg()] = secondArg() }
        every { storage.getString(any()) } returns null
        every { storage.getInteger(any()) } returns null
        val config = McpConfig(storage, mockk<Logging>(relaxed = true))
        val ui = ConfigUi(config, emptyList())

        try {
            val checkbox = ui.component.descendants()
                .filterIsInstance<JCheckBox>()
                .single { it.text == "Require approval for Target scope changes" }
            assertTrue(checkbox.isSelected)

            config.requireScopeChangeApproval = false
            SwingUtilities.invokeAndWait { }
            assertFalse(checkbox.isSelected)

            SwingUtilities.invokeAndWait { checkbox.doClick() }
            assertTrue(config.requireScopeChangeApproval)
        } finally {
            ui.cleanup()
        }
    }
}

private fun Container.descendants(): Sequence<java.awt.Component> = sequence {
    components.forEach { component ->
        yield(component)
        if (component is Container) yieldAll(component.descendants())
    }
}
