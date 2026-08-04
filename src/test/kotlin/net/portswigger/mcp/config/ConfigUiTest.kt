package net.portswigger.mcp.config

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.persistence.Preferences
import io.mockk.*
import net.portswigger.mcp.ProductIdentity
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.unavailableMcpDiagnosticsSnapshot
import net.portswigger.mcp.config.components.WrappingText
import net.portswigger.mcp.presets.LocalWorkflowPresetListResult
import net.portswigger.mcp.presets.LocalWorkflowPresetMutationResult
import net.portswigger.mcp.presets.LocalWorkflowPresetStatus
import net.portswigger.mcp.presets.WorkflowPreset
import net.portswigger.mcp.presets.WorkflowPresetManagement
import net.portswigger.mcp.providers.ClaudeDesktopProvider
import net.portswigger.mcp.providers.ConnectionDoctor
import net.portswigger.mcp.providers.DoctorExchange
import net.portswigger.mcp.providers.ManualProxyInstallerProvider
import net.portswigger.mcp.providers.ProxyJarManager
import net.portswigger.mcp.security.McpAuditSink
import net.portswigger.mcp.security.NoOpMcpAuditSink
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.awt.Container
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SwingUtilities

class ConfigUiTest {
    @Test
    fun `UI identifies the independent fork and distributor boundary`() {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns null
        every { storage.getString(any()) } returns null
        every { storage.getInteger(any()) } returns null
        val config = McpConfig(
            storage,
            mockk<Logging>(relaxed = true),
            net.portswigger.mcp.testPreferences(),
        )
        val ui = ConfigUi(config, emptyList())

        try {
            val labels = ui.component.descendants().filterIsInstance<JLabel>().map { it.text }.toSet()
            assertTrue(ProductIdentity.PRODUCT_NAME in labels)
            assertTrue(ProductIdentity.UNOFFICIAL_NOTICE in labels)
        } finally {
            ui.cleanup()
        }
    }

    @Test
    fun `MCP tab integrates local preset management without an execution action`() {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns null
        every { storage.getString(any()) } returns null
        every { storage.getInteger(any()) } returns null
        val config = McpConfig(
            storage,
            mockk<Logging>(relaxed = true),
            net.portswigger.mcp.testPreferences(),
        )
        val management = object : WorkflowPresetManagement {
            override fun list() = LocalWorkflowPresetListResult(LocalWorkflowPresetStatus.OK)
            override fun save(preset: WorkflowPreset, overwrite: Boolean) =
                LocalWorkflowPresetMutationResult(LocalWorkflowPresetStatus.OK, preset = preset)
            override fun delete(name: String) =
                LocalWorkflowPresetMutationResult(LocalWorkflowPresetStatus.OK, deleted = false)
        }
        val ui = ConfigUi(
            config = config,
            providers = emptyList(),
            diagnosticsProvider = ::unavailableMcpDiagnosticsSnapshot,
            auditLog = NoOpMcpAuditSink,
            proxyProvenance = null,
            proxyVerified = false,
            clearSessionApprovals = { 0 },
            workflowPresetManager = management,
        )

        try {
            val labels = ui.component.descendants().filterIsInstance<JLabel>().map { it.text }.toSet()
            assertTrue("Workflow Preset Manager" in labels)
            val buttons = ui.component.descendants().filterIsInstance<JButton>().map { it.text }.toSet()
            assertTrue("Refresh presets" in buttons)
            assertTrue("New preset..." in buttons)
            assertTrue(buttons.none { it.contains("execute", ignoreCase = true) })
        } finally {
            ui.cancelBackgroundWork()
            ui.cleanup()
        }
    }

    @Test
    fun `MCP tab exposes exactly five setup clients and keeps proxy extraction separate`() {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns null
        every { storage.getString(any()) } returns null
        every { storage.getInteger(any()) } returns null
        val logging = mockk<Logging>(relaxed = true)
        val config = McpConfig(storage, logging, net.portswigger.mcp.testPreferences())
        val proxyJarManager = ProxyJarManager(logging, proxyDirectory = Path.of("build", "config-ui-test-proxy"))
        val ui = ConfigUi(
            config,
            listOf(
                ClaudeDesktopProvider(logging, proxyJarManager),
                ManualProxyInstallerProvider(logging, proxyJarManager),
            ),
        )
        try {
            val selector = ui.component.descendants().filterIsInstance<JComboBox<*>>()
                .single { it.name == "clientSetupSelector" }
            assertEquals(5, selector.itemCount)
            assertEquals(
                listOf(
                    "Claude Desktop",
                    "Claude Code",
                    "VS Code / GitHub Copilot",
                    "Cursor",
                    "OpenAI Codex",
                ),
                (0 until selector.itemCount).map { selector.getItemAt(it).toString() },
            )
            val buttons = ui.component.descendants().filterIsInstance<JButton>().map { it.text }.toSet()
            assertTrue("Install to Claude Desktop" in buttons)
            assertTrue("Extract proxy jar..." in buttons)
            assertTrue("Run Connection Doctor" in buttons)
        } finally {
            ui.cleanup()
        }
    }

    @Test
    fun `setup preview and Doctor read bearer only for the matching running listener`() {
        val token = "t".repeat(43)
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns null
        every { storage.getString(any()) } returns null
        every { storage.getInteger(any()) } returns null
        val preferences = mockk<Preferences>(relaxed = true)
        every { preferences.getString(any()) } returns token
        val config = McpConfig(storage, mockk<Logging>(relaxed = true), preferences)
        val diagnostics = AtomicReference(unavailableMcpDiagnosticsSnapshot().copy(state = "stopped"))
        val exchanges = AtomicInteger()
        lateinit var ui: ConfigUi
        SwingUtilities.invokeAndWait {
            ui = ConfigUi(
                config = config,
                providers = emptyList(),
                diagnosticsProvider = diagnostics::get,
                auditLog = NoOpMcpAuditSink,
                proxyProvenance = null,
                proxyVerified = false,
                clearSessionApprovals = { 0 },
                connectionDoctor = ConnectionDoctor(DoctorExchange {
                    exchanges.incrementAndGet()
                    400
                }),
            )
        }

        try {
            val buttons = ui.component.descendants().filterIsInstance<JButton>().associateBy { it.name }
            val refresh = buttons.getValue("refreshSetupPreviewButton")
            val copyPreview = buttons.getValue("copySetupPreviewButton")
            val runDoctor = buttons.getValue("runConnectionDoctorButton")
            val hostField = ui.component.descendants().filterIsInstance<JTextField>()
                .single { it.name == "serverHostField" }
            val portField = ui.component.descendants().filterIsInstance<JTextField>()
                .single { it.name == "serverPortField" }
            val preview = ui.component.descendants().filterIsInstance<JTextArea>()
                .single { it.name == "clientSetupPreview" }

            SwingUtilities.invokeAndWait { refresh.doClick() }
            assertTrue(copyPreview.isEnabled)
            verify(exactly = 0) { preferences.getString(any()) }
            val initialPreview = preview.text
            SwingUtilities.invokeAndWait { ui.getConfig() }
            assertTrue(copyPreview.isEnabled)
            assertEquals(initialPreview, preview.text)

            SwingUtilities.invokeAndWait { portField.text = "9877" }
            assertTrue(copyPreview.isEnabled)
            assertEquals("Refresh and copy configuration", copyPreview.text)
            assertTrue(preview.text.contains("preview unavailable"))
            SwingUtilities.invokeAndWait { refresh.doClick() }
            assertTrue(copyPreview.isEnabled)
            assertEquals("Copy configuration", copyPreview.text)
            verify(exactly = 0) { preferences.getString(any()) }

            SwingUtilities.invokeAndWait { runDoctor.doClick() }
            awaitButtonEnabled(runDoctor)
            verify(exactly = 0) { preferences.getString(any()) }
            assertEquals(0, exchanges.get())

            diagnostics.set(
                unavailableMcpDiagnosticsSnapshot().copy(
                    state = "running",
                    endpoint = "http://127.0.0.1:9876/mcp",
                ),
            )
            SwingUtilities.invokeAndWait { runDoctor.doClick() }
            awaitButtonEnabled(runDoctor)
            verify(exactly = 0) { preferences.getString(any()) }
            assertEquals(0, exchanges.get())

            diagnostics.set(
                unavailableMcpDiagnosticsSnapshot().copy(
                    state = "running",
                    endpoint = "http://127.0.0.1:9877/mcp",
                ),
            )
            SwingUtilities.invokeAndWait { runDoctor.doClick() }
            awaitButtonEnabled(runDoctor)
            verify(exactly = 1) { preferences.getString(any()) }
            assertEquals(1, exchanges.get())

            SwingUtilities.invokeAndWait { hostField.text = "::1" }
            diagnostics.set(
                unavailableMcpDiagnosticsSnapshot().copy(
                    state = "running",
                    endpoint = "http://[::1]:9877/mcp",
                ),
            )
            SwingUtilities.invokeAndWait { runDoctor.doClick() }
            awaitButtonEnabled(runDoctor)
            verify(exactly = 2) { preferences.getString(any()) }
            assertEquals(2, exchanges.get())

            diagnostics.set(
                unavailableMcpDiagnosticsSnapshot().copy(
                    state = "running",
                    endpoint = "http://::1:9877/mcp",
                ),
            )
            SwingUtilities.invokeAndWait { runDoctor.doClick() }
            awaitButtonEnabled(runDoctor)
            verify(exactly = 2) { preferences.getString(any()) }
            assertEquals(2, exchanges.get())

            ui.cancelBackgroundWork()
            ui.cancelBackgroundWork()
            SwingUtilities.invokeAndWait { runDoctor.doClick() }
            verify(exactly = 2) { preferences.getString(any()) }
            assertEquals(2, exchanges.get())
        } finally {
            ui.cancelBackgroundWork()
            ui.cancelBackgroundWork()
            ui.cleanup()
            ui.cleanup()
        }
    }

    @Test
    fun `Doctor evidence survives a duplicate listener state and is invalidated by a transition`() {
        val token = "l".repeat(43)
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns null
        every { storage.getString(any()) } returns null
        every { storage.getInteger(any()) } returns null
        val preferences = mockk<Preferences>(relaxed = true)
        every { preferences.getString(any()) } returns token
        val config = McpConfig(storage, mockk<Logging>(relaxed = true), preferences)
        val diagnostics = unavailableMcpDiagnosticsSnapshot().copy(
            state = "running",
            endpoint = "http://127.0.0.1:9876/mcp",
        )
        val exchanges = AtomicInteger()
        lateinit var ui: ConfigUi
        SwingUtilities.invokeAndWait {
            ui = ConfigUi(
                config = config,
                providers = emptyList(),
                diagnosticsProvider = { diagnostics },
                auditLog = NoOpMcpAuditSink,
                proxyProvenance = null,
                proxyVerified = false,
                clearSessionApprovals = { 0 },
                connectionDoctor = ConnectionDoctor(DoctorExchange {
                    exchanges.incrementAndGet()
                    400
                }),
            )
        }

        try {
            val runDoctor = ui.component.descendants().filterIsInstance<JButton>()
                .single { it.name == "runConnectionDoctorButton" }
            val copyEvidence = ui.component.descendants().filterIsInstance<JButton>()
                .single { it.name == "copyDoctorEvidenceButton" }
            val result = ui.component.descendants().filterIsInstance<WrappingText>()
                .single { it.name == "doctorResultText" }

            SwingUtilities.invokeAndWait { runDoctor.doClick() }
            awaitButtonEnabled(runDoctor)
            assertTrue(awaitOnEdtCondition { copyEvidence.isEnabled && result.text.contains("admitted") })
            assertEquals(1, exchanges.get())

            ui.updateServerState(ServerState.Running)
            SwingUtilities.invokeAndWait { Unit }
            assertTrue(awaitOnEdtCondition { copyEvidence.isEnabled && result.text.contains("admitted") })
            assertEquals(1, exchanges.get())

            ui.updateServerState(ServerState.Stopped)
            assertTrue(awaitOnEdtCondition {
                !copyEvidence.isEnabled && result.text.contains("local listener state changed")
            })
            SwingUtilities.invokeAndWait {
                assertTrue(result.text.contains("does not prove that an external client works"))
            }
            assertEquals(1, exchanges.get())
        } finally {
            ui.cleanup()
        }
    }

    @Test
    fun `credential rotation attempt invalidates Doctor evidence even when persistence is uncertain`() {
        val token = "r".repeat(43)
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns null
        every { storage.getString(any()) } returns null
        every { storage.getInteger(any()) } returns null
        val preferences = mockk<Preferences>(relaxed = true)
        every { preferences.getString(any()) } returns token
        val config = McpConfig(storage, mockk<Logging>(relaxed = true), preferences)
        val diagnostics = unavailableMcpDiagnosticsSnapshot().copy(
            state = "running",
            endpoint = "http://127.0.0.1:9876/mcp",
        )
        val exchanges = AtomicInteger()
        lateinit var ui: ConfigUi
        SwingUtilities.invokeAndWait {
            ui = ConfigUi(
                config = config,
                providers = emptyList(),
                diagnosticsProvider = { diagnostics },
                auditLog = NoOpMcpAuditSink,
                proxyProvenance = null,
                proxyVerified = false,
                clearSessionApprovals = { 0 },
                connectionDoctor = ConnectionDoctor(DoctorExchange {
                    exchanges.incrementAndGet()
                    400
                }),
            )
        }

        mockkObject(Dialogs)
        try {
            val confirmation = AtomicInteger(JOptionPane.CANCEL_OPTION)
            every {
                Dialogs.showConfirmDialog(
                    any(), any(), JOptionPane.OK_CANCEL_OPTION, "Rotate local bearer token"
                )
            } answers { confirmation.get() }
            val buttons = ui.component.descendants().filterIsInstance<JButton>().toList()
            val runDoctor = buttons.single { it.name == "runConnectionDoctorButton" }
            val copyEvidence = buttons.single { it.name == "copyDoctorEvidenceButton" }
            val rotateToken = buttons.single { it.name == "rotateLocalBearerTokenButton" }
            val result = ui.component.descendants().filterIsInstance<WrappingText>()
                .single { it.name == "doctorResultText" }

            SwingUtilities.invokeAndWait { runDoctor.doClick() }
            awaitButtonEnabled(runDoctor)
            assertTrue(awaitOnEdtCondition { copyEvidence.isEnabled && result.text.contains("admitted") })

            SwingUtilities.invokeAndWait {
                rotateToken.doClick()
                assertTrue(copyEvidence.isEnabled)
                assertTrue(result.text.contains("admitted"))
                confirmation.set(JOptionPane.OK_OPTION)
                rotateToken.doClick()
                assertFalse(copyEvidence.isEnabled)
                assertTrue(result.text.contains("credential rotation was attempted"))
                assertTrue(result.text.contains("does not prove that an external client works"))
                assertFalse(result.text.contains(token))
            }
            assertEquals(1, exchanges.get())
        } finally {
            unmockkObject(Dialogs)
            ui.cleanup()
        }
    }

    @Test
    fun `queued listener failure is discarded when cleanup wins before EDT publication`() {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns null
        every { storage.getString(any()) } returns null
        every { storage.getInteger(any()) } returns null
        val config = McpConfig(
            storage,
            mockk<Logging>(relaxed = true),
            net.portswigger.mcp.testPreferences(),
        )
        lateinit var ui: ConfigUi
        SwingUtilities.invokeAndWait { ui = ConfigUi(config, emptyList()) }

        mockkObject(Dialogs)
        try {
            every { Dialogs.showMessageDialog(any(), any(), any()) } returns Unit
            ui.cancelBackgroundWork()
            val edtBlocked = CountDownLatch(1)
            val allowCleanup = CountDownLatch(1)
            SwingUtilities.invokeLater {
                edtBlocked.countDown()
                if (allowCleanup.await(5, TimeUnit.SECONDS)) ui.cleanup()
            }
            assertTrue(edtBlocked.await(5, TimeUnit.SECONDS))

            ui.updateServerState(ServerState.Failed(IllegalStateException("late listener failure")))
            allowCleanup.countDown()
            SwingUtilities.invokeAndWait { Unit }

            verify(exactly = 0) { Dialogs.showMessageDialog(any(), any(), any()) }
        } finally {
            unmockkObject(Dialogs)
            ui.cleanup()
        }
    }

    @Test
    fun `listener transition published after cleanup does not re-enable detached endpoint fields`() {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns null
        every { storage.getString(any()) } returns null
        every { storage.getInteger(any()) } returns null
        val config = McpConfig(
            storage,
            mockk<Logging>(relaxed = true),
            net.portswigger.mcp.testPreferences(),
        )
        lateinit var ui: ConfigUi
        SwingUtilities.invokeAndWait {
            ui = ConfigUi(config, emptyList())
            ui.updateServerState(ServerState.Running)
        }
        SwingUtilities.invokeAndWait { Unit }
        val hostField = ui.component.descendants().filterIsInstance<JTextField>()
            .single { it.name == "serverHostField" }
        val portField = ui.component.descendants().filterIsInstance<JTextField>()
            .single { it.name == "serverPortField" }

        try {
            assertFalse(hostField.isEnabled)
            assertFalse(portField.isEnabled)
            ui.cancelBackgroundWork()
            ui.cleanup()

            SwingUtilities.invokeAndWait { ui.updateServerState(ServerState.Stopped) }

            assertFalse(hostField.isEnabled)
            assertFalse(portField.isEnabled)
        } finally {
            ui.cleanup()
        }
    }

    @Test
    fun `cleanup from a non EDT thread is synchronous and idempotent`() {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns null
        every { storage.getString(any()) } returns null
        every { storage.getInteger(any()) } returns null
        val config = McpConfig(
            storage,
            mockk<Logging>(relaxed = true),
            net.portswigger.mcp.testPreferences(),
        )
        lateinit var ui: ConfigUi
        SwingUtilities.invokeAndWait { ui = ConfigUi(config, emptyList()) }
        val failure = AtomicReference<Throwable?>()

        val worker = Thread {
            try {
                ui.cleanup()
                ui.cleanup()
            } catch (error: Throwable) {
                failure.set(error)
            }
        }
        worker.start()
        worker.join(5_000)

        assertFalse(worker.isAlive)
        assertEquals(null, failure.get())
        SwingUtilities.invokeAndWait { Unit }
    }

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
    fun `confirmed allow all HTTP requests checkbox inversely controls the secure approval policy`() {
        val booleans = mutableMapOf("requireHttpRequestApproval" to true)
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers { booleans[firstArg()] }
        every { storage.setBoolean(any(), any()) } answers { booleans[firstArg()] = secondArg() }
        every { storage.getString(any()) } returns null
        every { storage.getInteger(any()) } returns null
        val config = McpConfig(
            storage,
            mockk<Logging>(relaxed = true),
            net.portswigger.mcp.testPreferences(),
        )
        val ui = ConfigUi(config, emptyList())

        mockkObject(Dialogs)
        try {
            every {
                Dialogs.showConfirmDialog(any(), any(), JOptionPane.YES_NO_OPTION, any())
            } returns JOptionPane.YES_OPTION
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
            verify(exactly = 1) {
                Dialogs.showConfirmDialog(any(), any(), JOptionPane.YES_NO_OPTION, any())
            }
        } finally {
            unmockkObject(Dialogs)
            ui.cleanup()
        }
    }

    @Test
    fun `MCP tab exposes bounded session and persistent approval reset controls`() {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns null
        every { storage.getString(any()) } returns null
        every { storage.getInteger(any()) } returns null
        val config = McpConfig(
            storage,
            mockk<Logging>(relaxed = true),
            net.portswigger.mcp.testPreferences(),
        )
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
    fun `sensitive Advanced and Diagnostics actions expose focus and consequence descriptions`() {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns null
        every { storage.getString(any()) } returns null
        every { storage.getInteger(any()) } returns null
        val config = McpConfig(
            storage,
            mockk<Logging>(relaxed = true),
            net.portswigger.mcp.testPreferences(),
        )
        val ui = ConfigUi(config, emptyList())

        try {
            val buttons = ui.component.descendants().filterIsInstance<JButton>().associateBy { it.text }
            listOf(
                "Copy local bearer token",
                "Rotate local bearer token...",
                "Reset active session approvals",
                "Reset all persistent approvals...",
                "Refresh",
                "Copy redacted diagnostics",
                "Copy recent redacted audit",
                "Clear audit...",
            ).forEach { label ->
                val button = buttons.getValue(label)
                assertTrue(button.isFocusPainted, "$label must retain visible keyboard focus")
                assertTrue(
                    !button.accessibleContext.accessibleDescription.isNullOrBlank(),
                    "$label must describe its consequence",
                )
            }
        } finally {
            ui.cleanup()
        }
    }

    @Test
    fun `clear audit requires explicit confirmation`() {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns null
        every { storage.getString(any()) } returns null
        every { storage.getInteger(any()) } returns null
        val config = McpConfig(
            storage,
            mockk<Logging>(relaxed = true),
            net.portswigger.mcp.testPreferences(),
        )
        val auditLog = mockk<McpAuditSink>(relaxed = true)
        val ui = ConfigUi(
            config = config,
            providers = emptyList(),
            diagnosticsProvider = ::unavailableMcpDiagnosticsSnapshot,
            auditLog = auditLog,
            proxyProvenance = null,
            proxyVerified = false,
            clearSessionApprovals = { 0 },
        )
        var choice = JOptionPane.CANCEL_OPTION

        mockkObject(Dialogs)
        try {
            every {
                Dialogs.showConfirmDialog(
                    any(),
                    match { it.contains("cannot be undone") },
                    JOptionPane.OK_CANCEL_OPTION,
                    "Clear MCP audit",
                )
            } answers { choice }
            val button = ui.component.descendants()
                .filterIsInstance<JButton>()
                .single { it.text == "Clear audit..." }

            SwingUtilities.invokeAndWait { button.doClick() }
            verify(exactly = 0) { auditLog.clear() }

            choice = JOptionPane.OK_OPTION
            SwingUtilities.invokeAndWait { button.doClick() }
            verify(exactly = 1) { auditLog.clear() }
        } finally {
            unmockkObject(Dialogs)
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
        val config = McpConfig(
            storage,
            mockk<Logging>(relaxed = true),
            net.portswigger.mcp.testPreferences(),
        )
        val ui = ConfigUi(config, emptyList())
        mockkObject(Dialogs)
        try {
            every {
                Dialogs.showConfirmDialog(
                    any(), any(), JOptionPane.OK_CANCEL_OPTION, "Reset persistent MCP approvals"
                )
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
            assertTrue(checkboxes.getValue("Require approval for request routing and derived-request actions").isSelected)
            assertTrue(checkboxes.getValue("Require approval for Target scope changes").isSelected)
            assertTrue(checkboxes.getValue("Require approval for project data access").isSelected)
        } finally {
            unmockkObject(Dialogs)
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
        val config = McpConfig(
            storage,
            mockk<Logging>(relaxed = true),
            net.portswigger.mcp.testPreferences(),
        )
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

private fun awaitButtonEnabled(button: JButton) {
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
    while (System.nanoTime() < deadline) {
        val enabled = AtomicReference(false)
        SwingUtilities.invokeAndWait { enabled.set(button.isEnabled) }
        if (enabled.get()) return
        Thread.sleep(10)
    }
    assertTrue(button.isEnabled, "button did not become enabled before the deadline")
}

private fun awaitOnEdtCondition(
    timeoutSeconds: Long = 5,
    condition: () -> Boolean,
): Boolean {
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds)
    while (System.nanoTime() < deadline) {
        val result = AtomicReference(false)
        SwingUtilities.invokeAndWait { result.set(condition()) }
        if (result.get()) return true
        Thread.sleep(10)
    }
    return false
}

private fun Container.descendants(): Sequence<java.awt.Component> = sequence {
    components.forEach { component ->
        yield(component)
        if (component is Container) yieldAll(component.descendants())
    }
}
