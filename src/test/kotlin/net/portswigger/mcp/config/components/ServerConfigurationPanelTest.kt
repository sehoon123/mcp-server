package net.portswigger.mcp.config.components

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkObject
import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.Test
import java.awt.Component
import java.awt.Container
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JOptionPane
import javax.swing.SwingUtilities
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ServerConfigurationPanelTest {
    @Test
    fun `YOLO button enables one global bypass and disabling restores saved policies`() {
        val config = config()
        lateinit var panel: ServerConfigurationPanel
        SwingUtilities.invokeAndWait {
            panel = ServerConfigurationPanel(
                config = config,
                enabledToggle = Design.createToggleSwitch(true) {},
                validationErrorLabel = WarningLabel(),
            )
        }
        val yoloButton = descendants(panel)
            .filterIsInstance<JButton>()
            .single { it.text.startsWith("Enable YOLO mode") }

        mockkObject(Dialogs)
        try {
            every {
                Dialogs.showConfirmDialog(
                    any(),
                    match { it.contains("bypasses every MCP approval prompt") },
                    JOptionPane.YES_NO_OPTION,
                    "Enable YOLO mode",
                )
            } returns JOptionPane.NO_OPTION

            SwingUtilities.invokeAndWait { yoloButton.doClick() }
            assertFalse(config.approvalYoloMode)

            every {
                Dialogs.showConfirmDialog(
                    any(),
                    match { it.contains("bypasses every MCP approval prompt") },
                    JOptionPane.YES_NO_OPTION,
                    "Enable YOLO mode",
                )
            } returns JOptionPane.YES_OPTION
            SwingUtilities.invokeAndWait { yoloButton.doClick() }

            assertTrue(config.approvalYoloMode)
            assertTrue(yoloButton.text == "Disable YOLO mode")
            val granularApproval = descendants(panel)
                .filterIsInstance<JCheckBox>()
                .single { it.text == "Require approval for request routing and derived-request actions" }
            assertFalse(granularApproval.isEnabled)
            assertTrue(config.requireRequestActionApproval)

            SwingUtilities.invokeAndWait { yoloButton.doClick() }

            assertFalse(config.approvalYoloMode)
            assertTrue(yoloButton.text.startsWith("Enable YOLO mode"))
            assertTrue(granularApproval.isEnabled)
            assertTrue(config.requireRequestActionApproval)
        } finally {
            unmockkObject(Dialogs)
        }
    }

    @Test
    fun `high consequence trust toggles require confirmation only in the unsafe direction`() {
        val config = config()
        lateinit var panel: ServerConfigurationPanel
        SwingUtilities.invokeAndWait {
            panel = ServerConfigurationPanel(
                config = config,
                enabledToggle = Design.createToggleSwitch(true) {},
                validationErrorLabel = WarningLabel(),
            )
        }
        val checkBoxes = descendants(panel).filterIsInstance<JCheckBox>().associateBy { it.text }
        var choice = JOptionPane.NO_OPTION

        mockkObject(Dialogs)
        try {
            every {
                Dialogs.showConfirmDialog(any(), any(), JOptionPane.YES_NO_OPTION, any())
            } answers { choice }

            fun exercise(label: String, isUnsafe: () -> Boolean) {
                val checkBox = checkBoxes.getValue(label)
                SwingUtilities.invokeAndWait { checkBox.doClick() }
                assertFalse(isUnsafe(), "$label must stay safe when confirmation is denied")

                choice = JOptionPane.YES_OPTION
                SwingUtilities.invokeAndWait { checkBox.doClick() }
                assertTrue(isUnsafe(), "$label must persist after confirmation")

                choice = JOptionPane.NO_OPTION
                SwingUtilities.invokeAndWait { checkBox.doClick() }
                assertFalse(isUnsafe(), "$label must return to safety without confirmation")
            }

            exercise("Enable tools that can edit your config") { config.configEditingTooling }
            exercise("Always allow all outbound HTTP requests") { !config.requireHttpRequestApproval }
            exercise("Require approval for request routing and derived-request actions") {
                !config.requireRequestActionApproval
            }
            exercise("Require approval for Target scope changes") { !config.requireScopeChangeApproval }
            exercise("Require approval for project data access") { !config.requireDataAccessApproval }
            exercise("Always allow HTTP history access") { config.alwaysAllowHttpHistory }
            exercise("Always allow Site Map access") { config.alwaysAllowSiteMap }
            exercise("Always allow WebSocket history access") { config.alwaysAllowWebSocketHistory }
            exercise("Always allow Organizer access") { config.alwaysAllowOrganizer }
            exercise("Always allow Scanner issue access") { config.alwaysAllowScannerIssues }
            exercise("Always allow Collaborator interaction access") {
                config.alwaysAllowCollaboratorInteractions
            }
            exercise("Filter config credentials") { !config.filterConfigCredentials }

            config.requireHttpRequestApproval = false
            panel.updatePersistentApprovalControls()
            SwingUtilities.invokeAndWait { }
            assertTrue(checkBoxes.getValue("Always allow all outbound HTTP requests").isSelected)

            io.mockk.verify(exactly = 24) {
                Dialogs.showConfirmDialog(any(), any(), JOptionPane.YES_NO_OPTION, any())
            }
        } finally {
            unmockkObject(Dialogs)
        }
    }

    @Test
    fun `trust toggle confirmation failure keeps the persisted and visible state safe`() {
        val config = config()
        lateinit var panel: ServerConfigurationPanel
        SwingUtilities.invokeAndWait {
            panel = ServerConfigurationPanel(
                config = config,
                enabledToggle = Design.createToggleSwitch(true) {},
                validationErrorLabel = WarningLabel(),
            )
        }
        val checkBox = descendants(panel)
            .filterIsInstance<JCheckBox>()
            .single { it.text == "Enable tools that can edit your config" }

        mockkObject(Dialogs)
        try {
            every {
                Dialogs.showConfirmDialog(any(), any(), JOptionPane.YES_NO_OPTION, any())
            } throws IllegalStateException("dialog unavailable")

            SwingUtilities.invokeAndWait { checkBox.doClick() }

            assertFalse(checkBox.isSelected)
            assertFalse(config.configEditingTooling)
        } finally {
            unmockkObject(Dialogs)
        }
    }

    @Test
    fun `trust toggle persistence failure restores the effective unsafe state`() {
        val config = config(
            booleanOverrides = mapOf("filterConfigCredentials" to false),
            failingBooleanKey = "filterConfigCredentials",
        )
        lateinit var panel: ServerConfigurationPanel
        SwingUtilities.invokeAndWait {
            panel = ServerConfigurationPanel(
                config = config,
                enabledToggle = Design.createToggleSwitch(true) {},
                validationErrorLabel = WarningLabel(),
            )
        }
        val checkBox = descendants(panel)
            .filterIsInstance<JCheckBox>()
            .single { it.text == "Filter config credentials" }

        mockkObject(Dialogs)
        try {
            every {
                Dialogs.showConfirmDialog(any(), any(), JOptionPane.YES_NO_OPTION, any())
            } returns JOptionPane.YES_OPTION

            SwingUtilities.invokeAndWait { checkBox.doClick() }

            assertFalse(checkBox.isSelected)
            assertFalse(config.filterConfigCredentials)
        } finally {
            unmockkObject(Dialogs)
        }
    }

    @Test
    fun `failed safe approval writes restore the effective persisted selection`() {
        fun exercise(
            label: String,
            key: String,
            initialValue: Boolean,
            expectedSelectionAfterClick: Boolean,
        ) {
            val config = config(
                booleanOverrides = mapOf(key to initialValue),
                failingBooleanKey = key,
            )
            lateinit var panel: ServerConfigurationPanel
            SwingUtilities.invokeAndWait {
                panel = ServerConfigurationPanel(
                    config = config,
                    enabledToggle = Design.createToggleSwitch(true) {},
                    validationErrorLabel = WarningLabel(),
                )
            }
            val checkBox = descendants(panel)
                .filterIsInstance<JCheckBox>()
                .single { it.text == label }

            SwingUtilities.invokeAndWait { checkBox.doClick() }

            assertTrue(checkBox.isSelected == expectedSelectionAfterClick, label)
        }

        exercise(
            label = "Require approval for request routing and derived-request actions",
            key = "requireRequestActionApproval",
            initialValue = false,
            expectedSelectionAfterClick = false,
        )
        exercise(
            label = "Always allow HTTP history access",
            key = "_alwaysAllowHttpHistory",
            initialValue = true,
            expectedSelectionAfterClick = true,
        )
    }

    @Test
    fun `programmatic approval refresh preserves dormant per-source policies`() {
        val config = config().apply {
            alwaysAllowHttpHistory = true
            alwaysAllowSiteMap = true
            alwaysAllowWebSocketHistory = true
            alwaysAllowOrganizer = true
            alwaysAllowScannerIssues = true
            alwaysAllowCollaboratorInteractions = true
        }
        lateinit var panel: ServerConfigurationPanel
        SwingUtilities.invokeAndWait {
            panel = ServerConfigurationPanel(
                config = config,
                enabledToggle = Design.createToggleSwitch(true) {},
                validationErrorLabel = WarningLabel(),
            )
        }

        config.requireDataAccessApproval = false
        panel.updatePersistentApprovalControls()
        SwingUtilities.invokeAndWait { }
        assertDormantPerSourcePoliciesPreserved(config)

        config.requireDataAccessApproval = true
        panel.updateDataAccessCheckboxes()
        SwingUtilities.invokeAndWait { }
        assertDormantPerSourcePoliciesPreserved(config)
    }

    @Test
    fun `persisted active YOLO mode is visible when the panel is constructed`() {
        val config = config().apply { approvalYoloMode = true }
        lateinit var panel: ServerConfigurationPanel

        SwingUtilities.invokeAndWait {
            panel = ServerConfigurationPanel(
                config = config,
                enabledToggle = Design.createToggleSwitch(true) {},
                validationErrorLabel = WarningLabel(),
            )
        }

        val yoloButton = descendants(panel)
            .filterIsInstance<JButton>()
            .single { it.text == "Disable YOLO mode" }
        assertTrue(yoloButton.isEnabled)
        val granularApproval = descendants(panel)
            .filterIsInstance<JCheckBox>()
            .single { it.text == "Require approval for request routing and derived-request actions" }
        assertFalse(granularApproval.isEnabled)
    }

    @Test
    fun `failed persistence cannot visually or operationally enable YOLO mode`() {
        val config = config(failYoloEnable = true)
        lateinit var panel: ServerConfigurationPanel
        SwingUtilities.invokeAndWait {
            panel = ServerConfigurationPanel(
                config = config,
                enabledToggle = Design.createToggleSwitch(true) {},
                validationErrorLabel = WarningLabel(),
            )
        }
        val yoloButton = descendants(panel)
            .filterIsInstance<JButton>()
            .single { it.text.startsWith("Enable YOLO mode") }

        mockkObject(Dialogs)
        try {
            every {
                Dialogs.showConfirmDialog(any(), any(), JOptionPane.YES_NO_OPTION, "Enable YOLO mode")
            } returns JOptionPane.YES_OPTION
            SwingUtilities.invokeAndWait { yoloButton.doClick() }

            assertFalse(config.approvalYoloMode)
            assertTrue(yoloButton.text.startsWith("Enable YOLO mode"))
        } finally {
            unmockkObject(Dialogs)
        }
    }

    private fun assertDormantPerSourcePoliciesPreserved(config: McpConfig) {
        assertTrue(config.alwaysAllowHttpHistory)
        assertTrue(config.alwaysAllowSiteMap)
        assertTrue(config.alwaysAllowWebSocketHistory)
        assertTrue(config.alwaysAllowOrganizer)
        assertTrue(config.alwaysAllowScannerIssues)
        assertTrue(config.alwaysAllowCollaboratorInteractions)
    }

    private fun config(
        failYoloEnable: Boolean = false,
        booleanOverrides: Map<String, Boolean> = emptyMap(),
        failingBooleanKey: String? = null,
    ): McpConfig {
        val values = mutableMapOf<String, Any>().apply { putAll(booleanOverrides) }
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers {
            values[firstArg()] as? Boolean ?: when (firstArg<String>()) {
                "enabled", "requireHttpRequestApproval", "requireRequestActionApproval",
                "requireScopeChangeApproval", "requireDataAccessApproval", "filterConfigCredentials" -> true
                else -> false
            }
        }
        every { storage.setBoolean(any(), any()) } answers {
            val key = firstArg<String>()
            val value = secondArg<Boolean>()
            if ((failYoloEnable && key == "approvalYoloMode" && value) || key == failingBooleanKey) {
                throw IllegalStateException("storage unavailable")
            }
            values[key] = value
        }
        every { storage.getString(any()) } answers { values[firstArg()] as? String ?: "" }
        every { storage.setString(any(), any()) } answers { values[firstArg()] = secondArg<String>() }
        return McpConfig(storage, mockk<Logging>(relaxed = true), net.portswigger.mcp.testPreferences())
    }

    private fun descendants(root: Container): Sequence<Component> = sequence {
        for (component in root.components) {
            yield(component)
            if (component is Container) yieldAll(descendants(component))
        }
    }
}
