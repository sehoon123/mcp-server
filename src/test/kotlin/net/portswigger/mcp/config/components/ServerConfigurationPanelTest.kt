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
                Dialogs.showConfirmDialog(any(), match { it.contains("bypasses every MCP approval prompt") }, JOptionPane.YES_NO_OPTION)
            } returns JOptionPane.NO_OPTION

            SwingUtilities.invokeAndWait { yoloButton.doClick() }
            assertFalse(config.approvalYoloMode)

            every {
                Dialogs.showConfirmDialog(any(), match { it.contains("bypasses every MCP approval prompt") }, JOptionPane.YES_NO_OPTION)
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
            every { Dialogs.showConfirmDialog(any(), any(), JOptionPane.YES_NO_OPTION) } returns JOptionPane.YES_OPTION
            SwingUtilities.invokeAndWait { yoloButton.doClick() }

            assertFalse(config.approvalYoloMode)
            assertTrue(yoloButton.text.startsWith("Enable YOLO mode"))
        } finally {
            unmockkObject(Dialogs)
        }
    }

    private fun config(failYoloEnable: Boolean = false): McpConfig {
        val values = mutableMapOf<String, Any>()
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers {
            values[firstArg()] as? Boolean ?: when (firstArg<String>()) {
                "enabled", "requireHttpRequestApproval", "requireRequestActionApproval",
                "requireScopeChangeApproval", "requireDataAccessApproval" -> true
                else -> false
            }
        }
        every { storage.setBoolean(any(), any()) } answers {
            val key = firstArg<String>()
            val value = secondArg<Boolean>()
            if (failYoloEnable && key == "approvalYoloMode" && value) {
                throw IllegalStateException("storage unavailable")
            }
            values[key] = value
        }
        every { storage.getString(any()) } answers { values[firstArg()] as? String ?: "" }
        every { storage.setString(any(), any()) } answers { values[firstArg()] = secondArg<String>() }
        return McpConfig(storage, mockk<Logging>(relaxed = true))
    }

    private fun descendants(root: Container): Sequence<Component> = sequence {
        for (component in root.components) {
            yield(component)
            if (component is Container) yieldAll(descendants(component))
        }
    }
}
