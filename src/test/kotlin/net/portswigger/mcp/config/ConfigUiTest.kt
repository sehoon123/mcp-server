package net.portswigger.mcp.config

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.awt.Container
import javax.swing.JCheckBox
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
