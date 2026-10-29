package net.portswigger.mcp.config.components

import burp.api.montoya.persistence.Preferences
import io.mockk.every
import io.mockk.mockk
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.testPreferences
import org.junit.jupiter.api.Test
import java.awt.Component
import java.awt.Container
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JTextField
import javax.swing.SwingUtilities
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HttpRateLimitPanelTest {
    @Test
    fun `operator can enable apply a live rate and disable even with an invalid draft rate`() = onEdt {
        val config = config()
        val panel = HttpRateLimitPanel(config)
        val enabled = panel.descendants().filterIsInstance<JCheckBox>().single()
        val rate = panel.descendants().filterIsInstance<JTextField>().single()
        val apply = panel.descendants().filterIsInstance<JButton>().single()
        val status = panel.descendants().filterIsInstance<WrappingText>().single { it.name == "httpRateLimitStatus" }
        assertFalse(enabled.isSelected)
        assertTrue(status.text.startsWith("OFF:"))
        rate.text = "25"
        enabled.doClick(0)
        assertTrue(enabled.isSelected)
        assertTrue(config.httpRateLimitEnabled)
        assertEquals(25, config.httpRequestsPerSecond)
        assertTrue(status.text.startsWith("ON: 25"))
        rate.text = "5"
        apply.doClick(0)
        assertEquals(5, config.httpRequestsPerSecond)
        assertTrue(config.httpRateLimitEnabled)
        rate.text = "invalid"
        enabled.doClick(0)
        assertFalse(enabled.isSelected)
        assertFalse(config.httpRateLimitEnabled)
        assertTrue(status.text.startsWith("OFF:"))
    }

    @Test
    fun `invalid input never enables or changes a limit and storage failure restores visible state`() = onEdt {
        val preferences = testPreferences()
        val config = config(preferences)
        val panel = HttpRateLimitPanel(config)
        val enabled = panel.descendants().filterIsInstance<JCheckBox>().single()
        val rate = panel.descendants().filterIsInstance<JTextField>().single()
        val status = panel.descendants().filterIsInstance<WrappingText>().single { it.name == "httpRateLimitStatus" }
        for (invalid in listOf("", "0", "-1", "1.5", "10001", "2147483648", "NaN")) {
            rate.text = invalid
            enabled.doClick(0)
            assertFalse(config.httpRateLimitEnabled)
            assertFalse(enabled.isSelected)
            assertEquals(10, config.httpRequestsPerSecond)
            assertTrue(status.text.contains("unchanged"))
        }
        rate.text = "10"
        every { preferences.setBoolean(any(), any()) } throws IllegalStateException("unavailable")
        enabled.doClick(0)
        assertFalse(enabled.isSelected)
        assertFalse(config.httpRateLimitEnabled)
        assertTrue(status.text.contains("Could not save"))
        assertTrue(status.text.endsWith("OFF."))
    }

    @Test
    fun `failed disabling or rate write reports the still active effective limit`() = onEdt {
        val preferences = testPreferences()
        val config = config(preferences).apply { httpRateLimitEnabled = true }
        val panel = HttpRateLimitPanel(config)
        val enabled = panel.descendants().filterIsInstance<JCheckBox>().single()
        val rate = panel.descendants().filterIsInstance<JTextField>().single()
        val apply = panel.descendants().filterIsInstance<JButton>().single()
        val status = panel.descendants().filterIsInstance<WrappingText>().single { it.name == "httpRateLimitStatus" }
        every { preferences.setBoolean(any(), any()) } throws IllegalStateException("unavailable")
        enabled.doClick(0)
        assertTrue(enabled.isSelected)
        assertTrue(config.httpRateLimitEnabled)
        every { preferences.setInteger(any(), any()) } throws IllegalStateException("unavailable")
        rate.text = "100"
        apply.doClick(0)
        assertEquals(10, config.httpRequestsPerSecond)
        assertTrue(status.text.contains("ON at 10"))
    }

    @Test
    fun `commit then throw warns about reload while showing unchanged runtime state`() = onEdt {
        val preferences = testPreferences()
        val config = config(preferences)
        val panel = HttpRateLimitPanel(config)
        val enabled = panel.descendants().filterIsInstance<JCheckBox>().single()
        val status = panel.descendants().filterIsInstance<WrappingText>().single { it.name == "httpRateLimitStatus" }
        every { preferences.setBoolean(any(), true) } answers {
            every { preferences.getBoolean(firstArg()) } returns true
            throw IllegalStateException("write completion uncertain")
        }
        enabled.doClick(0)
        assertFalse(enabled.isSelected)
        assertFalse(config.httpRateLimitEnabled)
        assertTrue(config(preferences).httpRateLimitEnabled)
        assertTrue(status.text.contains("check the setting after reload"))
        assertTrue(status.text.endsWith("OFF."))
    }

    private fun config(preferences: Preferences = testPreferences()) =
        McpConfig(mockk(relaxed = true), mockk(relaxed = true), preferences)

    private fun onEdt(block: () -> Unit) = SwingUtilities.invokeAndWait(block)

    private fun Container.descendants(): Sequence<Component> = sequence {
        for (child in components) {
            yield(child)
            if (child is Container) yieldAll(child.descendants())
        }
    }
}
