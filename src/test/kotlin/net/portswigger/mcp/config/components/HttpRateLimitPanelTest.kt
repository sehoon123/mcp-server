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

    @Test
    fun `statistics refresh on EDT without replacing form errors and stop after cleanup`() = onEdt {
        var reads = 0
        var unavailable = false
        val snapshot = net.portswigger.mcp.HttpRateLimitSnapshot(true, 10, false, 42, 9, 3, 20, 12.25, 35.5, 2)
        val panel = HttpRateLimitPanel(config()) {
            assertTrue(SwingUtilities.isEventDispatchThread())
            reads++
            if (unavailable) throw IllegalStateException("PRIVATE_SENTINEL")
            snapshot
        }
        try {
            val stats = panel.descendants().filterIsInstance<WrappingText>().single { it.name == "httpRateLimitStatistics" }
            assertTrue(stats.text.contains("Last full second: 9"))
            assertTrue(stats.text.contains("waiting: 3"))
            assertTrue(stats.text.contains("12.3/35.5 ms"))
            val rate = panel.descendants().filterIsInstance<JTextField>().single()
            rate.text = "invalid"
            panel.descendants().filterIsInstance<JButton>().single().doClick(0)
            val status = panel.descendants().filterIsInstance<WrappingText>().single { it.name == "httpRateLimitStatus" }
            panel.refreshStatistics()
            assertTrue(status.text.contains("unchanged"))
            assertEquals("invalid", rate.text)
            unavailable = true
            panel.refreshStatistics()
            assertEquals("HTTP rate statistics unavailable.", stats.text)
            panel.cleanup()
            val before = reads
            panel.refreshStatistics()
            assertEquals(before, reads)
            panel.cleanup()
        } finally {
            panel.cleanup()
        }
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
