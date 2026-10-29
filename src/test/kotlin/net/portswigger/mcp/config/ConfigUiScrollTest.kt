package net.portswigger.mcp.config

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import net.portswigger.mcp.config.components.WrappingText
import net.portswigger.mcp.testPreferences
import org.junit.jupiter.api.Test
import java.awt.Component
import java.awt.Container
import java.awt.Point
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.SwingUtilities
import javax.swing.text.DefaultCaret
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ConfigUiScrollTest {
    @Test
    fun `tab opens at top on every showing transition without resetting ordinary scrolling`() {
        lateinit var ui: ConfigUi
        lateinit var tabs: JTabbedPane
        lateinit var scroll: JScrollPane
        SwingUtilities.invokeAndWait {
            ui = ui()
            tabs = JTabbedPane().apply {
                addTab("Other", JPanel())
                addTab("MCP Bridge", ui.component)
                setSize(1400, 800)
                addNotify()
            }
            layoutTree(tabs)
            scroll = ui.component.descendants().filterIsInstance<JScrollPane>()
                .single { it.name == "mcpSettingsScroll" }
        }
        try {
            repeat(2) {
                SwingUtilities.invokeAndWait {
                    scroll.viewport.viewPosition = Point(0, 300)
                    assertTrue(scroll.viewport.viewPosition.y > 0)
                    tabs.selectedIndex = 1
                    assertTrue(ui.component.isShowing)
                    layoutTree(tabs)
                }
                SwingUtilities.invokeAndWait { }
                SwingUtilities.invokeAndWait {
                    assertEquals(0, scroll.viewport.viewPosition.y)
                    scroll.viewport.viewPosition = Point(0, 200)
                    layoutTree(tabs)
                    assertEquals(200, scroll.viewport.viewPosition.y)
                    tabs.selectedIndex = 0
                }
            }
        } finally {
            SwingUtilities.invokeAndWait {
                ui.cleanup()
                tabs.removeNotify()
            }
        }
    }

    @Test
    fun `display text and unfocused preview updates do not scroll the settings viewport`() {
        lateinit var ui: ConfigUi
        lateinit var scroll: JScrollPane
        SwingUtilities.invokeAndWait {
            ui = ui()
            ui.component.setSize(1400, 800)
            layoutTree(ui.component)
            scroll = ui.component.descendants().filterIsInstance<JScrollPane>()
                .single { it.name == "mcpSettingsScroll" }
        }
        try {
            // Drain caret work queued during construction before establishing the operator's position.
            SwingUtilities.invokeAndWait { }
            SwingUtilities.invokeAndWait {
                scroll.viewport.viewPosition = Point(0, 200)
                ui.component.descendants().filterIsInstance<WrappingText>().forEach { text ->
                    text.updateUI()
                    assertEquals(DefaultCaret.NEVER_UPDATE, (text.caret as DefaultCaret).updatePolicy)
                    text.updateContent(text.text + " Updated.")
                }
                val preview = ui.component.descendants().filterIsInstance<JTextArea>()
                    .single { it.name == "clientSetupPreview" }
                preview.updateUI()
                assertEquals(DefaultCaret.NEVER_UPDATE, (preview.caret as DefaultCaret).updatePolicy)
                assertTrue(preview.isFocusable)
                preview.caretPosition = preview.document.length
                preview.text = "Refreshed preview\nSecond line"
                preview.caretPosition = 0
            }
            SwingUtilities.invokeAndWait { }
            SwingUtilities.invokeAndWait { assertEquals(200, scroll.viewport.viewPosition.y) }
        } finally {
            ui.cleanup()
        }
    }

    private fun ui(): ConfigUi {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getString(any()) } returns null
        every { storage.getBoolean(any()) } returns null
        every { storage.getInteger(any()) } returns null
        return ConfigUi(McpConfig(storage, mockk<Logging>(relaxed = true), testPreferences()), emptyList())
    }

    private fun layoutTree(root: Container) {
        repeat(3) {
            root.invalidate()
            root.doLayout()
            root.components.filterIsInstance<Container>().forEach(::layoutChildren)
        }
    }

    private fun layoutChildren(root: Container) {
        root.invalidate()
        root.doLayout()
        root.components.filterIsInstance<Container>().forEach(::layoutChildren)
    }

    private fun Container.descendants(): Sequence<Component> = sequence {
        for (child in components) {
            yield(child)
            if (child is Container) yieldAll(child.descendants())
        }
    }
}
