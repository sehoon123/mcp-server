package net.portswigger.mcp.config

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import net.portswigger.mcp.config.components.AdaptiveButtonPanel
import net.portswigger.mcp.config.components.ResponsiveColumnsPanel
import net.portswigger.mcp.config.components.WidthTrackingPanel
import net.portswigger.mcp.config.components.WrappingText
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.awt.Color
import java.awt.Component
import java.awt.Container
import java.awt.Dimension
import java.awt.Font
import java.awt.event.ActionEvent
import javax.accessibility.AccessibleRole
import javax.accessibility.AccessibleState
import javax.swing.AbstractButton
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextField
import javax.swing.JViewport
import javax.swing.KeyStroke
import javax.swing.SwingUtilities
import javax.swing.UIManager

class ResponsiveUiComponentsTest {
    @Test
    fun `minimum supported MCP tab fits at 100 150 and 200 percent in light and dark themes`() {
        runOnEdt {
            TEST_THEMES.forEach { theme ->
                withUiTheme(theme) {
                    listOf(1f, 1.5f, 2f).forEach { scale ->
                        withUiFontScale(scale) {
                            try {
                                assertMinimumLayoutFits(expectStackedActions = scale == 2f)
                            } catch (failure: AssertionError) {
                                throw AssertionError(
                                    "${theme.name} theme at ${(scale * 100).toInt()}%: ${failure.message}",
                                    failure,
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    @Test
    fun `wide layout keeps two columns only when the active font scale leaves enough room`() {
        runOnEdt {
            withUiFontScale(1f) {
                val columns = ResponsiveColumnsPanel(JPanel(), JScrollPane(WidthTrackingPanel()))
                columns.setSize(1_600, 720)
                columns.doLayout()
                assertEquals(ResponsiveColumnsPanel.Layout.TWO_COLUMNS, columns.activeLayout)

                withUiFontScale(2f) {
                    columns.doLayout()
                    assertEquals(ResponsiveColumnsPanel.Layout.SINGLE_COLUMN, columns.activeLayout)
                }
            }
        }
    }

    @Test
    fun `adaptive action panel stacks only when its full row cannot fit`() {
        runOnEdt {
            val buttons = listOf(
                JButton("Reset active session approvals"),
                JButton("Reset all persistent approvals..."),
            )
            val panel = AdaptiveButtonPanel(buttons)
            buttons.forEach { button ->
                assertEquals(
                    "pressed",
                    button.getInputMap(JComponent.WHEN_FOCUSED).get(KeyStroke.getKeyStroke("pressed ENTER")),
                )
                assertEquals(
                    "released",
                    button.getInputMap(JComponent.WHEN_FOCUSED).get(KeyStroke.getKeyStroke("released ENTER")),
                )
                button.updateUI()
                assertEquals(
                    "pressed",
                    button.getInputMap(JComponent.WHEN_FOCUSED).get(KeyStroke.getKeyStroke("pressed ENTER")),
                )
                assertEquals(
                    "released",
                    button.getInputMap(JComponent.WHEN_FOCUSED).get(KeyStroke.getKeyStroke("released ENTER")),
                )
            }
            val rowWidth = buttons.sumOf { it.preferredSize.width } + Design.Spacing.SM

            panel.setSize(rowWidth, panel.preferredSize.height)
            panel.doLayout()
            assertEquals(buttons[0].y, buttons[1].y)

            panel.setSize(buttons.maxOf { it.preferredSize.width }, panel.minimumSize.height)
            panel.doLayout()
            assertTrue(buttons[1].y > buttons[0].y)
            buttons.forEach(::assertButtonTextFits)
        }
    }

    @Test
    fun `wrapping text grows vertically instead of overflowing its parent`() {
        runOnEdt {
            val text = WrappingText(
                "Session approvals are memory-only and expire on session deletion, idle eviction, listener restart, or Burp shutdown."
            )
            val parent = javax.swing.JPanel().apply {
                layout = javax.swing.BoxLayout(this, javax.swing.BoxLayout.Y_AXIS)
                add(text)
                size = Dimension(260, 200)
            }

            parent.doLayout()
            text.setSize(260, text.preferredSize.height)
            assertTrue(text.preferredSize.height > text.getFontMetrics(text.font).height)
            assertTrue(text.preferredSize.width <= parent.width)
            assertEquals(text.text, text.accessibleContext.accessibleName)
        }
    }

    @Test
    fun `custom server toggle has native keyboard and accessibility behavior`() {
        runOnEdt {
            var selected = false
            val toggle = Design.createToggleSwitch(false) { selected = it }
            toggle.accessibleContext.accessibleName = "MCP server enabled"

            assertEquals(JComponent::class.java, toggle.javaClass.superclass)
            assertTrue(toggle.isFocusable)
            assertEquals(AccessibleRole.TOGGLE_BUTTON, toggle.accessibleContext.accessibleRole)
            assertEquals("MCP server enabled", toggle.accessibleContext.accessibleName)

            val enterKey = KeyStroke.getKeyStroke("released ENTER")
            val actionKey = toggle.getInputMap(javax.swing.JComponent.WHEN_FOCUSED).get(enterKey)
            assertNotNull(actionKey)
            toggle.actionMap.get(actionKey).actionPerformed(ActionEvent(toggle, ActionEvent.ACTION_PERFORMED, "enter"))

            assertTrue(toggle.accessibleContext.accessibleStateSet.contains(AccessibleState.CHECKED))
            assertTrue(selected)

            val normalSize = toggle.preferredSize
            withUiFontScale(2f) {
                val enlarged = Design.createToggleSwitch(false) {}
                assertTrue(enlarged.preferredSize.width >= (normalSize.width * 1.5).toInt())
                assertTrue(enlarged.preferredSize.height >= (normalSize.height * 1.5).toInt())
            }
        }
    }

    @Test
    fun `links and styled buttons retain visible keyboard focus support`() {
        runOnEdt {
            val anchor = Anchor("Manual install steps", "https://example.invalid/")
            assertTrue(anchor.isFocusable)
            assertNotNull(anchor.inputMap.get(KeyStroke.getKeyStroke("released SPACE")))
            assertNotNull(anchor.inputMap.get(KeyStroke.getKeyStroke("released ENTER")))

            var activated = false
            val button = Design.createFilledButton("Allow Once").apply {
                addActionListener { activated = true }
            }
            assertTrue(button.isFocusPainted)
            val pressedKey = KeyStroke.getKeyStroke("pressed ENTER")
            val releasedKey = KeyStroke.getKeyStroke("released ENTER")
            val pressedActionKey = button.getInputMap(JComponent.WHEN_FOCUSED).get(pressedKey)
            val releasedActionKey = button.getInputMap(JComponent.WHEN_FOCUSED).get(releasedKey)
            assertEquals("pressed", pressedActionKey)
            assertEquals("released", releasedActionKey)

            button.actionMap.get(pressedActionKey).actionPerformed(
                ActionEvent(button, ActionEvent.ACTION_PERFORMED, "enter-pressed"),
            )
            assertFalse(activated)
            button.actionMap.get(releasedActionKey).actionPerformed(
                ActionEvent(button, ActionEvent.ACTION_PERFORMED, "enter-released"),
            )
            assertTrue(activated)
        }
    }

    private fun assertMinimumLayoutFits(expectStackedActions: Boolean = false) {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns null
        every { storage.getString(any()) } returns null
        every { storage.getInteger(any()) } returns null
        val config = McpConfig(storage, mockk<Logging>(relaxed = true))
        val ui = ConfigUi(config, emptyList())

        try {
            ui.component.setSize(1_024, 720)
            repeat(5) { layoutRecursively(ui.component) }

            val columns = ui.component.descendants()
                .filterIsInstance<ResponsiveColumnsPanel>()
                .single()
            assertEquals(ResponsiveColumnsPanel.Layout.SINGLE_COLUMN, columns.activeLayout)

            val settingsSurface = ui.component.descendants()
                .filterIsInstance<WidthTrackingPanel>()
                .single()
            val viewport = settingsSurface.parent as JViewport
            val scrollPane = viewport.parent as JScrollPane
            assertTrue(settingsSurface.scrollableTracksViewportWidth)
            assertEquals(viewport.extentSize.width, settingsSurface.width)
            assertEquals(0, viewport.viewPosition.x)
            assertEquals(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER, scrollPane.horizontalScrollBarPolicy)
            assertFalse(scrollPane.horizontalScrollBar.isVisible, "The settings surface must not show a horizontal scrollbar")

            ui.component.descendants()
                .filterIsInstance<AdaptiveButtonPanel>()
                .forEach(::assertChildrenDoNotOverlap)
            assertChildrenDoNotOverlap(columns)

            val surface = Design.Colors.surface
            ui.component.descendants()
                .filterIsInstance<WrappingText>()
                .filter { it.isVisible }
                .forEach { text ->
                    assertTrue(
                        contrastRatio(text.foreground, surface) >= 3.0,
                        "Wrapped settings text must remain readable in the active theme: '${text.text}'",
                    )
                }

            val buttons = ui.component.descendants()
                .filterIsInstance<AbstractButton>()
                .filter { it.isVisible && it.text.isNotBlank() && it.width > 0 }
                .toList()
            assertTrue(buttons.isNotEmpty())
            buttons.forEach(::assertButtonTextFits)

            ui.component.descendants()
                .filterIsInstance<JLabel>()
                .filter { it.isVisible && !it.text.isNullOrBlank() && it.width > 0 }
                .forEach { label ->
                    val requiredWidth = label.getFontMetrics(label.font).stringWidth(label.text) +
                        label.insets.left + label.insets.right
                    assertTrue(
                        label.width >= requiredWidth,
                        "Settings label is clipped: '${label.text}' (${label.width} < $requiredWidth)",
                    )
                }

            ui.component.descendants()
                .filterIsInstance<JTextField>()
                .filter { it.isVisible && it.height > 0 }
                .forEach { field ->
                    val requiredHeight = field.getFontMetrics(field.font).height +
                        field.insets.top + field.insets.bottom
                    assertTrue(
                        field.height >= requiredHeight,
                        "Text field is vertically clipped (${field.height} < $requiredHeight)",
                    )
                }

            ui.component.descendants()
                .filterIsInstance<WrappingText>()
                .filter { it.isVisible && it.width > 0 }
                .forEach { text ->
                    assertTrue(
                        text.height >= text.preferredSize.height,
                        "Wrapped settings text is vertically clipped: '${text.text}' " +
                            "(${text.height} < ${text.preferredSize.height})",
                    )
                }

            if (expectStackedActions) {
                val hasStackedPanel = ui.component.descendants()
                    .filterIsInstance<AdaptiveButtonPanel>()
                    .any { panel ->
                        val children = panel.components.filterIsInstance<AbstractButton>()
                        children.size > 1 && children.map(Component::getY).distinct().size > 1
                    }
                assertTrue(hasStackedPanel, "Enlarged controls should stack instead of clipping")
            }
        } finally {
            ui.cleanup()
        }
    }

    private fun assertButtonTextFits(button: AbstractButton) {
        val metrics = button.getFontMetrics(button.font)
        val requiredWidth = metrics.stringWidth(button.text) + button.insets.left + button.insets.right
        val requiredHeight = metrics.height + button.insets.top + button.insets.bottom
        assertTrue(
            button.width >= requiredWidth,
            "Button label is horizontally clipped: '${button.text}' (${button.width} < $requiredWidth)",
        )
        assertTrue(
            button.height >= requiredHeight,
            "Button label is vertically clipped: '${button.text}' (${button.height} < $requiredHeight)",
        )
    }

    private fun assertChildrenDoNotOverlap(container: Container) {
        val children = container.components.filter { it.isVisible && it.width > 0 && it.height > 0 }
        children.forEachIndexed { index, left ->
            children.drop(index + 1).forEach { right ->
                assertFalse(
                    left.bounds.intersects(right.bounds),
                    "Responsive controls overlap in ${container.javaClass.simpleName}: " +
                        "${left.javaClass.simpleName} and ${right.javaClass.simpleName}",
                )
            }
        }
    }
}

private fun layoutRecursively(container: Container) {
    container.doLayout()
    container.components.filterIsInstance<Container>().forEach(::layoutRecursively)
}

private fun Container.descendants(): Sequence<Component> = sequence {
    components.forEach { component ->
        yield(component)
        if (component is Container) yieldAll(component.descendants())
    }
}

private data class TestTheme(
    val name: String,
    val colors: Map<String, Color>,
)

private val TEST_THEMES = listOf(
    TestTheme(
        name = "light",
        colors = mapOf(
            "Panel.background" to Color(0xFAFAFA),
            "Label.foreground" to Color(0x202124),
            "Label.disabledForeground" to Color(0x5F6368),
            "Component.borderColor" to Color(0x9AA0A6),
            "Component.focusColor" to Color(0x0B57D0),
            "Separator.foreground" to Color(0xDADCE0),
            "Burp.primaryButtonBackground" to Color(0xC84E1B),
            "Burp.primaryButtonForeground" to Color.WHITE,
            "Burp.errorColor" to Color(0xB3261E),
            "Burp.warningColor" to Color(0x9A5B00),
            "List.background" to Color.WHITE,
            "List.selectionBackground" to Color(0xD2E3FC),
            "List.selectionForeground" to Color(0x174EA6),
            "List.hoverBackground" to Color(0xF1F3F4),
            "List.alternateRowColor" to Color(0xF8F9FA),
            "List.border" to Color(0xDADCE0),
        ),
    ),
    TestTheme(
        name = "dark",
        colors = mapOf(
            "Panel.background" to Color(0x202124),
            "Label.foreground" to Color(0xF1F3F4),
            "Label.disabledForeground" to Color(0xBDC1C6),
            "Component.borderColor" to Color(0x80868B),
            "Component.focusColor" to Color(0x8AB4F8),
            "Separator.foreground" to Color(0x3C4043),
            "Burp.primaryButtonBackground" to Color(0xFF8A50),
            "Burp.primaryButtonForeground" to Color(0x202124),
            "Burp.errorColor" to Color(0xF28B82),
            "Burp.warningColor" to Color(0xFDD663),
            "List.background" to Color(0x292A2D),
            "List.selectionBackground" to Color(0x3C4043),
            "List.selectionForeground" to Color(0x8AB4F8),
            "List.hoverBackground" to Color(0x303134),
            "List.alternateRowColor" to Color(0x252629),
            "List.border" to Color(0x5F6368),
        ),
    ),
)

private fun withUiTheme(theme: TestTheme, action: () -> Unit) {
    val originals = theme.colors.keys.associateWith(UIManager::get)
    try {
        theme.colors.forEach(UIManager::put)
        action()
    } finally {
        originals.forEach { (key, value) ->
            if (value == null) UIManager.getDefaults().remove(key) else UIManager.put(key, value)
        }
    }
}

private fun contrastRatio(foreground: Color, background: Color): Double {
    fun luminance(color: Color): Double {
        fun linear(channel: Int): Double {
            val normalized = channel / 255.0
            return if (normalized <= 0.04045) normalized / 12.92 else Math.pow((normalized + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * linear(color.red) + 0.7152 * linear(color.green) + 0.0722 * linear(color.blue)
    }

    val foregroundLuminance = luminance(foreground)
    val backgroundLuminance = luminance(background)
    val lighter = maxOf(foregroundLuminance, backgroundLuminance)
    val darker = minOf(foregroundLuminance, backgroundLuminance)
    return (lighter + 0.05) / (darker + 0.05)
}

private fun withUiFontScale(scale: Float, action: () -> Unit) {
    val keys = listOf(
        "Label.font",
        "Button.font",
        "CheckBox.font",
        "TextArea.font",
        "TextField.font",
        "Spinner.font",
        "List.font",
    )
    val originals = keys.associateWith { UIManager.getFont(it) }
    try {
        keys.forEach { key ->
            val base = originals[key] ?: Font("Dialog", Font.PLAIN, 14)
            UIManager.put(key, base.deriveFont(base.size2D * scale))
        }
        action()
    } finally {
        originals.forEach { (key, value) -> UIManager.put(key, value) }
    }
}

private fun runOnEdt(action: () -> Unit) {
    if (SwingUtilities.isEventDispatchThread()) action() else SwingUtilities.invokeAndWait(action)
}
