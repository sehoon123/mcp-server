package net.portswigger.mcp.config

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.awt.Font
import java.awt.GridLayout
import javax.swing.JButton
import javax.swing.SwingUtilities
import javax.swing.UIManager

class DialogsTest {
    @Test
    fun `approval choices keep full labels at normal and enlarged UI font sizes`() {
        runOnEdt {
            val originalFont = UIManager.getFont("Label.font") ?: Font("Dialog", Font.PLAIN, 14)
            try {
                assertAllProductionLabelsFit()

                UIManager.put("Label.font", originalFont.deriveFont(originalFont.size2D * 2f))
                assertAllProductionLabelsFit()
            } finally {
                UIManager.put("Label.font", originalFont)
            }
        }
    }

    @Test
    fun `five choice approval layout preserves order and styles only final choice as denial`() {
        runOnEdt {
            val options = arrayOf(
                "Allow Once",
                "Allow All for This Session",
                "Always Allow Host",
                "Always Allow Host:Port",
                "Deny",
            )
            var selected = -1
            val panel = Dialogs.createOptionButtonPanel(options) { selected = it }
            val buttons = panel.components.filterIsInstance<JButton>()
            val layout = panel.layout as GridLayout

            assertEquals(options.toList(), buttons.map(JButton::getText))
            assertEquals(options.size, layout.rows)
            assertEquals(1, layout.columns)
            assertEquals(Design.Colors.primary, buttons[1].foreground)
            assertEquals(Design.Colors.warning, buttons[2].foreground)
            assertEquals(Design.Colors.warning, buttons[3].foreground)
            assertTrue(buttons[2].accessibleContext.accessibleDescription.contains("Persistent approval"))
            assertEquals(Design.Colors.error, buttons.last().foreground)

            buttons.forEach(JButton::updateUI)
            assertEquals(Design.Colors.warning, buttons[2].foreground)
            assertEquals(Design.Colors.warning, buttons[3].foreground)
            assertEquals(Design.Colors.error, buttons.last().foreground)

            buttons[3].doClick()
            assertEquals(3, selected)
        }
    }

    private fun assertAllProductionLabelsFit() {
        productionOptionSets().forEach { options ->
            val panel = Dialogs.createOptionButtonPanel(options)
            panel.setSize(panel.preferredSize)
            panel.doLayout()

            panel.components.filterIsInstance<JButton>().forEach { button ->
                val metrics = button.getFontMetrics(button.font)
                val requiredWidth = metrics.stringWidth(button.text) + button.insets.left + button.insets.right
                val requiredHeight = metrics.height + button.insets.top + button.insets.bottom
                assertTrue(
                    button.width >= requiredWidth,
                    "Approval label is horizontally clipped: '${button.text}' (${button.width} < $requiredWidth)",
                )
                assertTrue(
                    button.height >= requiredHeight,
                    "Approval label is vertically clipped: '${button.text}' (${button.height} < $requiredHeight)",
                )
                assertEquals(Design.Typography.labelLarge.size2D, button.font.size2D)
            }
        }
    }

    private fun productionOptionSets(): List<Array<String>> {
        val shared = arrayOf("Allow Once", "Allow for This Session", "Always Allow", "Deny")
        val dataSources = listOf(
            "HTTP history",
            "Site Map items",
            "WebSocket history",
            "Organizer items",
            "Scanner issues",
            "Collaborator interactions",
        )
        return buildList {
            add(
                arrayOf(
                    "Allow Once",
                    "Allow All for This Session",
                    "Always Allow Host",
                    "Always Allow Host:Port",
                    "Deny",
                ),
            )
            add(shared)
            dataSources.forEach { source ->
                add(
                    arrayOf(
                        "Allow Once",
                        "Allow $source for This Session",
                        "Always Allow $source",
                        "Deny",
                    ),
                )
            }
            add(arrayOf("Allow Once", "Deny"))
        }
    }
}

private fun runOnEdt(action: () -> Unit) {
    if (SwingUtilities.isEventDispatchThread()) {
        action()
    } else {
        SwingUtilities.invokeAndWait(action)
    }
}
