package net.portswigger.mcp.config

import java.awt.*
import java.awt.event.KeyEvent
import javax.swing.*

/**
 * Shared Design constants and utilities for consistent theming across the application
 */
object Design {

    object Colors {
        val primary: Color get() = UIManager.getColor("Burp.primaryButtonBackground") ?: Color(0xD86633)
        val onPrimary: Color get() = UIManager.getColor("Burp.primaryButtonForeground") ?: Color.WHITE
        val surface: Color get() = UIManager.getColor("Panel.background") ?: Color(0xFFFBFF)
        val onSurface: Color get() = UIManager.getColor("Label.foreground") ?: Color(0x1A1A1A)
        val onSurfaceVariant: Color get() = UIManager.getColor("Label.disabledForeground") ?: Color(0x666666)
        val outline: Color get() = UIManager.getColor("Component.borderColor") ?: Color(0xCCCCCC)
        val outlineVariant: Color get() = UIManager.getColor("Separator.foreground") ?: Color(0xE0E0E0)
        val error: Color get() = UIManager.getColor("Burp.errorColor") ?: Color(0xB3261E)
        val warning: Color get() = UIManager.getColor("Burp.warningColor") ?: Color(0xF57C00)
        val listBackground: Color get() = UIManager.getColor("List.background") ?: Color.WHITE
        val listBorder: Color get() = UIManager.getColor("List.border") ?: Color(0xDDDDDD)
    }

    object Typography {
        private val baseFont: Font get() = UIManager.getFont("Label.font") ?: Font("Inter", Font.PLAIN, 14)
        private val baseSize: Int get() = baseFont.size

        val headlineMedium: Font get() = baseFont.deriveFont(Font.BOLD, (baseSize * 2.0f))
        val titleMedium: Font get() = baseFont.deriveFont(Font.BOLD, (baseSize * 1.14f))
        val bodyLarge: Font get() = baseFont.deriveFont(Font.PLAIN, (baseSize * 1.14f))
        val bodyMedium: Font get() = baseFont.deriveFont(Font.PLAIN, baseSize.toFloat())
        val labelLarge: Font get() = baseFont.deriveFont(Font.BOLD, baseSize.toFloat())
        val labelMedium: Font get() = baseFont.deriveFont(Font.BOLD, (baseSize * 0.86f))
    }

    object Spacing {
        private val baseSize: Int get() = (UIManager.getFont("Label.font")?.size ?: 14)
        private val scaleFactor: Float get() = baseSize / 14f

        val SM: Int get() = (8 * scaleFactor).toInt().coerceAtLeast(4)
        val MD: Int get() = (16 * scaleFactor).toInt().coerceAtLeast(8)
        val LG: Int get() = (24 * scaleFactor).toInt().coerceAtLeast(12)
        val XL: Int get() = (32 * scaleFactor).toInt().coerceAtLeast(16)
    }

    private fun calculateTextFitSize(button: JButton, sizingText: String): Dimension {
        val font = Typography.labelLarge
        val metrics = button.getFontMetrics(font)
        val textWidth = metrics.stringWidth(sizingText)
        val textHeight = metrics.height

        val horizontalPadding = Spacing.LG * 2
        val verticalPadding = Spacing.SM * 2 + 4

        val minWidth = textWidth + horizontalPadding
        val minHeight = textHeight + verticalPadding

        return Dimension(
            minWidth.coerceAtLeast(80),
            minHeight.coerceAtLeast(40)
        )
    }

    private const val ENTER_BINDING_MARKER = "burp-mcp-enter-binding"

    internal fun enableKeyboardActivation(button: AbstractButton) {
        fun installEnterBinding() {
            button.getInputMap(JComponent.WHEN_FOCUSED).apply {
                // Consume both phases so a root pane's safe default button cannot also handle Enter.
                put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0, false), "pressed")
                put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0, true), "released")
            }
        }

        button.isFocusPainted = true
        installEnterBinding()
        if (button.getClientProperty(ENTER_BINDING_MARKER) != true) {
            button.putClientProperty(ENTER_BINDING_MARKER, true)
            button.addPropertyChangeListener("UI") { installEnterBinding() }
        }
    }

    private fun applyButtonBaseStyle(
        button: JButton,
        customSize: Dimension?,
        sizingText: String = button.text,
    ) {
        button.apply {
            font = Typography.labelLarge
            enableKeyboardActivation(this)
            cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)

            val textFitSize = calculateTextFitSize(this, sizingText)
            minimumSize = textFitSize
            preferredSize = customSize ?: textFitSize
        }
    }

    fun createFilledButton(text: String, customSize: Dimension? = null): JButton {
        return object : JButton(text) {
            init {
                updateColorsAndSizing()
                applyButtonBaseStyle(this, customSize)
            }

            override fun updateUI() {
                super.updateUI()
                updateColorsAndSizing()
                applyButtonBaseStyle(this, customSize)
            }

            private fun updateColorsAndSizing() {
                background = Colors.primary
                foreground = Colors.onPrimary
                border = BorderFactory.createEmptyBorder(Spacing.SM + 2, Spacing.LG, Spacing.SM + 2, Spacing.LG)
            }
        }
    }

    fun createOutlinedButton(
        text: String,
        customSize: Dimension? = null,
        sizingText: String = text,
    ): JButton {
        return object : JButton(text) {
            init {
                updateColorsAndSizing()
                applyButtonBaseStyle(this, customSize, sizingText)
            }

            override fun updateUI() {
                super.updateUI()
                updateColorsAndSizing()
                applyButtonBaseStyle(this, customSize, sizingText)
            }

            private fun updateColorsAndSizing() {
                background = Colors.surface
                foreground = Colors.primary
                border = BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(Colors.outline, 1),
                    BorderFactory.createEmptyBorder(Spacing.SM + 1, Spacing.LG - 1, Spacing.SM + 1, Spacing.LG - 1)
                )
            }
        }
    }

    internal fun createSemanticOutlinedButton(text: String, semanticColor: () -> Color): JButton {
        return object : JButton(text) {
            init {
                updateColorsAndSizing()
                applyButtonBaseStyle(this, null)
            }

            override fun updateUI() {
                super.updateUI()
                updateColorsAndSizing()
                applyButtonBaseStyle(this, null)
            }

            private fun updateColorsAndSizing() {
                val color = semanticColor()
                background = Colors.surface
                foreground = color
                border = BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(color, 1),
                    BorderFactory.createEmptyBorder(Spacing.SM + 1, Spacing.LG - 1, Spacing.SM + 1, Spacing.LG - 1),
                )
            }
        }
    }

    fun createToggleSwitch(initialState: Boolean = false, onToggle: (Boolean) -> Unit): JToggleButton {
        return JToggleButton(if (initialState) "On" else "Off", initialState).apply {
            name = "serverEnabledToggle"
            toolTipText = "Enable or disable the MCP server"
            enableKeyboardActivation(this)
            addItemListener { text = if (isSelected) "On" else "Off" }
            addActionListener { onToggle(isSelected) }
        }
    }

    fun createSectionLabel(text: String): JLabel {
        return object : JLabel(text) {
            init {
                updateColors()
                alignmentX = LEFT_ALIGNMENT
            }

            override fun updateUI() {
                super.updateUI()
                updateColors()
            }

            private fun updateColors() {
                font = Typography.titleMedium
                foreground = Colors.onSurface
            }
        }
    }
}
