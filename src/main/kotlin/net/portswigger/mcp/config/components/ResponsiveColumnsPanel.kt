package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import java.awt.BorderLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import javax.swing.BorderFactory
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.UIManager
import kotlin.math.roundToInt

class ResponsiveColumnsPanel(private val leftPanel: JPanel, private val rightPanel: JScrollPane) : JPanel() {
    private val minWidthForTwoColumns: Int
        get() = scaledBreakpoint(1_120)
    private val minWidthForLargePadding: Int
        get() = scaledBreakpoint(720)
    private var lastLayout = Layout.SINGLE_COLUMN
    private var lastPaddingSize = PaddingSize.SMALL
    private var isInitialized = false

    internal val activeLayout: Layout get() = lastLayout

    enum class Layout { SINGLE_COLUMN, TWO_COLUMNS }
    enum class PaddingSize { SMALL, LARGE }

    init {
        isInitialized = true
        updateLayout()
    }

    override fun updateUI() {
        super.updateUI()
        if (isInitialized) {
            updateLayout() // Reapply layout with updated theme colors
        }
    }

    override fun doLayout() {
        val currentLayout = if (width >= minWidthForTwoColumns) Layout.TWO_COLUMNS else Layout.SINGLE_COLUMN
        val currentPaddingSize = if (width >= minWidthForLargePadding) PaddingSize.LARGE else PaddingSize.SMALL

        if (currentLayout != lastLayout || currentPaddingSize != lastPaddingSize) {
            lastLayout = currentLayout
            lastPaddingSize = currentPaddingSize
            updateLayout()
        }
        super.doLayout()
    }

    private fun updateLayout() {
        removeAll()

        val padding = when (lastPaddingSize) {
            PaddingSize.LARGE -> Design.Spacing.LG
            PaddingSize.SMALL -> Design.Spacing.SM
        }

        if (rightPanel.viewport.view is JPanel) {
            val contentPanel = rightPanel.viewport.view as JPanel
            contentPanel.border = BorderFactory.createEmptyBorder(padding, padding, padding, padding)
        }

        when (lastLayout) {
            Layout.TWO_COLUMNS -> {
                layout = GridBagLayout()
                val c = GridBagConstraints().apply {
                    fill = GridBagConstraints.BOTH
                    weighty = 1.0
                }

                c.gridx = 0
                c.gridy = 0
                c.weightx = 0.35
                add(leftPanel, c)

                c.gridx = 1
                c.weightx = 0.65
                add(rightPanel, c)
            }

            Layout.SINGLE_COLUMN -> {
                layout = BorderLayout()
                val headerWrapper = JPanel(BorderLayout()).apply {
                    isOpaque = false
                    border = BorderFactory.createEmptyBorder(padding, padding, Design.Spacing.MD, padding)
                    add(leftPanel, BorderLayout.CENTER)
                }

                add(headerWrapper, BorderLayout.NORTH)
                add(rightPanel, BorderLayout.CENTER)
            }
        }

        revalidate()
        repaint()
    }

    private fun scaledBreakpoint(baseWidth: Int): Int {
        val fontSize = UIManager.getFont("Label.font")?.size2D ?: 14f
        return (baseWidth * (fontSize / 14f).coerceAtLeast(1f)).roundToInt()
    }
}
