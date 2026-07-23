package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import java.awt.Dimension
import javax.swing.AbstractButton
import javax.swing.JPanel

/**
 * Keeps action buttons on one row when they fit and stacks them without clipping when the available width shrinks.
 */
internal class AdaptiveButtonPanel(
    buttons: List<AbstractButton>,
) : JPanel(null) {
    private val actionButtons = buttons.toList()

    init {
        isOpaque = false
        alignmentX = LEFT_ALIGNMENT
        actionButtons.forEach { button ->
            Design.enableKeyboardActivation(button)
            add(button)
        }
    }

    override fun getPreferredSize(): Dimension {
        val metrics = layoutMetrics()
        val availableWidth = resolvedAvailableWidth()
        val content = if (availableWidth > 0 && metrics.rowWidth > availableWidth) {
            Dimension(metrics.columnWidth, metrics.columnHeight)
        } else {
            Dimension(metrics.rowWidth, metrics.rowHeight)
        }
        val panelInsets = insets
        return Dimension(
            content.width + panelInsets.left + panelInsets.right,
            content.height + panelInsets.top + panelInsets.bottom,
        )
    }

    override fun getMinimumSize(): Dimension {
        val metrics = layoutMetrics()
        val panelInsets = insets
        return Dimension(
            metrics.columnWidth + panelInsets.left + panelInsets.right,
            metrics.columnHeight + panelInsets.top + panelInsets.bottom,
        )
    }

    override fun getMaximumSize(): Dimension = Dimension(Int.MAX_VALUE, preferredSize.height)

    override fun doLayout() {
        val metrics = layoutMetrics()
        val panelInsets = insets
        val availableWidth = (width - panelInsets.left - panelInsets.right).coerceAtLeast(0)

        if (metrics.rowWidth <= availableWidth) {
            var x = panelInsets.left
            actionButtons.forEach { button ->
                val preferred = button.preferredSize
                val y = panelInsets.top + (metrics.rowHeight - preferred.height) / 2
                button.setBounds(x, y, preferred.width, preferred.height)
                x += preferred.width + Design.Spacing.SM
            }
        } else {
            var y = panelInsets.top
            actionButtons.forEach { button ->
                val preferred = button.preferredSize
                button.setBounds(panelInsets.left, y, preferred.width, preferred.height)
                y += preferred.height + Design.Spacing.SM
            }
        }
    }

    private fun resolvedAvailableWidth(): Int {
        val panelInsets = insets
        val parentWidth = parent?.let {
            val parentInsets = it.insets
            it.width - parentInsets.left - parentInsets.right - panelInsets.left - panelInsets.right
        } ?: 0
        if (parentWidth > 0) return parentWidth
        return (width - panelInsets.left - panelInsets.right).coerceAtLeast(0)
    }

    private fun layoutMetrics(): LayoutMetrics {
        val sizes = actionButtons.map(AbstractButton::getPreferredSize)
        if (sizes.isEmpty()) return LayoutMetrics(0, 0, 0, 0)

        val gap = Design.Spacing.SM
        return LayoutMetrics(
            rowWidth = sizes.sumOf { it.width } + gap * (sizes.size - 1),
            rowHeight = sizes.maxOf { it.height },
            columnWidth = sizes.maxOf { it.width },
            columnHeight = sizes.sumOf { it.height } + gap * (sizes.size - 1),
        )
    }

    private data class LayoutMetrics(
        val rowWidth: Int,
        val rowHeight: Int,
        val columnWidth: Int,
        val columnHeight: Int,
    )
}
