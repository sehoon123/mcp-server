package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import java.awt.Dimension
import java.awt.Insets
import javax.swing.JTextArea
import javax.swing.plaf.TextUI
import javax.swing.plaf.UIResource
import javax.swing.text.View
import kotlin.math.ceil

internal enum class WrappingTextStyle {
    BODY_MEDIUM,
    BODY_LARGE,
    PRIMARY_BODY_LARGE,
    LABEL_MEDIUM,
}

/**
 * Read-only text that follows the Burp font and wraps to the space its parent can actually provide.
 * Unlike an HTML JLabel, this also preserves explicit newlines and exposes the plain text to assistive tools.
 */
internal class WrappingText(
    content: String,
    private val style: WrappingTextStyle = WrappingTextStyle.BODY_MEDIUM,
    private val fallbackMaxWidth: Int = 640,
) : JTextArea(content) {
    private var initialized = false

    init {
        isEditable = false
        isFocusable = false
        isOpaque = false
        lineWrap = true
        wrapStyleWord = true
        margin = Insets(0, 0, 0, 0)
        border = null
        alignmentX = LEFT_ALIGNMENT
        initialized = true
        applyStyle()
        getAccessibleContext().accessibleName = content
    }

    override fun updateUI() {
        super.updateUI()
        if (initialized) {
            applyStyle()
            if (border is UIResource) border = null
        }
    }

    fun updateContent(content: String) {
        if (text != content) text = content
        getAccessibleContext().accessibleName = content
        revalidate()
        repaint()
    }

    override fun getPreferredSize(): Dimension {
        if (!initialized) return super.getPreferredSize()

        val wrapWidth = resolvedWrapWidth().coerceAtLeast(1)
        val textInsets = insets
        val viewWidth = (wrapWidth - textInsets.left - textInsets.right).coerceAtLeast(1)
        val rootView = (ui as? TextUI)?.getRootView(this) ?: return super.getPreferredSize()
        rootView.setSize(viewWidth.toFloat(), Float.MAX_VALUE)
        val textHeight = ceil(rootView.getPreferredSpan(View.Y_AXIS).toDouble()).toInt()
        val preferredHeight = (textHeight + textInsets.top + textInsets.bottom)
            .coerceAtLeast(getFontMetrics(font).height + textInsets.top + textInsets.bottom)
        return Dimension(wrapWidth, preferredHeight)
    }

    override fun getMinimumSize(): Dimension {
        val textInsets = insets
        return Dimension(
            0,
            getFontMetrics(font).height + textInsets.top + textInsets.bottom,
        )
    }

    override fun getMaximumSize(): Dimension = Dimension(Int.MAX_VALUE, preferredSize.height)

    private fun resolvedWrapWidth(): Int {
        val parentWidth = parent?.let {
            val parentInsets = it.insets
            it.width - parentInsets.left - parentInsets.right
        } ?: 0
        if (parentWidth > 0) return parentWidth
        if (width > 0) return width

        val metrics = getFontMetrics(font)
        val naturalWidth = text.lineSequence()
            .maxOfOrNull { metrics.stringWidth(it) }
            ?.plus(insets.left + insets.right + 1)
            ?: 1
        val scale = (font.size2D / 14f).coerceAtLeast(1f)
        return naturalWidth.coerceAtMost((fallbackMaxWidth * scale).toInt())
    }

    private fun applyStyle() {
        font = when (style) {
            WrappingTextStyle.BODY_MEDIUM -> Design.Typography.bodyMedium
            WrappingTextStyle.BODY_LARGE,
            WrappingTextStyle.PRIMARY_BODY_LARGE -> Design.Typography.bodyLarge
            WrappingTextStyle.LABEL_MEDIUM -> Design.Typography.labelMedium
        }
        foreground = if (style == WrappingTextStyle.PRIMARY_BODY_LARGE) {
            Design.Colors.onSurface
        } else {
            Design.Colors.onSurfaceVariant
        }
        background = Design.Colors.surface
        margin = Insets(0, 0, 0, 0)
    }
}
