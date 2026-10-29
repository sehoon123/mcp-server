package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.MAX_HTTP_REQUESTS_PER_SECOND
import net.portswigger.mcp.config.McpConfig
import java.awt.FlowLayout
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JCheckBox
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField

internal class HttpRateLimitPanel(private val config: McpConfig) : JPanel() {
    private val enabled = JCheckBox("Limit HTTP requests across Burp", config.httpRateLimitEnabled).apply {
        name = "httpRateLimitEnabled"
        font = Design.Typography.bodyLarge
        alignmentX = LEFT_ALIGNMENT
    }
    private val rate = JTextField(config.httpRequestsPerSecond.toString(), 6).apply {
        name = "httpRequestsPerSecond"
        accessibleContext.accessibleName = "HTTP requests per second"
        accessibleContext.accessibleDescription = "Whole number from 1 to $MAX_HTTP_REQUESTS_PER_SECOND"
    }
    private val status = WrappingText("").apply { name = "httpRateLimitStatus" }

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        alignmentX = LEFT_ALIGNMENT
        add(Design.createSectionLabel("Global HTTP Rate Limit"))
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(enabled)
        add(JPanel(FlowLayout(FlowLayout.LEFT, Design.Spacing.SM, 0)).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            add(JLabel("Requests per second:").apply { labelFor = rate })
            add(rate)
            add(Design.createOutlinedButton("Apply limit").apply { addActionListener { save(toggle = false) } })
        })
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(WrappingText(
            "One shared limit for Proxy, Repeater, Intruder, Scanner and extension requests handled by Burp. " +
                "Works even when the MCP server is off; saved across projects and restarts. " +
                "Delays requests, so large queues can time out. WebSocket messages and traffic bypassing Burp's " +
                "HTTP handlers are not covered."
        ))
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(status)
        enabled.addActionListener { save(toggle = true) }
        rate.addActionListener { save(toggle = false) }
        showState()
    }

    override fun updateUI() {
        super.updateUI()
        background = Design.Colors.surface
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1),
            BorderFactory.createEmptyBorder(Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD),
        )
    }

    private fun save(toggle: Boolean) {
        if (!toggle || enabled.isSelected) {
            val value = rate.text.trim().toIntOrNull()
            if (value == null || value !in 1..MAX_HTTP_REQUESTS_PER_SECOND) {
                enabled.isSelected = config.httpRateLimitEnabled
                status.updateContent("Enter a whole number from 1 to $MAX_HTTP_REQUESTS_PER_SECOND; limit unchanged.")
                return
            }
            try {
                config.httpRequestsPerSecond = value
            } catch (_: Exception) {
                showSaveFailure()
                return
            }
        }
        try {
            if (toggle) config.httpRateLimitEnabled = enabled.isSelected
            showState()
        } catch (_: Exception) {
            showSaveFailure()
        }
    }

    private fun showState() {
        enabled.isSelected = config.httpRateLimitEnabled
        status.updateContent(
            if (config.httpRateLimitEnabled) "ON: ${config.httpRequestsPerSecond} requests/second shared across Burp."
            else "OFF: HTTP requests are not delayed by this extension."
        )
    }

    fun focusEnabledControl(): Boolean = enabled.requestFocusInWindow()

    private fun showSaveFailure() {
        showState()
        status.updateContent("Could not save reliably; check the setting after reload. Current limit: " +
            if (config.httpRateLimitEnabled) "ON at ${config.httpRequestsPerSecond} requests/second."
            else "OFF.")
    }
}
