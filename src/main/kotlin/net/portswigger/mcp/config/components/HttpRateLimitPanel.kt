package net.portswigger.mcp.config.components

import net.portswigger.mcp.HttpRateLimitSnapshot
import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.MAX_HTTP_REQUESTS_PER_SECOND
import net.portswigger.mcp.config.McpConfig
import java.awt.FlowLayout
import java.util.Locale
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JCheckBox
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.SwingUtilities
import javax.swing.Timer

internal class HttpRateLimitPanel(
    private val config: McpConfig,
    private val snapshotProvider: (() -> HttpRateLimitSnapshot?)? = null,
) : JPanel() {
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
    private val statistics = WrappingText("").apply { name = "httpRateLimitStatistics" }
    private var closed = false
    private val refreshTimer = Timer(1_000) { refreshStatistics() }

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
        add(statistics)
        enabled.addActionListener { save(toggle = true) }
        rate.addActionListener { save(toggle = false) }
        showState()
        if (SwingUtilities.isEventDispatchThread()) refreshStatistics() else SwingUtilities.invokeLater(::refreshStatistics)
        if (snapshotProvider != null) refreshTimer.start()
    }

    internal fun refreshStatistics() {
        check(SwingUtilities.isEventDispatchThread()) { "HTTP rate statistics must refresh on the EDT" }
        if (closed) return
        statistics.updateContent(runCatching { snapshotProvider?.invoke()?.let(::formatHttpRateLimitStatistics) }
            .getOrNull() ?: "HTTP rate statistics unavailable.")
    }

    fun cleanup() {
        check(SwingUtilities.isEventDispatchThread()) { "HTTP rate statistics cleanup must run on the EDT" }
        closed = true
        refreshTimer.stop()
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

internal fun formatHttpRateLimitStatistics(snapshot: HttpRateLimitSnapshot): String = with(snapshot) {
    val average = String.format(Locale.ROOT, "%.1f", averageWaitMillis)
    val maximum = String.format(Locale.ROOT, "%.1f", maxWaitMillis)
    "Last full second: ${lastCompleteSecondAdmissions ?: "warming up"} paced admissions; waiting: $waitingRequests.\n" +
        "Since extension load: $pacedAdmissions paced admissions; $finishedWaits finished waits " +
        "(average/max $average/$maximum ms); $interruptedRequests interrupted admissions.\n" +
        "Callback pacing, not wire RPS. Waits exclude lock acquisition and include disable/unload/interruption. " +
        if (closed) "Limiter closed." else "Counters are not persisted."
}
