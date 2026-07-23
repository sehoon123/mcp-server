package net.portswigger.mcp.config.components

import net.portswigger.mcp.McpDiagnosticsSnapshot
import net.portswigger.mcp.config.DEFAULT_AUDIT_RETENTION_ENTRIES
import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.MAX_AUDIT_RETENTION_ENTRIES
import net.portswigger.mcp.config.MIN_AUDIT_RETENTION_ENTRIES
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.providers.ProxyProvenance
import net.portswigger.mcp.security.McpAuditSink
import net.portswigger.mcp.security.safeSingleLine
import java.awt.FlowLayout
import java.awt.Font
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.time.Instant
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSpinner
import javax.swing.JTextArea
import javax.swing.SpinnerNumberModel
import javax.swing.Timer

internal class DiagnosticsPanel(
    private val config: McpConfig,
    private val diagnosticsProvider: () -> McpDiagnosticsSnapshot,
    private val auditLog: McpAuditSink,
    private val proxyProvenance: ProxyProvenance?,
    private val proxyVerified: Boolean,
    private val clearSessionApprovals: () -> Int = { 0 },
    private val onPersistentApprovalsReset: () -> Unit = {},
) : JPanel() {
    private val diagnosticsArea = JTextArea(13, 64)
    private val statusLabel = WrappingText(" ", WrappingTextStyle.LABEL_MEDIUM)
    private val refreshTimer = Timer(1_000) { refresh() }

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        alignmentX = LEFT_ALIGNMENT
        updateColors()
        buildPanel()
        refresh()
        refreshTimer.isRepeats = true
        refreshTimer.start()
    }

    override fun updateUI() {
        super.updateUI()
        updateColors()
    }

    fun cleanup() {
        refreshTimer.stop()
    }

    private fun updateColors() {
        background = Design.Colors.surface
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1),
            BorderFactory.createEmptyBorder(Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD),
        )
    }

    private fun buildPanel() {
        add(Design.createSectionLabel("Diagnostics and Safety"))
        add(Box.createVerticalStrut(Design.Spacing.SM))

        add(JCheckBox("Emergency read-only mode").apply {
            isOpaque = false
            isSelected = config.emergencyReadOnlyMode
            alignmentX = LEFT_ALIGNMENT
            accessibleContext.accessibleDescription =
                "Blocks tools that are not explicitly marked read-only"
            addActionListener {
                config.emergencyReadOnlyMode = isSelected
                auditLog.recordLocalEvent(
                    tool = "emergency_read_only_mode",
                    outcome = if (isSelected) "enabled" else "disabled",
                )
                refresh()
            }
        })
        add(WrappingText("Blocks tools that are not explicitly marked read-only."))
        add(WrappingText(
            "Existing Scanner work is not cancelled; new mutation, routing, generation, and active actions are blocked."
        ))
        add(Box.createVerticalStrut(Design.Spacing.SM))

        add(JCheckBox("Persist bounded redacted MCP audit records").apply {
            isOpaque = false
            isSelected = config.auditLoggingEnabled
            alignmentX = LEFT_ALIGNMENT
            addActionListener {
                if (isSelected) {
                    config.auditLoggingEnabled = true
                    auditLog.recordLocalEvent("audit_logging", "enabled")
                } else {
                    auditLog.recordLocalEvent("audit_logging", "disabled")
                    config.auditLoggingEnabled = false
                }
                refresh()
            }
        })

        val retentionPanel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            add(JLabel("Audit retention entries: "))
            add(JSpinner(SpinnerNumberModel(
                config.auditRetentionEntries.coerceIn(MIN_AUDIT_RETENTION_ENTRIES, MAX_AUDIT_RETENTION_ENTRIES),
                MIN_AUDIT_RETENTION_ENTRIES,
                MAX_AUDIT_RETENTION_ENTRIES,
                50,
            )).apply {
                addChangeListener {
                    config.auditRetentionEntries = (value as Number).toInt()
                    auditLog.trimToConfiguredRetention()
                    refresh()
                }
            })
        }
        add(retentionPanel)
        add(Box.createVerticalStrut(Design.Spacing.SM))

        diagnosticsArea.apply {
            isEditable = false
            lineWrap = false
            font = Font(Font.MONOSPACED, Font.PLAIN, font.size)
            background = Design.Colors.listBackground
            foreground = Design.Colors.onSurface
            border = BorderFactory.createEmptyBorder(Design.Spacing.SM, Design.Spacing.SM, Design.Spacing.SM, Design.Spacing.SM)
        }
        add(JScrollPane(diagnosticsArea).apply {
            alignmentX = LEFT_ALIGNMENT
            border = BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1)
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED
            verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
        })
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(WrappingText(
            "Session approvals are memory-only and expire on session deletion, idle eviction, listener restart, or Burp shutdown."
        ))
        add(Box.createVerticalStrut(Design.Spacing.SM))

        val resetSessionApprovalsButton = JButton("Reset active session approvals").apply {
            addActionListener {
                runCatching { clearSessionApprovals() }
                    .onSuccess { cleared ->
                        auditLog.recordLocalEvent("session_approvals", "reset")
                        statusLabel.updateContent("$cleared active session approval grants reset")
                        refresh()
                    }
                    .onFailure {
                        statusLabel.updateContent("Could not reset active session approvals")
                    }
            }
        }
        val resetPersistentApprovalsButton = JButton("Reset all persistent approvals...").apply {
            addActionListener {
                val choice = JOptionPane.showConfirmDialog(
                    this@DiagnosticsPanel,
                    "Restore all MCP approval policies to prompt-by-default? " +
                        "This clears saved HTTP targets and all persistent approval bypasses.",
                    "Reset persistent MCP approvals",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.WARNING_MESSAGE,
                )
                if (choice == JOptionPane.OK_OPTION) {
                    runCatching {
                        config.resetPersistentApprovals()
                        onPersistentApprovalsReset()
                    }.onSuccess {
                        auditLog.recordLocalEvent("persistent_approvals", "reset_to_prompt")
                        statusLabel.updateContent("Persistent approvals reset to prompt-by-default")
                        refresh()
                    }.onFailure {
                        statusLabel.updateContent("Could not reset persistent approvals")
                    }
                }
            }
        }
        add(AdaptiveButtonPanel(listOf(resetSessionApprovalsButton, resetPersistentApprovalsButton)))
        add(Box.createVerticalStrut(Design.Spacing.SM))

        val refreshButton = JButton("Refresh").apply { addActionListener { refresh() } }
        val copyDiagnosticsButton = JButton("Copy redacted diagnostics").apply {
            addActionListener { copyToClipboard(diagnosticsArea.text, "Diagnostics copied") }
        }
        val copyAuditButton = JButton("Copy recent redacted audit").apply {
            addActionListener {
                val exported = auditLog.exportJsonLines(100)
                if (exported.isEmpty()) statusLabel.updateContent("No audit records to copy")
                else copyToClipboard(exported, "Recent redacted audit copied")
            }
        }
        val clearAuditButton = JButton("Clear audit...").apply {
            addActionListener {
                val choice = JOptionPane.showConfirmDialog(
                    this@DiagnosticsPanel,
                    "Delete all persisted MCP audit records? This cannot be undone.",
                    "Clear MCP audit",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.WARNING_MESSAGE,
                )
                if (choice == JOptionPane.OK_OPTION) {
                    auditLog.clear()
                    statusLabel.updateContent("Audit records cleared")
                    refresh()
                }
            }
        }
        add(AdaptiveButtonPanel(listOf(refreshButton, copyDiagnosticsButton, copyAuditButton, clearAuditButton)))
        add(statusLabel)
    }

    private fun refresh() {
        diagnosticsArea.text = runCatching {
            formatMcpDiagnostics(
                diagnostics = diagnosticsProvider(),
                readOnlyMode = config.emergencyReadOnlyMode,
                auditEnabled = config.auditLoggingEnabled,
                auditEntries = auditLog.size(),
                auditRetention = config.auditRetentionEntries.coerceIn(
                    MIN_AUDIT_RETENTION_ENTRIES,
                    MAX_AUDIT_RETENTION_ENTRIES,
                ),
                proxyProvenance = proxyProvenance,
                proxyVerified = proxyVerified,
            )
        }.getOrElse { error ->
            "Diagnostics unavailable: ${error::class.simpleName ?: "Exception"}"
        }
        diagnosticsArea.caretPosition = 0
    }

    private fun copyToClipboard(value: String, success: String) {
        runCatching {
            Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(value), null)
        }.onSuccess {
            statusLabel.updateContent(success)
        }.onFailure {
            statusLabel.updateContent("Could not access the system clipboard")
        }
    }
}

internal fun formatMcpDiagnostics(
    diagnostics: McpDiagnosticsSnapshot,
    readOnlyMode: Boolean,
    auditEnabled: Boolean,
    auditEntries: Int,
    auditRetention: Int = DEFAULT_AUDIT_RETENTION_ENTRIES,
    proxyProvenance: ProxyProvenance?,
    proxyVerified: Boolean,
): String = buildString {
    appendLine("State: ${diagnostics.state}")
    appendLine("Endpoint: ${diagnostics.endpoint ?: "not bound"}")
    appendLine("Server: burp-suite ${diagnostics.serverVersion}")
    appendLine("Protocol target: ${diagnostics.protocolVersion}")
    appendLine("Started: ${diagnostics.startedAtEpochMillis.asInstantOrNever()}")
    appendLine("Last MCP activity: ${diagnostics.lastActivityEpochMillis.asInstantOrNever()}")
    appendLine("HTTP calls: ${diagnostics.activeHttpCalls}/${diagnostics.maxHttpCalls} active, peak ${diagnostics.peakHttpCalls}")
    appendLine(
        "Sessions: ${diagnostics.activeSessions} active + ${diagnostics.pendingSessions} pending / ${diagnostics.maxSessions}"
    )
    appendLine(
        "Session approvals: ${diagnostics.sessionApprovalGrants} grants across " +
            "${diagnostics.sessionsWithApprovals} active sessions"
    )
    appendLine(
        "Event streams: ${diagnostics.activeEventStreams} active, ${diagnostics.openedEventStreams} opened, " +
            "${diagnostics.closedEventStreams} closed, ${diagnostics.reopenedEventStreams} reopened"
    )
    appendLine(
        "Liveness: pings=${diagnostics.livenessPingsSent}, responses=${diagnostics.livenessResponses}, " +
            "timeouts=${diagnostics.livenessTimeouts}, errors=${diagnostics.livenessErrors}, " +
            "heartbeat-failures=${diagnostics.heartbeatFailures}"
    )
    appendLine(
        "Session cleanup: DELETE=${diagnostics.sessionDeleteRequests}, " +
            "pressure-evictions=${diagnostics.pressureEvictions}, idle-evictions=${diagnostics.idleEvictions}"
    )
    appendLine(
        "Totals: ${diagnostics.totalRequests} requests, ${diagnostics.initializedSessions} initialized sessions, " +
            "${diagnostics.idleEvictions} idle evictions"
    )
    appendLine(
        "Rejections: auth=${diagnostics.authenticationRejections}, host/origin=${diagnostics.hostOriginRejections}, " +
            "metadata=${diagnostics.metadataRejections}, overload=${diagnostics.overloadRejections}, " +
            "session-capacity=${diagnostics.sessionCapacityRejections}"
    )
    appendLine("Emergency read-only: ${if (readOnlyMode) "enabled" else "disabled"}")
    appendLine(
        "Redacted audit: ${if (auditEnabled) "enabled" else "disabled"}, $auditEntries/$auditRetention retained, max age 30 days"
    )
    if (proxyProvenance == null) {
        appendLine("Embedded proxy: provenance unavailable; verified=$proxyVerified")
    } else {
        appendLine("Embedded proxy: ${proxyProvenance.version}, verified=$proxyVerified")
        appendLine("Proxy commit: ${proxyProvenance.commit}")
        appendLine("Proxy SHA-256: ${proxyProvenance.sha256}")
    }
    diagnostics.lastError?.let { appendLine("Last safe error: ${safeSingleLine(it)}") }
}.trimEnd()

private fun Long?.asInstantOrNever(): String = this?.let { Instant.ofEpochMilli(it).toString() } ?: "never"
