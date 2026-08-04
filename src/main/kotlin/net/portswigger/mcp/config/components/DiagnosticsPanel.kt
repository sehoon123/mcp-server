package net.portswigger.mcp.config.components

import net.portswigger.mcp.EdtWatchdogSnapshot
import net.portswigger.mcp.McpDiagnosticsSnapshot
import net.portswigger.mcp.ProductIdentity
import net.portswigger.mcp.config.DEFAULT_AUDIT_RETENTION_ENTRIES
import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.MAX_AUDIT_RETENTION_ENTRIES
import net.portswigger.mcp.config.MIN_AUDIT_RETENTION_ENTRIES
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.providers.ProxyProvenance
import net.portswigger.mcp.security.McpAuditSink
import net.portswigger.mcp.tools.HISTORY_PERFORMANCE_BUCKET_UPPER_MILLIS
import net.portswigger.mcp.tools.HistoryPerformanceMetric
import net.portswigger.mcp.security.safeSingleLine
import java.awt.FlowLayout
import java.awt.Font
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.time.Instant
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
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
    private val edtWatchdogProvider: () -> EdtWatchdogSnapshot = { EdtWatchdogSnapshot() },
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

        add(createSecurityToggle(
            text = "Emergency read-only mode",
            description = "Blocks tools that are not explicitly marked read-only",
            initialValue = config.emergencyReadOnlyMode,
            unsafeConfirmationTitle = "Disable Emergency read-only mode",
            unsafeConfirmation = "Authenticated MCP sessions may use mutation and active-action tools again. " +
                "Disable Emergency read-only mode?",
            currentValue = { config.emergencyReadOnlyMode },
            failureStatus = "Could not update Emergency read-only mode",
            onChange = { config.emergencyReadOnlyMode = it },
            onPersisted = { enabled ->
                auditLog.recordLocalEvent(
                    tool = "emergency_read_only_mode",
                    outcome = if (enabled) "enabled" else "disabled",
                )
            },
        ))
        add(WrappingText("Blocks tools that are not explicitly marked read-only."))
        add(WrappingText(
            "Existing Scanner work is not cancelled; new mutation, routing, generation, and active actions are blocked."
        ))
        add(Box.createVerticalStrut(Design.Spacing.SM))

        add(createSecurityToggle(
            text = "Persist bounded redacted MCP audit records",
            description = "Retains bounded, redacted records of MCP activity in Burp settings",
            initialValue = config.auditLoggingEnabled,
            unsafeConfirmationTitle = "Disable MCP audit persistence",
            unsafeConfirmation = "Future MCP activity will not be retained in the bounded redacted audit. " +
                "Disable MCP audit persistence?",
            currentValue = { config.auditLoggingEnabled },
            failureStatus = "Could not update MCP audit persistence",
            onChange = { config.auditLoggingEnabled = it },
            onPersisted = { enabled ->
                if (enabled) auditLog.recordLocalEvent("audit_logging", "enabled")
                else auditLog.recordAuditDisabled()
            },
        ))

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

        val resetSessionApprovalsButton = Design.createOutlinedButton("Reset active session approvals").apply {
            accessibleContext.accessibleDescription = "Remove all in-memory MCP session approval grants"
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
        val resetPersistentApprovalsButton = Design.createOutlinedButton("Reset all persistent approvals...").apply {
            accessibleContext.accessibleDescription =
                "After confirmation, restore persistent MCP approval policies to prompt-by-default"
            addActionListener {
                val choice = Dialogs.showConfirmDialog(
                    this@DiagnosticsPanel,
                    "Restore all MCP approval policies to prompt-by-default? " +
                        "This disables YOLO mode and clears saved HTTP targets and all persistent approval bypasses.",
                    JOptionPane.OK_CANCEL_OPTION,
                    "Reset persistent MCP approvals",
                )
                if (choice == JOptionPane.OK_OPTION) {
                    val reset = runCatching { config.resetPersistentApprovals() }
                    val reconciled = runCatching {
                        onPersistentApprovalsReset()
                        refresh()
                    }
                    if (reset.isSuccess && reconciled.isSuccess) {
                        auditLog.recordLocalEvent("persistent_approvals", "reset_to_prompt")
                        statusLabel.updateContent("Persistent approvals reset to prompt-by-default")
                    } else {
                        statusLabel.updateContent("Could not reset persistent approvals")
                    }
                }
            }
        }
        add(AdaptiveButtonPanel(listOf(resetSessionApprovalsButton, resetPersistentApprovalsButton)))
        add(Box.createVerticalStrut(Design.Spacing.SM))

        val refreshButton = Design.createOutlinedButton("Refresh").apply {
            accessibleContext.accessibleDescription = "Refresh the displayed redacted MCP diagnostics"
            addActionListener { refresh() }
        }
        val copyDiagnosticsButton = Design.createOutlinedButton("Copy redacted diagnostics").apply {
            accessibleContext.accessibleDescription =
                "Copy the displayed redacted MCP diagnostics to the system clipboard"
            addActionListener { copyToClipboard(diagnosticsArea.text, "Diagnostics copied") }
        }
        val copyAuditButton = Design.createOutlinedButton("Copy recent redacted audit").apply {
            accessibleContext.accessibleDescription =
                "Copy up to 100 recent redacted MCP audit records to the system clipboard"
            addActionListener {
                val exported = auditLog.exportJsonLines(100)
                if (exported.isEmpty()) statusLabel.updateContent("No audit records to copy")
                else copyToClipboard(exported, "Recent redacted audit copied")
            }
        }
        val clearAuditButton = Design.createSemanticOutlinedButton("Clear audit...") { Design.Colors.error }.apply {
            accessibleContext.accessibleDescription =
                "After confirmation, permanently delete all persisted MCP audit records"
            addActionListener {
                val choice = Dialogs.showConfirmDialog(
                    this@DiagnosticsPanel,
                    "Delete all persisted MCP audit records? This cannot be undone.",
                    JOptionPane.OK_CANCEL_OPTION,
                    "Clear MCP audit",
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

    private fun createSecurityToggle(
        text: String,
        description: String,
        initialValue: Boolean,
        unsafeConfirmationTitle: String,
        unsafeConfirmation: String,
        currentValue: () -> Boolean,
        failureStatus: String,
        onChange: (Boolean) -> Unit,
        onPersisted: (Boolean) -> Unit,
    ): JCheckBox = JCheckBox(text).apply {
        isOpaque = false
        isSelected = initialValue
        alignmentX = LEFT_ALIGNMENT
        accessibleContext.accessibleDescription = description
        addActionListener {
            val selected = isSelected
            if (!selected && !confirmUnsafeSelection(unsafeConfirmationTitle, unsafeConfirmation)) {
                isSelected = runCatching(currentValue).getOrDefault(true)
                return@addActionListener
            }
            try {
                onChange(selected)
            } catch (_: Exception) {
                isSelected = runCatching(currentValue).getOrDefault(!selected)
                statusLabel.updateContent(failureStatus)
                refresh()
                return@addActionListener
            }
            statusLabel.updateContent(" ")
            onPersisted(selected)
            refresh()
        }
    }

    private fun confirmUnsafeSelection(title: String, message: String): Boolean = try {
        Dialogs.showConfirmDialog(
            this@DiagnosticsPanel,
            message,
            JOptionPane.YES_NO_OPTION,
            title,
        ) == JOptionPane.YES_OPTION
    } catch (_: Exception) {
        false
    }

    private fun refresh() {
        diagnosticsArea.text = runCatching {
            formatMcpDiagnostics(
                diagnostics = diagnosticsProvider(),
                readOnlyMode = config.emergencyReadOnlyMode,
                yoloMode = config.approvalYoloMode,
                auditEnabled = config.auditLoggingEnabled,
                auditEntries = auditLog.size(),
                auditRetention = config.auditRetentionEntries.coerceIn(
                    MIN_AUDIT_RETENTION_ENTRIES,
                    MAX_AUDIT_RETENTION_ENTRIES,
                ),
                proxyProvenance = proxyProvenance,
                proxyVerified = proxyVerified,
                edtWatchdog = edtWatchdogProvider(),
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
    yoloMode: Boolean = false,
    auditEnabled: Boolean,
    auditEntries: Int,
    auditRetention: Int = DEFAULT_AUDIT_RETENTION_ENTRIES,
    proxyProvenance: ProxyProvenance?,
    proxyVerified: Boolean,
    edtWatchdog: EdtWatchdogSnapshot = EdtWatchdogSnapshot(),
): String = buildString {
    appendLine("State: ${diagnostics.state}")
    appendLine("Endpoint: ${diagnostics.endpoint ?: "not bound"}")
    appendLine("Server: ${ProductIdentity.MCP_SERVER_NAME} ${diagnostics.serverVersion}")
    appendLine("Loaded artifact SHA-256: ${diagnostics.loadedArtifactSha256 ?: "unavailable"}")
    appendLine("Protocol target: ${diagnostics.protocolVersion}")
    appendLine("Started: ${diagnostics.startedAtEpochMillis.asInstantOrNever()}")
    appendLine("Last MCP activity: ${diagnostics.lastActivityEpochMillis.asInstantOrNever()}")
    appendLine(
        "Swing EDT delay: samples=${edtWatchdog.samples}, " +
            "coalesced=${edtWatchdog.coalescedProbes}, " +
            ">=100ms=${edtWatchdog.delaysAtLeast100Millis}, " +
            ">=250ms=${edtWatchdog.delaysAtLeast250Millis}, " +
            ">=1s=${edtWatchdog.delaysAtLeast1Second}, " +
            "max=${edtWatchdog.maxDelayMillis}ms, errors=${edtWatchdog.errors}",
    )
    diagnostics.historyPerformance.metrics.forEach { metric ->
        appendLine(
            "History ${metric.metric.displayLabel()}: active=${metric.active}, attempts=${metric.attempts}, " +
                "completed=${metric.completed}, failed=${metric.failed}, cancelled=${metric.cancelled}, " +
                "total=${metric.totalNanos}ns, max=${metric.maxNanos}ns, " +
                "buckets=${metric.latencyBuckets.formatHistoryBuckets()}",
        )
    }
    appendLine(
        "WebSocket search outcomes: active=${diagnostics.webSocketSearchActive}, " +
            "completed=${diagnostics.webSocketSearchCompleted}, cancelled=${diagnostics.webSocketSearchCancelled}",
    )
    appendLine("HTTP calls: ${diagnostics.activeHttpCalls}/${diagnostics.maxHttpCalls} active, peak ${diagnostics.peakHttpCalls}")
    appendLine(
        "Sessions: ${diagnostics.activeSessions} active + ${diagnostics.pendingSessions} pending / ${diagnostics.maxSessions}"
    )
    appendLine(
        "Session approvals: ${diagnostics.sessionApprovalGrants} grants across " +
            "${diagnostics.sessionsWithApprovals} active sessions"
    )
    appendLine("Project changes observed: ${diagnostics.projectBoundaryResets}")
    appendLine(
        "Initialized session protocol requests: 2025-03-26=${diagnostics.initializedWithProtocol20250326}, " +
            "2025-06-18=${diagnostics.initializedWithProtocol20250618}, " +
            "2025-11-25=${diagnostics.initializedWithProtocol20251125}, " +
            "other=${diagnostics.initializedWithOtherProtocol}, " +
            "not-reported=${diagnostics.initializedWithoutProtocolHeader}"
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
    appendLine("YOLO approval bypass: ${if (yoloMode) "enabled" else "disabled"}")
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

private fun HistoryPerformanceMetric.displayLabel(): String = when (this) {
    HistoryPerformanceMetric.INDEX_PROXY_ACQUISITION -> "index Proxy acquisition"
    HistoryPerformanceMetric.INDEX_PROXY_PROCESSING -> "index Proxy processing"
    HistoryPerformanceMetric.INDEX_SITE_MAP_ACQUISITION -> "index Site Map acquisition"
    HistoryPerformanceMetric.INDEX_SITE_MAP_PROCESSING -> "index Site Map processing"
    HistoryPerformanceMetric.INDEX_ORGANIZER_ACQUISITION -> "index Organizer acquisition"
    HistoryPerformanceMetric.INDEX_ORGANIZER_PROCESSING -> "index Organizer processing"
    HistoryPerformanceMetric.HTTP_SEARCH_PROXY_ACQUISITION -> "HTTP search Proxy acquisition"
    HistoryPerformanceMetric.HTTP_SEARCH_SITE_MAP_ACQUISITION -> "HTTP search Site Map acquisition"
    HistoryPerformanceMetric.HTTP_SEARCH_ORGANIZER_ACQUISITION -> "HTTP search Organizer acquisition"
    HistoryPerformanceMetric.HTTP_SEARCH_PROCESSING -> "HTTP search processing"
    HistoryPerformanceMetric.WEBSOCKET_SEARCH_ACQUISITION -> "WebSocket search acquisition"
    HistoryPerformanceMetric.WEBSOCKET_SEARCH_PROCESSING -> "WebSocket search processing"
    HistoryPerformanceMetric.RELATED_CORRELATION_MONTOYA_ACQUISITION -> "related correlation Montoya acquisition"
    HistoryPerformanceMetric.RELATED_CORRELATION_EXTENSION_PROCESSING -> "related correlation extension processing"
    HistoryPerformanceMetric.SCANNER_DELTA_MONTOYA_ACQUISITION -> "Scanner delta Montoya acquisition"
    HistoryPerformanceMetric.SCANNER_DELTA_EXTENSION_PROCESSING -> "Scanner delta extension processing"
}

private fun List<Long>.formatHistoryBuckets(): String = buildString {
    HISTORY_PERFORMANCE_BUCKET_UPPER_MILLIS.forEachIndexed { index, upperMillis ->
        if (index > 0) append(',')
        append('<').append(upperMillis).append("ms=")
            .append(this@formatHistoryBuckets.getOrElse(index) { 0 })
    }
    append(',').append(">=5000ms=")
        .append(this@formatHistoryBuckets.getOrElse(HISTORY_PERFORMANCE_BUCKET_UPPER_MILLIS.size) { 0 })
}
