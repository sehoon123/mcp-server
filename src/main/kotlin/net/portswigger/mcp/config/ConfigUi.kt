package net.portswigger.mcp.config

import io.ktor.util.network.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import net.portswigger.mcp.EdtWatchdogSnapshot
import net.portswigger.mcp.McpDiagnosticsSnapshot
import net.portswigger.mcp.McpServerStartupException
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.unavailableMcpDiagnosticsSnapshot
import net.portswigger.mcp.providers.ProxyProvenance
import net.portswigger.mcp.security.McpAuditSink
import net.portswigger.mcp.security.NoOpMcpAuditSink
import net.portswigger.mcp.security.safeExceptionSummary
import net.portswigger.mcp.security.safeSingleLine
import net.portswigger.mcp.Swing
import net.portswigger.mcp.config.components.*
import net.portswigger.mcp.providers.Provider
import java.awt.BorderLayout
import java.awt.Component.CENTER_ALIGNMENT
import java.awt.GridBagLayout
import javax.swing.*
import javax.swing.Box.*
import javax.swing.JOptionPane.ERROR_MESSAGE

class ConfigUi internal constructor(
    private val config: McpConfig,
    private val providers: List<Provider>,
    private val diagnosticsProvider: () -> McpDiagnosticsSnapshot,
    private val auditLog: McpAuditSink,
    private val proxyProvenance: ProxyProvenance?,
    private val proxyVerified: Boolean,
    private val clearSessionApprovals: () -> Int,
    private val edtWatchdogProvider: () -> EdtWatchdogSnapshot = { EdtWatchdogSnapshot() },
) {
    constructor(config: McpConfig, providers: List<Provider>) : this(
        config = config,
        providers = providers,
        diagnosticsProvider = ::unavailableMcpDiagnosticsSnapshot,
        auditLog = NoOpMcpAuditSink,
        proxyProvenance = null,
        proxyVerified = false,
        clearSessionApprovals = { 0 },
    )

    private val panel = JPanel(BorderLayout())
    private val extensionVersion = runCatching { diagnosticsProvider().serverVersion }.getOrDefault("unknown")
    val component: JComponent get() = panel

    private val listenerHandles = mutableListOf<ListenerHandle>()

    private val enabledToggle: ToggleSwitch = Design.createToggleSwitch(false) { enabled ->
        if (suppressToggleEvents) return@createToggleSwitch

        if (enabled) {
            ConfigValidation.validateServerConfig(hostField.text, portField.text)?.let { error ->
                validationErrorLabel.text = error
                validationErrorLabel.isVisible = true
                suppressToggleEvents = true
                enabledToggle.setState(false, animate = true)
                suppressToggleEvents = false
                return@createToggleSwitch
            }
        }

        validationErrorLabel.isVisible = false
        config.enabled = enabled
        toggleListener?.invoke(enabled)
    }
    private val validationErrorLabel = WarningLabel()
    private val hostField = JTextField(15)
    private val portField = JTextField(5)
    private val reinstallNotice = WarningLabel("Make sure to reinstall after changing server settings")

    private lateinit var serverConfigurationPanel: ServerConfigurationPanel
    private lateinit var advancedOptionsPanel: AdvancedOptionsPanel
    private lateinit var autoApproveTargetsPanel: AutoApproveTargetsPanel
    private lateinit var diagnosticsPanel: DiagnosticsPanel
    private lateinit var installationPanel: InstallationPanel

    private var toggleListener: ((Boolean) -> Unit)? = null
    private var suppressToggleEvents: Boolean = false

    private val dataAccessRefreshListener: () -> Unit = {
        serverConfigurationPanel.updateDataAccessCheckboxes()
    }
    private val requestActionApprovalRefreshListener: () -> Unit = {
        serverConfigurationPanel.updateRequestActionApprovalCheckbox()
    }
    private val scopeChangeApprovalRefreshListener: () -> Unit = {
        serverConfigurationPanel.updateScopeChangeApprovalCheckbox()
    }

    init {
        enabledToggle.setState(config.enabled, animate = false)
        hostField.text = config.host
        portField.text = config.port.toString()

        initializeComponents()
        buildUi()
    }

    private fun initializeComponents() {
        serverConfigurationPanel = ServerConfigurationPanel(
            config = config, enabledToggle = enabledToggle, validationErrorLabel = validationErrorLabel
        )

        advancedOptionsPanel = AdvancedOptionsPanel(
            config = config,
            hostField = hostField,
            portField = portField,
            reinstallNotice = reinstallNotice,
        )

        autoApproveTargetsPanel = AutoApproveTargetsPanel(config = config)

        diagnosticsPanel = DiagnosticsPanel(
            config = config,
            diagnosticsProvider = diagnosticsProvider,
            auditLog = auditLog,
            proxyProvenance = proxyProvenance,
            proxyVerified = proxyVerified,
            clearSessionApprovals = clearSessionApprovals,
            onPersistentApprovalsReset = serverConfigurationPanel::updatePersistentApprovalControls,
            edtWatchdogProvider = edtWatchdogProvider,
        )

        installationPanel = InstallationPanel(
            config = config, providers = providers, reinstallNotice = reinstallNotice, parentComponent = panel
        )

        setupConfigListeners()
    }

    private fun setupConfigListeners() {
        listenerHandles += config.addDataAccessChangeListener(dataAccessRefreshListener)
        listenerHandles += config.addRequestActionApprovalChangeListener(requestActionApprovalRefreshListener)
        listenerHandles += config.addScopeChangeApprovalChangeListener(scopeChangeApprovalRefreshListener)
    }

    fun cleanup() {
        listenerHandles.forEach { it.remove() }
        listenerHandles.clear()

        if (::autoApproveTargetsPanel.isInitialized) {
            autoApproveTargetsPanel.cleanup()
        }
        if (::diagnosticsPanel.isInitialized) {
            diagnosticsPanel.cleanup()
        }
    }

    fun onEnabledToggled(listener: (Boolean) -> Unit) {
        toggleListener = listener
    }

    fun getConfig(): McpConfig {
        ConfigValidation.normalizeLoopbackHost(hostField.text)?.let {
            config.host = it
            hostField.text = it
        }
        portField.text.trim().toIntOrNull()?.let { config.port = it }
        return config
    }

    fun updateServerState(state: ServerState) {
        CoroutineScope(Dispatchers.Swing).launch {
            suppressToggleEvents = true

            val enableAdvancedOptions = state is ServerState.Stopped || state is ServerState.Failed
            if (::advancedOptionsPanel.isInitialized) {
                advancedOptionsPanel.setFieldsEnabled(enableAdvancedOptions)
            }

            when (state) {
                ServerState.Starting, ServerState.Stopping -> {
                    enabledToggle.isEnabled = false
                }

                ServerState.Running -> {
                    enabledToggle.isEnabled = true
                    enabledToggle.setState(true, animate = false)
                }

                ServerState.Stopped -> {
                    enabledToggle.isEnabled = true
                    enabledToggle.setState(false, animate = false)
                }

                is ServerState.Failed -> {
                    enabledToggle.isEnabled = true
                    enabledToggle.setState(false, animate = false)

                    val friendlyMessage = when (state.exception) {
                        is UnresolvedAddressException -> "Unable to resolve address"
                        is McpServerStartupException -> safeSingleLine(
                            state.exception.message ?: "MCP server startup failed"
                        )
                        else -> safeExceptionSummary(state.exception)
                    }

                    Dialogs.showMessageDialog(
                        panel, "Failed to start Burp MCP Server: $friendlyMessage", ERROR_MESSAGE
                    )
                }
            }

            suppressToggleEvents = false
        }
    }

    private fun buildUi() {
        val leftPanel = JPanel(GridBagLayout())

        val headerBox = createVerticalBox().apply {
            add(JLabel("Burp MCP Server").apply {
                font = Design.Typography.headlineMedium
                foreground = Design.Colors.onSurface
                alignmentX = CENTER_ALIGNMENT
            })
            add(createVerticalStrut(Design.Spacing.MD))
            add(JLabel("Burp MCP Server exposes Burp tooling to AI clients.").apply {
                font = Design.Typography.bodyLarge
                foreground = Design.Colors.onSurfaceVariant
                alignmentX = CENTER_ALIGNMENT
            })
            add(createVerticalStrut(Design.Spacing.SM))
            add(JLabel(formatMcpVersionLabel(extensionVersion)).apply {
                font = Design.Typography.labelMedium
                foreground = Design.Colors.onSurfaceVariant
                alignmentX = CENTER_ALIGNMENT
            })
            add(createVerticalStrut(Design.Spacing.MD))
            add(
                Anchor(
                    text = "Learn more about the Model Context Protocol",
                    url = "https://modelcontextprotocol.io/introduction"
                ).apply { alignmentX = CENTER_ALIGNMENT })
        }

        leftPanel.add(headerBox)

        val rightPanelContent = WidthTrackingPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            background = Design.Colors.surface
            border = BorderFactory.createEmptyBorder(
                Design.Spacing.LG, Design.Spacing.LG, Design.Spacing.LG, Design.Spacing.LG
            )
        }

        val rightPanel = JScrollPane(rightPanelContent).apply {
            border = null
            background = Design.Colors.surface
            viewport.background = Design.Colors.surface
            verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            verticalScrollBar.unitIncrement = 16
        }

        rightPanelContent.add(serverConfigurationPanel)
        rightPanelContent.add(createVerticalStrut(Design.Spacing.LG))

        rightPanelContent.add(autoApproveTargetsPanel)

        rightPanelContent.add(createVerticalStrut(15))
        rightPanelContent.add(advancedOptionsPanel)
        rightPanelContent.add(createVerticalStrut(Design.Spacing.LG))
        rightPanelContent.add(diagnosticsPanel)
        rightPanelContent.add(createVerticalGlue())
        rightPanelContent.add(reinstallNotice)
        rightPanelContent.add(createVerticalStrut(10))

        rightPanelContent.add(installationPanel)

        val columnsPanel = ResponsiveColumnsPanel(leftPanel, rightPanel)
        panel.add(columnsPanel, BorderLayout.CENTER)
    }
}

internal fun formatMcpVersionLabel(version: String): String =
    "Extension version: ${safeSingleLine(version, 64).ifBlank { "unknown" }}"
