package net.portswigger.mcp.config

import io.ktor.util.network.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import net.portswigger.mcp.EdtWatchdogSnapshot
import net.portswigger.mcp.McpDiagnosticsSnapshot
import net.portswigger.mcp.McpServerStartupException
import net.portswigger.mcp.ProductIdentity
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.unavailableMcpDiagnosticsSnapshot
import net.portswigger.mcp.presets.WorkflowPresetManagement
import net.portswigger.mcp.providers.ClaudeDesktopProvider
import net.portswigger.mcp.providers.ClientSetupEndpoint
import net.portswigger.mcp.providers.ConnectionDoctor
import net.portswigger.mcp.providers.DoctorListenerCode
import net.portswigger.mcp.providers.DoctorRequestConfig
import net.portswigger.mcp.providers.ManualProxyInstallerProvider
import net.portswigger.mcp.providers.ProxyProvenance
import net.portswigger.mcp.providers.doctorListenerCode
import net.portswigger.mcp.providers.streamableHttpEndpoint
import net.portswigger.mcp.security.McpAuditSink
import net.portswigger.mcp.security.NoOpMcpAuditSink
import net.portswigger.mcp.security.safeExceptionSummary
import net.portswigger.mcp.security.safeSingleLine
import net.portswigger.mcp.Swing
import net.portswigger.mcp.config.components.*
import net.portswigger.mcp.providers.Provider
import net.portswigger.mcp.providers.ProviderInstallConfig
import java.awt.BorderLayout
import java.awt.Component.CENTER_ALIGNMENT
import java.awt.GridBagLayout
import java.lang.reflect.InvocationTargetException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import javax.swing.*
import javax.swing.Box.*
import javax.swing.JOptionPane.ERROR_MESSAGE
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

class ConfigUi internal constructor(
    private val config: McpConfig,
    private val providers: List<Provider>,
    private val diagnosticsProvider: () -> McpDiagnosticsSnapshot,
    private val auditLog: McpAuditSink,
    private val proxyProvenance: ProxyProvenance?,
    private val proxyVerified: Boolean,
    private val clearSessionApprovals: () -> Int,
    private val edtWatchdogProvider: () -> EdtWatchdogSnapshot = { EdtWatchdogSnapshot() },
    private val connectionDoctor: ConnectionDoctor = ConnectionDoctor(),
    private val workflowPresetManager: WorkflowPresetManagement? = null,
    private val cleanupErrorReporter: (String) -> Unit = {},
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
    private val initialDiagnosticsUiState = runCatching { diagnosticsProvider() }
        .getOrNull()
        ?.let { snapshot -> snapshot.serverVersion to doctorListenerCode(snapshot.state) }
        ?: ("unknown" to DoctorListenerCode.UNAVAILABLE)
    private val extensionVersion = initialDiagnosticsUiState.first
    private var lastDoctorListenerCode = initialDiagnosticsUiState.second
    val component: JComponent get() = panel

    private val listenerHandles = CopyOnWriteArrayList<ListenerHandle>()
    private val cleanupStarted = AtomicBoolean()

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
        try {
            if (::clientSetupPanel.isInitialized) {
                clientSetupPanel.markDoctorResultStale(DoctorResultStaleReason.LISTENER_STATE_CHANGED)
            }
        } finally {
            toggleListener?.invoke(enabled)
        }
    }
    private val validationErrorLabel = WarningLabel()
    private val hostField = JTextField(15).apply { name = "serverHostField" }
    private val portField = JTextField(5).apply { name = "serverPortField" }
    private val reinstallNotice = WarningLabel("Make sure to reinstall after changing server settings")

    private lateinit var serverConfigurationPanel: ServerConfigurationPanel
    private lateinit var advancedOptionsPanel: AdvancedOptionsPanel
    private lateinit var autoApproveTargetsPanel: AutoApproveTargetsPanel
    private lateinit var diagnosticsPanel: DiagnosticsPanel
    private lateinit var workflowPresetPanel: WorkflowPresetPanel
    private lateinit var clientSetupPanel: ClientSetupPanel

    private var toggleListener: ((Boolean) -> Unit)? = null
    private var suppressToggleEvents: Boolean = false
    private var endpointDocumentListenersInstalled = false

    private val endpointChangeListener = object : DocumentListener {
        override fun insertUpdate(event: DocumentEvent?) = endpointChanged()
        override fun removeUpdate(event: DocumentEvent?) = endpointChanged()
        override fun changedUpdate(event: DocumentEvent?) = endpointChanged()

        private fun endpointChanged() {
            if (::clientSetupPanel.isInitialized) clientSetupPanel.markEndpointStale()
        }
    }
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
            onBearerTokenRotationAttempted = {
                if (::clientSetupPanel.isInitialized) {
                    clientSetupPanel.markDoctorResultStale(
                        DoctorResultStaleReason.CREDENTIAL_ROTATION_ATTEMPTED,
                    )
                }
            },
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

        require(
            providers.all { it is ClaudeDesktopProvider || it is ManualProxyInstallerProvider } &&
                providers.count { it is ClaudeDesktopProvider } <= 1 &&
                providers.count { it is ManualProxyInstallerProvider } <= 1
        ) { "Client setup providers must be the unique supported Claude Desktop and manual proxy providers" }
        workflowPresetManager?.let { manager ->
            workflowPresetPanel = WorkflowPresetPanel(
                management = manager,
                parentComponent = panel,
            )
        }

        val claudeDesktopProvider = providers.filterIsInstance<ClaudeDesktopProvider>().singleOrNull()
        val manualProxyProvider = providers.filterIsInstance<ManualProxyInstallerProvider>().singleOrNull()
        clientSetupPanel = ClientSetupPanel(
            initialEndpoint = initialClientSetupEndpoint(),
            claudeDesktopInstaller = claudeDesktopProvider,
            prepareProxyExtraction = manualProxyProvider?.let { provider -> provider::prepareExtraction },
            reinstallNotice = reinstallNotice,
            parentComponent = panel,
            endpointProvider = ::clientSetupEndpointSnapshot,
            installConfigProvider = ::providerInstallSnapshot,
            doctorConfigProvider = ::doctorRequestSnapshot,
            connectionDoctor = connectionDoctor,
        )

        setupConfigListeners()
    }

    private fun setupConfigListeners() {
        listenerHandles += config.addDataAccessChangeListener(dataAccessRefreshListener)
        listenerHandles += config.addRequestActionApprovalChangeListener(requestActionApprovalRefreshListener)
        listenerHandles += config.addScopeChangeApprovalChangeListener(scopeChangeApprovalRefreshListener)
        hostField.document.addDocumentListener(endpointChangeListener)
        portField.document.addDocumentListener(endpointChangeListener)
        endpointDocumentListenersInstalled = true
    }

    fun cleanup() {
        if (!cleanupStarted.compareAndSet(false, true)) return
        if (SwingUtilities.isEventDispatchThread()) {
            cleanupOnEdt()
            return
        }
        try {
            SwingUtilities.invokeAndWait(::cleanupOnEdt)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            SwingUtilities.invokeLater(::cleanupOnEdt)
        } catch (_: InvocationTargetException) {
            cleanupStarted.set(false)
            reportCleanupFailure()
        }
    }

    private fun cleanupOnEdt() {
        check(SwingUtilities.isEventDispatchThread()) { "MCP configuration UI cleanup must run on the EDT" }
        var failed = false
        fun cleanupStep(action: () -> Unit) {
            try {
                action()
            } catch (_: Exception) {
                failed = true
            }
        }

        val handles = listenerHandles.toList()
        listenerHandles.clear()
        handles.forEach { handle -> cleanupStep(handle::remove) }
        if (endpointDocumentListenersInstalled) {
            cleanupStep {
                hostField.document.removeDocumentListener(endpointChangeListener)
                portField.document.removeDocumentListener(endpointChangeListener)
            }
            endpointDocumentListenersInstalled = false
        }

        if (::autoApproveTargetsPanel.isInitialized) {
            cleanupStep(autoApproveTargetsPanel::cleanup)
        }
        if (::diagnosticsPanel.isInitialized) {
            cleanupStep(diagnosticsPanel::cleanup)
        }
        if (::workflowPresetPanel.isInitialized) {
            cleanupStep(workflowPresetPanel::cleanup)
        }
        if (::clientSetupPanel.isInitialized) {
            cleanupStep(clientSetupPanel::cleanup)
        }
        if (failed) reportCleanupFailure()
    }

    private fun reportCleanupFailure() {
        runCatching { cleanupErrorReporter("MCP configuration UI cleanup failed") }
    }

    /** Cancels panel-owned work before the listener begins shutting down. Full cleanup remains idempotent. */
    fun cancelBackgroundWork() {
        if (::workflowPresetPanel.isInitialized) {
            workflowPresetPanel.cancelBackgroundWorkAndAwait()
        }
        if (::clientSetupPanel.isInitialized) {
            clientSetupPanel.cancelBackgroundWork()
        }
    }

    private fun initialClientSetupEndpoint(): ClientSetupEndpoint? = runCatching {
        ClientSetupEndpoint.from(config.host, config.port)
    }.getOrNull()

    private fun clientSetupEndpointSnapshot(): ClientSetupEndpoint {
        check(SwingUtilities.isEventDispatchThread()) { "client endpoint must be captured on the EDT" }
        val hostText = hostField.text
        val portText = portField.text
        ConfigValidation.validateServerConfig(hostText, portText)?.let { error ->
            throw IllegalArgumentException(error)
        }
        val port = requireNotNull(portText.trim().toIntOrNull()) { "MCP endpoint port is invalid" }
        return ClientSetupEndpoint.from(hostText, port)
    }

    private fun doctorRequestSnapshot(): DoctorRequestConfig {
        check(SwingUtilities.isEventDispatchThread()) { "Connection Doctor configuration must be captured on the EDT" }
        val diagnostics = runCatching { diagnosticsProvider() }.getOrNull()
        val listener = doctorListenerCode(diagnostics?.state)
        val endpoint = runCatching { clientSetupEndpointSnapshot() }.getOrNull()
            ?: return DoctorRequestConfig(
                host = "",
                port = 0,
                bearerToken = null,
                listener = listener,
                configurationValid = false,
            )
        val displayedEndpoint = streamableHttpEndpoint(endpoint.host, endpoint.port)
        val endpointMatchesListener = listener != DoctorListenerCode.RUNNING || diagnostics?.endpoint == displayedEndpoint
        val token = if (listener == DoctorListenerCode.RUNNING && endpointMatchesListener) {
            config.localBearerToken
        } else {
            null
        }
        return DoctorRequestConfig(
            endpoint.host,
            endpoint.port,
            token,
            listener,
            endpointMatchesListener = endpointMatchesListener,
        )
    }

    private fun providerInstallSnapshot(): ProviderInstallConfig {
        check(SwingUtilities.isEventDispatchThread()) { "provider configuration must be captured on the EDT" }
        val hostText = hostField.text
        val portText = portField.text
        ConfigValidation.validateServerConfig(hostText, portText)?.let { error ->
            throw IllegalArgumentException(error)
        }
        val host = requireNotNull(ConfigValidation.normalizeLoopbackHost(hostText)) {
            "MCP endpoint host must be 127.0.0.1 or ::1"
        }
        val port = requireNotNull(portText.trim().toIntOrNull()) { "MCP endpoint port is invalid" }
        return ProviderInstallConfig(host, port, config.localBearerToken)
    }

    fun onEnabledToggled(listener: (Boolean) -> Unit) {
        toggleListener = listener
    }

    fun getConfig(): McpConfig {
        ConfigValidation.normalizeLoopbackHost(hostField.text)?.let {
            config.host = it
            if (hostField.text != it) hostField.text = it
        }
        portField.text.trim().toIntOrNull()?.let { config.port = it }
        return config
    }

    fun updateServerState(state: ServerState) {
        CoroutineScope(Dispatchers.Swing).launch {
            suppressToggleEvents = true

            val nextDoctorListenerCode = state.toDoctorListenerCode()
            if (nextDoctorListenerCode != lastDoctorListenerCode) {
                lastDoctorListenerCode = nextDoctorListenerCode
                if (::clientSetupPanel.isInitialized) {
                    clientSetupPanel.markDoctorResultStale(DoctorResultStaleReason.LISTENER_STATE_CHANGED)
                }
            }

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
                        panel, "Failed to start ${ProductIdentity.PRODUCT_NAME}: $friendlyMessage", ERROR_MESSAGE
                    )
                }
            }

            suppressToggleEvents = false
        }
    }

    private fun buildUi() {
        val leftPanel = JPanel(GridBagLayout())

        val headerBox = createVerticalBox().apply {
            add(JLabel(ProductIdentity.PRODUCT_NAME).apply {
                font = Design.Typography.headlineMedium
                foreground = Design.Colors.onSurface
                alignmentX = CENTER_ALIGNMENT
            })
            add(createVerticalStrut(Design.Spacing.MD))
            add(JLabel("Exposes Burp tooling to AI clients through MCP.").apply {
                font = Design.Typography.bodyLarge
                foreground = Design.Colors.onSurfaceVariant
                alignmentX = CENTER_ALIGNMENT
            })
            add(createVerticalStrut(Design.Spacing.SM))
            add(JLabel(ProductIdentity.UNOFFICIAL_NOTICE).apply {
                font = Design.Typography.labelMedium
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
        if (::workflowPresetPanel.isInitialized) {
            rightPanelContent.add(createVerticalStrut(Design.Spacing.LG))
            rightPanelContent.add(workflowPresetPanel)
        }
        rightPanelContent.add(createVerticalGlue())
        rightPanelContent.add(reinstallNotice)
        rightPanelContent.add(createVerticalStrut(10))

        rightPanelContent.add(clientSetupPanel)

        val columnsPanel = ResponsiveColumnsPanel(leftPanel, rightPanel)
        panel.add(columnsPanel, BorderLayout.CENTER)
    }
}

private fun ServerState.toDoctorListenerCode(): DoctorListenerCode = when (this) {
    ServerState.Starting -> DoctorListenerCode.STARTING
    ServerState.Running -> DoctorListenerCode.RUNNING
    ServerState.Stopping -> DoctorListenerCode.STOPPING
    ServerState.Stopped -> DoctorListenerCode.STOPPED
    is ServerState.Failed -> DoctorListenerCode.FAILED
}

internal fun formatMcpVersionLabel(version: String): String =
    "Extension version: ${safeSingleLine(version, 64).ifBlank { "unknown" }}"
