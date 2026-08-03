package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Anchor
import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.providers.BEARER_TOKEN_ENVIRONMENT_VARIABLE
import net.portswigger.mcp.providers.ClientSetupCatalog
import net.portswigger.mcp.providers.ClientSetupDefinition
import net.portswigger.mcp.providers.ClientSetupEndpoint
import net.portswigger.mcp.providers.ClientSetupId
import net.portswigger.mcp.providers.ClientSetupTransport
import net.portswigger.mcp.providers.ConnectionDoctor
import net.portswigger.mcp.providers.DoctorListenerCode
import net.portswigger.mcp.providers.DoctorProbeCode
import net.portswigger.mcp.providers.DoctorReport
import net.portswigger.mcp.providers.DoctorRequestConfig
import net.portswigger.mcp.providers.Provider
import net.portswigger.mcp.providers.ProviderInstallConfig
import net.portswigger.mcp.providers.ProviderInstallOperation
import net.portswigger.mcp.providers.formatDoctorEvidence
import net.portswigger.mcp.providers.formatDoctorSummary
import net.portswigger.mcp.security.safeExceptionSummary
import java.awt.Dimension
import java.awt.Font
import java.awt.KeyboardFocusManager
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.awt.event.FocusAdapter
import java.awt.event.FocusEvent
import java.awt.event.InputEvent
import java.awt.event.KeyEvent
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Future
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.accessibility.AccessibleRelation
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.DefaultComboBoxModel
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JOptionPane.ERROR_MESSAGE
import javax.swing.JOptionPane.INFORMATION_MESSAGE
import javax.swing.JOptionPane.YES_NO_OPTION
import javax.swing.JOptionPane.YES_OPTION
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.KeyStroke
import javax.swing.SwingUtilities

internal fun interface ClientSetupClipboard {
    fun copy(value: String)
}

private const val SETUP_TEXT_FALLBACK_WIDTH = 480

internal enum class DoctorResultStaleReason {
    ENDPOINT_CHANGED,
    LISTENER_STATE_CHANGED,
    CREDENTIAL_ROTATION_ATTEMPTED,
}

private fun DoctorResultStaleReason.cause(): String = when (this) {
    DoctorResultStaleReason.ENDPOINT_CHANGED -> "the displayed endpoint changed"
    DoctorResultStaleReason.LISTENER_STATE_CHANGED -> "the local listener state changed"
    DoctorResultStaleReason.CREDENTIAL_ROTATION_ATTEMPTED -> "credential rotation was attempted"
}

private fun DoctorResultStaleReason.summary(): String =
    "The last started Connection Doctor local-admission check no longer applies because ${cause()}. " +
        "Run a new check when available. This check does not prove that an external client works."

private fun applyPreviewAreaStyle(area: JTextArea) {
    area.font = Font(Font.MONOSPACED, Font.PLAIN, Design.Typography.bodyMedium.size)
    area.foreground = Design.Colors.onSurface
    area.background = Design.Colors.surface
}

private object SystemClientSetupClipboard : ClientSetupClipboard {
    override fun copy(value: String) {
        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(value), null)
    }
}

internal class ClientSetupPanel(
    private val initialEndpoint: ClientSetupEndpoint?,
    private val claudeDesktopInstaller: Provider?,
    private val prepareProxyExtraction: (() -> ProviderInstallOperation?)?,
    private val reinstallNotice: WarningLabel,
    private val parentComponent: JComponent,
    private val endpointProvider: () -> ClientSetupEndpoint,
    private val installConfigProvider: () -> ProviderInstallConfig,
    private val doctorConfigProvider: () -> DoctorRequestConfig,
    private val connectionDoctor: ConnectionDoctor = ConnectionDoctor(),
    private val clipboard: ClientSetupClipboard = SystemClientSetupClipboard,
    private val definitions: List<ClientSetupDefinition> = ClientSetupCatalog.definitions,
) : JPanel() {
    private val closed = AtomicBoolean(false)
    private val actionExecutor = ThreadPoolExecutor(
        1,
        1,
        0L,
        TimeUnit.MILLISECONDS,
        ArrayBlockingQueue(1),
        { runnable -> Thread(runnable, "burp-mcp-client-setup").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )

    @Volatile
    private var activeFuture: Future<*>? = null
    private var actionInProgress = false
    private var currentEndpoint: ClientSetupEndpoint? = initialEndpoint
    private var doctorEvidence: String? = null
    // Opaque identity fences late results without retaining endpoint, listener, or credential values.
    private var doctorContextGeneration = Any()
    private var doctorHasStarted = false
    private var panelInitialized = false

    private val clientSelector = JComboBox(DefaultComboBoxModel(definitions.toTypedArray())).apply {
        name = "clientSetupSelector"
        maximumSize = Dimension(Int.MAX_VALUE, preferredSize.height)
        alignmentX = LEFT_ALIGNMENT
        accessibleContext.accessibleName = "MCP client"
        accessibleContext.accessibleDescription = "Selects a client-specific local setup preview"
    }
    private val clientLabel = JLabel("Client").apply {
        font = Design.Typography.labelLarge
        foreground = Design.Colors.onSurface
        alignmentX = LEFT_ALIGNMENT
        labelFor = clientSelector
    }
    private val transportText = WrappingText("", WrappingTextStyle.LABEL_MEDIUM)
    private val guidanceText = WrappingText(
        "",
        WrappingTextStyle.BODY_MEDIUM,
        fallbackMaxWidth = SETUP_TEXT_FALLBACK_WIDTH,
    )
    private val safetyText = WrappingText(
        "Safe preview only: copy the current token using the control above, then use it for $BEARER_TOKEN_ENVIRONMENT_VARIABLE or the client's password input. The current credential and resolved local filesystem paths are never included here. Refresh after changing the host or port, and compare this example with the documentation for your installed client version.",
        WrappingTextStyle.BODY_MEDIUM,
        fallbackMaxWidth = SETUP_TEXT_FALLBACK_WIDTH,
    )
    private val previewArea = object : JTextArea(12, 56) {
        override fun updateUI() {
            super.updateUI()
            applyPreviewAreaStyle(this)
        }
    }.apply {
        name = "clientSetupPreview"
        isEditable = false
        isFocusable = true
        lineWrap = false
        tabSize = 2
        focusTraversalKeysEnabled = true
        setFocusTraversalKeys(
            KeyboardFocusManager.FORWARD_TRAVERSAL_KEYS,
            setOf(KeyStroke.getKeyStroke(KeyEvent.VK_TAB, 0)),
        )
        setFocusTraversalKeys(
            KeyboardFocusManager.BACKWARD_TRAVERSAL_KEYS,
            setOf(KeyStroke.getKeyStroke(KeyEvent.VK_TAB, InputEvent.SHIFT_DOWN_MASK)),
        )
        border = BorderFactory.createEmptyBorder(
            Design.Spacing.SM,
            Design.Spacing.SM,
            Design.Spacing.SM,
            Design.Spacing.SM,
        )
        accessibleContext.accessibleName = "Client configuration preview"
        accessibleContext.accessibleDescription = "Read-only configuration preview without the current bearer credential"
    }
    private val previewLabel = JLabel("Configuration preview").apply {
        font = Design.Typography.labelLarge
        foreground = Design.Colors.onSurface
        alignmentX = LEFT_ALIGNMENT
        labelFor = previewArea
    }
    private val previewScroll = object : JScrollPane(previewArea) {
        override fun getMaximumSize(): Dimension = Dimension(Int.MAX_VALUE, preferredSize.height)
    }.apply {
        name = "clientSetupPreviewScroll"
        alignmentX = LEFT_ALIGNMENT
        verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
        horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED
        border = BorderFactory.createLineBorder(Design.Colors.outline, 1)
    }

    private val refreshPreviewButton = Design.createOutlinedButton("Refresh preview").apply {
        name = "refreshSetupPreviewButton"
        accessibleContext.accessibleDescription = "Refreshes the safe preview from the displayed numeric loopback host and port"
        addActionListener { refreshPreview() }
    }
    private val copyPreviewButton = Design.createOutlinedButton("Copy configuration").apply {
        name = "copySetupPreviewButton"
        accessibleContext.accessibleDescription = "Copies exactly the visible secret-free configuration preview"
        addActionListener { copyPreview() }
    }
    private val installClaudeButton = Design.createFilledButton(
        claudeDesktopInstaller?.installButtonText ?: "Install to Claude Desktop",
    ).apply {
        name = "installClaudeDesktopButton"
        accessibleContext.accessibleDescription = "Confirms and installs the current endpoint and bearer in Claude Desktop's private configuration"
        addActionListener { installClaudeDesktop() }
    }
    private val clientActionsHost = JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        isOpaque = false
        alignmentX = LEFT_ALIGNMENT
    }

    private val extractProxyButton = Design.createOutlinedButton("Extract proxy jar...").apply {
        name = "extractProxyJarButton"
        accessibleContext.accessibleDescription = "Selects a destination and extracts the verified stdio proxy without reading the bearer credential"
        addActionListener { extractProxyJar() }
    }
    private val runDoctorButton = Design.createFilledButton("Run Connection Doctor").apply {
        name = "runConnectionDoctorButton"
        accessibleContext.accessibleDescription = "Runs one bounded authenticated check against the configured numeric loopback MCP endpoint"
        addActionListener { runConnectionDoctor() }
    }
    private val copyEvidenceButton = Design.createOutlinedButton("Copy safe evidence").apply {
        name = "copyDoctorEvidenceButton"
        isEnabled = false
        accessibleContext.accessibleDescription =
            "Copies the fixed local-admission-only scope marker and controlled Connection Doctor result codes " +
                "without endpoint, credential, response, or path data. An external client is not tested. " +
                "Available only after a run that still matches the current endpoint, listener, and credential context."
        addActionListener { copyDoctorEvidence() }
    }
    private val doctorResultText = WrappingText(
        "Connection Doctor has not run. It checks local listener admission only, not a full MCP handshake or third-party client configuration.",
        WrappingTextStyle.BODY_MEDIUM,
        fallbackMaxWidth = SETUP_TEXT_FALLBACK_WIDTH,
    ).apply {
        name = "doctorResultText"
        accessibleContext.accessibleDescription = "Latest Connection Doctor result"
    }
    private val previewStatusText = WrappingText(
        "No preview action has run.",
        WrappingTextStyle.LABEL_MEDIUM,
    ).apply {
        name = "clientSetupPreviewStatus"
        accessibleContext.accessibleDescription = "Latest client preview or copy status"
    }
    private val actionStatusText = WrappingText(
        "No background client setup action has run.",
        WrappingTextStyle.LABEL_MEDIUM,
    ).apply {
        name = "clientSetupActionStatus"
        accessibleContext.accessibleDescription = "Latest installation, extraction, or Connection Doctor status"
    }

    init {
        require(definitions.map { it.id } == ClientSetupId.entries) {
            "Client Setup Center requires the exact ordered five-client catalog"
        }
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        alignmentX = LEFT_ALIGNMENT
        panelInitialized = true
        updateColors()
        updatePreviewStyle()
        buildPanel()
        installAccessibilityRelations()
        previewArea.addFocusListener(object : FocusAdapter() {
            override fun focusGained(event: FocusEvent?) = updatePreviewBorder(true)
            override fun focusLost(event: FocusEvent?) = updatePreviewBorder(false)
        })
        clientSelector.addActionListener { updateSelectedClient() }
        updateSelectedClient()
    }

    override fun updateUI() {
        super.updateUI()
        updateColors()
        if (panelInitialized) updatePreviewStyle()
    }

    fun cancelBackgroundWork() {
        if (!closed.compareAndSet(false, true)) return
        activeFuture?.cancel(true)
        actionExecutor.shutdownNow()
    }

    fun cleanup() = cancelBackgroundWork()

    fun markEndpointStale() {
        check(SwingUtilities.isEventDispatchThread()) { "client endpoint changes belong to the EDT" }
        if (closed.get()) return
        markDoctorResultStale(DoctorResultStaleReason.ENDPOINT_CHANGED)
        currentEndpoint = null
        renderPreview()
        showPreviewStatus("Host or port changed. Refresh the preview before copying configuration.")
    }

    fun markDoctorResultStale(reason: DoctorResultStaleReason) {
        check(SwingUtilities.isEventDispatchThread()) { "Connection Doctor freshness changes belong to the EDT" }
        if (closed.get()) return
        doctorContextGeneration = Any()
        doctorEvidence = null
        if (doctorHasStarted) {
            val staleSummary = reason.summary()
            if (doctorResultText.text != staleSummary) doctorResultText.updateContent(staleSummary)
        }
        updateMutationButtonState()
    }

    private fun updateColors() {
        background = Design.Colors.surface
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1),
            BorderFactory.createEmptyBorder(
                Design.Spacing.MD,
                Design.Spacing.MD,
                Design.Spacing.MD,
                Design.Spacing.MD,
            ),
        )
    }

    private fun updatePreviewStyle() {
        applyPreviewAreaStyle(previewArea)
        updatePreviewBorder(previewArea.isFocusOwner)
    }

    private fun updatePreviewBorder(focused: Boolean) {
        previewScroll.border = BorderFactory.createLineBorder(
            if (focused) Design.Colors.primary else Design.Colors.outline,
            1,
        )
    }

    private fun installAccessibilityRelations() {
        refreshPreviewButton.accessibleContext.accessibleRelationSet.add(
            AccessibleRelation(AccessibleRelation.CONTROLLER_FOR, previewStatusText),
        )
        copyPreviewButton.accessibleContext.accessibleRelationSet.add(
            AccessibleRelation(AccessibleRelation.CONTROLLER_FOR, previewStatusText),
        )
        previewStatusText.accessibleContext.accessibleRelationSet.add(
            AccessibleRelation(
                AccessibleRelation.CONTROLLED_BY,
                arrayOf(refreshPreviewButton, copyPreviewButton),
            ),
        )
        runDoctorButton.accessibleContext.accessibleRelationSet.add(
            AccessibleRelation(AccessibleRelation.CONTROLLER_FOR, doctorResultText),
        )
        doctorResultText.accessibleContext.accessibleRelationSet.add(
            AccessibleRelation(AccessibleRelation.CONTROLLED_BY, runDoctorButton),
        )
        val backgroundActionButtons = arrayOf(
            installClaudeButton,
            extractProxyButton,
            runDoctorButton,
            copyEvidenceButton,
        )
        backgroundActionButtons.forEach { button ->
            button.accessibleContext.accessibleRelationSet.add(
                AccessibleRelation(AccessibleRelation.CONTROLLER_FOR, actionStatusText),
            )
        }
        actionStatusText.accessibleContext.accessibleRelationSet.add(
            AccessibleRelation(AccessibleRelation.CONTROLLED_BY, backgroundActionButtons),
        )
    }

    private fun buildPanel() {
        add(Design.createSectionLabel("Client Setup Center"))
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(
            WrappingText(
                "Choose a client to preview its local setup. Only Claude Desktop has an automatic configuration installer; the other clients remain preview-and-copy only.",
                WrappingTextStyle.BODY_MEDIUM,
                fallbackMaxWidth = SETUP_TEXT_FALLBACK_WIDTH,
            ),
        )
        add(Box.createVerticalStrut(Design.Spacing.MD))
        add(clientLabel)
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(clientSelector)
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(transportText)
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(guidanceText)
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(safetyText)
        add(Box.createVerticalStrut(Design.Spacing.MD))
        add(previewLabel)
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(previewScroll)
        add(Box.createVerticalStrut(Design.Spacing.MD))
        add(clientActionsHost)
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(previewStatusText)
        add(Box.createVerticalStrut(Design.Spacing.MD))
        add(
            Anchor(
                text = "Open complete client setup guidance",
                url = "https://github.com/sehoon123/mcp-server?tab=readme-ov-file#configure-clients",
            ).apply { alignmentX = LEFT_ALIGNMENT },
        )

        if (prepareProxyExtraction != null) {
            add(Box.createVerticalStrut(Design.Spacing.LG))
            add(Design.createSectionLabel("Advanced/manual stdio"))
            add(Box.createVerticalStrut(Design.Spacing.SM))
            add(
                WrappingText(
                    "Extract the verified proxy jar only for a separately managed stdio setup. Native HTTP clients do not use this jar.",
                    WrappingTextStyle.BODY_MEDIUM,
                    fallbackMaxWidth = SETUP_TEXT_FALLBACK_WIDTH,
                ),
            )
            add(Box.createVerticalStrut(Design.Spacing.SM))
            add(AdaptiveButtonPanel(listOf(extractProxyButton)).apply { alignmentX = LEFT_ALIGNMENT })
        }

        add(Box.createVerticalStrut(Design.Spacing.LG))
        add(Design.createSectionLabel("Connection Doctor"))
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(
            WrappingText(
                "Runs one body-discarding, no-redirect request only while Burp reports the listener running. It creates no MCP session and returns controlled status text only.",
                WrappingTextStyle.BODY_MEDIUM,
                fallbackMaxWidth = SETUP_TEXT_FALLBACK_WIDTH,
            ),
        )
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(AdaptiveButtonPanel(listOf(runDoctorButton, copyEvidenceButton)).apply { alignmentX = LEFT_ALIGNMENT })
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(doctorResultText)
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(actionStatusText)
    }

    private fun selectedDefinition(): ClientSetupDefinition =
        requireNotNull(clientSelector.selectedItem as? ClientSetupDefinition)

    private fun updateSelectedClient() {
        val definition = selectedDefinition()
        transportText.updateContent(
            when (definition.transport) {
                ClientSetupTransport.STDIO_PROXY -> "Transport: verified local stdio proxy"
                ClientSetupTransport.NATIVE_HTTP -> "Transport: native Streamable HTTP"
            },
        )
        guidanceText.updateContent(definition.guidance)
        previewArea.accessibleContext.accessibleName = "${definition.displayName} configuration preview"
        if (!actionInProgress) {
            showActionStatus("No background setup action has run for ${definition.displayName}.")
        }
        renderPreview()
        rebuildClientActions()
    }

    private fun renderPreview() {
        val endpoint = currentEndpoint
        if (endpoint == null) {
            previewArea.text = "Configuration preview unavailable. Enter a valid numeric loopback host and port, then choose Refresh preview."
            copyPreviewButton.isEnabled = false
        } else {
            previewArea.text = ClientSetupCatalog.render(selectedDefinition().id, endpoint)
            copyPreviewButton.isEnabled = true
        }
        previewArea.caretPosition = 0
    }

    private fun rebuildClientActions() {
        val buttons = buildList {
            add(refreshPreviewButton)
            add(copyPreviewButton)
            if (
                selectedDefinition().id == ClientSetupId.CLAUDE_DESKTOP &&
                selectedDefinition().automaticInstallAvailable &&
                claudeDesktopInstaller != null
            ) {
                add(installClaudeButton)
            }
        }
        clientActionsHost.removeAll()
        clientActionsHost.add(AdaptiveButtonPanel(buttons).apply { alignmentX = LEFT_ALIGNMENT })
        clientActionsHost.revalidate()
        clientActionsHost.repaint()
        updateMutationButtonState()
    }

    private fun refreshPreview() {
        check(SwingUtilities.isEventDispatchThread()) { "client preview refresh belongs to the EDT" }
        if (closed.get()) return
        currentEndpoint = try {
            endpointProvider()
        } catch (_: Exception) {
            null
        }
        renderPreview()
        showPreviewStatus(
            if (currentEndpoint == null) "Preview unavailable until the local host and port are valid."
            else "Secret-free preview refreshed.",
        )
    }

    private fun copyPreview() {
        check(SwingUtilities.isEventDispatchThread()) { "client preview copy belongs to the EDT" }
        if (closed.get() || !copyPreviewButton.isEnabled) return
        try {
            clipboard.copy(previewArea.text)
            showPreviewStatus("Configuration preview copied.")
        } catch (_: Exception) {
            showPreviewStatus("Clipboard copy is unavailable.")
        }
    }

    private fun installClaudeDesktop() {
        check(SwingUtilities.isEventDispatchThread()) { "Claude Desktop installation must start on the EDT" }
        val provider = claudeDesktopInstaller ?: return
        if (closed.get() || actionInProgress || selectedDefinition().id != ClientSetupId.CLAUDE_DESKTOP) return

        provider.confirmationText?.let { confirmation ->
            if (Dialogs.showConfirmDialog(parentComponent, confirmation, YES_NO_OPTION) != YES_OPTION) return
        }
        if (closed.get() || actionInProgress || selectedDefinition().id != ClientSetupId.CLAUDE_DESKTOP) return
        val snapshot = try {
            installConfigProvider()
        } catch (error: Exception) {
            showProviderError("Cannot install for ${provider.name}", error)
            return
        }
        val operation = try {
            provider.prepareInstall(snapshot)
        } catch (error: Exception) {
            showProviderError("Cannot prepare installation for ${provider.name}", error)
            return
        } ?: return
        if (closed.get() || actionInProgress || selectedDefinition().id != ClientSetupId.CLAUDE_DESKTOP) return

        submitProviderOperation(
            operation = operation,
            runningText = "Claude Desktop installation is running.",
            successText = "Claude Desktop installation completed with an owner-only backup. Restart Claude Desktop before reconnecting.",
            failurePrefix = "Claude Desktop installation failed",
            hideReinstallNotice = true,
        )
    }

    private fun extractProxyJar() {
        check(SwingUtilities.isEventDispatchThread()) { "proxy extraction must start on the EDT" }
        val prepare = prepareProxyExtraction ?: return
        if (closed.get() || actionInProgress) return
        val operation = try {
            prepare()
        } catch (error: Exception) {
            showProviderError("Cannot prepare proxy extraction", error)
            return
        } ?: return
        if (closed.get() || actionInProgress) return

        submitProviderOperation(
            operation = operation,
            runningText = "Proxy extraction is running.",
            successText = "Proxy jar extracted successfully.",
            failurePrefix = "Proxy extraction failed",
            hideReinstallNotice = false,
        )
    }

    private fun submitProviderOperation(
        operation: ProviderInstallOperation,
        runningText: String,
        successText: String,
        failurePrefix: String,
        hideReinstallNotice: Boolean,
    ) {
        setActionInProgress(true)
        showActionStatus(runningText)
        submitBackground(
            task = operation::execute,
            onSuccess = {
                if (hideReinstallNotice) reinstallNotice.isVisible = false
                showActionStatus(successText)
                Dialogs.showMessageDialog(parentComponent, successText, INFORMATION_MESSAGE)
            },
            onFailure = { error ->
                val message = "$failurePrefix: ${safeExceptionSummary(error)}"
                showActionStatus(message)
                Dialogs.showMessageDialog(parentComponent, message, ERROR_MESSAGE)
            },
        )
    }

    private fun runConnectionDoctor() {
        check(SwingUtilities.isEventDispatchThread()) { "Connection Doctor must start on the EDT" }
        if (closed.get() || actionInProgress) return
        val snapshot = try {
            doctorConfigProvider()
        } catch (_: Exception) {
            if (!closed.get()) {
                publishDoctorReport(
                    DoctorReport(
                        DoctorListenerCode.UNKNOWN,
                        DoctorProbeCode.INVALID_CONFIGURATION,
                    ),
                )
            }
            return
        }
        if (closed.get()) return

        val contextGeneration = doctorContextGeneration
        doctorHasStarted = true
        doctorEvidence = null
        copyEvidenceButton.isEnabled = false
        doctorResultText.updateContent("Connection Doctor is running a bounded local check...")
        setActionInProgress(true)
        val submitted = submitBackground(
            task = { connectionDoctor.run(snapshot) },
            onSuccess = { report -> publishDoctorReportIfCurrent(report, contextGeneration) },
            onFailure = {
                publishDoctorReportIfCurrent(
                    DoctorReport(
                        snapshot.listener,
                        DoctorProbeCode.CONNECTION_FAILED,
                    ),
                    contextGeneration,
                )
            },
        )
        if (!submitted && !closed.get()) {
            doctorHasStarted = false
            doctorResultText.updateContent(
                "Connection Doctor could not start. No local-admission check was performed.",
            )
            updateMutationButtonState()
        }
    }

    private fun publishDoctorReportIfCurrent(report: DoctorReport, contextGeneration: Any) {
        check(SwingUtilities.isEventDispatchThread()) { "Connection Doctor results belong to the EDT" }
        if (doctorContextGeneration !== contextGeneration) {
            doctorEvidence = null
            updateMutationButtonState()
            showActionStatus("Connection Doctor result discarded because its local context changed.")
            return
        }
        publishDoctorReport(report)
    }

    private fun publishDoctorReport(report: DoctorReport) {
        check(SwingUtilities.isEventDispatchThread()) { "Connection Doctor results belong to the EDT" }
        doctorHasStarted = true
        doctorEvidence = formatDoctorEvidence(report)
        doctorResultText.updateContent(formatDoctorSummary(report))
        updateMutationButtonState()
        showActionStatus("Connection Doctor status updated.")
    }

    private fun copyDoctorEvidence() {
        check(SwingUtilities.isEventDispatchThread()) { "Doctor evidence copy belongs to the EDT" }
        val evidence = doctorEvidence ?: return
        if (closed.get() || actionInProgress) return
        copyControlled(evidence, "Safe Connection Doctor evidence copied.")
    }

    private fun copyControlled(value: String, successText: String) {
        try {
            clipboard.copy(value)
            showActionStatus(successText)
        } catch (_: Exception) {
            showActionStatus("Clipboard copy is unavailable.")
        }
    }

    private fun <T> submitBackground(
        task: () -> T,
        onSuccess: (T) -> Unit,
        onFailure: (Throwable) -> Unit,
    ): Boolean = try {
        activeFuture = actionExecutor.submit {
            val outcome = runCatching(task)
            SwingUtilities.invokeLater {
                if (closed.get()) return@invokeLater
                activeFuture = null
                setActionInProgress(false)
                outcome.fold(onSuccess, onFailure)
            }
        }
        true
    } catch (_: RejectedExecutionException) {
        setActionInProgress(false)
        if (!closed.get()) showActionStatus("Background setup actions are unavailable.")
        false
    }

    private fun showProviderError(prefix: String, error: Throwable) {
        val message = "$prefix: ${safeExceptionSummary(error)}"
        showActionStatus(message)
        Dialogs.showMessageDialog(parentComponent, message, ERROR_MESSAGE)
    }

    private fun showPreviewStatus(content: String) {
        previewStatusText.updateContent(content)
    }

    private fun showActionStatus(content: String) {
        actionStatusText.updateContent(content)
    }

    private fun setActionInProgress(value: Boolean) {
        check(SwingUtilities.isEventDispatchThread()) { "client setup action state belongs to the EDT" }
        actionInProgress = value
        updateMutationButtonState()
    }

    private fun updateMutationButtonState() {
        installClaudeButton.isEnabled = !actionInProgress
        extractProxyButton.isEnabled = !actionInProgress
        runDoctorButton.isEnabled = !actionInProgress
        copyEvidenceButton.isEnabled = !actionInProgress && doctorEvidence != null
    }
}
