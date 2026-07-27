package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.config.ToggleSwitch
import net.portswigger.mcp.security.findBurpFrame
import java.awt.FlowLayout
import java.awt.event.ItemEvent
import javax.swing.*
import javax.swing.Box.createHorizontalStrut
import javax.swing.Box.createVerticalStrut

class ServerConfigurationPanel(
    private val config: McpConfig,
    private val enabledToggle: ToggleSwitch,
    private val validationErrorLabel: WarningLabel
) : JPanel() {

    private lateinit var yoloModeButton: JButton
    private lateinit var yoloModeStatus: WrappingText
    private lateinit var alwaysAllowHttpHistoryCheckBox: JCheckBox
    private lateinit var alwaysAllowSiteMapCheckBox: JCheckBox
    private lateinit var alwaysAllowWebSocketHistoryCheckBox: JCheckBox
    private lateinit var alwaysAllowOrganizerCheckBox: JCheckBox
    private lateinit var alwaysAllowScannerIssuesCheckBox: JCheckBox
    private lateinit var alwaysAllowCollaboratorInteractionsCheckBox: JCheckBox
    private lateinit var allowAllHttpRequestsCheckBox: JCheckBox
    private lateinit var requestActionApprovalCheckBox: JCheckBox
    private lateinit var scopeChangeApprovalCheckBox: JCheckBox
    private lateinit var dataAccessApprovalCheckBox: JCheckBox

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        updateColors()
        alignmentX = LEFT_ALIGNMENT

        buildPanel()
    }

    override fun updateUI() {
        super.updateUI()
        updateColors()
    }

    private fun updateColors() {
        background = Design.Colors.surface
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1),
            BorderFactory.createEmptyBorder(Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD)
        )
    }

    private fun buildPanel() {
        add(Design.createSectionLabel("Server Configuration"))
        add(createVerticalStrut(Design.Spacing.MD))

        val enabledPanel = createEnabledPanel()
        add(enabledPanel)
        add(createVerticalStrut(Design.Spacing.MD))

        add(createYoloModePanel())
        add(createVerticalStrut(Design.Spacing.MD))

        val configEditingToolingCheckBox = createCheckBoxWithSubtitle(
            "Enable tools that can edit your config",
            "WARNING: Can execute code",
            config.configEditingTooling
        ) { config.configEditingTooling = it }
        add(configEditingToolingCheckBox)
        add(createVerticalStrut(Design.Spacing.MD))

        val allowAllHttpRequestsPanel = createCheckBoxWithSubtitle(
            "Always allow all outbound HTTP requests",
            "WARNING: Disables per-target approval for every destination",
            !config.requireHttpRequestApproval,
            onChange = { allowAll -> config.requireHttpRequestApproval = !allowAll },
            onCreated = { allowAllHttpRequestsCheckBox = it },
        )
        add(allowAllHttpRequestsPanel)
        add(createVerticalStrut(Design.Spacing.MD))

        requestActionApprovalCheckBox = createStandardCheckBox(
            "Require approval for request routing and derived-request actions", config.requireRequestActionApproval
        ) { config.requireRequestActionApproval = it }
        add(requestActionApprovalCheckBox)
        add(createVerticalStrut(Design.Spacing.MD))

        scopeChangeApprovalCheckBox = createStandardCheckBox(
            "Require approval for Target scope changes", config.requireScopeChangeApproval
        ) { config.requireScopeChangeApproval = it }
        add(scopeChangeApprovalCheckBox)
        add(createVerticalStrut(Design.Spacing.MD))

        dataAccessApprovalCheckBox = createDataAccessApprovalCheckBox()
        add(dataAccessApprovalCheckBox)
        add(createVerticalStrut(Design.Spacing.SM))

        alwaysAllowHttpHistoryCheckBox = createIndentedCheckBox(
            "Always allow HTTP history access", config.alwaysAllowHttpHistory, config.requireDataAccessApproval
        ) { config.alwaysAllowHttpHistory = it }
        add(alwaysAllowHttpHistoryCheckBox)
        add(createVerticalStrut(Design.Spacing.SM))

        alwaysAllowSiteMapCheckBox = createIndentedCheckBox(
            "Always allow Site Map access", config.alwaysAllowSiteMap, config.requireDataAccessApproval
        ) { config.alwaysAllowSiteMap = it }
        add(alwaysAllowSiteMapCheckBox)
        add(createVerticalStrut(Design.Spacing.SM))

        alwaysAllowWebSocketHistoryCheckBox = createIndentedCheckBox(
            "Always allow WebSocket history access",
            config.alwaysAllowWebSocketHistory,
            config.requireDataAccessApproval
        ) { config.alwaysAllowWebSocketHistory = it }
        add(alwaysAllowWebSocketHistoryCheckBox)
        add(createVerticalStrut(Design.Spacing.SM))

        alwaysAllowOrganizerCheckBox = createIndentedCheckBox(
            "Always allow Organizer access",
            config.alwaysAllowOrganizer,
            config.requireDataAccessApproval
        ) { config.alwaysAllowOrganizer = it }
        add(alwaysAllowOrganizerCheckBox)
        add(createVerticalStrut(Design.Spacing.SM))

        alwaysAllowScannerIssuesCheckBox = createIndentedCheckBox(
            "Always allow Scanner issue access",
            config.alwaysAllowScannerIssues,
            config.requireDataAccessApproval
        ) { config.alwaysAllowScannerIssues = it }
        add(alwaysAllowScannerIssuesCheckBox)
        add(createVerticalStrut(Design.Spacing.SM))

        alwaysAllowCollaboratorInteractionsCheckBox = createIndentedCheckBox(
            "Always allow Collaborator interaction access",
            config.alwaysAllowCollaboratorInteractions,
            config.requireDataAccessApproval
        ) { config.alwaysAllowCollaboratorInteractions = it }
        add(alwaysAllowCollaboratorInteractionsCheckBox)
        add(createVerticalStrut(Design.Spacing.MD))

        val filterConfigCredentialsCheckBox = createCheckBoxWithSubtitle(
            "Filter config credentials",
            "Hides sensitive data in config files (Platform Authentication, socks proxy, etc.)",
            config.filterConfigCredentials
        ) { config.filterConfigCredentials = it }
        add(filterConfigCredentialsCheckBox)

        add(validationErrorLabel)
        refreshPersistentApprovalControls()
    }

    private fun createYoloModePanel(): JPanel {
        yoloModeButton = Design.createSemanticOutlinedButton("Enable YOLO mode...") { Design.Colors.error }.apply {
            alignmentX = LEFT_ALIGNMENT
            addActionListener { toggleYoloMode() }
        }
        yoloModeStatus = WrappingText("", WrappingTextStyle.LABEL_MEDIUM)
        return JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            alignmentX = LEFT_ALIGNMENT
            isOpaque = false
            add(yoloModeButton)
            add(createVerticalStrut(Design.Spacing.SM))
            add(yoloModeStatus)
        }
    }

    private fun toggleYoloMode() {
        if (config.approvalYoloMode) {
            persistYoloMode(false)
            return
        }

        val confirmed = Dialogs.showConfirmDialog(
            findBurpFrame(),
            "YOLO mode bypasses every MCP approval prompt, including outbound traffic, project-data reads, " +
                "request routing, Target scope changes, Scanner actions, configuration access, editor changes, " +
                "and Burp global-control changes.\n\nAn authenticated MCP client may read sensitive data, send " +
                "network requests, and mutate Burp state without another prompt. Validation, project binding, " +
                "operation bounds, bearer authentication, and Emergency read-only mode remain active.\n\n" +
                "Enable YOLO mode?",
            JOptionPane.YES_NO_OPTION,
        )
        if (confirmed == JOptionPane.YES_OPTION) {
            persistYoloMode(true)
        }
    }

    private fun persistYoloMode(enabled: Boolean) {
        val persisted = runCatching { config.approvalYoloMode = enabled }
        refreshPersistentApprovalControls()
        if (persisted.isFailure) {
            yoloModeStatus.updateContent(
                if (enabled) {
                    "Could not enable YOLO mode; approval prompts remain governed by the saved granular policies."
                } else {
                    "Could not disable YOLO mode; all approval prompts remain bypassed."
                }
            )
        }
    }

    private fun createEnabledPanel(): JPanel {
        val enabledPanel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 4)).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
        }
        enabledToggle.accessibleContext.accessibleName = "MCP server enabled"
        enabledPanel.add(JLabel("Enabled").apply {
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
            labelFor = enabledToggle
        })
        enabledPanel.add(createHorizontalStrut(Design.Spacing.MD))
        enabledPanel.add(enabledToggle)
        return enabledPanel
    }

    private fun createDataAccessApprovalCheckBox(): JCheckBox {
        return createStandardCheckBox(
            "Require approval for project data access", config.requireDataAccessApproval
        ) { enabled ->
            config.requireDataAccessApproval = enabled
            if (!enabled) {
                config.alwaysAllowHttpHistory = false
                config.alwaysAllowSiteMap = false
                config.alwaysAllowWebSocketHistory = false
                config.alwaysAllowOrganizer = false
                config.alwaysAllowScannerIssues = false
                config.alwaysAllowCollaboratorInteractions = false
                alwaysAllowHttpHistoryCheckBox.isSelected = false
                alwaysAllowSiteMapCheckBox.isSelected = false
                alwaysAllowWebSocketHistoryCheckBox.isSelected = false
                alwaysAllowOrganizerCheckBox.isSelected = false
                alwaysAllowScannerIssuesCheckBox.isSelected = false
                alwaysAllowCollaboratorInteractionsCheckBox.isSelected = false
            }
            alwaysAllowHttpHistoryCheckBox.isEnabled = enabled
            alwaysAllowSiteMapCheckBox.isEnabled = enabled
            alwaysAllowWebSocketHistoryCheckBox.isEnabled = enabled
            alwaysAllowOrganizerCheckBox.isEnabled = enabled
            alwaysAllowScannerIssuesCheckBox.isEnabled = enabled
            alwaysAllowCollaboratorInteractionsCheckBox.isEnabled = enabled
        }
    }

    fun updateDataAccessCheckboxes() {
        SwingUtilities.invokeLater {
            dataAccessApprovalCheckBox.isSelected = config.requireDataAccessApproval
            alwaysAllowHttpHistoryCheckBox.isSelected = config.alwaysAllowHttpHistory
            alwaysAllowSiteMapCheckBox.isSelected = config.alwaysAllowSiteMap
            alwaysAllowWebSocketHistoryCheckBox.isSelected = config.alwaysAllowWebSocketHistory
            alwaysAllowOrganizerCheckBox.isSelected = config.alwaysAllowOrganizer
            alwaysAllowScannerIssuesCheckBox.isSelected = config.alwaysAllowScannerIssues
            alwaysAllowCollaboratorInteractionsCheckBox.isSelected = config.alwaysAllowCollaboratorInteractions
            updateDataAccessEnabledState(config.requireDataAccessApproval)
        }
    }

    fun updatePersistentApprovalControls() {
        SwingUtilities.invokeLater { refreshPersistentApprovalControls() }
    }

    private fun refreshPersistentApprovalControls() {
        allowAllHttpRequestsCheckBox.isSelected = !config.requireHttpRequestApproval
        requestActionApprovalCheckBox.isSelected = config.requireRequestActionApproval
        scopeChangeApprovalCheckBox.isSelected = config.requireScopeChangeApproval
        dataAccessApprovalCheckBox.isSelected = config.requireDataAccessApproval
        alwaysAllowHttpHistoryCheckBox.isSelected = config.alwaysAllowHttpHistory
        alwaysAllowSiteMapCheckBox.isSelected = config.alwaysAllowSiteMap
        alwaysAllowWebSocketHistoryCheckBox.isSelected = config.alwaysAllowWebSocketHistory
        alwaysAllowOrganizerCheckBox.isSelected = config.alwaysAllowOrganizer
        alwaysAllowScannerIssuesCheckBox.isSelected = config.alwaysAllowScannerIssues
        alwaysAllowCollaboratorInteractionsCheckBox.isSelected = config.alwaysAllowCollaboratorInteractions

        val yoloEnabled = config.approvalYoloMode
        yoloModeButton.text = if (yoloEnabled) "Disable YOLO mode" else "Enable YOLO mode..."
        yoloModeButton.accessibleContext.accessibleName = yoloModeButton.text
        yoloModeButton.accessibleContext.accessibleDescription = if (yoloEnabled) {
            "Disable the global MCP approval-prompt bypass and resume the saved granular approval policies"
        } else {
            "After one warning, bypass every MCP approval prompt until disabled"
        }
        yoloModeStatus.updateContent(
            if (yoloEnabled) {
                "ACTIVE: all MCP approval prompts are bypassed. Granular policies below are preserved and resume when disabled."
            } else {
                "One local confirmation bypasses all MCP approval prompts. Validation and other execution safeguards remain active."
            }
        )

        val granularControlsEnabled = !yoloEnabled
        allowAllHttpRequestsCheckBox.isEnabled = granularControlsEnabled
        requestActionApprovalCheckBox.isEnabled = granularControlsEnabled
        scopeChangeApprovalCheckBox.isEnabled = granularControlsEnabled
        dataAccessApprovalCheckBox.isEnabled = granularControlsEnabled
        updateDataAccessEnabledState(config.requireDataAccessApproval)
        revalidate()
        repaint()
    }

    private fun updateDataAccessEnabledState(approvalRequired: Boolean) {
        val enabled = approvalRequired && !config.approvalYoloMode
        alwaysAllowHttpHistoryCheckBox.isEnabled = enabled
        alwaysAllowSiteMapCheckBox.isEnabled = enabled
        alwaysAllowWebSocketHistoryCheckBox.isEnabled = enabled
        alwaysAllowOrganizerCheckBox.isEnabled = enabled
        alwaysAllowScannerIssuesCheckBox.isEnabled = enabled
        alwaysAllowCollaboratorInteractionsCheckBox.isEnabled = enabled
    }

    fun updateRequestActionApprovalCheckbox() {
        SwingUtilities.invokeLater {
            requestActionApprovalCheckBox.isSelected = config.requireRequestActionApproval
        }
    }

    fun updateScopeChangeApprovalCheckbox() {
        SwingUtilities.invokeLater {
            scopeChangeApprovalCheckBox.isSelected = config.requireScopeChangeApproval
        }
    }

    private fun createStandardCheckBox(
        text: String, initialValue: Boolean, onChange: (Boolean) -> Unit
    ): JCheckBox {
        return JCheckBox(text).apply {
            alignmentX = LEFT_ALIGNMENT
            isSelected = initialValue
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
            addItemListener { event ->
                onChange(event.stateChange == ItemEvent.SELECTED)
            }
        }
    }

    private fun createIndentedCheckBox(
        text: String, initialValue: Boolean, enabled: Boolean, onChange: (Boolean) -> Unit
    ): JCheckBox {
        return JCheckBox(text).apply {
            alignmentX = LEFT_ALIGNMENT
            isSelected = initialValue
            isEnabled = enabled
            font = Design.Typography.bodyMedium
            foreground = Design.Colors.onSurfaceVariant
            border = BorderFactory.createEmptyBorder(0, Design.Spacing.LG, 0, 0)
            addItemListener { event ->
                onChange(event.stateChange == ItemEvent.SELECTED)
            }
        }
    }

    private fun createCheckBoxWithSubtitle(
        mainText: String,
        subtitleText: String,
        initialValue: Boolean,
        onCreated: (JCheckBox) -> Unit = {},
        onChange: (Boolean) -> Unit,
    ): JPanel {
        val checkBox = JCheckBox(mainText).apply {
            alignmentX = LEFT_ALIGNMENT
            isSelected = initialValue
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
            accessibleContext.accessibleDescription = subtitleText
            addItemListener { event ->
                onChange(event.stateChange == ItemEvent.SELECTED)
            }
        }

        onCreated(checkBox)

        val subtitle = WrappingText(subtitleText, WrappingTextStyle.LABEL_MEDIUM).apply {
            border = BorderFactory.createEmptyBorder(0, Design.Spacing.LG, 0, 0)
        }

        return JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            alignmentX = LEFT_ALIGNMENT
            isOpaque = false
            add(checkBox)
            add(subtitle)
        }
    }

}