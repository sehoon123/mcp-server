package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.McpConfig
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.*
import javax.swing.Box.createVerticalStrut
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

class AdvancedOptionsPanel(
    private val config: McpConfig,
    private val hostField: JTextField,
    private val portField: JTextField,
    private val reinstallNotice: WarningLabel
) : JPanel() {
    private val tokenStatus = WrappingText(" ", WrappingTextStyle.LABEL_MEDIUM)

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        updateColors()
        alignmentX = LEFT_ALIGNMENT

        buildPanel()
        setupFieldTracking()
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
        add(Design.createSectionLabel("Advanced Options"))
        add(createVerticalStrut(Design.Spacing.MD))

        val formPanel = createFormPanel(
            "Server host:" to hostField, "Server port:" to portField
        )
        add(formPanel)
        add(createVerticalStrut(Design.Spacing.SM))
        add(WrappingText(
            "The server accepts only numeric loopback binds and requires a per-installation bearer token."
        ))
        add(createVerticalStrut(Design.Spacing.SM))

        val copyTokenButton = JButton("Copy local bearer token").apply {
            addActionListener {
                copyTokenToClipboard(config.localBearerToken).onSuccess {
                    tokenStatus.updateContent("Bearer token copied; treat the clipboard as sensitive")
                }.onFailure {
                    tokenStatus.updateContent("Could not access the system clipboard")
                }
            }
        }
        val rotateTokenButton = JButton("Rotate local bearer token...").apply {
            addActionListener {
                val confirmed = JOptionPane.showConfirmDialog(
                    this@AdvancedOptionsPanel,
                    "Existing native and stdio client credentials will stop working. " +
                        "After rotation, restart the MCP server and reinstall or update every client.",
                    "Rotate local bearer token",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.WARNING_MESSAGE,
                )
                if (confirmed == JOptionPane.OK_OPTION) {
                    val token = config.rotateLocalBearerToken()
                    reinstallNotice.isVisible = true
                    copyTokenToClipboard(token).onSuccess {
                        tokenStatus.updateContent("Token rotated and copied; restart the server and update clients")
                    }.onFailure {
                        tokenStatus.updateContent("Token rotated; restart the server and update clients")
                    }
                }
            }
        }
        add(AdaptiveButtonPanel(listOf(copyTokenButton, rotateTokenButton)))
        add(createVerticalStrut(Design.Spacing.SM))
        add(tokenStatus)
    }

    private fun copyTokenToClipboard(token: String): Result<Unit> = runCatching {
        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(token), null)
    }

    private fun setupFieldTracking() {
        trackChanges(hostField)
        trackChanges(portField)
    }

    private fun trackChanges(field: JTextField) {
        field.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent?) = handle()
            override fun removeUpdate(e: DocumentEvent?) = handle()
            override fun changedUpdate(e: DocumentEvent?) = handle()
            fun handle() {
                reinstallNotice.isVisible = true
            }
        })
    }

    private fun createFormPanel(vararg fields: Pair<String, JComponent>): JPanel {
        val formPanel = JPanel(GridBagLayout()).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
        }

        val gbc = GridBagConstraints().apply {
            insets = Insets(Design.Spacing.SM, 0, Design.Spacing.SM, Design.Spacing.MD)
            anchor = GridBagConstraints.WEST
        }

        fields.forEachIndexed { index, (labelText, field) ->
            gbc.gridx = 0
            gbc.gridy = index
            gbc.fill = GridBagConstraints.NONE
            gbc.weightx = 0.0
            formPanel.add(JLabel(labelText).apply {
                font = Design.Typography.bodyLarge
                foreground = Design.Colors.onSurface
                labelFor = field
            }, gbc)

            gbc.gridx = 1
            gbc.fill = GridBagConstraints.HORIZONTAL
            gbc.weightx = 1.0
            gbc.insets = Insets(Design.Spacing.SM, 0, Design.Spacing.SM, 0)

            if (field is JTextField) {
                field.font = Design.Typography.bodyLarge
            }

            formPanel.add(field, gbc)

            gbc.insets = Insets(Design.Spacing.SM, 0, Design.Spacing.SM, Design.Spacing.MD)
        }

        return formPanel
    }

    fun setFieldsEnabled(enabled: Boolean) {
        hostField.isEnabled = enabled
        portField.isEnabled = enabled
    }

}