package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Anchor
import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.providers.Provider
import net.portswigger.mcp.providers.ProviderInstallConfig
import net.portswigger.mcp.security.safeExceptionSummary
import java.awt.FlowLayout
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import javax.swing.*
import javax.swing.Box.createVerticalStrut
import javax.swing.JOptionPane.*

class InstallationPanel(
    private val providers: List<Provider>,
    private val reinstallNotice: WarningLabel,
    private val parentComponent: JComponent,
    private val installConfigProvider: () -> ProviderInstallConfig,
) : JPanel() {
    private val providerButtons = ArrayList<JButton>(providers.size)
    private val installExecutor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "burp-mcp-provider-install").apply { isDaemon = true }
    }

    @Volatile
    private var closed = false
    private var installInProgress = false

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

    fun cleanup() {
        closed = true
        installExecutor.shutdownNow()
    }

    private fun updateColors() {
        background = Design.Colors.surface
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1),
            BorderFactory.createEmptyBorder(Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD)
        )
    }

    private fun buildPanel() {
        add(Design.createSectionLabel("Installation"))
        add(createVerticalStrut(Design.Spacing.SM))

        val installOptions = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            alignmentX = LEFT_ALIGNMENT
            isOpaque = false
        }

        installOptions.add(createButtonRow())
        add(installOptions)
        add(createVerticalStrut(Design.Spacing.SM))
        add(createManualInstallPanel())
    }

    private fun createButtonRow(): JPanel = AdaptiveButtonPanel(
        providers.map(::createProviderButton),
    )

    private fun createProviderButton(provider: Provider): JButton =
        Design.createFilledButton(provider.installButtonText).apply {
            providerButtons += this
            addActionListener { handleProviderInstall(provider) }
        }

    private fun handleProviderInstall(provider: Provider) {
        check(SwingUtilities.isEventDispatchThread()) { "provider installation must be initiated on the EDT" }
        if (closed || installInProgress) return

        val snapshot = try {
            installConfigProvider()
        } catch (e: Exception) {
            Dialogs.showMessageDialog(
                parentComponent,
                "Cannot install for ${provider.name}: ${safeExceptionSummary(e)}",
                ERROR_MESSAGE,
            )
            return
        }

        val confirmationText = provider.confirmationText
        if (confirmationText != null) {
            val result = Dialogs.showConfirmDialog(parentComponent, confirmationText, YES_NO_OPTION)
            if (result != YES_OPTION) return
        }

        val operation = try {
            provider.prepareInstall(snapshot)
        } catch (e: Exception) {
            Dialogs.showMessageDialog(
                parentComponent,
                "Cannot prepare installation for ${provider.name}: ${safeExceptionSummary(e)}",
                ERROR_MESSAGE,
            )
            return
        } ?: return

        setInstallInProgress(true)
        try {
            installExecutor.execute {
                val outcome = runCatching { operation.execute() }
                SwingUtilities.invokeLater {
                    if (closed) return@invokeLater
                    setInstallInProgress(false)
                    outcome.fold(
                        onSuccess = { message ->
                            reinstallNotice.isVisible = false
                            if (message != null) {
                                Dialogs.showMessageDialog(parentComponent, message, INFORMATION_MESSAGE)
                            }
                        },
                        onFailure = { error ->
                            Dialogs.showMessageDialog(
                                parentComponent,
                                "Failed to install for ${provider.name}: ${safeExceptionSummary(error)}",
                                ERROR_MESSAGE,
                            )
                        },
                    )
                }
            }
        } catch (_: RejectedExecutionException) {
            setInstallInProgress(false)
            if (!closed) {
                Dialogs.showMessageDialog(parentComponent, "Provider installation is unavailable", ERROR_MESSAGE)
            }
        }
    }

    private fun setInstallInProgress(value: Boolean) {
        check(SwingUtilities.isEventDispatchThread()) { "provider installation UI state belongs to the EDT" }
        installInProgress = value
        providerButtons.forEach { it.isEnabled = !value }
    }

    private fun createManualInstallPanel(): JPanel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply {
        alignmentX = LEFT_ALIGNMENT
        isOpaque = false
        add(
            Anchor(
                text = "Manual install steps",
                url = "https://github.com/sehoon123/mcp-server?tab=readme-ov-file#manual-installations",
            )
        )
    }
}
