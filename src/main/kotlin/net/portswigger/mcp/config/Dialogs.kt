package net.portswigger.mcp.config

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.ui.editor.EditorOptions
import net.portswigger.mcp.config.components.WrappingText
import net.portswigger.mcp.config.components.WrappingTextStyle
import java.awt.*
import java.awt.event.ActionEvent
import java.awt.event.KeyEvent
import javax.swing.*
import javax.swing.border.EmptyBorder
import java.util.concurrent.atomic.AtomicReference

object Dialogs {
    private val activeOptionDialog = AtomicReference<JDialog?>()

    internal fun dismissActiveOptionDialog() {
        activeOptionDialog.get()?.dispose()
    }

    private fun wrapText(text: String, maxWidth: Int = 50): String {
        if (text.length <= maxWidth) return text

        val words = text.split(" ")
        val result = StringBuilder()
        var currentLine = StringBuilder()

        for (word in words) {
            if (currentLine.length + word.length + 1 <= maxWidth) {
                if (currentLine.isNotEmpty()) currentLine.append(" ")
                currentLine.append(word)
            } else {
                if (result.isNotEmpty()) result.append("\n")
                result.append(currentLine.toString())
                currentLine = StringBuilder(word)
            }
        }

        if (currentLine.isNotEmpty()) {
            if (result.isNotEmpty()) result.append("\n")
            result.append(currentLine.toString())
        }

        return result.toString()
    }

    private fun createDialog(parent: Component?): JDialog {
        val parentWindow = SwingUtilities.getWindowAncestor(parent)
        return JDialog(parentWindow, "", Dialog.ModalityType.APPLICATION_MODAL).apply {
            background = Design.Colors.surface
            defaultCloseOperation = JDialog.DISPOSE_ON_CLOSE
            isResizable = true

            val escapeAction = object : AbstractAction() {
                override fun actionPerformed(e: ActionEvent?) {
                    dispose()
                }
            }

            rootPane.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "escape"
            )
            rootPane.actionMap.put("escape", escapeAction)
        }
    }

    fun showMessageDialog(
        parent: Component?, message: String, messageType: Int
    ) {
        val dialog = createDialog(parent)

        val iconLabel = when (messageType) {
            JOptionPane.ERROR_MESSAGE -> JLabel("⚠").apply {
                font = Design.Typography.headlineMedium
                foreground = Design.Colors.error
                horizontalAlignment = SwingConstants.CENTER
                preferredSize = Dimension(40, 40)
            }

            JOptionPane.WARNING_MESSAGE -> JLabel("⚠").apply {
                font = Design.Typography.headlineMedium
                foreground = Design.Colors.warning
                horizontalAlignment = SwingConstants.CENTER
                preferredSize = Dimension(40, 40)
            }

            JOptionPane.INFORMATION_MESSAGE -> JLabel("ⓘ").apply {
                font = Design.Typography.headlineMedium
                foreground = Design.Colors.primary
                horizontalAlignment = SwingConstants.CENTER
                preferredSize = Dimension(40, 40)
            }

            else -> null
        }

        val messageLabel = WrappingText(
            wrapText(message),
            WrappingTextStyle.PRIMARY_BODY_LARGE,
            fallbackMaxWidth = 560,
        )

        val contentPanel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            background = Design.Colors.surface
            border = EmptyBorder(Design.Spacing.XL, Design.Spacing.XL, Design.Spacing.LG, Design.Spacing.XL)
        }

        if (iconLabel != null) {
            iconLabel.alignmentX = Component.CENTER_ALIGNMENT
            contentPanel.add(iconLabel)
            contentPanel.add(Box.createVerticalStrut(Design.Spacing.MD))
        }

        messageLabel.alignmentX = Component.CENTER_ALIGNMENT
        contentPanel.add(messageLabel)
        contentPanel.add(Box.createVerticalStrut(Design.Spacing.LG))

        val okButton = Design.createFilledButton("OK").apply {
            alignmentX = Component.CENTER_ALIGNMENT
            addActionListener {
                dialog.dispose()
            }
        }

        contentPanel.add(okButton)

        dialog.contentPane = contentPanel
        dialog.rootPane.defaultButton = okButton
        dialog.pack()
        dialog.setLocationRelativeTo(parent)
        SwingUtilities.invokeLater { okButton.requestFocusInWindow() }
        dialog.isVisible = true
    }

    fun showConfirmDialog(
        parent: Component?, message: String, optionType: Int
    ): Int {
        val dialog = createDialog(parent)
        var result = JOptionPane.CANCEL_OPTION

        val messageLabel = WrappingText(
            message,
            WrappingTextStyle.PRIMARY_BODY_LARGE,
            fallbackMaxWidth = 560,
        )

        val contentPanel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            background = Design.Colors.surface
            border = EmptyBorder(Design.Spacing.XL, Design.Spacing.XL, Design.Spacing.LG, Design.Spacing.XL)
        }

        messageLabel.alignmentX = Component.CENTER_ALIGNMENT
        contentPanel.add(messageLabel)
        contentPanel.add(Box.createVerticalStrut(Design.Spacing.LG))

        val buttonPanel = JPanel(FlowLayout(FlowLayout.CENTER, Design.Spacing.MD, 0)).apply {
            background = Design.Colors.surface
            alignmentX = Component.CENTER_ALIGNMENT
        }
        var safeDefaultButton: JButton? = null

        when (optionType) {
            JOptionPane.YES_NO_OPTION -> {
                val noButton = Design.createOutlinedButton("No").apply {
                    addActionListener {
                        result = JOptionPane.NO_OPTION
                        dialog.dispose()
                    }
                }
                val yesButton = Design.createFilledButton("Yes").apply {
                    addActionListener {
                        result = JOptionPane.YES_OPTION
                        dialog.dispose()
                    }
                }
                buttonPanel.add(noButton)
                buttonPanel.add(yesButton)
                safeDefaultButton = noButton
            }

            JOptionPane.OK_CANCEL_OPTION -> {
                val cancelButton = Design.createOutlinedButton("Cancel").apply {
                    addActionListener {
                        result = JOptionPane.CANCEL_OPTION
                        dialog.dispose()
                    }
                }
                val okButton = Design.createFilledButton("OK").apply {
                    addActionListener {
                        result = JOptionPane.OK_OPTION
                        dialog.dispose()
                    }
                }
                buttonPanel.add(cancelButton)
                buttonPanel.add(okButton)
                safeDefaultButton = cancelButton
            }
        }

        contentPanel.add(buttonPanel)

        dialog.contentPane = contentPanel
        dialog.rootPane.defaultButton = safeDefaultButton
        dialog.pack()
        dialog.setLocationRelativeTo(parent)
        safeDefaultButton?.let { button ->
            SwingUtilities.invokeLater { button.requestFocusInWindow() }
        }
        dialog.isVisible = true

        return result
    }

    fun showInputDialog(
        parent: Component?, message: String
    ): String? {
        val dialog = createDialog(parent)
        var result: String? = null

        val messageLabel = WrappingText(
            message,
            WrappingTextStyle.PRIMARY_BODY_LARGE,
            fallbackMaxWidth = 560,
        )

        val inputField = JTextField(20).apply {
            font = Design.Typography.bodyLarge
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Design.Colors.outline, 1), BorderFactory.createEmptyBorder(
                    Design.Spacing.SM, Design.Spacing.MD, Design.Spacing.SM, Design.Spacing.MD
                )
            )
            background = Design.Colors.listBackground
            foreground = Design.Colors.onSurface
            maximumSize = Dimension(Int.MAX_VALUE, preferredSize.height)
        }

        val contentPanel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            background = Design.Colors.surface
            border = EmptyBorder(Design.Spacing.XL, Design.Spacing.XL, Design.Spacing.LG, Design.Spacing.XL)
        }

        messageLabel.alignmentX = Component.LEFT_ALIGNMENT
        contentPanel.add(messageLabel)
        contentPanel.add(Box.createVerticalStrut(Design.Spacing.MD))

        inputField.alignmentX = Component.LEFT_ALIGNMENT
        contentPanel.add(inputField)
        contentPanel.add(Box.createVerticalStrut(Design.Spacing.LG))

        val buttonPanel = JPanel(FlowLayout(FlowLayout.RIGHT, Design.Spacing.MD, 0)).apply {
            background = Design.Colors.surface
            alignmentX = Component.LEFT_ALIGNMENT
        }

        val cancelButton = Design.createOutlinedButton("Cancel").apply {
            addActionListener {
                result = null
                dialog.dispose()
            }
        }

        val okButton = Design.createFilledButton("OK").apply {
            addActionListener {
                result = inputField.text?.takeIf { it.isNotBlank() }
                dialog.dispose()
            }
        }

        val enterAction = object : AbstractAction() {
            override fun actionPerformed(e: ActionEvent?) {
                result = inputField.text?.takeIf { it.isNotBlank() }
                dialog.dispose()
            }
        }

        inputField.getInputMap(JComponent.WHEN_FOCUSED).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "enter"
        )
        inputField.actionMap.put("enter", enterAction)

        buttonPanel.add(cancelButton)
        buttonPanel.add(okButton)
        contentPanel.add(buttonPanel)

        dialog.contentPane = contentPanel
        dialog.rootPane.defaultButton = okButton
        dialog.pack()
        dialog.setLocationRelativeTo(parent)

        SwingUtilities.invokeLater {
            inputField.requestFocusInWindow()
        }

        dialog.isVisible = true

        return result
    }

    internal fun createOptionButtonPanel(
        options: Array<String>,
        onSelected: (Int) -> Unit = {},
    ): JPanel {
        require(options.isNotEmpty()) { "At least one dialog option is required" }

        val buttons = options.mapIndexed { index, option ->
            val button = when {
                index == 0 -> Design.createFilledButton(option)
                index == options.lastIndex ->
                    Design.createSemanticOutlinedButton(option) { Design.Colors.error }
                option.startsWith("Always Allow") ->
                    Design.createSemanticOutlinedButton(option) { Design.Colors.warning }.apply {
                        accessibleContext.accessibleDescription =
                            "Persistent approval; remains enabled until reset in MCP settings"
                    }
                else -> Design.createOutlinedButton(option)
            }
            button.apply {
                addActionListener { onSelected(index) }
            }
        }

        val buttonWidth = buttons.maxOf { it.preferredSize.width }
        val buttonHeight = buttons.maxOf { it.preferredSize.height }
        buttons.forEach { button ->
            val fittedSize = Dimension(buttonWidth, buttonHeight)
            button.minimumSize = fittedSize
            button.preferredSize = fittedSize
            button.maximumSize = fittedSize
        }

        val gap = Design.Spacing.SM
        val panelSize = Dimension(
            buttonWidth,
            buttonHeight * buttons.size + gap * (buttons.size - 1),
        )
        return JPanel(GridLayout(buttons.size, 1, 0, gap)).apply {
            background = Design.Colors.surface
            alignmentX = Component.CENTER_ALIGNMENT
            minimumSize = panelSize
            preferredSize = panelSize
            maximumSize = panelSize
            buttons.forEach(::add)
        }
    }

    fun showOptionDialog(
        parent: Component?,
        message: String,
        options: Array<String>,
        requestContent: String? = null,
        api: MontoyaApi? = null
    ): Int {
        val dialog = createDialog(parent)
        var result = -1

        val messageArea = JTextArea(message).apply {
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
            background = Design.Colors.surface
            isEditable = false
            isOpaque = false
            lineWrap = true
            wrapStyleWord = true
            columns = 30
            rows = 0
            minimumSize = Dimension(0, 0)
            preferredSize = Dimension(400, 200)
            maximumSize = Dimension(400, 220)
            alignmentX = Component.CENTER_ALIGNMENT
        }

        val messageScrollPane = JScrollPane(messageArea).apply {
            border = null
            isOpaque = false
            viewport.isOpaque = false
            verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            minimumSize = Dimension(0, 0)
            preferredSize = Dimension(400, 200)
            maximumSize = Dimension(400, 220)
            alignmentX = Component.CENTER_ALIGNMENT
        }

        val contentPanel = JPanel().apply {
            background = Design.Colors.surface
        }
        var denialButton: JButton? = null

        if (!requestContent.isNullOrBlank()) {
            contentPanel.layout = BorderLayout()

            val leftPanel = JPanel().apply {
                layout = BorderLayout()
                background = Design.Colors.surface
                minimumSize = Dimension(400, 300)
            }

            val requestComponent = if (api != null) {
                try {
                    val httpRequestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)
                    httpRequestEditor.request = HttpRequest.httpRequest(requestContent)
                    httpRequestEditor.uiComponent().apply {
                        minimumSize = Dimension(400, 200)
                    }
                } catch (_: Exception) {
                    JTextArea(requestContent).apply {
                        font = Design.Typography.bodyMedium
                        foreground = Design.Colors.onSurface
                        background = Design.Colors.listBackground
                        isEditable = false
                        lineWrap = false
                        tabSize = 4
                    }.let { textArea ->
                        JScrollPane(textArea).apply {
                            verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
                            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED
                            border = BorderFactory.createLineBorder(Design.Colors.outline, 1)
                            minimumSize = Dimension(400, 200)
                        }
                    }
                }
            } else {
                JTextArea(requestContent).apply {
                    font = Design.Typography.bodyMedium
                    foreground = Design.Colors.onSurface
                    background = Design.Colors.listBackground
                    isEditable = false
                    lineWrap = false
                    tabSize = 4
                }.let { textArea ->
                    JScrollPane(textArea).apply {
                        verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
                        horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED
                        border = BorderFactory.createLineBorder(Design.Colors.outline, 1)
                        minimumSize = Dimension(400, 200)
                    }
                }
            }

            leftPanel.add(requestComponent, BorderLayout.CENTER)

            val buttonPanel = createOptionButtonPanel(options) { index ->
                result = index
                dialog.dispose()
            }
            denialButton = buttonPanel.components.filterIsInstance<JButton>().lastOrNull()
            val rightContentWidth = maxOf(messageScrollPane.preferredSize.width, buttonPanel.preferredSize.width)
            val rightPanelWidth = rightContentWidth + Design.Spacing.LG + Design.Spacing.XL
            val rightPanelHeight = maxOf(
                400,
                messageScrollPane.preferredSize.height + Design.Spacing.LG + buttonPanel.preferredSize.height +
                    Design.Spacing.XL * 2,
            )
            leftPanel.preferredSize = Dimension(420, rightPanelHeight)

            val rightPanel = JPanel().apply {
                layout = BoxLayout(this, BoxLayout.Y_AXIS)
                background = Design.Colors.surface
                minimumSize = Dimension(rightPanelWidth, rightPanelHeight)
                maximumSize = Dimension(rightPanelWidth, Int.MAX_VALUE)
                preferredSize = Dimension(rightPanelWidth, rightPanelHeight)
                border = EmptyBorder(Design.Spacing.XL, Design.Spacing.LG, Design.Spacing.XL, Design.Spacing.XL)
            }

            rightPanel.add(messageScrollPane)
            rightPanel.add(Box.createVerticalStrut(Design.Spacing.LG))
            rightPanel.add(Box.createVerticalGlue())
            rightPanel.add(buttonPanel)

            contentPanel.add(leftPanel, BorderLayout.CENTER)
            contentPanel.add(rightPanel, BorderLayout.EAST)
        } else {
            contentPanel.layout = BoxLayout(contentPanel, BoxLayout.Y_AXIS)
            contentPanel.border =
                EmptyBorder(Design.Spacing.XL, Design.Spacing.XL, Design.Spacing.XL, Design.Spacing.XL)

            contentPanel.add(messageScrollPane)
            contentPanel.add(Box.createVerticalStrut(Design.Spacing.XL))

            val buttonPanel = createOptionButtonPanel(options) { index ->
                result = index
                dialog.dispose()
            }
            denialButton = buttonPanel.components.filterIsInstance<JButton>().lastOrNull()
            contentPanel.add(buttonPanel)
        }

        dialog.contentPane = contentPanel
        dialog.rootPane.defaultButton = denialButton
        dialog.pack()

        if (parent != null && parent.isDisplayable) {
            dialog.setLocationRelativeTo(parent)

            dialog.isAlwaysOnTop = true
            dialog.toFront()
            dialog.requestFocus()
        } else {
            val screenSize = Toolkit.getDefaultToolkit().screenSize
            val dialogSize = dialog.size
            dialog.setLocation(
                (screenSize.width - dialogSize.width) / 2, (screenSize.height - dialogSize.height) / 2
            )
        }

        denialButton?.let { button ->
            SwingUtilities.invokeLater { button.requestFocusInWindow() }
        }
        activeOptionDialog.set(dialog)
        try {
            dialog.isVisible = true
        } finally {
            activeOptionDialog.compareAndSet(dialog, null)
        }

        if (dialog.isDisplayable) {
            SwingUtilities.invokeLater {
                dialog.isAlwaysOnTop = false
                dialog.toFront()
            }
        }

        return result
    }
}