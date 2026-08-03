package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.presets.MAX_WORKFLOW_PRESET_DESCRIPTION_CHARS
import net.portswigger.mcp.presets.MAX_WORKFLOW_PRESET_NAME_CHARS
import net.portswigger.mcp.presets.SavedHttpComparison
import net.portswigger.mcp.presets.SavedHttpSearch
import net.portswigger.mcp.presets.SavedWebSocketSearch
import net.portswigger.mcp.presets.WorkflowPreset
import net.portswigger.mcp.presets.WorkflowPresetDefinition
import net.portswigger.mcp.presets.WorkflowPresetType
import net.portswigger.mcp.presets.executionNeutralInputPreview
import net.portswigger.mcp.presets.validateWorkflowPreset
import net.portswigger.mcp.tools.HttpComparisonEncoding
import net.portswigger.mcp.tools.HttpComparisonPart
import net.portswigger.mcp.tools.HttpMessageSource
import net.portswigger.mcp.tools.WebSocketSearchDirection
import java.awt.BorderLayout
import java.awt.CardLayout
import java.awt.Component
import java.awt.Dialog
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.event.ActionEvent
import java.awt.event.KeyEvent
import java.util.Locale
import java.util.concurrent.atomic.AtomicReference
import javax.accessibility.AccessibleRelation
import javax.swing.AbstractAction
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JRootPane
import javax.swing.JTextField
import javax.swing.KeyStroke
import javax.swing.ScrollPaneConstants
import javax.swing.SwingUtilities
import javax.swing.WindowConstants
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

internal const val MAX_WORKFLOW_PRESET_EDITOR_RAW_FIELD_CHARS = 16_384

internal fun interface WorkflowPresetEditor {
    fun edit(parent: Component, existing: WorkflowPreset?): WorkflowPreset?
}

internal fun installWorkflowPresetEditorCancellation(rootPane: JRootPane, cancel: () -> Unit) {
    rootPane.defaultButton = null
    rootPane.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
        KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
        "cancel-preset-editor",
    )
    rootPane.actionMap.put("cancel-preset-editor", object : AbstractAction() {
        override fun actionPerformed(event: ActionEvent?) = cancel()
    })
}

internal fun createWorkflowPresetSaveButton(
    creating: Boolean,
    form: WorkflowPresetEditorForm,
    onAccepted: (WorkflowPreset) -> Unit,
): JButton {
    check(SwingUtilities.isEventDispatchThread()) { "workflow preset save control belongs to the EDT" }
    return Design.createFilledButton(if (creating) "Create preset" else "Save changes").apply {
        name = "saveWorkflowPresetEditButton"
        isEnabled = false
        accessibleContext.accessibleDescription =
            "Stores the validated project-local preset without reading or executing traffic"
        addActionListener { form.toPreset()?.let(onAccepted) }
        form.setValidationListener { isEnabled = it }
    }
}

/** Structured local editor; it deliberately has no cursor, reference, traffic, result, or execution controls. */
internal object SwingWorkflowPresetEditor : WorkflowPresetEditor {
    override fun edit(parent: Component, existing: WorkflowPreset?): WorkflowPreset? {
        check(SwingUtilities.isEventDispatchThread()) { "workflow preset editor belongs to the EDT" }
        val form = WorkflowPresetEditorForm(existing)
        val result = AtomicReference<WorkflowPreset?>()
        val parentWindow = SwingUtilities.getWindowAncestor(parent)
        val dialog = JDialog(parentWindow, if (existing == null) "New workflow preset" else "Edit workflow preset", Dialog.ModalityType.APPLICATION_MODAL).apply {
            defaultCloseOperation = WindowConstants.DISPOSE_ON_CLOSE
            isResizable = true
        }

        val cancelButton = Design.createOutlinedButton("Cancel").apply {
            name = "cancelWorkflowPresetEditButton"
            addActionListener { dialog.dispose() }
        }
        val saveButton = createWorkflowPresetSaveButton(existing == null, form) { preset ->
            result.set(preset)
            dialog.dispose()
        }
        val buttons = JPanel(FlowLayout(FlowLayout.RIGHT, Design.Spacing.SM, 0)).apply {
            isOpaque = false
            add(cancelButton)
            add(saveButton)
        }
        val scroll = JScrollPane(form).apply {
            border = null
            horizontalScrollBarPolicy = ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER
            verticalScrollBarPolicy = ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED
            verticalScrollBar.unitIncrement = 16
        }
        dialog.contentPane = JPanel(BorderLayout(0, Design.Spacing.MD)).apply {
            background = Design.Colors.surface
            border = BorderFactory.createEmptyBorder(
                Design.Spacing.LG,
                Design.Spacing.LG,
                Design.Spacing.LG,
                Design.Spacing.LG,
            )
            add(scroll, BorderLayout.CENTER)
            add(buttons, BorderLayout.SOUTH)
        }
        installWorkflowPresetEditorCancellation(dialog.rootPane, dialog::dispose)
        dialog.minimumSize = Dimension(520, 420)
        dialog.preferredSize = Dimension(720, 680)
        dialog.pack()
        dialog.setLocationRelativeTo(parent)
        SwingUtilities.invokeLater { if (existing == null) form.requestNameFocus() else cancelButton.requestFocusInWindow() }
        dialog.isVisible = true
        return result.get()
    }
}

internal class WorkflowPresetEditorForm(existing: WorkflowPreset?) : JPanel() {
    private val nameField = editorField("workflowPresetNameField", 32)
    private val descriptionField = editorField("workflowPresetDescriptionField", 32)
    private val typeSelector = JComboBox(arrayOf("HTTP metadata search", "WebSocket metadata search", "HTTP comparison")).apply {
        name = "workflowPresetTypeSelector"
        maximumSize = Dimension(Int.MAX_VALUE, preferredSize.height)
        accessibleContext.accessibleName = "Workflow preset type"
    }
    private val definitionCards = JPanel(CardLayout()).apply { isOpaque = false }
    private val validationText = WrappingText(" ", WrappingTextStyle.LABEL_MEDIUM).apply {
        name = "workflowPresetValidationText"
        accessibleContext.accessibleDescription = "Workflow preset validation status"
    }
    private val inputPreviewText = WrappingText(
        "Execution-neutral preview is available when the settings are valid.",
        WrappingTextStyle.BODY_MEDIUM,
        fallbackMaxWidth = 640,
    ).apply {
        name = "workflowPresetInputPreviewText"
        accessibleContext.accessibleDescription =
            "Privacy-bounded effective input preview that never reads or executes traffic"
    }
    private var validationListener: (Boolean) -> Unit = {}

    private val httpSourcesField = editorField("workflowPresetHttpSourcesField")
    private val httpHostField = editorField("workflowPresetHttpHostField")
    private val httpPathField = editorField("workflowPresetHttpPathField")
    private val httpMethodsField = editorField("workflowPresetHttpMethodsField")
    private val httpStatusCodesField = editorField("workflowPresetHttpStatusCodesField")
    private val httpMimeTypesField = editorField("workflowPresetHttpMimeTypesField")
    private val httpInScope = triStateCombo("workflowPresetHttpInScopeSelector")
    private val httpHasResponse = triStateCombo("workflowPresetHttpHasResponseSelector")
    private val httpNewestFirst = triStateCombo("workflowPresetHttpNewestFirstSelector")
    private val httpDefaultLimitField = editorField("workflowPresetHttpDefaultLimitField", 8)

    private val webSocketDirection = JComboBox(arrayOf("Use default", "Client to server", "Server to client")).apply {
        name = "workflowPresetWebSocketDirectionSelector"
    }
    private val webSocketListenerPortField = editorField("workflowPresetWebSocketListenerPortField", 8)
    private val webSocketNewestFirst = triStateCombo("workflowPresetWebSocketNewestFirstSelector")
    private val webSocketDefaultLimitField = editorField("workflowPresetWebSocketDefaultLimitField", 8)

    private val comparisonPart = JComboBox(
        arrayOf(
            "Use default", "Request", "Request headers", "Request body",
            "Response", "Response headers", "Response body",
        ),
    ).apply { name = "workflowPresetComparisonPartSelector" }
    private val comparisonLimitField = editorField("workflowPresetComparisonLimitField", 10)
    private val comparisonEncoding = JComboBox(arrayOf("Use default", "Text", "Base64")).apply {
        name = "workflowPresetComparisonEncodingSelector"
    }
    private val comparisonIgnoreHeadersField = editorField("workflowPresetComparisonIgnoreHeadersField")
    private val comparisonVariations = triStateCombo("workflowPresetComparisonVariationsSelector")

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        isOpaque = false
        alignmentX = LEFT_ALIGNMENT

        add(
            WrappingText(
                "Presets are stored only in the current Burp project. Store reusable filters only; do not enter credentials, traffic content, cursors, message references, or connection IDs.",
                WrappingTextStyle.BODY_MEDIUM,
                fallbackMaxWidth = 640,
            ),
        )
        add(Box.createVerticalStrut(Design.Spacing.MD))
        add(
            formPanel(
                "Name" to nameField,
                "Description (optional)" to descriptionField,
                "Workflow type" to typeSelector,
            ),
        )
        add(Box.createVerticalStrut(Design.Spacing.MD))

        definitionCards.add(httpPanel(), WorkflowPresetType.HTTP_SEARCH.name)
        definitionCards.add(webSocketPanel(), WorkflowPresetType.WEBSOCKET_SEARCH.name)
        definitionCards.add(comparisonPanel(), WorkflowPresetType.HTTP_COMPARISON.name)
        definitionCards.alignmentX = LEFT_ALIGNMENT
        add(definitionCards)
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(validationText)
        add(Box.createVerticalStrut(Design.Spacing.MD))
        add(Design.createSectionLabel("Execution-neutral input preview").apply { labelFor = inputPreviewText })
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(inputPreviewText)

        typeSelector.addActionListener { showSelectedDefinition() }
        load(existing)
        nameField.isEditable = existing == null
        nameField.accessibleContext.accessibleDescription = if (existing == null) {
            "Unique preset name, one to 64 characters"
        } else {
            "Existing preset name; create a new preset to use another name"
        }
        showSelectedDefinition()
        installLiveValidation()
        refreshValidationState()
    }

    fun requestNameFocus() {
        nameField.requestFocusInWindow()
    }

    fun setValidationListener(listener: (Boolean) -> Unit) {
        check(SwingUtilities.isEventDispatchThread()) { "workflow preset validation listener belongs to the EDT" }
        validationListener = listener
        refreshValidationState()
    }

    fun toPreset(): WorkflowPreset? = parsePreset().also(::publishValidationState)

    private fun parsePreset(): WorkflowPreset? = try {
        require(selectedTextFields().all { it.document.length <= MAX_WORKFLOW_PRESET_EDITOR_RAW_FIELD_CHARS })
        val name = nameField.text.trim()
        require(name.length in 1..MAX_WORKFLOW_PRESET_NAME_CHARS && name.none(Char::isISOControl))
        val description = descriptionField.text.takeUnless(String::isEmpty)?.also {
            require(it.length <= MAX_WORKFLOW_PRESET_DESCRIPTION_CHARS && it.none(Char::isISOControl))
        }
        val definition = when (selectedType()) {
            WorkflowPresetType.HTTP_SEARCH -> WorkflowPresetDefinition(httpSearch = SavedHttpSearch(
                sources = parseSources(httpSourcesField.text),
                host = optionalText(httpHostField.text),
                pathContains = optionalText(httpPathField.text),
                methods = parseList(httpMethodsField.text)?.map { it.uppercase(Locale.ROOT) },
                statusCodes = parseIntegerList(httpStatusCodesField.text, 100..599),
                mimeTypes = parseList(httpMimeTypesField.text)?.map { it.uppercase(Locale.ROOT) },
                inScopeOnly = triStateValue(httpInScope),
                hasResponse = triStateValue(httpHasResponse),
                newestFirst = triStateValue(httpNewestFirst),
                defaultLimit = optionalInteger(httpDefaultLimitField.text, 1..50),
            ))
            WorkflowPresetType.WEBSOCKET_SEARCH -> WorkflowPresetDefinition(webSocketSearch = SavedWebSocketSearch(
                direction = when (webSocketDirection.selectedIndex) {
                    0 -> null
                    1 -> WebSocketSearchDirection.CLIENT_TO_SERVER
                    else -> WebSocketSearchDirection.SERVER_TO_CLIENT
                },
                listenerPort = optionalInteger(webSocketListenerPortField.text, 1..65_535),
                newestFirst = triStateValue(webSocketNewestFirst),
                defaultLimit = optionalInteger(webSocketDefaultLimitField.text, 1..50),
            ))
            WorkflowPresetType.HTTP_COMPARISON -> WorkflowPresetDefinition(httpComparison = SavedHttpComparison(
                part = comparisonPart.selectedIndex.takeIf { it > 0 }?.let { HttpComparisonPart.entries[it - 1] },
                limitBytesPerMessage = optionalInteger(comparisonLimitField.text, 1..1_048_576),
                excerptEncoding = when (comparisonEncoding.selectedIndex) {
                    0 -> null
                    1 -> HttpComparisonEncoding.TEXT
                    else -> HttpComparisonEncoding.BASE64
                },
                ignoreHeaders = parseList(comparisonIgnoreHeadersField.text),
                includeResponseVariations = triStateValue(comparisonVariations),
            ))
        }
        WorkflowPreset(name, description, definition).also(::validateWorkflowPreset)
    } catch (_: IllegalArgumentException) {
        null
    }

    private fun selectedType(): WorkflowPresetType = WorkflowPresetType.entries[typeSelector.selectedIndex]

    private fun selectedTextFields(): List<JTextField> = buildList {
        add(nameField)
        add(descriptionField)
        when (selectedType()) {
            WorkflowPresetType.HTTP_SEARCH -> addAll(
                listOf(
                    httpSourcesField,
                    httpHostField,
                    httpPathField,
                    httpMethodsField,
                    httpStatusCodesField,
                    httpMimeTypesField,
                    httpDefaultLimitField,
                ),
            )
            WorkflowPresetType.WEBSOCKET_SEARCH -> addAll(
                listOf(webSocketListenerPortField, webSocketDefaultLimitField),
            )
            WorkflowPresetType.HTTP_COMPARISON -> addAll(
                listOf(comparisonLimitField, comparisonIgnoreHeadersField),
            )
        }
    }

    private fun showSelectedDefinition() {
        (definitionCards.layout as CardLayout).show(definitionCards, selectedType().name)
        definitionCards.revalidate()
        definitionCards.repaint()
    }

    private fun installLiveValidation() {
        val listener = object : DocumentListener {
            override fun insertUpdate(event: DocumentEvent?) = refreshValidationState()
            override fun removeUpdate(event: DocumentEvent?) = refreshValidationState()
            override fun changedUpdate(event: DocumentEvent?) = refreshValidationState()
        }
        listOf(
            nameField,
            descriptionField,
            httpSourcesField,
            httpHostField,
            httpPathField,
            httpMethodsField,
            httpStatusCodesField,
            httpMimeTypesField,
            httpDefaultLimitField,
            webSocketListenerPortField,
            webSocketDefaultLimitField,
            comparisonLimitField,
            comparisonIgnoreHeadersField,
        ).forEach { it.document.addDocumentListener(listener) }
        listOf(
            typeSelector,
            httpInScope,
            httpHasResponse,
            httpNewestFirst,
            webSocketDirection,
            webSocketNewestFirst,
            comparisonPart,
            comparisonEncoding,
            comparisonVariations,
        ).forEach { it.addActionListener { refreshValidationState() } }
    }

    private fun refreshValidationState() {
        check(SwingUtilities.isEventDispatchThread()) { "workflow preset validation belongs to the EDT" }
        publishValidationState(parsePreset())
    }

    private fun publishValidationState(preset: WorkflowPreset?) {
        val valid = preset != null
        validationText.updateContent(
            if (valid) {
                "Preset settings are valid. Saving stores settings only and does not read or execute traffic."
            } else {
                "Preset settings are invalid. Check required lengths, comma-separated values, numeric bounds, and the selected workflow type."
            },
        )
        inputPreviewText.updateContent(
            preset?.executionNeutralInputPreview()
                ?: "Execution-neutral preview is available when the settings are valid; no traffic is read or executed.",
        )
        validationListener(valid)
    }

    private fun httpPanel(): JPanel = formPanel(
        "Sources" to httpSourcesField,
        "Host (optional)" to httpHostField,
        "Path contains (optional)" to httpPathField,
        "Methods" to httpMethodsField,
        "Status codes" to httpStatusCodesField,
        "MIME types" to httpMimeTypesField,
        "In scope only" to httpInScope,
        "Has response" to httpHasResponse,
        "Newest first" to httpNewestFirst,
        "Default limit" to httpDefaultLimitField,
    ).also {
        httpSourcesField.toolTipText = "Comma-separated: proxy, site_map, organizer. Blank uses Proxy."
        httpMethodsField.toolTipText = "Optional comma-separated HTTP methods"
        httpStatusCodesField.toolTipText = "Optional comma-separated codes from 100 to 599"
        httpMimeTypesField.toolTipText = "Optional comma-separated Burp MIME type names"
    }

    private fun webSocketPanel(): JPanel = formPanel(
        "Direction" to webSocketDirection,
        "Listener port" to webSocketListenerPortField,
        "Newest first" to webSocketNewestFirst,
        "Default limit" to webSocketDefaultLimitField,
    )

    private fun comparisonPanel(): JPanel = formPanel(
        "Message part" to comparisonPart,
        "Bytes per message" to comparisonLimitField,
        "Excerpt encoding" to comparisonEncoding,
        "Ignored headers" to comparisonIgnoreHeadersField,
        "Response variations" to comparisonVariations,
    ).also {
        comparisonIgnoreHeadersField.toolTipText = "Optional comma-separated header names"
    }

    private fun load(existing: WorkflowPreset?) {
        if (existing == null) {
            typeSelector.selectedIndex = WorkflowPresetType.HTTP_SEARCH.ordinal
            return
        }
        nameField.text = existing.name
        descriptionField.text = existing.description.orEmpty()
        typeSelector.selectedIndex = existing.definition.kind().ordinal
        existing.definition.httpSearch?.let { saved ->
            httpSourcesField.text = saved.sources?.joinToString(", ") { it.serialLabel() }.orEmpty()
            httpHostField.text = saved.host.orEmpty()
            httpPathField.text = saved.pathContains.orEmpty()
            httpMethodsField.text = saved.methods?.joinToString(", ").orEmpty()
            httpStatusCodesField.text = saved.statusCodes?.joinToString(", ").orEmpty()
            httpMimeTypesField.text = saved.mimeTypes?.joinToString(", ").orEmpty()
            setTriState(httpInScope, saved.inScopeOnly)
            setTriState(httpHasResponse, saved.hasResponse)
            setTriState(httpNewestFirst, saved.newestFirst)
            httpDefaultLimitField.text = saved.defaultLimit?.toString().orEmpty()
        }
        existing.definition.webSocketSearch?.let { saved ->
            webSocketDirection.selectedIndex = when (saved.direction) {
                null -> 0
                WebSocketSearchDirection.CLIENT_TO_SERVER -> 1
                WebSocketSearchDirection.SERVER_TO_CLIENT -> 2
            }
            webSocketListenerPortField.text = saved.listenerPort?.toString().orEmpty()
            setTriState(webSocketNewestFirst, saved.newestFirst)
            webSocketDefaultLimitField.text = saved.defaultLimit?.toString().orEmpty()
        }
        existing.definition.httpComparison?.let { saved ->
            comparisonPart.selectedIndex = saved.part?.ordinal?.plus(1) ?: 0
            comparisonLimitField.text = saved.limitBytesPerMessage?.toString().orEmpty()
            comparisonEncoding.selectedIndex = when (saved.excerptEncoding) {
                null -> 0
                HttpComparisonEncoding.TEXT -> 1
                HttpComparisonEncoding.BASE64 -> 2
            }
            comparisonIgnoreHeadersField.text = saved.ignoreHeaders?.joinToString(", ").orEmpty()
            setTriState(comparisonVariations, saved.includeResponseVariations)
        }
    }
}

private fun editorField(nameValue: String, columns: Int = 28): JTextField = JTextField(columns).apply {
    name = nameValue
    font = Design.Typography.bodyMedium
    maximumSize = Dimension(Int.MAX_VALUE, preferredSize.height)
}

private fun triStateCombo(nameValue: String): JComboBox<String> =
    JComboBox(arrayOf("Use default", "Yes", "No")).apply { name = nameValue }

private fun triStateValue(combo: JComboBox<String>): Boolean? = when (combo.selectedIndex) {
    0 -> null
    1 -> true
    else -> false
}

private fun setTriState(combo: JComboBox<String>, value: Boolean?) {
    combo.selectedIndex = when (value) {
        null -> 0
        true -> 1
        false -> 2
    }
}

private fun optionalText(raw: String): String? = raw.takeUnless(String::isEmpty)

private fun parseList(raw: String): List<String>? {
    require(raw.length <= MAX_WORKFLOW_PRESET_EDITOR_RAW_FIELD_CHARS)
    if (raw.isBlank()) return null
    var delimiters = 0
    raw.forEach { character ->
        if (character == ',') {
            delimiters++
            require(delimiters < 32)
        }
    }
    return raw.split(',').map(String::trim).also { values ->
        require(values.isNotEmpty() && values.size <= 32 && values.all(String::isNotEmpty))
        require(values.none { value -> value.any(Char::isISOControl) })
    }
}

private fun parseSources(raw: String): List<HttpMessageSource>? = parseList(raw)?.map { value ->
    when (value.lowercase(Locale.ROOT)) {
        "proxy" -> HttpMessageSource.PROXY
        "site_map", "site map", "sitemap" -> HttpMessageSource.SITE_MAP
        "organizer" -> HttpMessageSource.ORGANIZER
        else -> throw IllegalArgumentException("invalid source")
    }
}.also { sources -> require(sources == null || sources.distinct().size == sources.size) }

private fun parseIntegerList(raw: String, range: IntRange): List<Int>? = parseList(raw)?.map { value ->
    requireNotNull(value.toIntOrNull()).also { require(it in range) }
}

private fun optionalInteger(raw: String, range: IntRange): Int? {
    if (raw.isBlank()) return null
    return requireNotNull(raw.trim().toIntOrNull()).also { require(it in range) }
}

private fun HttpMessageSource.serialLabel(): String = when (this) {
    HttpMessageSource.PROXY -> "proxy"
    HttpMessageSource.SITE_MAP -> "site_map"
    HttpMessageSource.ORGANIZER -> "organizer"
}

private fun formPanel(vararg fields: Pair<String, JComponent>): JPanel = JPanel(GridBagLayout()).apply {
    isOpaque = false
    alignmentX = Component.LEFT_ALIGNMENT
    fields.forEachIndexed { row, (labelText, field) ->
        val label = JLabel(labelText).apply {
            font = Design.Typography.bodyMedium
            foreground = Design.Colors.onSurface
            labelFor = field
        }
        field.accessibleContext.accessibleName = labelText
        field.accessibleContext.accessibleRelationSet.add(
            AccessibleRelation(AccessibleRelation.LABELED_BY, label),
        )
        add(label, GridBagConstraints().apply {
            gridx = 0
            gridy = row
            weightx = 0.0
            anchor = GridBagConstraints.NORTHWEST
            insets = Insets(Design.Spacing.SM, 0, Design.Spacing.SM, Design.Spacing.MD)
        })
        add(field, GridBagConstraints().apply {
            gridx = 1
            gridy = row
            weightx = 1.0
            fill = GridBagConstraints.HORIZONTAL
            anchor = GridBagConstraints.NORTHWEST
            insets = Insets(Design.Spacing.SM, 0, Design.Spacing.SM, 0)
        })
    }
}
