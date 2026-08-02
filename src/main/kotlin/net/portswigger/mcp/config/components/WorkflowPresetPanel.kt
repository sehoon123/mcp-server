package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.presets.LocalWorkflowPresetListResult
import net.portswigger.mcp.presets.LocalWorkflowPresetMutationResult
import net.portswigger.mcp.presets.LocalWorkflowPresetStatus
import net.portswigger.mcp.presets.WorkflowPreset
import net.portswigger.mcp.presets.WorkflowPresetManagement
import net.portswigger.mcp.presets.WorkflowPresetType
import net.portswigger.mcp.presets.workflowPresetNameKey
import java.awt.Dimension
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
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.ListSelectionModel
import javax.swing.SwingUtilities
import javax.swing.table.AbstractTableModel

private const val PRESET_PANEL_TEXT_FALLBACK_WIDTH = 480

internal fun interface WorkflowPresetDeleteConfirmation {
    fun confirm(parent: JComponent, preset: WorkflowPreset): Boolean
}

private object SwingWorkflowPresetDeleteConfirmation : WorkflowPresetDeleteConfirmation {
    override fun confirm(parent: JComponent, preset: WorkflowPreset): Boolean =
        Dialogs.showConfirmDialog(
            parent,
            "Delete the selected workflow preset? This changes only the current Burp project's saved settings and does not execute traffic.",
            javax.swing.JOptionPane.YES_NO_OPTION,
        ) == javax.swing.JOptionPane.YES_OPTION
}

internal class WorkflowPresetPanel(
    private val management: WorkflowPresetManagement,
    private val parentComponent: JComponent,
    private val editor: WorkflowPresetEditor = SwingWorkflowPresetEditor,
    private val deleteConfirmation: WorkflowPresetDeleteConfirmation = SwingWorkflowPresetDeleteConfirmation,
) : JPanel() {
    private val closed = AtomicBoolean(false)
    private val worker = ThreadPoolExecutor(
        1,
        1,
        0L,
        TimeUnit.MILLISECONDS,
        ArrayBlockingQueue(1),
        { runnable -> Thread(runnable, "burp-mcp-workflow-presets").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )

    @Volatile
    private var activeFuture: Future<*>? = null
    private var actionInProgress = false
    private var initialRefreshRequested = false
    private var panelInitialized = false
    private val tableModel = WorkflowPresetTableModel()
    private val table = object : JTable(tableModel) {
        override fun updateUI() {
            super.updateUI()
            rowHeight = getFontMetrics(font).height + Design.Spacing.SM
            preferredScrollableViewportSize = Dimension(560, rowHeight * 6)
        }
    }.apply {
        name = "workflowPresetTable"
        setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        fillsViewportHeight = true
        autoCreateRowSorter = false
        rowSelectionAllowed = true
        columnSelectionAllowed = false
        accessibleContext.accessibleName = "Saved workflow presets"
        accessibleContext.accessibleDescription =
            "Project-local presets available for management; selecting a row does not execute it"
    }
    private val tableScroll = object : JScrollPane(table) {
        override fun getMaximumSize(): Dimension = Dimension(Int.MAX_VALUE, preferredSize.height)
    }.apply {
        name = "workflowPresetTableScroll"
        alignmentX = LEFT_ALIGNMENT
        border = BorderFactory.createLineBorder(Design.Colors.outline, 1)
    }
    private val refreshButton = Design.createOutlinedButton("Refresh presets").apply {
        name = "refreshWorkflowPresetsButton"
        accessibleContext.accessibleDescription = "Reads saved presets from the current Burp project"
        addActionListener { refreshPresets() }
    }
    private val createButton = Design.createFilledButton("New preset...").apply {
        name = "newWorkflowPresetButton"
        accessibleContext.accessibleDescription = "Opens a structured editor for a new project-local preset"
        addActionListener { createPreset() }
    }
    private val editButton = Design.createOutlinedButton("Edit selected...").apply {
        name = "editWorkflowPresetButton"
        isEnabled = false
        accessibleContext.accessibleDescription = "Edits the selected preset without executing it"
        addActionListener { editSelectedPreset() }
    }
    private val deleteButton = Design.createOutlinedButton("Delete selected...").apply {
        name = "deleteWorkflowPresetButton"
        isEnabled = false
        accessibleContext.accessibleDescription = "Confirms deletion of the selected project-local preset"
        addActionListener { deleteSelectedPreset() }
    }
    private val selectionText = WrappingText(
        "No preset selected.",
        WrappingTextStyle.BODY_MEDIUM,
        fallbackMaxWidth = PRESET_PANEL_TEXT_FALLBACK_WIDTH,
    ).apply {
        name = "workflowPresetSelectionText"
        accessibleContext.accessibleDescription = "Selected workflow preset summary"
    }
    private val statusText = WrappingText(
        "Preset list has not been loaded.",
        WrappingTextStyle.PRIMARY_BODY_MEDIUM,
        fallbackMaxWidth = PRESET_PANEL_TEXT_FALLBACK_WIDTH,
    ).apply {
        name = "workflowPresetStatusText"
        accessibleContext.accessibleDescription = "Latest workflow preset management status"
    }

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        alignmentX = LEFT_ALIGNMENT
        updateColors()
        buildPanel()
        table.selectionModel.addListSelectionListener { event ->
            if (!event.valueIsAdjusting) updateSelectionState()
        }
        installAccessibilityRelations()
        panelInitialized = true
    }

    override fun addNotify() {
        super.addNotify()
        if (!initialRefreshRequested && !closed.get()) {
            initialRefreshRequested = true
            SwingUtilities.invokeLater {
                if (!closed.get() && !actionInProgress) refreshPresets()
            }
        }
    }

    override fun updateUI() {
        super.updateUI()
        updateColors()
        if (panelInitialized) {
            tableScroll.border = BorderFactory.createLineBorder(Design.Colors.outline, 1)
        }
    }

    fun cleanup() {
        cancelBackgroundWork()
    }

    fun cancelBackgroundWorkAndAwait() {
        cancelBackgroundWork()
        try {
            worker.awaitTermination(2, TimeUnit.SECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun cancelBackgroundWork() {
        if (closed.compareAndSet(false, true)) {
            activeFuture?.cancel(true)
            worker.shutdownNow()
        }
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

    private fun buildPanel() {
        add(Design.createSectionLabel("Workflow Preset Manager"))
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(
            WrappingText(
                "Create, inspect, update, or delete reusable search and comparison settings in the current Burp project. This local manager never executes a preset, reads traffic, or changes the MCP catalog.",
                WrappingTextStyle.BODY_MEDIUM,
                fallbackMaxWidth = PRESET_PANEL_TEXT_FALLBACK_WIDTH,
            ),
        )
        add(Box.createVerticalStrut(Design.Spacing.MD))
        add(tableScroll)
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(selectionText)
        add(Box.createVerticalStrut(Design.Spacing.MD))
        add(
            AdaptiveButtonPanel(listOf(refreshButton, createButton, editButton, deleteButton)).apply {
                alignmentX = LEFT_ALIGNMENT
            },
        )
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(statusText)
    }

    private fun installAccessibilityRelations() {
        val buttons = arrayOf(refreshButton, createButton, editButton, deleteButton)
        buttons.forEach { button ->
            button.accessibleContext.accessibleRelationSet.add(
                AccessibleRelation(AccessibleRelation.CONTROLLER_FOR, statusText),
            )
        }
        statusText.accessibleContext.accessibleRelationSet.add(
            AccessibleRelation(AccessibleRelation.CONTROLLED_BY, buttons),
        )
        table.accessibleContext.accessibleRelationSet.add(
            AccessibleRelation(AccessibleRelation.CONTROLLER_FOR, selectionText),
        )
        selectionText.accessibleContext.accessibleRelationSet.add(
            AccessibleRelation(AccessibleRelation.CONTROLLED_BY, table),
        )
    }

    private fun refreshPresets() {
        check(SwingUtilities.isEventDispatchThread()) { "preset refresh belongs to the EDT" }
        if (closed.get() || actionInProgress) return
        setActionInProgress(true)
        showStatus("Reading project-local presets...")
        submitBackground(
            task = management::list,
            onSuccess = ::publishList,
            onFailure = { showStatus("Preset refresh was interrupted. Choose Refresh presets to try again.") },
        )
    }

    private fun createPreset() {
        check(SwingUtilities.isEventDispatchThread()) { "preset creation belongs to the EDT" }
        if (closed.get() || actionInProgress) return
        val draft = editor.edit(parentComponent, null) ?: return
        if (closed.get() || actionInProgress) return
        submitMutation(
            runningText = "Saving the new project-local preset...",
            mutation = { management.save(draft, overwrite = false) },
            successText = { result ->
                if (result.created) "Preset created."
                else "Preset save completed."
            },
        )
    }

    private fun editSelectedPreset() {
        check(SwingUtilities.isEventDispatchThread()) { "preset editing belongs to the EDT" }
        if (closed.get() || actionInProgress) return
        val existing = selectedPreset() ?: return
        val edited = editor.edit(parentComponent, existing) ?: return
        if (closed.get() || actionInProgress) return
        val fixedIdentity = edited.copy(name = existing.name)
        submitMutation(
            runningText = "Saving changes to the selected preset...",
            mutation = { management.save(fixedIdentity, overwrite = true) },
            successText = { result ->
                if (result.replaced) "Preset changes saved."
                else "Preset save completed."
            },
        )
    }

    private fun deleteSelectedPreset() {
        check(SwingUtilities.isEventDispatchThread()) { "preset deletion belongs to the EDT" }
        if (closed.get() || actionInProgress) return
        val selected = selectedPreset() ?: return
        if (!deleteConfirmation.confirm(parentComponent, selected)) return
        if (closed.get() || actionInProgress) return
        submitMutation(
            runningText = "Deleting the selected project-local preset...",
            mutation = { management.delete(selected.name) },
            successText = { result ->
                if (result.deleted) "Preset deleted."
                else "The preset was already absent; the list was refreshed."
            },
        )
    }

    private fun submitMutation(
        runningText: String,
        mutation: () -> LocalWorkflowPresetMutationResult,
        successText: (LocalWorkflowPresetMutationResult) -> String,
    ) {
        setActionInProgress(true)
        showStatus(runningText)
        submitBackground(
            task = {
                val result = mutation()
                MutationPublication(
                    mutation = result,
                    refreshed = if (result.status == LocalWorkflowPresetStatus.OK) management.list() else null,
                )
            },
            onSuccess = { publication ->
                val result = publication.mutation
                if (result.status == LocalWorkflowPresetStatus.OK) {
                    publication.refreshed?.takeIf { it.status == LocalWorkflowPresetStatus.OK }?.let(::replaceTable)
                    showStatus(
                        if (publication.refreshed?.status == LocalWorkflowPresetStatus.OK) successText(result)
                        else "${successText(result)} Choose Refresh presets to reconcile the visible list.",
                    )
                } else {
                    showStatus(mutationStatusText(result.status))
                }
            },
            onFailure = {
                showStatus("Preset storage operation was interrupted. Reconcile the current project before retrying.")
            },
        )
    }

    private fun publishList(result: LocalWorkflowPresetListResult) {
        if (result.status == LocalWorkflowPresetStatus.OK) {
            replaceTable(result)
            showStatus(
                if (result.presets.isEmpty()) "No workflow presets are stored in the current project."
                else "Loaded ${result.presets.size} project-local workflow preset${if (result.presets.size == 1) "" else "s"}.",
            )
        } else {
            showStatus(listStatusText(result.status))
        }
    }

    private fun replaceTable(result: LocalWorkflowPresetListResult) {
        val previousName = selectedPreset()?.name
        tableModel.replace(result.presets)
        val restoredIndex = previousName?.let { name ->
            result.presets.indexOfFirst { workflowPresetNameKey(it.name) == workflowPresetNameKey(name) }
        } ?: -1
        if (restoredIndex >= 0) table.setRowSelectionInterval(restoredIndex, restoredIndex)
        else table.clearSelection()
        updateSelectionState()
    }

    private fun selectedPreset(): WorkflowPreset? =
        table.selectedRow.takeIf { it >= 0 }?.let(tableModel::presetAt)

    private fun updateSelectionState() {
        val preset = selectedPreset()
        selectionText.updateContent(
            if (preset == null) {
                "No preset selected."
            } else {
                val description = preset.description?.takeIf(String::isNotBlank)?.let { " Description: $it" }.orEmpty()
                "Selected: ${preset.name}. Type: ${preset.definition.kind().displayName()}.$description Editing or deleting requires an explicit action; selection never executes traffic."
            },
        )
        updateButtonState()
    }

    private fun <T> submitBackground(
        task: () -> T,
        onSuccess: (T) -> Unit,
        onFailure: (Throwable) -> Unit,
    ) {
        try {
            activeFuture = worker.submit {
                val outcome = runCatching(task)
                SwingUtilities.invokeLater {
                    if (closed.get()) return@invokeLater
                    activeFuture = null
                    setActionInProgress(false)
                    outcome.fold(onSuccess, onFailure)
                }
            }
        } catch (_: RejectedExecutionException) {
            setActionInProgress(false)
            if (!closed.get()) showStatus("Workflow preset background actions are unavailable.")
        }
    }

    private fun setActionInProgress(value: Boolean) {
        check(SwingUtilities.isEventDispatchThread()) { "preset action state belongs to the EDT" }
        actionInProgress = value
        updateButtonState()
    }

    private fun updateButtonState() {
        val hasSelection = selectedPreset() != null
        refreshButton.isEnabled = !actionInProgress
        createButton.isEnabled = !actionInProgress
        editButton.isEnabled = !actionInProgress && hasSelection
        deleteButton.isEnabled = !actionInProgress && hasSelection
        table.isEnabled = !actionInProgress
    }

    private fun showStatus(content: String) {
        statusText.updateContent(content)
    }

    private data class MutationPublication(
        val mutation: LocalWorkflowPresetMutationResult,
        val refreshed: LocalWorkflowPresetListResult?,
    )
}

private class WorkflowPresetTableModel : AbstractTableModel() {
    private var presets: List<WorkflowPreset> = emptyList()

    override fun getRowCount(): Int = presets.size
    override fun getColumnCount(): Int = 3
    override fun getColumnName(column: Int): String = when (column) {
        0 -> "Name"
        1 -> "Type"
        else -> "Description"
    }
    override fun getValueAt(rowIndex: Int, columnIndex: Int): String {
        val preset = presets[rowIndex]
        return when (columnIndex) {
            0 -> preset.name
            1 -> preset.definition.kind().displayName()
            else -> preset.description.orEmpty()
        }
    }
    override fun isCellEditable(rowIndex: Int, columnIndex: Int): Boolean = false

    fun replace(next: List<WorkflowPreset>) {
        presets = next.toList()
        fireTableDataChanged()
    }

    fun presetAt(index: Int): WorkflowPreset = presets[index]
}

private fun WorkflowPresetType.displayName(): String = when (this) {
    WorkflowPresetType.HTTP_SEARCH -> "HTTP metadata search"
    WorkflowPresetType.WEBSOCKET_SEARCH -> "WebSocket metadata search"
    WorkflowPresetType.HTTP_COMPARISON -> "HTTP comparison"
}

private fun listStatusText(status: LocalWorkflowPresetStatus): String = when (status) {
    LocalWorkflowPresetStatus.PROJECT_CHANGED -> "The Burp project changed while presets were being read. Refresh the new project."
    LocalWorkflowPresetStatus.PROJECT_UNAVAILABLE -> "The current Burp project is unavailable."
    LocalWorkflowPresetStatus.STORED_DATA_INVALID -> "Stored workflow preset data is invalid. The original value was preserved without modification."
    LocalWorkflowPresetStatus.STORAGE_UNAVAILABLE -> "Workflow preset storage is unavailable."
    LocalWorkflowPresetStatus.CAPACITY_REACHED -> "Workflow preset storage capacity was reached."
    LocalWorkflowPresetStatus.INVALID_ARGUMENT,
    LocalWorkflowPresetStatus.ALREADY_EXISTS,
    LocalWorkflowPresetStatus.UNCERTAIN -> "Workflow presets could not be read safely."
    LocalWorkflowPresetStatus.OK -> "Workflow presets loaded."
}

private fun mutationStatusText(status: LocalWorkflowPresetStatus): String = when (status) {
    LocalWorkflowPresetStatus.INVALID_ARGUMENT -> "Preset settings are invalid and were not stored."
    LocalWorkflowPresetStatus.PROJECT_CHANGED -> "The Burp project changed before the preset operation completed."
    LocalWorkflowPresetStatus.PROJECT_UNAVAILABLE -> "The current Burp project is unavailable; no preset operation started."
    LocalWorkflowPresetStatus.ALREADY_EXISTS -> "A preset with that name already exists. Select it and choose Edit selected instead."
    LocalWorkflowPresetStatus.CAPACITY_REACHED -> "The project has reached its bounded workflow preset capacity."
    LocalWorkflowPresetStatus.STORED_DATA_INVALID -> "Stored workflow preset data is invalid. The original value was preserved without modification."
    LocalWorkflowPresetStatus.STORAGE_UNAVAILABLE -> "Workflow preset storage is unavailable."
    LocalWorkflowPresetStatus.UNCERTAIN -> "Preset storage may have changed. Do not retry automatically; refresh and reconcile the current project first."
    LocalWorkflowPresetStatus.OK -> "Preset operation completed."
}
