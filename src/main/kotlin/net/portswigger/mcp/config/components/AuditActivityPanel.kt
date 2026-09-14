package net.portswigger.mcp.config.components

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.MAX_AUDIT_RETENTION_ENTRIES
import net.portswigger.mcp.security.McpAuditRecord
import java.awt.BorderLayout
import java.awt.Dimension
import java.time.Instant
import java.util.regex.Pattern
import javax.swing.BoxLayout
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.ListSelectionModel
import javax.swing.RowFilter
import javax.swing.RowSorter
import javax.swing.SortOrder
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.table.TableRowSorter

/** Local view of the existing sanitized audit snapshot; never reads traffic or owns persistence. */
internal class AuditActivityPanel : JPanel() {
    private val model = AuditTableModel()
    private val sorter = TableRowSorter(model)
    private var refreshing = false
    private var available = true
    private val table = object : JTable(model) {
        override fun updateUI() {
            super.updateUI()
            rowHeight = getFontMetrics(font).height + Design.Spacing.SM
            preferredScrollableViewportSize = Dimension(560, rowHeight * 6)
        }
    }.apply {
        name = "auditActivityTable"
        accessibleContext.accessibleName = "Recent redacted MCP activity"
        accessibleContext.accessibleDescription = "Sort retained audit metadata; selection never executes an action"
        rowSorter = sorter
        setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        fillsViewportHeight = true
        autoResizeMode = JTable.AUTO_RESIZE_OFF
        val widths = intArrayOf(200, 240, 160, 90, 100, 140)
        widths.forEachIndexed { index, width -> columnModel.getColumn(index).preferredWidth = width }
        columnModel.getColumn(0).cellRenderer = object : DefaultTableCellRenderer() {
            override fun setValue(value: Any?) {
                super.setValue((value as? Long)?.let { Instant.ofEpochMilli(it).toString() } ?: "")
            }
        }
    }
    private val filterField = JTextField(18).apply {
        name = "auditActivityFilter"
        accessibleContext.accessibleName = "Filter audit tool, outcome or session"
        toolTipText = "Case-insensitive literal text, not a regular expression"
    }
    private val clearFilterButton = Design.createOutlinedButton("Clear filter").apply {
        name = "auditActivityClearFilter"
        accessibleContext.accessibleDescription = "Clear the activity filter without deleting audit records"
        isEnabled = false
        addActionListener {
            filterField.text = ""
            filterField.requestFocusInWindow()
        }
    }
    private val countLabel = JLabel().apply { alignmentX = LEFT_ALIGNMENT }
    private val details = JTextArea(5, 40).apply {
        name = "auditActivityDetails"
        accessibleContext.accessibleName = "Selected redacted audit record"
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
    }
    private val json = Json { prettyPrint = true; encodeDefaults = true }

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        alignmentX = LEFT_ALIGNMENT
        isOpaque = false
        add(Design.createSectionLabel("Recent redacted activity"))
        add(WrappingText("Local audit metadata only; no argument values, credentials or request/response content."))
        add(object : JPanel(BorderLayout(Design.Spacing.SM, 0)) {
            override fun getMaximumSize() = Dimension(Int.MAX_VALUE, preferredSize.height)
        }.apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            add(JLabel("Filter:").apply { labelFor = filterField }, BorderLayout.WEST)
            add(filterField, BorderLayout.CENTER)
            add(clearFilterButton, BorderLayout.EAST)
        })
        add(countLabel)
        listOf(table, details).forEach { component ->
            add(object : JScrollPane(component) {
                override fun getMaximumSize() = Dimension(Int.MAX_VALUE, preferredSize.height)
            }.apply { alignmentX = LEFT_ALIGNMENT })
        }
        sorter.sortKeys = listOf(RowSorter.SortKey(0, SortOrder.DESCENDING))
        sorter.addRowSorterListener { updateCount() }
        table.selectionModel.addListSelectionListener { event ->
            if (!refreshing && !event.valueIsAdjusting) showSelection()
        }
        filterField.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(event: DocumentEvent) = filter()
            override fun removeUpdate(event: DocumentEvent) = filter()
            override fun changedUpdate(event: DocumentEvent) = filter()
        })
        updateCount()
    }

    fun refresh(records: List<McpAuditRecord>) {
        available = true
        val bounded = records.takeLast(MAX_AUDIT_RETENTION_ENTRIES)
        if (bounded != model.records) {
            val selected = selectedRecord()
            refreshing = true
            try {
                table.clearSelection()
                model.records = bounded
                model.fireTableDataChanged()
                val row = bounded.indexOf(selected)
                if (row >= 0) {
                    val visibleRow = table.convertRowIndexToView(row)
                    if (visibleRow >= 0) table.setRowSelectionInterval(visibleRow, visibleRow)
                }
            } finally {
                refreshing = false
            }
            showSelection()
        }
        updateCount()
    }

    fun unavailable() {
        refresh(emptyList())
        available = false
        updateCount()
    }

    private fun filter() {
        clearFilterButton.isEnabled = filterField.text.isNotEmpty()
        sorter.rowFilter = filterField.text.takeIf { it.isNotEmpty() }?.let {
            RowFilter.regexFilter("(?iu)${Pattern.quote(it)}", 1, 2, 5)
        }
        showSelection()
        updateCount()
    }

    private fun selectedRecord(): McpAuditRecord? = table.selectedRow.takeIf { it >= 0 }
        ?.let { model.records.getOrNull(table.convertRowIndexToModel(it)) }

    private fun showSelection() {
        val text = selectedRecord()?.let { json.encodeToString(it) }.orEmpty()
        if (details.text != text) {
            details.text = text
            details.caretPosition = 0
        }
    }

    private fun updateCount() {
        countLabel.text = if (available) "${table.rowCount} of ${model.rowCount} records" else "Audit unavailable"
    }
}

private class AuditTableModel : AbstractTableModel() {
    var records: List<McpAuditRecord> = emptyList()
    private val columns = arrayOf("Time (UTC)", "Tool / event", "Outcome", "Duration (ms)", "Access", "Session correlation")

    override fun getRowCount() = records.size
    override fun getColumnCount() = columns.size
    override fun getColumnName(column: Int) = columns[column]
    override fun getColumnClass(column: Int): Class<*> =
        if (column == 0 || column == 3) Long::class.javaObjectType else String::class.java
    override fun isCellEditable(row: Int, column: Int) = false
    override fun getValueAt(row: Int, column: Int): Any = records[row].let {
        when (column) {
            0 -> it.timestampEpochMillis
            1 -> it.tool
            2 -> it.outcome
            3 -> it.durationMillis
            4 -> if (it.readOnly) "Read-only" else "Stateful"
            5 -> it.sessionCorrelation
            else -> ""
        }
    }
}
