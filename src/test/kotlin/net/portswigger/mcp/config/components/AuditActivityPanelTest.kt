package net.portswigger.mcp.config.components

import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import net.portswigger.mcp.config.MAX_AUDIT_RETENTION_ENTRIES
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.McpAuditApproval
import net.portswigger.mcp.security.McpAuditRecord
import net.portswigger.mcp.security.McpAuditSink
import net.portswigger.mcp.unavailableMcpDiagnosticsSnapshot
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.awt.Component
import java.awt.Container
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.RowSorter
import javax.swing.SortOrder
import javax.swing.SwingUtilities

class AuditActivityPanelTest {
    @Test
    fun `activity sorts numerically filters literally and preserves the selected record on refresh`() = onEdt {
        val panel = AuditActivityPanel()
        val table = descendants(panel).filterIsInstance<JTable>().single()
        val filter = descendants(panel).filterIsInstance<JTextField>().single()
        val details = descendants(panel).filterIsInstance<JTextArea>().single { it.name == "auditActivityDetails" }
        val records = listOf(record(1, "read.message", 2), record(2, "readXmessage", 100), record(3, "check_scope", 10))
        panel.refresh(records)

        assertEquals("check_scope", table.getValueAt(0, 1))
        assertFalse(table.isCellEditable(0, 1))
        table.rowSorter.sortKeys = listOf(RowSorter.SortKey(3, SortOrder.ASCENDING))
        assertEquals(listOf(2L, 10L, 100L), (0 until table.rowCount).map { table.getValueAt(it, 3) })
        table.setRowSelectionInterval(1, 1)
        val selection = details.text
        assertTrue(selection.contains("check_scope"))
        assertTrue(selection.contains("argumentKeys"))
        assertTrue(selection.contains("allow_once"))
        details.select(10, 30)
        panel.refresh(records + record(4, "another_read", 1))
        assertEquals(selection, details.text)
        assertEquals(10, details.selectionStart)
        assertEquals(30, details.selectionEnd)
        assertEquals("check_scope", table.getValueAt(table.selectedRow, 1))
        panel.refresh(records + record(4, "another_read", 1))
        assertEquals(selection, details.text)
        assertEquals(30, details.caretPosition)
        filter.text = "scope"
        assertEquals(selection, details.text)
        assertEquals(10, details.selectionStart)
        assertEquals(30, details.selectionEnd)

        filter.text = "READ.MESSAGE"
        assertEquals(1, table.rowCount)
        assertEquals("read.message", table.getValueAt(0, 1))
        assertEquals("", details.text)
        filter.text = "["
        assertEquals(0, table.rowCount)
        filter.text = ""
        assertEquals(4, table.rowCount)
        panel.refresh(emptyList())
        assertEquals(0, table.rowCount)
        assertEquals("", details.text)
    }

    @Test
    fun `audit read failure survives filter changes and clears until a successful snapshot`() = onEdt {
        val panel = AuditActivityPanel()
        val filter = descendants(panel).filterIsInstance<JTextField>().single()
        val table = descendants(panel).filterIsInstance<JTable>().single()
        val count = descendants(panel).filterIsInstance<JLabel>().single { it.text == "0 of 0 records" }
        panel.refresh(listOf(record(1, "read", 1)))
        table.setRowSelectionInterval(0, 0)
        panel.unavailable()
        filter.text = "read"
        assertEquals("Audit unavailable", count.text)
        filter.text = ""
        assertEquals("Audit unavailable", count.text)
        assertEquals(0, table.rowCount)
        assertEquals("", descendants(panel).filterIsInstance<JTextArea>().single { it.name == "auditActivityDetails" }.text)
        panel.refresh(emptyList())
        assertEquals("0 of 0 records", count.text)
        panel.refresh(listOf(record(2, "recovered", 2)))
        assertEquals("1 of 1 records", count.text)
    }

    @Test
    fun `clear filter is accessible restores only the view and retains an unavailable status`() = onEdt {
        val panel = AuditActivityPanel()
        val filter = descendants(panel).filterIsInstance<JTextField>().single()
        val table = descendants(panel).filterIsInstance<JTable>().single()
        val clear = descendants(panel).filterIsInstance<JButton>().single { it.name == "auditActivityClearFilter" }
        assertEquals("Clear filter", clear.accessibleContext.accessibleName)
        assertTrue(clear.accessibleContext.accessibleDescription.contains("without deleting"))
        assertFalse(clear.isEnabled)
        panel.refresh(listOf(record(1, "first", 1), record(2, "second", 2)))
        filter.text = "first"
        assertEquals(1, table.rowCount)
        assertTrue(clear.isEnabled)
        clear.doClick()
        assertEquals("", filter.text)
        assertEquals(2, table.rowCount)
        assertFalse(clear.isEnabled)
        filter.text = "["
        panel.unavailable()
        clear.doClick()
        assertTrue(descendants(panel).filterIsInstance<JLabel>().any { it.text == "Audit unavailable" })
    }

    @Test
    fun `activity retains only the bounded newest suffix and clears details when a record disappears`() = onEdt {
        val panel = AuditActivityPanel()
        val table = descendants(panel).filterIsInstance<JTable>().single()
        val details = descendants(panel).filterIsInstance<JTextArea>().single { it.name == "auditActivityDetails" }
        val records = (0 until MAX_AUDIT_RETENTION_ENTRIES + 5).map { record(it, "event_$it", it.toLong()) }
        panel.refresh(records)
        assertEquals(MAX_AUDIT_RETENTION_ENTRIES, table.rowCount)
        assertEquals("event_5", table.model.getValueAt(0, 1))
        table.setRowSelectionInterval(0, 0)
        assertTrue(details.text.isNotEmpty())
        panel.refresh(listOf(record(2_000, "replacement", 1)))
        assertEquals("", details.text)
        assertEquals(-1, table.selectedRow)
    }

    @Test
    fun `diagnostics uses the retention bound hides failed snapshots and stops reads after cleanup`() = onEdt {
        val config = mockk<McpConfig>(relaxed = true)
        every { config.auditRetentionEntries } returns 50
        val audit = mockk<McpAuditSink>(relaxed = true)
        var records = listOf(record(1, "first_read", 1))
        every { audit.snapshot(50) } answers { records }
        val panel = DiagnosticsPanel(config, ::unavailableMcpDiagnosticsSnapshot, audit, null, false)
        try {
            val table = descendants(panel).filterIsInstance<JTable>().single()
            val refresh = descendants(panel).filterIsInstance<JButton>().single { it.text == "Refresh" }
            val details = descendants(panel).filterIsInstance<JTextArea>().single { it.name == "auditActivityDetails" }
            assertEquals(1, table.rowCount)
            records = records + record(2, "second_read", 2)
            refresh.doClick()
            assertEquals(2, table.rowCount)
            table.setRowSelectionInterval(0, 0)
            assertTrue(details.text.contains("second_read"))
            records = emptyList()
            refresh.doClick()
            assertEquals(0, table.rowCount)
            assertEquals("", details.text)

            every { audit.snapshot(50) } throws IllegalStateException("private-failure-value")
            refresh.doClick()
            assertEquals(0, table.rowCount)
            assertTrue(descendants(panel).filterIsInstance<JLabel>().any { it.text == "Audit unavailable" })
            assertFalse(descendants(panel).filterIsInstance<JTextArea>().any { it.text.contains("private-failure-value") })
            panel.cleanup()
            refresh.doClick()
            verify(exactly = 4) { audit.snapshot(50) }
        } finally {
            panel.cleanup()
        }
    }

    private fun record(timestamp: Int, tool: String, duration: Long) = McpAuditRecord(
        timestampEpochMillis = timestamp.toLong(),
        sessionCorrelation = "0123456789ab",
        tool = tool,
        readOnly = true,
        argumentKeys = listOf("projectId", "ref"),
        approvals = listOf(McpAuditApproval("data_access", "allow_once")),
        durationMillis = duration,
        outcome = "ok",
    )

    private fun onEdt(action: () -> Unit) = SwingUtilities.invokeAndWait(action)

    private fun descendants(root: Container): Sequence<Component> = sequence {
        for (component in root.components) {
            yield(component)
            if (component is Container) yieldAll(descendants(component))
        }
    }
}
