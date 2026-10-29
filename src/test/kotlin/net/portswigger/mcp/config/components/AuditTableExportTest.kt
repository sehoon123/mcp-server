package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.MAX_AUDIT_RETENTION_ENTRIES
import org.junit.jupiter.api.Test
import kotlin.test.*

class AuditTableExportTest {
    private val columns = listOf("Time", "Tool", "Outcome", "Duration", "Access", "Session")
    private fun row(value: String) = listOf(value, "", "", "", "", "")

    @Test
    fun `CSV quotes every cell preserves order and neutralizes formulas after whitespace or controls`() {
        val values = listOf("=1", " +1", "\t@SUM(1)", " \u0000-2", "\nplain", "a,\"b\"\r\nc", "한😀")
        val csv = exportAuditTable(columns, values.map(::row), AuditExportFormat.CSV)
        assertTrue(csv.startsWith("\"Time\",\"Tool\",\"Outcome\""))
        for (value in values.take(5)) assertTrue(csv.contains("\"'$value\""))
        assertTrue(csv.contains("\"a,\"\"b\"\"\r\nc\""))
        assertTrue(csv.indexOf("=1") < csv.indexOf("+1"))
        assertTrue(csv.endsWith("\"한😀\",\"\",\"\",\"\",\"\",\"\"\r\n"))
    }

    @Test
    fun `HTML escapes all cells and labels with no scripts links or external assets`() {
        val html = exportAuditTable(columns.map { "$it<&\"'>" }, listOf(row("</td><script>alert('x')</script>")), AuditExportFormat.HTML)
        assertTrue(html.startsWith("<!doctype html>"))
        assertTrue(html.contains("&lt;/td&gt;&lt;script&gt;"))
        assertTrue(html.contains("Time&lt;&amp;&quot;&#39;&gt;"))
        assertFalse(html.contains("<script"))
        assertFalse(html.contains("href="))
        assertFalse(html.contains("src="))
        assertTrue(html.endsWith("</tbody></table></body></html>"))
    }

    @Test
    fun `byte bound includes complete wrappers escaping and multibyte characters and never returns a prefix`() {
        for (format in AuditExportFormat.entries) {
            val overhead = exportAuditTable(columns, listOf(row("")), format).toByteArray().size
            val room = MAX_AUDIT_TABLE_EXPORT_BYTES - overhead
            val unicode = "한😀".repeat(room / 7) + "x".repeat(room % 7)
            assertEquals(MAX_AUDIT_TABLE_EXPORT_BYTES, exportAuditTable(columns, listOf(row(unicode)), format).toByteArray().size)
            assertFailsWith<IllegalArgumentException> { exportAuditTable(columns, listOf(row(unicode + "x")), format) }
            assertFailsWith<IllegalArgumentException> { exportAuditTable(columns, listOf(row("x".repeat(MAX_AUDIT_TABLE_EXPORT_BYTES + 1))), format) }
        }
        assertFailsWith<IllegalArgumentException> { exportAuditTable(columns, listOf(row("&".repeat(14000))), AuditExportFormat.HTML) }
    }

    @Test
    fun `empty snapshots are explicit complete tables and the row and column bounds are enforced`() {
        assertEquals(1, exportAuditTable(columns, emptyList(), AuditExportFormat.CSV).split("\r\n").filter(String::isNotEmpty).size)
        assertTrue(exportAuditTable(columns, emptyList(), AuditExportFormat.HTML).contains("0 visible records"))
        assertTrue(exportAuditTable(columns, List(MAX_AUDIT_RETENTION_ENTRIES) { row("") }, AuditExportFormat.CSV).isNotEmpty())
        for (format in AuditExportFormat.entries) {
            assertFailsWith<IllegalArgumentException> { exportAuditTable(columns, List(MAX_AUDIT_RETENTION_ENTRIES + 1) { row("") }, format) }
            assertFailsWith<IllegalArgumentException> { exportAuditTable(columns, listOf(listOf("bad")), format) }
        }
    }
}
