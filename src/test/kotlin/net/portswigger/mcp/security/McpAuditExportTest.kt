package net.portswigger.mcp.security

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals

class McpAuditExportTest {
    private val json = Json { encodeDefaults = true }

    @Test
    fun `export fits exact JSONL boundaries without charging an unused newline`() {
        val records = listOf(record("older"), record("newer"))
        val lines = records.map { json.encodeToString(it) }
        val full = lines.joinToString("\n")

        assertEquals(full, encodeBoundedAuditJsonLines(records, full.length))
        assertEquals(lines.last(), encodeBoundedAuditJsonLines(records, full.length - 1))
        assertEquals(lines.last(), encodeBoundedAuditJsonLines(records, lines.last().length))
        assertEquals("", encodeBoundedAuditJsonLines(records, lines.last().length - 1))
        assertEquals("", encodeBoundedAuditJsonLines(records, 0))
        assertEquals("", encodeBoundedAuditJsonLines(emptyList(), 0))
    }

    @Test
    fun `oversized newest record never substitutes an older misleading record`() {
        val records = listOf(record("old"), record("newest_" + "x".repeat(100)))
        val cap = json.encodeToString(records.first()).length
        assertEquals("", encodeBoundedAuditJsonLines(records, cap))
    }

    @Test
    fun `export rejects invalid internal budgets and overlarge snapshots`() {
        assertThrows<IllegalArgumentException> { encodeBoundedAuditJsonLines(emptyList(), -1) }
        assertThrows<IllegalArgumentException> { encodeBoundedAuditJsonLines(emptyList(), 64 * 1024 + 1) }
        assertThrows<IllegalArgumentException> { encodeBoundedAuditJsonLines(List(1001) { record("event") }) }
    }

    private fun record(tool: String) = McpAuditRecord(
        timestampEpochMillis = 1,
        sessionCorrelation = "abcdef123456",
        tool = tool,
        readOnly = true,
        argumentKeys = emptyList(),
        approvals = emptyList(),
        durationMillis = 1,
        outcome = "completed",
    )
}
