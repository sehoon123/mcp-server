package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.MAX_AUDIT_RETENTION_ENTRIES

internal const val MAX_AUDIT_TABLE_EXPORT_BYTES = 64 * 1024
internal enum class AuditExportFormat { CSV, HTML }

/** Formats only the displayed metadata cells; never acquires traffic or resnapshots the audit sink. */
internal fun exportAuditTable(columns: List<String>, rows: List<List<String>>, format: AuditExportFormat): String {
    require(columns.size == 6 && rows.size <= MAX_AUDIT_RETENTION_ENTRIES)
    require(columns.all { it.length <= MAX_AUDIT_TABLE_EXPORT_BYTES } &&
        rows.all { it.size == columns.size && it.all { cell -> cell.length <= MAX_AUDIT_TABLE_EXPORT_BYTES } })
    val output = StringBuilder()
    var remaining = MAX_AUDIT_TABLE_EXPORT_BYTES
    fun append(text: String) {
        require(text.length <= remaining) { "Audit export exceeds 64 KiB" }
        val bytes = text.toByteArray(Charsets.UTF_8).size
        require(bytes <= remaining) { "Audit export exceeds 64 KiB" }
        remaining -= bytes
        output.append(text)
    }
    fun escaped(value: String, replacements: Map<Char, String>) {
        var start = 0
        for (index in value.indices) {
            val replacement = replacements[value[index]] ?: continue
            append(value.substring(start, index))
            append(replacement)
            start = index + 1
        }
        append(value.substring(start))
    }
    when (format) {
        AuditExportFormat.CSV -> {
            val quotes = mapOf('"' to "\"\"")
            for (row in listOf(columns) + rows) {
                row.forEachIndexed { index, value ->
                    if (index > 0) append(",")
                    append("\"")
                    val first = value.firstOrNull { !it.isWhitespace() && !it.isISOControl() }
                    if (first in listOf('=', '+', '-', '@') || value.firstOrNull()?.isISOControl() == true) append("'")
                    escaped(value, quotes)
                    append("\"")
                }
                append("\r\n")
            }
        }
        AuditExportFormat.HTML -> {
            val entities = mapOf('&' to "&amp;", '<' to "&lt;", '>' to "&gt;", '"' to "&quot;", '\'' to "&#39;")
            append("<!doctype html><html><head><meta charset=\"utf-8\"><title>Redacted MCP activity</title></head><body>")
            append("<h1>Redacted MCP activity</h1><p>${rows.size} visible records. Metadata only; not vulnerability evidence.</p><table><thead><tr>")
            for (column in columns) { append("<th>"); escaped(column, entities); append("</th>") }
            append("</tr></thead><tbody>")
            for (row in rows) {
                append("<tr>")
                for (cell in row) { append("<td>"); escaped(cell, entities); append("</td>") }
                append("</tr>")
            }
            append("</tbody></table></body></html>")
        }
    }
    return output.toString()
}
