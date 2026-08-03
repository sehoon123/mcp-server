package net.portswigger.mcp.presets

import net.portswigger.mcp.tools.HttpComparisonEncoding
import net.portswigger.mcp.tools.HttpComparisonPart
import net.portswigger.mcp.tools.HttpMessageSource
import net.portswigger.mcp.tools.WebSocketSearchDirection
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class WorkflowPresetInputPreviewTest {
    @Test
    fun `HTTP preview reflects effective adapter fields without exposing saved values`() {
        val preview = WorkflowPreset(
            name = "private-name-vector",
            description = "private-description-vector",
            definition = WorkflowPresetDefinition(httpSearch = SavedHttpSearch(
                sources = listOf(HttpMessageSource.PROXY, HttpMessageSource.ORGANIZER),
                host = "private-host-vector.test",
                pathContains = "/private-path-vector",
                methods = listOf("PRIVATE-METHOD-VECTOR", "POST"),
                statusCodes = listOf(201, 418),
                mimeTypes = listOf("PRIVATE_MIME_VECTOR"),
                inScopeOnly = true,
                hasResponse = false,
                newestFirst = false,
                defaultLimit = 7,
            )),
        ).executionNeutralInputPreview()

        assertTrue(preview.contains("sources 2 selected"))
        assertTrue(preview.contains("host filter set"))
        assertTrue(preview.contains("path filter set"))
        assertTrue(preview.contains("methods 2 selected"))
        assertTrue(preview.contains("status codes 2 selected"))
        assertTrue(preview.contains("MIME types 1 selected"))
        assertTrue(preview.contains("in-scope yes"))
        assertTrue(preview.contains("response presence no"))
        assertTrue(preview.contains("order oldest first"))
        assertTrue(preview.contains("page limit 7"))
        assertTrue(preview.contains("cursor is supplied only at execution"))
        assertTrue(preview.contains("never reads or executes traffic"))
        assertTrue(preview.length <= MAX_WORKFLOW_PRESET_INPUT_PREVIEW_CHARS)
        assertPrivateValuesAbsent(preview)
    }

    @Test
    fun `WebSocket preview is privacy-bounded and distinguishes saved defaults`() {
        val preview = WorkflowPreset(
            name = "socket",
            definition = WorkflowPresetDefinition(webSocketSearch = SavedWebSocketSearch(
                direction = WebSocketSearchDirection.SERVER_TO_CLIENT,
                listenerPort = 61_234,
                newestFirst = true,
                defaultLimit = null,
            )),
        ).executionNeutralInputPreview()

        assertTrue(preview.contains("direction server to client"))
        assertTrue(preview.contains("listener-port filter set"))
        assertTrue(preview.contains("order newest first"))
        assertTrue(preview.contains("page limit tool default"))
        assertTrue(preview.contains("Project identity and cursor are supplied only at execution"))
        assertTrue(preview.length <= MAX_WORKFLOW_PRESET_INPUT_PREVIEW_CHARS)
        assertFalse(preview.contains("61234"))
    }

    @Test
    fun `comparison preview uses invocation-free adapter values and hides header names`() {
        val preview = WorkflowPreset(
            name = "compare",
            definition = WorkflowPresetDefinition(httpComparison = SavedHttpComparison(
                part = HttpComparisonPart.RESPONSE_HEADERS,
                limitBytesPerMessage = 65_536,
                excerptEncoding = HttpComparisonEncoding.BASE64,
                ignoreHeaders = listOf("private-header-vector", "date"),
                includeResponseVariations = false,
            )),
        ).executionNeutralInputPreview()

        assertTrue(preview.contains("message part response headers"))
        assertTrue(preview.contains("bytes per message 65536"))
        assertTrue(preview.contains("excerpt encoding base64"))
        assertTrue(preview.contains("ignored headers 2 selected"))
        assertTrue(preview.contains("response variations no"))
        assertTrue(preview.contains("Project identity and message references are supplied only at execution"))
        assertTrue(preview.length <= MAX_WORKFLOW_PRESET_INPUT_PREVIEW_CHARS)
        assertFalse(preview.contains("private-header-vector"))
    }

    private fun assertPrivateValuesAbsent(preview: String) {
        listOf(
            "private-name-vector",
            "private-description-vector",
            "private-host-vector",
            "private-path-vector",
            "PRIVATE-METHOD-VECTOR",
            "PRIVATE_MIME_VECTOR",
            "201",
            "418",
        ).forEach { value -> assertFalse(preview.contains(value), "preview leaked $value") }
    }
}
