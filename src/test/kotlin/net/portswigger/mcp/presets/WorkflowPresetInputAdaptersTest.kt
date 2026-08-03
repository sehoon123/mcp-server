package net.portswigger.mcp.presets

import net.portswigger.mcp.tools.CompareHttpMessages
import net.portswigger.mcp.tools.HttpComparisonEncoding
import net.portswigger.mcp.tools.HttpComparisonPart
import net.portswigger.mcp.tools.HttpMessageReference
import net.portswigger.mcp.tools.HttpMessageSource
import net.portswigger.mcp.tools.SearchHttpMessages
import net.portswigger.mcp.tools.SearchWebsocketMessages
import net.portswigger.mcp.tools.WebSocketSearchDirection
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class WorkflowPresetInputAdaptersTest {
    @Test
    fun `HTTP adapter maps every saved field and only runtime paging fields`() {
        val saved = SavedHttpSearch(
            sources = listOf(HttpMessageSource.PROXY, HttpMessageSource.ORGANIZER),
            host = "example.test",
            pathContains = "/api/items",
            methods = listOf("GET", "POST"),
            statusCodes = listOf(200, 404),
            mimeTypes = listOf("json", "xml"),
            inScopeOnly = true,
            hasResponse = false,
            newestFirst = false,
            defaultLimit = 7,
        )
        val expected = SearchHttpMessages(
            sources = saved.sources,
            host = saved.host,
            pathContains = saved.pathContains,
            methods = saved.methods,
            statusCodes = saved.statusCodes,
            mimeTypes = saved.mimeTypes,
            inScopeOnly = saved.inScopeOnly,
            hasResponse = saved.hasResponse,
            text = null,
            regex = null,
            searchIn = null,
            caseSensitive = null,
            newestFirst = saved.newestFirst,
            limit = 3,
            cursor = "opaque-π",
        )

        assertEquals(expected, saved.toHttpSearchInput(limit = 3, cursor = "opaque-π"))
        assertEquals(
            expected.copy(limit = 7, cursor = null),
            saved.toHttpSearchInput(limit = null, cursor = null),
        )
        assertNull(SavedHttpSearch().toHttpSearchInput(limit = null, cursor = null).limit)
    }

    @Test
    fun `WebSocket adapter maps every saved field and only runtime paging fields`() {
        val saved = SavedWebSocketSearch(
            direction = WebSocketSearchDirection.SERVER_TO_CLIENT,
            listenerPort = 8_080,
            newestFirst = false,
            defaultLimit = 9,
        )
        val expected = SearchWebsocketMessages(
            projectId = "project-vector",
            cursor = "opaque-π",
            limit = 4,
            webSocketId = null,
            direction = saved.direction,
            listenerPort = saved.listenerPort,
            regex = null,
            caseSensitive = null,
            newestFirst = saved.newestFirst,
        )

        assertEquals(
            expected,
            saved.toWebSocketSearchInput("project-vector", limit = 4, cursor = "opaque-π"),
        )
        assertEquals(
            expected.copy(cursor = null, limit = 9),
            saved.toWebSocketSearchInput("project-vector", limit = null, cursor = null),
        )
        assertNull(
            SavedWebSocketSearch().toWebSocketSearchInput(
                "project-vector",
                limit = null,
                cursor = null,
            ).limit,
        )
    }

    @Test
    fun `comparison adapter maps every saved field and invocation reference`() {
        val refs = listOf(
            HttpMessageReference(HttpMessageSource.PROXY, "1"),
            HttpMessageReference(HttpMessageSource.SITE_MAP, "sitemap_2_0123456789abcdef0123456789abcdef"),
        )
        val saved = SavedHttpComparison(
            part = HttpComparisonPart.RESPONSE_HEADERS,
            limitBytesPerMessage = 65_536,
            excerptEncoding = HttpComparisonEncoding.BASE64,
            ignoreHeaders = listOf("date", "x-request-id"),
            includeResponseVariations = false,
        )

        assertEquals(
            CompareHttpMessages(
                projectId = "project-vector",
                refs = refs,
                part = saved.part,
                limitBytesPerMessage = saved.limitBytesPerMessage,
                excerptEncoding = saved.excerptEncoding,
                ignoreHeaders = saved.ignoreHeaders,
                includeResponseVariations = saved.includeResponseVariations,
            ),
            saved.toHttpComparisonInput("project-vector", refs),
        )
    }

    @Test
    fun `preset validation uses the shared mappings and preserves bounds`() {
        val validDefinitions = listOf(
            WorkflowPresetDefinition(httpSearch = SavedHttpSearch(defaultLimit = 50)),
            WorkflowPresetDefinition(webSocketSearch = SavedWebSocketSearch(listenerPort = 65_535, defaultLimit = 1)),
            WorkflowPresetDefinition(httpComparison = SavedHttpComparison(limitBytesPerMessage = 1_048_576)),
        )
        validDefinitions.forEachIndexed { index, definition ->
            validateWorkflowPreset(WorkflowPreset("valid-$index", null, definition))
        }

        val invalidDefinitions = listOf(
            WorkflowPresetDefinition(httpSearch = SavedHttpSearch(defaultLimit = 51)),
            WorkflowPresetDefinition(webSocketSearch = SavedWebSocketSearch(listenerPort = 0)),
            WorkflowPresetDefinition(httpComparison = SavedHttpComparison(limitBytesPerMessage = 0)),
        )
        invalidDefinitions.forEachIndexed { index, definition ->
            assertFailsWith<IllegalArgumentException> {
                validateWorkflowPreset(WorkflowPreset("invalid-$index", null, definition))
            }
        }
    }
}
