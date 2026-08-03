package net.portswigger.mcp.presets

import net.portswigger.mcp.tools.HttpComparisonEncoding
import net.portswigger.mcp.tools.HttpComparisonPart
import net.portswigger.mcp.tools.WebSocketSearchDirection

internal const val MAX_WORKFLOW_PRESET_INPUT_PREVIEW_CHARS = 1_024
private const val WORKFLOW_PRESET_PREVIEW_PROJECT_ID = "preview"

/**
 * Builds a bounded, privacy-preserving description of the runtime input admitted by a saved preset.
 *
 * The preview intentionally uses the same Saved* -> runtime DTO adapters as validation and execution. It reports
 * bounded counts, choices, and limits but never includes caller-authored strings, listener ports, status-code values,
 * project identity, references, cursors, traffic, or results.
 */
internal fun WorkflowPreset.executionNeutralInputPreview(): String {
    validateWorkflowPreset(this)
    return when (definition.kind()) {
        WorkflowPresetType.HTTP_SEARCH -> {
            val input = requireNotNull(definition.httpSearch).toHttpSearchInput(limit = null, cursor = null)
            "Effective HTTP metadata-search input: " +
                "sources ${input.sources.countPreview()}; " +
                "host filter ${input.host.presencePreview()}; " +
                "path filter ${input.pathContains.presencePreview()}; " +
                "methods ${input.methods.countPreview()}; " +
                "status codes ${input.statusCodes.countPreview()}; " +
                "MIME types ${input.mimeTypes.countPreview()}; " +
                "in-scope ${input.inScopeOnly.booleanPreview()}; " +
                "response presence ${input.hasResponse.booleanPreview()}; " +
                "order ${input.newestFirst.orderPreview()}; " +
                "page limit ${input.limit.limitPreview()}. " +
                "Content predicates are excluded from presets; the cursor is supplied only at execution. " +
                "This preview never reads or executes traffic."
        }

        WorkflowPresetType.WEBSOCKET_SEARCH -> {
            val input = requireNotNull(definition.webSocketSearch).toWebSocketSearchInput(
                projectId = WORKFLOW_PRESET_PREVIEW_PROJECT_ID,
                limit = null,
                cursor = null,
            )
            "Effective WebSocket metadata-search input: " +
                "direction ${input.direction.directionPreview()}; " +
                "listener-port filter ${input.listenerPort.presencePreview()}; " +
                "order ${input.newestFirst.orderPreview()}; " +
                "page limit ${input.limit.limitPreview()}. " +
                "Project identity and cursor are supplied only at execution; connection ID and content predicates are excluded from presets. " +
                "This preview never reads or executes traffic."
        }

        WorkflowPresetType.HTTP_COMPARISON -> {
            val input = requireNotNull(definition.httpComparison).toHttpComparisonInput(
                projectId = WORKFLOW_PRESET_PREVIEW_PROJECT_ID,
                refs = emptyList(),
            )
            "Effective HTTP-comparison input: " +
                "message part ${input.part.partPreview()}; " +
                "bytes per message ${input.limitBytesPerMessage.limitPreview()}; " +
                "excerpt encoding ${input.excerptEncoding.encodingPreview()}; " +
                "ignored headers ${input.ignoreHeaders.countPreview()}; " +
                "response variations ${input.includeResponseVariations.booleanPreview()}. " +
                "Project identity and message references are supplied only at execution. " +
                "This preview never reads or executes traffic."
        }
    }.also { preview ->
        check(preview.length <= MAX_WORKFLOW_PRESET_INPUT_PREVIEW_CHARS) {
            "workflow preset input preview exceeded its fixed bound"
        }
    }
}

private fun Collection<*>?.countPreview(): String = when {
    this == null -> "tool default"
    isEmpty() -> "none"
    else -> "$size selected"
}

private fun Any?.presencePreview(): String = if (this == null) "not set" else "set"

private fun Boolean?.booleanPreview(): String = when (this) {
    null -> "tool default"
    true -> "yes"
    false -> "no"
}

private fun Boolean?.orderPreview(): String = when (this) {
    null -> "tool default"
    true -> "newest first"
    false -> "oldest first"
}

private fun Int?.limitPreview(): String = this?.toString() ?: "tool default"

private fun WebSocketSearchDirection?.directionPreview(): String = when (this) {
    null -> "tool default"
    WebSocketSearchDirection.CLIENT_TO_SERVER -> "client to server"
    WebSocketSearchDirection.SERVER_TO_CLIENT -> "server to client"
}

private fun HttpComparisonPart?.partPreview(): String = when (this) {
    null -> "tool default"
    HttpComparisonPart.REQUEST -> "request"
    HttpComparisonPart.REQUEST_HEADERS -> "request headers"
    HttpComparisonPart.REQUEST_BODY -> "request body"
    HttpComparisonPart.RESPONSE -> "response"
    HttpComparisonPart.RESPONSE_HEADERS -> "response headers"
    HttpComparisonPart.RESPONSE_BODY -> "response body"
}

private fun HttpComparisonEncoding?.encodingPreview(): String = when (this) {
    null -> "tool default"
    HttpComparisonEncoding.TEXT -> "text"
    HttpComparisonEncoding.BASE64 -> "base64"
}
