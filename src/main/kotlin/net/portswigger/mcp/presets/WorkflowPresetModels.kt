package net.portswigger.mcp.presets

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.schema.JsonSchemaExactlyOneOf
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.tools.HttpComparisonEncoding
import net.portswigger.mcp.tools.HttpComparisonPart
import net.portswigger.mcp.tools.HttpMessageReference
import net.portswigger.mcp.tools.HttpMessageSource
import net.portswigger.mcp.tools.SearchHttpMessagesResult
import net.portswigger.mcp.tools.SearchWebsocketMessagesResult
import net.portswigger.mcp.tools.StandardExecutionState
import net.portswigger.mcp.tools.ToolRetryGuidance
import net.portswigger.mcp.tools.CompareHttpMessagesResult
import net.portswigger.mcp.tools.WebSocketSearchDirection

internal const val MAX_WORKFLOW_PRESETS = 64
internal const val MAX_WORKFLOW_PRESET_ENVELOPE_BYTES = 256 * 1024
internal const val MAX_WORKFLOW_PRESET_NAME_CHARS = 64
internal const val MAX_WORKFLOW_PRESET_DESCRIPTION_CHARS = 256
internal const val MAX_WORKFLOW_PRESET_ERROR_CHARS = 384

@Serializable
internal data class WorkflowPresetEnvelope(
    val version: Int = 1,
    val presets: List<WorkflowPreset> = emptyList(),
)

@Serializable
internal data class WorkflowPreset(
    @JsonSchemaMetadata(minLength = 1, maxLength = MAX_WORKFLOW_PRESET_NAME_CHARS)
    val name: String,
    @JsonSchemaMetadata(maxLength = MAX_WORKFLOW_PRESET_DESCRIPTION_CHARS)
    val description: String? = null,
    val definition: WorkflowPresetDefinition,
)

@JsonSchemaExactlyOneOf("httpSearch", "webSocketSearch", "httpComparison")
@Serializable
internal data class WorkflowPresetDefinition(
    val httpSearch: SavedHttpSearch? = null,
    val webSocketSearch: SavedWebSocketSearch? = null,
    val httpComparison: SavedHttpComparison? = null,
) {
    fun kind(): WorkflowPresetType {
        val selected = listOfNotNull(
            httpSearch?.let { WorkflowPresetType.HTTP_SEARCH },
            webSocketSearch?.let { WorkflowPresetType.WEBSOCKET_SEARCH },
            httpComparison?.let { WorkflowPresetType.HTTP_COMPARISON },
        )
        require(selected.size == 1) { "definition must select exactly one workflow type" }
        return selected.single()
    }
}

@Serializable
internal data class SavedHttpSearch(
    @JsonSchemaMetadata(minItems = 1, maxItems = 3)
    val sources: List<HttpMessageSource>? = null,
    @JsonSchemaMetadata(minLength = 1, maxLength = 253)
    val host: String? = null,
    @JsonSchemaMetadata(minLength = 1, maxLength = 2048)
    val pathContains: String? = null,
    @JsonSchemaMetadata(minItems = 1, maxItems = 32)
    val methods: List<String>? = null,
    @JsonSchemaMetadata(minItems = 1, maxItems = 32)
    val statusCodes: List<Int>? = null,
    @JsonSchemaMetadata(minItems = 1, maxItems = 32)
    val mimeTypes: List<String>? = null,
    val inScopeOnly: Boolean? = null,
    val hasResponse: Boolean? = null,
    val newestFirst: Boolean? = null,
    @JsonSchemaMetadata(minimum = 1, maximum = 50, defaultJson = "25")
    val defaultLimit: Int? = null,
)

@Serializable
internal data class SavedWebSocketSearch(
    val direction: WebSocketSearchDirection? = null,
    @JsonSchemaMetadata(minimum = 1, maximum = 65535)
    val listenerPort: Int? = null,
    val newestFirst: Boolean? = null,
    @JsonSchemaMetadata(minimum = 1, maximum = 50, defaultJson = "25")
    val defaultLimit: Int? = null,
)

@Serializable
internal data class SavedHttpComparison(
    val part: HttpComparisonPart? = null,
    @JsonSchemaMetadata(minimum = 1, maximum = 1048576, defaultJson = "262144")
    val limitBytesPerMessage: Int? = null,
    val excerptEncoding: HttpComparisonEncoding? = null,
    @JsonSchemaMetadata(maxItems = 32)
    val ignoreHeaders: List<String>? = null,
    val includeResponseVariations: Boolean? = null,
)

@Serializable
internal enum class WorkflowPresetType {
    @SerialName("http_search") HTTP_SEARCH,
    @SerialName("websocket_search") WEBSOCKET_SEARCH,
    @SerialName("http_comparison") HTTP_COMPARISON,
}

@Serializable
internal enum class WorkflowPresetStatus {
    @SerialName("ok") OK,
    @SerialName("invalid_argument") INVALID_ARGUMENT,
    @SerialName("project_mismatch") PROJECT_MISMATCH,
    @SerialName("not_found") NOT_FOUND,
    @SerialName("already_exists") ALREADY_EXISTS,
    @SerialName("capacity_reached") CAPACITY_REACHED,
    @SerialName("burp_error") BURP_ERROR,
}

@Serializable
internal data class SaveWorkflowPreset(
    @JsonSchemaMetadata(minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(minLength = 1, maxLength = MAX_WORKFLOW_PRESET_NAME_CHARS)
    val name: String,
    @JsonSchemaMetadata(maxLength = MAX_WORKFLOW_PRESET_DESCRIPTION_CHARS)
    val description: String? = null,
    val definition: WorkflowPresetDefinition,
    @JsonSchemaMetadata(defaultJson = "false")
    val overwrite: Boolean = false,
)

@Serializable
internal data class SaveWorkflowPresetResult(
    val status: WorkflowPresetStatus,
    val retry: ToolRetryGuidance,
    val executionState: StandardExecutionState,
    val projectId: String?,
    val preset: WorkflowPreset? = null,
    val created: Boolean,
    val replaced: Boolean,
    @JsonSchemaMetadata(maxLength = MAX_WORKFLOW_PRESET_ERROR_CHARS)
    val error: String? = null,
)

@Serializable
internal data class ListWorkflowPresets(
    @JsonSchemaMetadata(minLength = 1, maxLength = 256)
    val projectId: String,
    val type: WorkflowPresetType? = null,
    @JsonSchemaMetadata(minimum = 0, maximum = 64, defaultJson = "0")
    val offset: Int = 0,
    @JsonSchemaMetadata(minimum = 1, maximum = 64, defaultJson = "25")
    val limit: Int = 25,
)

@Serializable
internal data class ListWorkflowPresetsResult(
    val status: WorkflowPresetStatus,
    val projectId: String?,
    val items: List<WorkflowPreset>,
    val total: Int,
    val returned: Int,
    val hasMore: Boolean,
    @JsonSchemaMetadata(maxLength = MAX_WORKFLOW_PRESET_ERROR_CHARS)
    val error: String? = null,
)

@Serializable
internal data class DeleteWorkflowPreset(
    @JsonSchemaMetadata(minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(minLength = 1, maxLength = MAX_WORKFLOW_PRESET_NAME_CHARS)
    val name: String,
)

@Serializable
internal data class DeleteWorkflowPresetResult(
    val status: WorkflowPresetStatus,
    val retry: ToolRetryGuidance,
    val executionState: StandardExecutionState,
    val projectId: String?,
    val deleted: Boolean,
    @JsonSchemaMetadata(maxLength = MAX_WORKFLOW_PRESET_ERROR_CHARS)
    val error: String? = null,
)

@Serializable
internal data class ExecuteWorkflowPreset(
    @JsonSchemaMetadata(minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(minLength = 1, maxLength = MAX_WORKFLOW_PRESET_NAME_CHARS)
    val name: String,
    @JsonSchemaMetadata(minimum = 1, maximum = 50)
    val limit: Int? = null,
    @JsonSchemaMetadata(maxLength = 32768)
    val cursor: String? = null,
    @JsonSchemaMetadata(minItems = 2, maxItems = 8)
    val refs: List<HttpMessageReference>? = null,
)

@Serializable
internal data class ExecuteWorkflowPresetResult(
    val status: WorkflowPresetStatus,
    val projectId: String?,
    val presetName: String? = null,
    val type: WorkflowPresetType? = null,
    val httpSearch: SearchHttpMessagesResult? = null,
    val webSocketSearch: SearchWebsocketMessagesResult? = null,
    val httpComparison: CompareHttpMessagesResult? = null,
    @JsonSchemaMetadata(maxLength = MAX_WORKFLOW_PRESET_ERROR_CHARS)
    val error: String? = null,
)
