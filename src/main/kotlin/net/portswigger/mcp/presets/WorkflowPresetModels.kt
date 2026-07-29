package net.portswigger.mcp.presets

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.schema.JsonSchemaExactlyOneOf
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.tools.HttpComparisonEncoding
import net.portswigger.mcp.tools.HttpComparisonPart
import net.portswigger.mcp.tools.HttpMessageReference
import net.portswigger.mcp.tools.HttpMessageSource
import net.portswigger.mcp.tools.MCP_PROJECT_ID_INPUT_DESCRIPTION
import net.portswigger.mcp.tools.READ_ONLY_TOOL_STATUS_DESCRIPTION
import net.portswigger.mcp.tools.SearchHttpMessagesResult
import net.portswigger.mcp.tools.SearchWebsocketMessagesResult
import net.portswigger.mcp.tools.StandardExecutionState
import net.portswigger.mcp.tools.TOOL_EXECUTION_STATE_DESCRIPTION
import net.portswigger.mcp.tools.TOOL_RETRY_DESCRIPTION
import net.portswigger.mcp.tools.TOOL_STATUS_RETRY_DESCRIPTION
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
    @JsonSchemaMetadata(description = "Stored preset name.", minLength = 1, maxLength = MAX_WORKFLOW_PRESET_NAME_CHARS)
    val name: String,
    @JsonSchemaMetadata(description = "Optional caller-authored preset description.", maxLength = MAX_WORKFLOW_PRESET_DESCRIPTION_CHARS)
    val description: String? = null,
    @JsonSchemaMetadata(description = "Exactly one saved workflow definition.")
    val definition: WorkflowPresetDefinition,
)

@JsonSchemaExactlyOneOf("httpSearch", "webSocketSearch", "httpComparison")
@Serializable
internal data class WorkflowPresetDefinition(
    @JsonSchemaMetadata(description = "Saved HTTP search; mutually exclusive with webSocketSearch and httpComparison.")
    val httpSearch: SavedHttpSearch? = null,
    @JsonSchemaMetadata(description = "Saved WebSocket search; mutually exclusive with httpSearch and httpComparison.")
    val webSocketSearch: SavedWebSocketSearch? = null,
    @JsonSchemaMetadata(description = "Saved HTTP comparison; mutually exclusive with httpSearch and webSocketSearch.")
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
    @JsonSchemaMetadata(description = "Stored HTTP sources to search.", minItems = 1, maxItems = 3)
    val sources: List<HttpMessageSource>? = null,
    @JsonSchemaMetadata(description = "Exact destination host filter.", minLength = 1, maxLength = 253)
    val host: String? = null,
    @JsonSchemaMetadata(description = "Literal request-path substring filter.", minLength = 1, maxLength = 2048)
    val pathContains: String? = null,
    @JsonSchemaMetadata(description = "HTTP method filters.", minItems = 1, maxItems = 32)
    val methods: List<String>? = null,
    @JsonSchemaMetadata(description = "HTTP response status filters.", minItems = 1, maxItems = 32)
    val statusCodes: List<Int>? = null,
    @JsonSchemaMetadata(description = "Response MIME-type filters.", minItems = 1, maxItems = 32)
    val mimeTypes: List<String>? = null,
    @JsonSchemaMetadata(description = "When true, return only in-scope messages.")
    val inScopeOnly: Boolean? = null,
    @JsonSchemaMetadata(description = "Filter by response presence.")
    val hasResponse: Boolean? = null,
    @JsonSchemaMetadata(description = "Return newest messages first.")
    val newestFirst: Boolean? = null,
    @JsonSchemaMetadata(description = "Default page size when execution does not supply limit.", minimum = 1, maximum = 50, defaultJson = "25")
    val defaultLimit: Int? = null,
)

@Serializable
internal data class SavedWebSocketSearch(
    @JsonSchemaMetadata(description = "WebSocket message direction filter.")
    val direction: WebSocketSearchDirection? = null,
    @JsonSchemaMetadata(description = "Proxy listener port filter.", minimum = 1, maximum = 65535)
    val listenerPort: Int? = null,
    @JsonSchemaMetadata(description = "Return newest messages first.")
    val newestFirst: Boolean? = null,
    @JsonSchemaMetadata(description = "Default page size when execution does not supply limit.", minimum = 1, maximum = 50, defaultJson = "25")
    val defaultLimit: Int? = null,
)

@Serializable
internal data class SavedHttpComparison(
    @JsonSchemaMetadata(description = "Request or response part to compare.")
    val part: HttpComparisonPart? = null,
    @JsonSchemaMetadata(description = "Maximum bytes inspected per message.", minimum = 1, maximum = 1048576, defaultJson = "262144")
    val limitBytesPerMessage: Int? = null,
    @JsonSchemaMetadata(description = "Encoding for the bounded comparison excerpt.")
    val excerptEncoding: HttpComparisonEncoding? = null,
    @JsonSchemaMetadata(description = "Header names excluded from comparison.", maxItems = 32)
    val ignoreHeaders: List<String>? = null,
    @JsonSchemaMetadata(description = "Include Burp response-variation attributes when available.")
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
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Preset name; trimmed before storage and matched case-insensitively.", minLength = 1, maxLength = MAX_WORKFLOW_PRESET_NAME_CHARS)
    val name: String,
    @JsonSchemaMetadata(description = "Optional caller-authored description persisted verbatim.", maxLength = MAX_WORKFLOW_PRESET_DESCRIPTION_CHARS)
    val description: String? = null,
    @JsonSchemaMetadata(description = "Exactly one saved workflow definition.")
    val definition: WorkflowPresetDefinition,
    @JsonSchemaMetadata(description = "Replace an existing case-insensitive same-name preset.", defaultJson = "false")
    val overwrite: Boolean = false,
)

@Serializable
internal data class SaveWorkflowPresetResult(
    @JsonSchemaMetadata(description = TOOL_STATUS_RETRY_DESCRIPTION)
    val status: WorkflowPresetStatus,
    @JsonSchemaMetadata(description = TOOL_RETRY_DESCRIPTION)
    val retry: ToolRetryGuidance,
    @JsonSchemaMetadata(description = TOOL_EXECUTION_STATE_DESCRIPTION)
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
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Optional preset-type filter.")
    val type: WorkflowPresetType? = null,
    @JsonSchemaMetadata(description = "Zero-based list offset.", minimum = 0, maximum = 64, defaultJson = "0")
    val offset: Int = 0,
    @JsonSchemaMetadata(description = "Maximum presets returned.", minimum = 1, maximum = 64, defaultJson = "25")
    val limit: Int = 25,
)

@Serializable
internal data class ListWorkflowPresetsResult(
    @JsonSchemaMetadata(description = READ_ONLY_TOOL_STATUS_DESCRIPTION)
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
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Case-insensitive preset name to delete.", minLength = 1, maxLength = MAX_WORKFLOW_PRESET_NAME_CHARS)
    val name: String,
)

@Serializable
internal data class DeleteWorkflowPresetResult(
    @JsonSchemaMetadata(description = TOOL_STATUS_RETRY_DESCRIPTION)
    val status: WorkflowPresetStatus,
    @JsonSchemaMetadata(description = TOOL_RETRY_DESCRIPTION)
    val retry: ToolRetryGuidance,
    @JsonSchemaMetadata(description = TOOL_EXECUTION_STATE_DESCRIPTION)
    val executionState: StandardExecutionState,
    val projectId: String?,
    val deleted: Boolean,
    @JsonSchemaMetadata(maxLength = MAX_WORKFLOW_PRESET_ERROR_CHARS)
    val error: String? = null,
)

@Serializable
internal data class ExecuteWorkflowPreset(
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Case-insensitive preset name to execute.", minLength = 1, maxLength = MAX_WORKFLOW_PRESET_NAME_CHARS)
    val name: String,
    @JsonSchemaMetadata(description = "Runtime page size for HTTP or WebSocket search; overrides saved defaultLimit.", minimum = 1, maximum = 50)
    val limit: Int? = null,
    @JsonSchemaMetadata(description = "Runtime continuation cursor accepted only by HTTP or WebSocket search presets.", maxLength = 32768)
    val cursor: String? = null,
    @JsonSchemaMetadata(description = "Runtime message references required only for HTTP comparison presets.", minItems = 2, maxItems = 8)
    val refs: List<HttpMessageReference>? = null,
)

@Serializable
internal data class ExecuteWorkflowPresetResult(
    @JsonSchemaMetadata(description = "Preset lookup outcome; burp_error is a read failure, and delegated result status remains authoritative.")
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
