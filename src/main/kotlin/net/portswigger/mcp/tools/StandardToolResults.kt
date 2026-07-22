package net.portswigger.mcp.tools

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.security.safeExceptionSummary

internal const val MAX_STANDARD_TOOL_ERROR_CHARS = 384
internal const val MAX_UTILITY_OUTPUT_CHARS = 1024 * 1024

@Serializable
internal enum class StandardToolStatus {
    @SerialName("ok")
    OK,

    @SerialName("invalid_argument")
    INVALID_ARGUMENT,

    @SerialName("access_denied")
    ACCESS_DENIED,

    @SerialName("disabled")
    DISABLED,

    @SerialName("not_available")
    NOT_AVAILABLE,

    @SerialName("not_editable")
    NOT_EDITABLE,

    @SerialName("limit_exceeded")
    LIMIT_EXCEEDED,

    @SerialName("burp_error")
    BURP_ERROR,
}

@Serializable
internal enum class ToolRetryGuidance {
    @SerialName("not_applicable")
    NOT_APPLICABLE,

    @SerialName("after_correction")
    AFTER_CORRECTION,

    @SerialName("after_user_action")
    AFTER_USER_ACTION,

    @SerialName("safe_to_retry")
    SAFE_TO_RETRY,

    @SerialName("do_not_retry")
    DO_NOT_RETRY,
}

@Serializable
internal enum class StandardExecutionState {
    @SerialName("not_started")
    NOT_STARTED,

    @SerialName("completed")
    COMPLETED,

    @SerialName("uncertain")
    UNCERTAIN,
}

@Serializable
internal data class TransformDataResult(
    val status: StandardToolStatus,
    val retry: ToolRetryGuidance,
    val operation: DataTransformOperation,
    @JsonSchemaMetadata(maxLength = MAX_UTILITY_OUTPUT_CHARS)
    val content: String? = null,
    @JsonSchemaMetadata(minimum = 0, maximum = 1048576)
    val contentChars: Int? = null,
    @JsonSchemaMetadata(maxLength = MAX_STANDARD_TOOL_ERROR_CHARS)
    val error: String? = null,
)

@Serializable
internal data class GenerateRandomStringResult(
    val status: StandardToolStatus,
    val retry: ToolRetryGuidance,
    @JsonSchemaMetadata(maxLength = 65536)
    val content: String? = null,
    @JsonSchemaMetadata(minimum = 0, maximum = 65536)
    val contentChars: Int? = null,
    @JsonSchemaMetadata(maxLength = MAX_STANDARD_TOOL_ERROR_CHARS)
    val error: String? = null,
)

@Serializable
internal data class GetBurpOptionsResult(
    val status: StandardToolStatus,
    val retry: ToolRetryGuidance,
    val level: BurpOptionsLevel,
    @JsonSchemaMetadata(maxLength = 1048576)
    val configuration: String? = null,
    @JsonSchemaMetadata(minimum = 0, maximum = 1048576)
    val configurationChars: Int? = null,
    val credentialsFiltered: Boolean? = null,
    @JsonSchemaMetadata(maxLength = MAX_STANDARD_TOOL_ERROR_CHARS)
    val error: String? = null,
)

@Serializable
internal data class SetBurpOptionsResult(
    val status: StandardToolStatus,
    val retry: ToolRetryGuidance,
    val executionState: StandardExecutionState,
    val level: BurpOptionsLevel,
    @JsonSchemaMetadata(maxLength = MAX_STANDARD_TOOL_ERROR_CHARS)
    val error: String? = null,
)

@Serializable
internal data class SetBurpControlStateResult(
    val status: StandardToolStatus,
    val retry: ToolRetryGuidance,
    val executionState: StandardExecutionState,
    val control: BurpControl,
    val enabled: Boolean,
    @JsonSchemaMetadata(maxLength = MAX_STANDARD_TOOL_ERROR_CHARS)
    val error: String? = null,
)

@Serializable
internal data class GetActiveEditorContentsResult(
    val status: StandardToolStatus,
    val retry: ToolRetryGuidance,
    @JsonSchemaMetadata(maxLength = 32768)
    val content: String? = null,
    @JsonSchemaMetadata(minimum = 0, maximum = 2147483647)
    val totalChars: Int? = null,
    val truncated: Boolean? = null,
    @JsonSchemaMetadata(maxLength = MAX_STANDARD_TOOL_ERROR_CHARS)
    val error: String? = null,
)

@Serializable
internal data class SetActiveEditorContentsResult(
    val status: StandardToolStatus,
    val retry: ToolRetryGuidance,
    val executionState: StandardExecutionState,
    @JsonSchemaMetadata(minimum = 0, maximum = 1048576)
    val contentChars: Int? = null,
    @JsonSchemaMetadata(maxLength = MAX_STANDARD_TOOL_ERROR_CHARS)
    val error: String? = null,
)

private val STANDARD_ERROR_WHITESPACE = Regex("[\\s\\p{Cc}]+")

internal fun boundedStandardToolError(message: String): String =
    message.replace(STANDARD_ERROR_WHITESPACE, " ").trim().take(MAX_STANDARD_TOOL_ERROR_CHARS)

internal fun standardToolException(prefix: String, error: Throwable): String =
    boundedStandardToolError("$prefix: ${safeExceptionSummary(error)}")
