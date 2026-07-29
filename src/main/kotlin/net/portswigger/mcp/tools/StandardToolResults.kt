package net.portswigger.mcp.tools

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.security.safeExceptionSummary

internal const val MAX_STANDARD_TOOL_ERROR_CHARS = 384
internal const val MAX_STRUCTURED_TOOL_ERROR_CHARS = 512
internal const val READ_ONLY_TOOL_STATUS_DESCRIPTION =
    "Outcome; burp_error means a bounded read failed and no mutation occurred. Reconcile project and cursor state before retrying."
internal const val TOOL_STATUS_RETRY_DESCRIPTION =
    "Outcome category. burp_error alone does not determine whether retry is safe; use retry and executionState."
internal const val READ_STATUS_RETRY_DESCRIPTION =
    "Read outcome. burp_error means the read failed; retry is the authoritative retry guidance."
internal const val TOOL_RETRY_DESCRIPTION =
    "Authoritative retry guidance for this outcome; do_not_retry takes precedence over the status value."
internal const val TOOL_EXECUTION_STATE_DESCRIPTION =
    "Authoritative side-effect state; uncertain means the change may exist and must not be retried automatically."

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

    // Retained so shared result-enum schemas stay compatible after the active-editor tools were removed.
    @SerialName("not_editable")
    NOT_EDITABLE,

    @SerialName("limit_exceeded")
    LIMIT_EXCEEDED,

    @SerialName("project_mismatch")
    PROJECT_MISMATCH,

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
internal data class GetBurpOptionsResult(
    @JsonSchemaMetadata(description = READ_STATUS_RETRY_DESCRIPTION)
    val status: StandardToolStatus,
    @JsonSchemaMetadata(description = TOOL_RETRY_DESCRIPTION)
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
    @JsonSchemaMetadata(description = TOOL_STATUS_RETRY_DESCRIPTION)
    val status: StandardToolStatus,
    @JsonSchemaMetadata(description = TOOL_RETRY_DESCRIPTION)
    val retry: ToolRetryGuidance,
    @JsonSchemaMetadata(description = TOOL_EXECUTION_STATE_DESCRIPTION)
    val executionState: StandardExecutionState,
    val level: BurpOptionsLevel,
    @JsonSchemaMetadata(maxLength = MAX_STANDARD_TOOL_ERROR_CHARS)
    val error: String? = null,
)

@Serializable
internal data class SetBurpControlStateResult(
    @JsonSchemaMetadata(description = TOOL_STATUS_RETRY_DESCRIPTION)
    val status: StandardToolStatus,
    @JsonSchemaMetadata(description = TOOL_RETRY_DESCRIPTION)
    val retry: ToolRetryGuidance,
    @JsonSchemaMetadata(description = TOOL_EXECUTION_STATE_DESCRIPTION)
    val executionState: StandardExecutionState,
    val control: BurpControl,
    val enabled: Boolean,
    @JsonSchemaMetadata(maxLength = MAX_STANDARD_TOOL_ERROR_CHARS)
    val error: String? = null,
)

private val STANDARD_ERROR_WHITESPACE = Regex("[\\s\\p{Cc}]+")

internal fun boundedStandardToolError(message: String): String =
    message.replace(STANDARD_ERROR_WHITESPACE, " ").trim().take(MAX_STANDARD_TOOL_ERROR_CHARS)

internal fun standardToolException(prefix: String, error: Throwable): String =
    boundedStandardToolError("$prefix: ${safeExceptionSummary(error)}")
