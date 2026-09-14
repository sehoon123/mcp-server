package net.portswigger.mcp.tools

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
enum class NativeToolStatus {
    @SerialName("ok")
    OK,

    @SerialName("invalid_argument")
    INVALID_ARGUMENT,

    @SerialName("invalid_id")
    INVALID_ID,

    @SerialName("access_denied")
    ACCESS_DENIED,

    @SerialName("disabled")
    DISABLED,

    @SerialName("not_available")
    NOT_AVAILABLE,

    @SerialName("not_found")
    NOT_FOUND,

    @SerialName("limit_exceeded")
    LIMIT_EXCEEDED,

    @SerialName("project_mismatch")
    PROJECT_MISMATCH,

    @SerialName("stale_state")
    STALE_STATE,

    @SerialName("burp_error")
    BURP_ERROR,

    @SerialName("execution_uncertain")
    EXECUTION_UNCERTAIN,
}

internal fun HttpMessageResolutionStatus.toNativeToolStatus(): NativeToolStatus = when (this) {
    HttpMessageResolutionStatus.ACCESS_DENIED -> NativeToolStatus.ACCESS_DENIED
    HttpMessageResolutionStatus.INVALID_ARGUMENT -> NativeToolStatus.INVALID_ARGUMENT
    HttpMessageResolutionStatus.INVALID_ID -> NativeToolStatus.INVALID_ID
    HttpMessageResolutionStatus.PROJECT_MISMATCH -> NativeToolStatus.PROJECT_MISMATCH
    HttpMessageResolutionStatus.NOT_FOUND -> NativeToolStatus.NOT_FOUND
    HttpMessageResolutionStatus.REQUEST_UNAVAILABLE -> NativeToolStatus.NOT_AVAILABLE
    HttpMessageResolutionStatus.BURP_ERROR -> NativeToolStatus.BURP_ERROR
}

internal fun NativeToolStatus.defaultRetry(): ToolRetryGuidance = when (this) {
    NativeToolStatus.OK -> ToolRetryGuidance.NOT_APPLICABLE
    NativeToolStatus.INVALID_ARGUMENT,
    NativeToolStatus.INVALID_ID,
    NativeToolStatus.LIMIT_EXCEEDED -> ToolRetryGuidance.AFTER_CORRECTION
    NativeToolStatus.ACCESS_DENIED,
    NativeToolStatus.DISABLED -> ToolRetryGuidance.AFTER_USER_ACTION
    NativeToolStatus.NOT_AVAILABLE,
    NativeToolStatus.NOT_FOUND,
    NativeToolStatus.PROJECT_MISMATCH,
    NativeToolStatus.STALE_STATE,
    NativeToolStatus.BURP_ERROR -> ToolRetryGuidance.SAFE_TO_RETRY
    NativeToolStatus.EXECUTION_UNCERTAIN -> ToolRetryGuidance.DO_NOT_RETRY
}

internal fun nativeToolError(message: String): String = boundedStandardToolError(message)
