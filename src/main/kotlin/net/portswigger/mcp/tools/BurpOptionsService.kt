package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.ProductIdentity
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.security.SensitiveActionAuditOperation
import net.portswigger.mcp.security.SensitiveActionSecurity
import net.portswigger.mcp.security.filterConfigCredentials

private const val MAX_CONFIGURATION_JSON_CHARS = 1024 * 1024

@Serializable
enum class BurpOptionsLevel {
    @SerialName("project")
    PROJECT,

    @SerialName("user")
    USER,
}

@Serializable
data class GetBurpOptions(
    @JsonSchemaMetadata(description = "Configuration level to read: project or user.")
    val level: BurpOptionsLevel,
)

@Serializable
data class SetBurpOptions(
    @JsonSchemaMetadata(description = "Configuration level to change: project or user.")
    val level: BurpOptionsLevel,
    @JsonSchemaMetadata(
        description = "Complete configuration JSON to import; project input requires project_options, user input requires user_options.",
        maxLength = MAX_CONFIGURATION_JSON_CHARS,
    )
    val json: String,
)

internal class BurpOptionsService(
    private val api: MontoyaApi,
    private val config: McpConfig,
    private val httpMetadataIndex: HttpMetadataIndex,
) {
    suspend fun get(input: GetBurpOptions): StructuredToolResponse<GetBurpOptionsResult> {
        val deniedMessage =
            "${if (input.level == BurpOptionsLevel.PROJECT) "Project" else "User"} configuration access denied by Burp Suite"
        val expectedProjectId = if (input.level == BurpOptionsLevel.PROJECT) {
            try {
                api.project().id()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return getFailure(
                    input.level,
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    standardToolException("Burp could not capture the project before configuration approval", e),
                )
            }
        } else {
            null
        }

        val approved = try {
            when (input.level) {
                BurpOptionsLevel.PROJECT -> SensitiveActionSecurity.checkPermission(
                    "read project configuration",
                    "Export project-level Burp configuration to the MCP client",
                    api = api,
                    config = config,
                    auditOperation = SensitiveActionAuditOperation.PROJECT_OPTIONS_READ,
                )

                BurpOptionsLevel.USER -> SensitiveActionSecurity.checkPermission(
                    "read user configuration",
                    "Export user-level Burp configuration to the MCP client",
                    api = api,
                    config = config,
                    auditOperation = SensitiveActionAuditOperation.USER_OPTIONS_READ,
                )
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return getFailure(
                input.level,
                StandardToolStatus.BURP_ERROR,
                ToolRetryGuidance.SAFE_TO_RETRY,
                standardToolException("Burp could not request configuration approval", e),
            )
        }

        val projectStableAfterApproval = try {
            api.isCurrentProject(expectedProjectId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return getFailure(
                input.level,
                StandardToolStatus.BURP_ERROR,
                ToolRetryGuidance.SAFE_TO_RETRY,
                standardToolException("Burp could not recheck the project after configuration approval", e),
            )
        }
        if (!projectStableAfterApproval) {
            return getFailure(
                input.level,
                StandardToolStatus.PROJECT_MISMATCH,
                ToolRetryGuidance.AFTER_USER_ACTION,
                "Burp project changed during project configuration approval",
            )
        }
        if (!approved) {
            return getFailure(
                input.level,
                StandardToolStatus.ACCESS_DENIED,
                ToolRetryGuidance.AFTER_USER_ACTION,
                deniedMessage,
                isError = false,
                text = deniedMessage,
            )
        }

        val exported = try {
            when (input.level) {
                BurpOptionsLevel.PROJECT -> api.burpSuite().exportProjectOptionsAsJson()
                BurpOptionsLevel.USER -> api.burpSuite().exportUserOptionsAsJson()
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return getFailure(
                input.level,
                StandardToolStatus.BURP_ERROR,
                ToolRetryGuidance.SAFE_TO_RETRY,
                standardToolException("Burp could not export configuration", e),
            )
        }

        val projectStableAfterExport = try {
            api.isCurrentProject(expectedProjectId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return getFailure(
                input.level,
                StandardToolStatus.BURP_ERROR,
                ToolRetryGuidance.SAFE_TO_RETRY,
                standardToolException("Burp could not recheck the project after configuration export", e),
            )
        }
        if (!projectStableAfterExport) {
            return getFailure(
                input.level,
                StandardToolStatus.PROJECT_MISMATCH,
                ToolRetryGuidance.AFTER_USER_ACTION,
                "Burp project changed while project configuration was exported",
            )
        }
        if (exported.length > MAX_CONFIGURATION_JSON_CHARS) {
            return getFailure(
                input.level,
                StandardToolStatus.LIMIT_EXCEEDED,
                ToolRetryGuidance.AFTER_USER_ACTION,
                "configuration exceeds the output limit",
            )
        }

        val credentialsFiltered = config.filterConfigCredentials
        val configuration = try {
            if (credentialsFiltered) filterConfigCredentials(exported) else exported
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return getFailure(
                input.level,
                StandardToolStatus.BURP_ERROR,
                ToolRetryGuidance.SAFE_TO_RETRY,
                standardToolException("Burp could not filter exported configuration", e),
            )
        }

        val projectStableAfterFiltering = try {
            api.isCurrentProject(expectedProjectId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return getFailure(
                input.level,
                StandardToolStatus.BURP_ERROR,
                ToolRetryGuidance.SAFE_TO_RETRY,
                standardToolException("Burp could not recheck the project after configuration filtering", e),
            )
        }
        if (!projectStableAfterFiltering) {
            return getFailure(
                input.level,
                StandardToolStatus.PROJECT_MISMATCH,
                ToolRetryGuidance.AFTER_USER_ACTION,
                "Burp project changed while project configuration was prepared",
            )
        }
        if (configuration.length > MAX_CONFIGURATION_JSON_CHARS) {
            return getFailure(
                input.level,
                StandardToolStatus.LIMIT_EXCEEDED,
                ToolRetryGuidance.AFTER_USER_ACTION,
                "filtered configuration exceeds the output limit",
            )
        }

        return StructuredToolResponse(
            GetBurpOptionsResult(
                StandardToolStatus.OK,
                ToolRetryGuidance.NOT_APPLICABLE,
                input.level,
                configuration = configuration,
                configurationChars = configuration.length,
                credentialsFiltered = credentialsFiltered,
            ),
            text = configuration,
        )
    }

    suspend fun set(input: SetBurpOptions): StructuredToolResponse<SetBurpOptionsResult> {
        if (input.json.length > MAX_CONFIGURATION_JSON_CHARS) {
            return setFailure(
                input.level,
                StandardToolStatus.INVALID_ARGUMENT,
                ToolRetryGuidance.AFTER_CORRECTION,
                StandardExecutionState.NOT_STARTED,
                "json is too large",
            )
        }

        val toolingDisabledMessage =
            "User has disabled configuration editing. They can enable it in Burp's ${ProductIdentity.SUITE_TAB_NAME} tab by selecting 'Enable tools that can edit your config'"
        if (!config.configEditingTooling) {
            return setFailure(
                input.level,
                StandardToolStatus.DISABLED,
                ToolRetryGuidance.AFTER_USER_ACTION,
                StandardExecutionState.NOT_STARTED,
                toolingDisabledMessage,
                isError = false,
                text = toolingDisabledMessage,
            )
        }

        val deniedMessage =
            "${if (input.level == BurpOptionsLevel.PROJECT) "Project" else "User"} configuration change denied by Burp Suite"
        val expectedProjectId = if (input.level == BurpOptionsLevel.PROJECT) {
            try {
                api.project().id()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return setFailure(
                    input.level,
                    StandardToolStatus.BURP_ERROR,
                    ToolRetryGuidance.SAFE_TO_RETRY,
                    StandardExecutionState.NOT_STARTED,
                    standardToolException("Burp could not capture the project before configuration-change approval", e),
                )
            }
        } else {
            null
        }

        val approved = try {
            when (input.level) {
                BurpOptionsLevel.PROJECT -> SensitiveActionSecurity.checkPermission(
                    "change project configuration",
                    "Merge supplied JSON into Burp project configuration",
                    input.json,
                    api = api,
                    config = config,
                    auditOperation = SensitiveActionAuditOperation.PROJECT_OPTIONS_WRITE,
                )

                BurpOptionsLevel.USER -> SensitiveActionSecurity.checkPermission(
                    "change user configuration",
                    "Merge supplied JSON into Burp user configuration",
                    input.json,
                    api = api,
                    config = config,
                    auditOperation = SensitiveActionAuditOperation.USER_OPTIONS_WRITE,
                )
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return setFailure(
                input.level,
                StandardToolStatus.BURP_ERROR,
                ToolRetryGuidance.SAFE_TO_RETRY,
                StandardExecutionState.NOT_STARTED,
                standardToolException("Burp could not request configuration-change approval", e),
            )
        }

        val projectStableAfterApproval = try {
            api.isCurrentProject(expectedProjectId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return setFailure(
                input.level,
                StandardToolStatus.BURP_ERROR,
                ToolRetryGuidance.SAFE_TO_RETRY,
                StandardExecutionState.NOT_STARTED,
                standardToolException("Burp could not recheck the project after configuration-change approval", e),
            )
        }
        if (!projectStableAfterApproval) {
            return setFailure(
                input.level,
                StandardToolStatus.PROJECT_MISMATCH,
                ToolRetryGuidance.AFTER_USER_ACTION,
                StandardExecutionState.NOT_STARTED,
                "Burp project changed during project configuration approval",
            )
        }
        if (!approved) {
            return setFailure(
                input.level,
                StandardToolStatus.ACCESS_DENIED,
                ToolRetryGuidance.AFTER_USER_ACTION,
                StandardExecutionState.NOT_STARTED,
                deniedMessage,
                isError = false,
                text = deniedMessage,
            )
        }

        val successMessage =
            "${if (input.level == BurpOptionsLevel.PROJECT) "Project" else "User"} configuration has been applied"
        val callContext = currentCoroutineContext()
        callContext.ensureActive()
        try {
            when (input.level) {
                BurpOptionsLevel.PROJECT -> {
                    api.logging().logToOutput("Applying project-level configuration through MCP")
                    httpMetadataIndex.withMutation {
                        api.burpSuite().importProjectOptionsFromJson(input.json)
                    }
                }

                BurpOptionsLevel.USER -> {
                    api.logging().logToOutput("Applying user-level configuration through MCP")
                    api.burpSuite().importUserOptionsFromJson(input.json)
                }
            }
        } catch (e: CancellationException) {
            if (!callContext.isActive) throw e
            return setFailure(
                input.level,
                StandardToolStatus.BURP_ERROR,
                ToolRetryGuidance.DO_NOT_RETRY,
                StandardExecutionState.UNCERTAIN,
                uncertainExecutionError(
                    "Configuration may have been partially applied",
                    e,
                    preserveCancellation = false,
                    maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
                ),
            )
        } catch (e: Exception) {
            return setFailure(
                input.level,
                StandardToolStatus.BURP_ERROR,
                ToolRetryGuidance.DO_NOT_RETRY,
                StandardExecutionState.UNCERTAIN,
                uncertainExecutionError(
                    "Configuration may have been partially applied",
                    e,
                    maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
                ),
            )
        }

        val projectStableAfterImport = try {
            api.isCurrentProject(expectedProjectId)
        } catch (e: CancellationException) {
            if (!callContext.isActive) throw e
            return setFailure(
                input.level,
                StandardToolStatus.BURP_ERROR,
                ToolRetryGuidance.DO_NOT_RETRY,
                StandardExecutionState.UNCERTAIN,
                uncertainExecutionError(
                    "Configuration may have been applied but the project boundary could not be rechecked",
                    e,
                    preserveCancellation = false,
                    maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
                ),
            )
        } catch (e: Exception) {
            return setFailure(
                input.level,
                StandardToolStatus.BURP_ERROR,
                ToolRetryGuidance.DO_NOT_RETRY,
                StandardExecutionState.UNCERTAIN,
                uncertainExecutionError(
                    "Configuration may have been applied but the project boundary could not be rechecked",
                    e,
                    preserveCancellation = false,
                    maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
                ),
            )
        }
        if (!projectStableAfterImport) {
            val error =
                "Configuration may have been applied while the Burp project changed; reconcile manually and do not retry automatically"
            return setFailure(
                input.level,
                StandardToolStatus.PROJECT_MISMATCH,
                ToolRetryGuidance.DO_NOT_RETRY,
                StandardExecutionState.UNCERTAIN,
                boundedStandardToolError(error),
                text = "Error: $error",
            )
        }

        return StructuredToolResponse(
            SetBurpOptionsResult(
                StandardToolStatus.OK,
                ToolRetryGuidance.NOT_APPLICABLE,
                StandardExecutionState.COMPLETED,
                input.level,
            ),
            text = successMessage,
        )
    }
}

private fun MontoyaApi.isCurrentProject(expectedProjectId: String?): Boolean =
    expectedProjectId == null || project().id() == expectedProjectId

private fun getFailure(
    level: BurpOptionsLevel,
    status: StandardToolStatus,
    retry: ToolRetryGuidance,
    error: String,
    isError: Boolean = true,
    text: String = "Error: $error",
) = StructuredToolResponse(
    GetBurpOptionsResult(status, retry, level, error = error),
    text = text,
    isError = isError,
)

private fun setFailure(
    level: BurpOptionsLevel,
    status: StandardToolStatus,
    retry: ToolRetryGuidance,
    executionState: StandardExecutionState,
    error: String,
    isError: Boolean = true,
    text: String = "Error: $error",
) = StructuredToolResponse(
    SetBurpOptionsResult(status, retry, executionState, level, error),
    text = text,
    isError = isError,
)
