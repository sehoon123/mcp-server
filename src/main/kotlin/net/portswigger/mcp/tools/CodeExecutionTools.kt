package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.bambda.BambdaImportResult as MontoyaBambdaImportResult
import burp.api.montoya.utilities.shell.ExecuteOptions
import burp.api.montoya.utilities.shell.ExitCodeBehavior
import burp.api.montoya.utilities.shell.StderrBehavior
import burp.api.montoya.utilities.shell.TimeoutBehavior
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.security.SensitiveActionAuditOperation
import net.portswigger.mcp.security.SensitiveActionSecurity
import net.portswigger.mcp.security.safeExceptionSummary
import net.portswigger.mcp.security.safeSingleLine
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.UUID
import java.util.concurrent.Semaphore
import java.util.regex.Pattern

private const val MAX_SHELL_ARGUMENTS = 64
private const val MAX_SHELL_ARGUMENT_CHARS = 4_096
private const val MAX_SHELL_COMMAND_CHARS = 32 * 1024
private const val MAX_SHELL_ENVIRONMENT = 32
private const val MAX_SHELL_ENVIRONMENT_CHARS = 32 * 1024
private const val MAX_SHELL_OUTPUT_CHARS = 64 * 1024
private const val DEFAULT_SHELL_OUTPUT_CHARS = 8 * 1024
private const val MAX_SHELL_TIMEOUT_SECONDS = 120
private const val MAX_BAMBDA_NAME_CHARS = 128
private const val MAX_BAMBDA_SOURCE_CHARS = 256 * 1024
private const val MAX_BAMBDA_ERRORS = 32
private const val MAX_BAMBDA_ERROR_CHARS = 384
private const val MAX_OWNED_BAMBDAS = 32
private const val MAX_CHAIN_STEPS = 8
private const val MAX_CHAIN_HEADERS = 32
private const val MAX_CHAIN_VARIABLES = 8
private const val MAX_CHAIN_BODY_CHARS = 64 * 1024
private const val MAX_CHAIN_TOTAL_CHARS = 128 * 1024
private val SHELL_ENVIRONMENT_NAME = Regex("[A-Za-z_][A-Za-z0-9_]{0,127}")
private val BAMBDA_NAME = Regex("[A-Za-z0-9][A-Za-z0-9 ._()/-]{0,127}")
private val BAMBDA_VARIABLE = Regex("[A-Za-z][A-Za-z0-9_]{0,63}")
private val HTTP_METHOD_TOKEN = Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}")
private val HTTP_HEADER_TOKEN = Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}")

@Serializable
enum class ShellInvocationMode {
    @SerialName("direct")
    DIRECT,

    @SerialName("system_shell")
    SYSTEM_SHELL,
}

@Serializable
enum class ShellTimeoutPolicy {
    @SerialName("fail_on_timeout")
    FAIL_ON_TIMEOUT,

    @SerialName("allow_timeout")
    ALLOW_TIMEOUT,
}

@Serializable
enum class ShellStderrPolicy {
    @SerialName("merge")
    MERGE,

    @SerialName("discard")
    DISCARD,
}

@Serializable
enum class ShellExitCodePolicy {
    @SerialName("fail_on_non_zero")
    FAIL_ON_NON_ZERO,

    @SerialName("allow_non_zero")
    ALLOW_NON_ZERO,
}

@Serializable
data class ExecuteLocalCommand(
    @JsonSchemaMetadata(description = "Use direct argv execution or explicit system-shell interpretation.")
    val mode: ShellInvocationMode,
    @JsonSchemaMetadata(description = "Non-empty argv for mode=direct; absent for system_shell.", minItems = 1, maxItems = MAX_SHELL_ARGUMENTS)
    val command: List<String>? = null,
    @JsonSchemaMetadata(description = "Command line for mode=system_shell; absent for direct.", minLength = 1, maxLength = MAX_SHELL_COMMAND_CHARS)
    val commandLine: String? = null,
    @JsonSchemaMetadata(description = "Native process timeout in seconds.", minimum = 1, maximum = 120, defaultJson = "30")
    val timeoutSeconds: Int? = null,
    @JsonSchemaMetadata(description = "Whether a native timeout raises an error.", defaultJson = "\"fail_on_timeout\"")
    val timeoutPolicy: ShellTimeoutPolicy? = null,
    @JsonSchemaMetadata(description = "Merge stderr into output or discard it.", defaultJson = "\"merge\"")
    val stderrPolicy: ShellStderrPolicy? = null,
    @JsonSchemaMetadata(description = "Whether a non-zero process exit raises an error.", defaultJson = "\"allow_non_zero\"")
    val exitCodePolicy: ShellExitCodePolicy? = null,
    @JsonSchemaMetadata(description = "Additional process environment variables.", maxProperties = MAX_SHELL_ENVIRONMENT)
    val environment: Map<String, String> = emptyMap(),
    @JsonSchemaMetadata(description = "Maximum characters returned to MCP; native ShellUtils materializes output before this preview is truncated.", minimum = 0, maximum = 65536, defaultJson = "8192")
    val outputLimitChars: Int? = null,
)

@Serializable
internal data class ExecuteLocalCommandResult(
    @JsonSchemaMetadata(description = TOOL_STATUS_RETRY_DESCRIPTION)
    val status: NativeToolStatus,
    @JsonSchemaMetadata(description = TOOL_RETRY_DESCRIPTION)
    val retry: ToolRetryGuidance,
    @JsonSchemaMetadata(description = TOOL_EXECUTION_STATE_DESCRIPTION)
    val executionState: StandardExecutionState,
    val mode: ShellInvocationMode,
    val shellInterpreted: Boolean,
    @JsonSchemaMetadata(minimum = 1, maximum = 120)
    val timeoutSeconds: Int,
    @JsonSchemaMetadata(maxLength = MAX_SHELL_OUTPUT_CHARS)
    val output: String? = null,
    @JsonSchemaMetadata(minimum = 0)
    val outputChars: Int? = null,
    @JsonSchemaMetadata(description = "True when output exceeded the selected outputLimitChars; that limit is at most the 65,536-character output bound.")
    val outputTruncated: Boolean? = null,
    @JsonSchemaMetadata(maxLength = MAX_STANDARD_TOOL_ERROR_CHARS)
    val error: String? = null,
)

internal class LocalCommandService(
    private val api: MontoyaApi,
    @Volatile private var config: McpConfig,
) {
    private val executionPermit = Semaphore(1, true)

    fun updateConfig(config: McpConfig) {
        this.config = config
    }

    suspend fun execute(input: ExecuteLocalCommand): ExecuteLocalCommandResult {
        val timeout = input.timeoutSeconds ?: 30
        val outputLimit = input.outputLimitChars ?: DEFAULT_SHELL_OUTPUT_CHARS
        val validationError = validateShellInput(input, timeout, outputLimit)
        if (validationError != null) return failure(input.mode, timeout, NativeToolStatus.INVALID_ARGUMENT, validationError)
        if (!config.codeExecutionTooling) {
            return failure(
                input.mode,
                timeout,
                NativeToolStatus.DISABLED,
                "local code-execution tools are disabled in Burp's MCP settings",
            )
        }

        val options = try {
            var value = ExecuteOptions.executeOptions()
                .withTimeout(Duration.ofSeconds(timeout.toLong()))
                .withTimeoutBehavior((input.timeoutPolicy ?: ShellTimeoutPolicy.FAIL_ON_TIMEOUT).toMontoya())
                .withStderrBehavior((input.stderrPolicy ?: ShellStderrPolicy.MERGE).toMontoya())
                .withExitCodeBehavior((input.exitCodePolicy ?: ShellExitCodePolicy.ALLOW_NON_ZERO).toMontoya())
            input.environment.forEach { (name, environmentValue) ->
                value = value.withEnvironmentVariable(name, environmentValue)
            }
            value
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return failure(
                input.mode,
                timeout,
                NativeToolStatus.BURP_ERROR,
                "Burp could not prepare command execution: ${safeExceptionSummary(e)}",
            )
        }
        val review = shellReview(input)
        val approved = try {
            SensitiveActionSecurity.checkPermission(
                action = "execute a local operating-system command",
                summary = "Run one ${input.mode.name.lowercase()} command with a ${timeout}s native timeout; the process runs with Burp's user permissions",
                reviewContent = review,
                api = api,
                config = config,
                auditOperation = SensitiveActionAuditOperation.SHELL_EXECUTION,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return failure(
                input.mode,
                timeout,
                NativeToolStatus.BURP_ERROR,
                "Burp could not request command approval: ${safeExceptionSummary(e)}",
            )
        }
        if (!approved) {
            return failure(input.mode, timeout, NativeToolStatus.ACCESS_DENIED, "local command execution denied by Burp Suite")
        }
        currentCoroutineContext().ensureActive()
        if (!config.codeExecutionTooling) {
            return failure(input.mode, timeout, NativeToolStatus.DISABLED, "local code-execution tools were disabled during approval")
        }
        if (!executionPermit.tryAcquire()) {
            return failure(input.mode, timeout, NativeToolStatus.LIMIT_EXCEEDED, "another MCP local command is already running")
        }
        if (config.emergencyReadOnlyMode || !config.codeExecutionTooling) {
            executionPermit.release()
            return failure(
                input.mode,
                timeout,
                NativeToolStatus.DISABLED,
                "local command execution was disabled before it started",
            )
        }

        return try {
            val output = when (input.mode) {
                ShellInvocationMode.DIRECT -> api.utilities().shellUtils().execute(options, *requireNotNull(input.command).toTypedArray())
                ShellInvocationMode.SYSTEM_SHELL -> api.utilities().shellUtils().dangerouslyExecute(options, requireNotNull(input.commandLine))
            }
            currentCoroutineContext().ensureActive()
            ExecuteLocalCommandResult(
                status = NativeToolStatus.OK,
                retry = ToolRetryGuidance.NOT_APPLICABLE,
                executionState = StandardExecutionState.COMPLETED,
                mode = input.mode,
                shellInterpreted = input.mode == ShellInvocationMode.SYSTEM_SHELL,
                timeoutSeconds = timeout,
                output = output.take(outputLimit),
                outputChars = output.length,
                outputTruncated = output.length > outputLimit,
            )
        } catch (e: CancellationException) {
            if (!currentCoroutineContext().isActive) throw e
            uncertain(input.mode, timeout, e)
        } catch (e: Exception) {
            uncertain(input.mode, timeout, e)
        } finally {
            executionPermit.release()
        }
    }

    private fun failure(
        mode: ShellInvocationMode,
        timeout: Int,
        status: NativeToolStatus,
        error: String,
    ) = ExecuteLocalCommandResult(
        status = status,
        retry = status.defaultRetry(),
        executionState = StandardExecutionState.NOT_STARTED,
        mode = mode,
        shellInterpreted = mode == ShellInvocationMode.SYSTEM_SHELL,
        timeoutSeconds = timeout.coerceIn(1, MAX_SHELL_TIMEOUT_SECONDS),
        error = nativeToolError(error),
    )

    private fun uncertain(mode: ShellInvocationMode, timeout: Int, error: Exception) = ExecuteLocalCommandResult(
        status = NativeToolStatus.EXECUTION_UNCERTAIN,
        retry = ToolRetryGuidance.DO_NOT_RETRY,
        executionState = StandardExecutionState.UNCERTAIN,
        mode = mode,
        shellInterpreted = mode == ShellInvocationMode.SYSTEM_SHELL,
        timeoutSeconds = timeout,
        error = uncertainExecutionError(
            "The local command may have executed or produced side effects",
            error,
            preserveCancellation = false,
            maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
        ),
    )
}

private fun validateShellInput(input: ExecuteLocalCommand, timeout: Int, outputLimit: Int): String? {
    if (timeout !in 1..MAX_SHELL_TIMEOUT_SECONDS) return "timeoutSeconds is out of range"
    if (outputLimit !in 0..MAX_SHELL_OUTPUT_CHARS) return "outputLimitChars is out of range"
    when (input.mode) {
        ShellInvocationMode.DIRECT -> {
            if (input.commandLine != null || input.command.isNullOrEmpty()) return "direct mode requires only a non-empty command argv"
            if (input.command.size > MAX_SHELL_ARGUMENTS) return "command has too many arguments"
            if (input.command.first().isBlank() || input.command.any { it.length > MAX_SHELL_ARGUMENT_CHARS || '\u0000' in it }) {
                return "the executable is empty or command arguments are too long or contain NUL"
            }
            if (input.command.sumOf(String::length) > MAX_SHELL_COMMAND_CHARS) return "combined command arguments are too large"
        }
        ShellInvocationMode.SYSTEM_SHELL -> {
            val line = input.commandLine
            if (input.command != null || line.isNullOrBlank()) return "system_shell mode requires only commandLine"
            if (line.length > MAX_SHELL_COMMAND_CHARS || '\u0000' in line) return "commandLine is too long or contains NUL"
        }
    }
    if (input.environment.size > MAX_SHELL_ENVIRONMENT) return "environment has too many entries"
    if (input.environment.keys.any { !SHELL_ENVIRONMENT_NAME.matches(it) }) return "environment contains an invalid variable name"
    if (input.environment.values.any { it.length > MAX_SHELL_ARGUMENT_CHARS || '\u0000' in it }) {
        return "environment values are too long or contain NUL"
    }
    if (input.environment.entries.sumOf { it.key.length + it.value.length } > MAX_SHELL_ENVIRONMENT_CHARS) {
        return "environment is too large"
    }
    return null
}

private fun shellReview(input: ExecuteLocalCommand): String = buildString {
    appendLine("mode=${input.mode.name.lowercase()}")
    when (input.mode) {
        ShellInvocationMode.DIRECT -> appendLine(requireNotNull(input.command).joinToString(" ") { it.reviewQuoted() })
        ShellInvocationMode.SYSTEM_SHELL -> appendLine(requireNotNull(input.commandLine))
    }
    if (input.environment.isNotEmpty()) {
        appendLine("environment:")
        input.environment.toSortedMap().forEach { (name, value) -> appendLine("$name=${value.reviewEscaped()}") }
    }
}

private fun String.reviewQuoted(): String = "\"${reviewEscaped()}\""
private fun String.reviewEscaped(): String = replace("\\", "\\\\")
    .replace("\"", "\\\"")
    .replace("\r", "\\r")
    .replace("\n", "\\n")

@Serializable
data class ImportBambda(
    @JsonSchemaMetadata(description = "Name for a Repeater CUSTOM_ACTION Bambda; reimporting this name replaces the same deterministic ID.", minLength = 1, maxLength = MAX_BAMBDA_NAME_CHARS)
    val name: String,
    @JsonSchemaMetadata(description = "Bare Java-compatible custom-action source; the server wraps it in Burp's Bambda envelope.", minLength = 1, maxLength = MAX_BAMBDA_SOURCE_CHARS)
    val source: String,
)

@Serializable
internal data class BambdaImportResult(
    @JsonSchemaMetadata(description = TOOL_STATUS_RETRY_DESCRIPTION + " Even when ok, check importStatus and importErrors.")
    val status: NativeToolStatus,
    @JsonSchemaMetadata(description = TOOL_RETRY_DESCRIPTION)
    val retry: ToolRetryGuidance,
    @JsonSchemaMetadata(description = TOOL_EXECUTION_STATE_DESCRIPTION)
    val executionState: StandardExecutionState,
    @JsonSchemaMetadata(maxLength = MAX_BAMBDA_NAME_CHARS)
    val name: String,
    @JsonSchemaMetadata(maxLength = 36)
    val bambdaId: String?,
    @JsonSchemaMetadata(maxLength = 32)
    val importStatus: String?,
    @JsonSchemaMetadata(maxItems = MAX_BAMBDA_ERRORS)
    val importErrors: List<String>,
    val importErrorsTruncated: Boolean,
    @JsonSchemaMetadata(maxLength = MAX_STANDARD_TOOL_ERROR_CHARS)
    val error: String? = null,
)

@Serializable
data class BambdaChainStep(
    @JsonSchemaMetadata(description = "HTTP method token for this generated step.", minLength = 1, maxLength = 32)
    val method: String,
    @JsonSchemaMetadata(description = "Origin-form path for this generated step.", minLength = 1, maxLength = 8192)
    val path: String,
    @JsonSchemaMetadata(description = "Static headers added to this generated request.", maxProperties = MAX_CHAIN_HEADERS)
    val headers: Map<String, String> = emptyMap(),
    @JsonSchemaMetadata(description = "Optional text body for this generated request.", maxLength = MAX_CHAIN_BODY_CHARS)
    val body: String? = null,
    @JsonSchemaMetadata(description = "Variable to first-level $.key JSON selector or one-group safe regex.", maxProperties = MAX_CHAIN_VARIABLES)
    val extract: Map<String, String> = emptyMap(),
    @JsonSchemaMetadata(description = "Previously extracted variable to a Header: value {{variable}} template.", maxProperties = MAX_CHAIN_VARIABLES)
    val inject: Map<String, String> = emptyMap(),
)

@Serializable
data class GenerateBambdaChain(
    @JsonSchemaMetadata(description = "Name for the generated Repeater CUSTOM_ACTION Bambda.", minLength = 1, maxLength = MAX_BAMBDA_NAME_CHARS)
    val name: String,
    @JsonSchemaMetadata(description = "Exact fixed destination host used by every generated step.", minLength = 1, maxLength = 253)
    val targetHostname: String,
    @JsonSchemaMetadata(description = "Fixed destination port.", minimum = 1, maximum = 65535)
    val targetPort: Int,
    @JsonSchemaMetadata(description = "Use HTTPS in generated request URLs.")
    val usesHttps: Boolean,
    @JsonSchemaMetadata(description = "Ordered requests sent when the custom action is manually or automatically run.", minItems = 1, maxItems = MAX_CHAIN_STEPS)
    val steps: List<BambdaChainStep>,
)

@Serializable
internal data class GenerateBambdaChainResult(
    @JsonSchemaMetadata(description = TOOL_STATUS_RETRY_DESCRIPTION + " Even when ok, check importStatus and importErrors.")
    val status: NativeToolStatus,
    @JsonSchemaMetadata(description = TOOL_RETRY_DESCRIPTION)
    val retry: ToolRetryGuidance,
    @JsonSchemaMetadata(description = TOOL_EXECUTION_STATE_DESCRIPTION)
    val executionState: StandardExecutionState,
    @JsonSchemaMetadata(maxLength = MAX_BAMBDA_NAME_CHARS)
    val name: String,
    @JsonSchemaMetadata(maxLength = 36)
    val bambdaId: String?,
    @JsonSchemaMetadata(maxLength = 32)
    val importStatus: String?,
    @JsonSchemaMetadata(maxItems = MAX_BAMBDA_ERRORS)
    val importErrors: List<String>,
    val importErrorsTruncated: Boolean,
    @JsonSchemaMetadata(maxLength = MAX_BAMBDA_SOURCE_CHARS)
    val generatedBambda: String?,
    @JsonSchemaMetadata(maxLength = MAX_STANDARD_TOOL_ERROR_CHARS)
    val error: String? = null,
)

internal class BambdaService(
    private val api: MontoyaApi,
    @Volatile private var config: McpConfig,
) {
    private val importPermit = Semaphore(1, true)
    private val ownedIds = HashSet<String>()

    fun updateConfig(config: McpConfig) {
        this.config = config
    }

    suspend fun import(input: ImportBambda): BambdaImportResult {
        val validationError = validateBambdaNameAndSource(input.name, input.source)
        if (validationError != null) return importFailure(input.name, NativeToolStatus.INVALID_ARGUMENT, validationError)
        val id = bambdaId(input.name)
        val envelope = wrapBambda(id, input.name, input.source)
        if (envelope.length > MAX_BAMBDA_SOURCE_CHARS) {
            return importFailure(input.name, NativeToolStatus.LIMIT_EXCEEDED, "wrapped Bambda exceeds the size limit", id)
        }
        return importEnvelope(input.name, id, envelope)
    }

    suspend fun generateAndImport(input: GenerateBambdaChain): GenerateBambdaChainResult {
        val source = try {
            generateChainSource(input)
        } catch (e: IllegalArgumentException) {
            return chainFailure(input.name, NativeToolStatus.INVALID_ARGUMENT, e.message.orEmpty())
        } catch (e: Exception) {
            return chainFailure(
                input.name,
                NativeToolStatus.BURP_ERROR,
                "Burp could not prepare the Bambda chain: ${safeExceptionSummary(e)}",
            )
        }
        val id = bambdaId(input.name)
        val envelope = wrapBambda(id, input.name, source)
        if (envelope.length > MAX_BAMBDA_SOURCE_CHARS) {
            return chainFailure(input.name, NativeToolStatus.LIMIT_EXCEEDED, "generated Bambda exceeds the size limit")
        }
        val imported = importEnvelope(input.name, id, envelope)
        return GenerateBambdaChainResult(
            status = imported.status,
            retry = imported.retry,
            executionState = imported.executionState,
            name = imported.name,
            bambdaId = imported.bambdaId,
            importStatus = imported.importStatus,
            importErrors = imported.importErrors,
            importErrorsTruncated = imported.importErrorsTruncated,
            generatedBambda = envelope,
            error = imported.error,
        )
    }

    private suspend fun importEnvelope(name: String, id: String, envelope: String): BambdaImportResult {
        if (!config.codeExecutionTooling) {
            return importFailure(
                name,
                NativeToolStatus.DISABLED,
                "Bambda and local code-execution tools are disabled in Burp's MCP settings",
                id,
            )
        }
        if (!hasBambdaCapacity(id)) {
            return importFailure(
                name,
                NativeToolStatus.LIMIT_EXCEEDED,
                "at most $MAX_OWNED_BAMBDAS distinct MCP-imported Bambda IDs are allowed per extension lifetime",
                id,
            )
        }
        val approved = try {
            SensitiveActionSecurity.checkPermission(
                action = "import a Repeater custom-action Bambda",
                summary = "Import '$name' as deterministic ID $id; an existing Bambda with this ID will be replaced and the code can run arbitrary actions when enabled in Burp",
                reviewContent = envelope,
                api = api,
                config = config,
                auditOperation = SensitiveActionAuditOperation.BAMBDA_IMPORT,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return importFailure(
                name,
                NativeToolStatus.BURP_ERROR,
                "Burp could not request Bambda approval: ${safeExceptionSummary(e)}",
                id,
            )
        }
        if (!approved) return importFailure(name, NativeToolStatus.ACCESS_DENIED, "Bambda import denied by Burp Suite", id)
        currentCoroutineContext().ensureActive()
        if (!config.codeExecutionTooling) {
            return importFailure(name, NativeToolStatus.DISABLED, "Bambda tools were disabled during approval", id)
        }
        if (!importPermit.tryAcquire()) {
            return importFailure(name, NativeToolStatus.LIMIT_EXCEEDED, "another MCP Bambda import is already running", id)
        }
        if (config.emergencyReadOnlyMode || !config.codeExecutionTooling) {
            importPermit.release()
            return importFailure(name, NativeToolStatus.DISABLED, "Bambda import was disabled before it started", id)
        }
        val bambdaApi = try {
            api.bambda()
        } catch (e: CancellationException) {
            importPermit.release()
            throw e
        } catch (e: Exception) {
            importPermit.release()
            return importFailure(
                name,
                NativeToolStatus.BURP_ERROR,
                "Burp could not access Bambda import: ${safeExceptionSummary(e)}",
                id,
            )
        }
        if (!reserveBambdaId(id)) {
            importPermit.release()
            return importFailure(
                name,
                NativeToolStatus.LIMIT_EXCEEDED,
                "at most $MAX_OWNED_BAMBDAS distinct MCP-imported Bambda IDs are allowed per extension lifetime",
                id,
            )
        }
        return try {
            val result = bambdaApi.importBambda(envelope)
            currentCoroutineContext().ensureActive()
            val rawErrors = result.importErrors().orEmpty()
            BambdaImportResult(
                status = NativeToolStatus.OK,
                retry = ToolRetryGuidance.NOT_APPLICABLE,
                executionState = StandardExecutionState.COMPLETED,
                name = name,
                bambdaId = id,
                importStatus = when (result.status()) {
                    MontoyaBambdaImportResult.Status.LOADED_WITHOUT_ERRORS -> "imported"
                    MontoyaBambdaImportResult.Status.LOADED_WITH_ERRORS -> "imported_with_errors"
                },
                importErrors = rawErrors.take(MAX_BAMBDA_ERRORS).map { safeSingleLine(it, MAX_BAMBDA_ERROR_CHARS) },
                importErrorsTruncated = rawErrors.size > MAX_BAMBDA_ERRORS || rawErrors.any { it.length > MAX_BAMBDA_ERROR_CHARS },
            )
        } catch (e: CancellationException) {
            if (!currentCoroutineContext().isActive) throw e
            importUncertain(name, id, e)
        } catch (e: Exception) {
            importUncertain(name, id, e)
        } finally {
            importPermit.release()
        }
    }

    private fun hasBambdaCapacity(id: String): Boolean = synchronized(ownedIds) {
        id in ownedIds || ownedIds.size < MAX_OWNED_BAMBDAS
    }

    private fun reserveBambdaId(id: String): Boolean = synchronized(ownedIds) {
        if (id in ownedIds) true
        else if (ownedIds.size >= MAX_OWNED_BAMBDAS) false
        else {
            ownedIds += id
            true
        }
    }

    private fun importFailure(
        name: String,
        status: NativeToolStatus,
        error: String,
        id: String? = null,
    ) = BambdaImportResult(
        status = status,
        retry = status.defaultRetry(),
        executionState = StandardExecutionState.NOT_STARTED,
        name = name.take(MAX_BAMBDA_NAME_CHARS),
        bambdaId = id,
        importStatus = null,
        importErrors = emptyList(),
        importErrorsTruncated = false,
        error = nativeToolError(error),
    )

    private fun importUncertain(name: String, id: String, error: Exception) = BambdaImportResult(
        status = NativeToolStatus.EXECUTION_UNCERTAIN,
        retry = ToolRetryGuidance.DO_NOT_RETRY,
        executionState = StandardExecutionState.UNCERTAIN,
        name = name,
        bambdaId = id,
        importStatus = null,
        importErrors = emptyList(),
        importErrorsTruncated = false,
        error = uncertainExecutionError(
            "Burp may have imported or replaced the Bambda",
            error,
            preserveCancellation = false,
            maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
        ),
    )

    private fun chainFailure(name: String, status: NativeToolStatus, error: String) = GenerateBambdaChainResult(
        status = status,
        retry = status.defaultRetry(),
        executionState = StandardExecutionState.NOT_STARTED,
        name = name.take(MAX_BAMBDA_NAME_CHARS),
        bambdaId = null,
        importStatus = null,
        importErrors = emptyList(),
        importErrorsTruncated = false,
        generatedBambda = null,
        error = nativeToolError(error),
    )
}

private fun validateBambdaNameAndSource(name: String, source: String): String? = when {
    !BAMBDA_NAME.matches(name) -> "name contains unsupported characters or exceeds its limit"
    source.isBlank() || source.length > MAX_BAMBDA_SOURCE_CHARS -> "source is empty or exceeds its size limit"
    '\u0000' in source -> "source must not contain NUL characters"
    else -> null
}

private fun bambdaId(name: String): String = UUID.nameUUIDFromBytes(
    "independent-mcp-bridge:$name".toByteArray(StandardCharsets.UTF_8),
).toString()

private fun wrapBambda(id: String, name: String, source: String): String = buildString {
    appendLine("id: $id")
    appendLine("name: $name")
    appendLine("function: CUSTOM_ACTION")
    appendLine("location: REPEATER")
    appendLine("source: |+")
    source.replace("\r\n", "\n").replace('\r', '\n').lines().forEach { appendLine("  $it") }
}

internal fun generateChainSource(input: GenerateBambdaChain): String {
    require(BAMBDA_NAME.matches(input.name)) { "name contains unsupported characters or exceeds its limit" }
    validateRawTarget(input.targetHostname, input.targetPort)
    require(input.steps.size in 1..MAX_CHAIN_STEPS) { "steps must contain between 1 and $MAX_CHAIN_STEPS items" }
    var totalChars = 0
    val availableVariables = linkedSetOf<String>()
    input.steps.forEachIndexed { index, step ->
        require(HTTP_METHOD_TOKEN.matches(step.method)) { "step ${index + 1} method is invalid" }
        require(step.path.length in 1..8_192 && step.path.startsWith('/') && step.path.none(Char::isISOControl)) {
            "step ${index + 1} path is invalid"
        }
        require(step.headers.size <= MAX_CHAIN_HEADERS) { "step ${index + 1} has too many headers" }
        step.headers.forEach { (name, value) -> validateChainHeader(index, name, value) }
        require(
            (step.body?.length ?: 0) <= MAX_CHAIN_BODY_CHARS &&
                (step.body == null || step.body.none { it.isISOControl() && it != '\r' && it != '\n' && it != '\t' })
        ) {
            "step ${index + 1} body is too large or contains an unsupported control character"
        }
        require(step.extract.size <= MAX_CHAIN_VARIABLES && step.inject.size <= MAX_CHAIN_VARIABLES) {
            "step ${index + 1} has too many extraction or injection entries"
        }
        step.inject.forEach { (variable, template) ->
            require(BAMBDA_VARIABLE.matches(variable) && variable in availableVariables) {
                "step ${index + 1} inject references an unavailable variable"
            }
            validateHeaderTemplate(index, variable, template)
        }
        step.extract.forEach { (variable, selector) ->
            require(BAMBDA_VARIABLE.matches(variable) && variable !in availableVariables) {
                "step ${index + 1} extract variable is invalid or duplicated"
            }
            validateExtractionSelector(index, selector)
        }
        availableVariables += step.extract.keys
        totalChars += step.path.length + (step.body?.length ?: 0) +
            step.headers.entries.sumOf { it.key.length + it.value.length } +
            step.extract.entries.sumOf { it.key.length + it.value.length } +
            step.inject.entries.sumOf { it.key.length + it.value.length }
    }
    require(totalChars <= MAX_CHAIN_TOTAL_CHARS) { "chain content exceeds the aggregate size limit" }

    val scheme = if (input.usesHttps) "https" else "http"
    val defaultPort = if (input.usesHttps) 443 else 80
    val bareHost = input.targetHostname.removePrefix("[").removeSuffix("]")
    val urlHost = if (':' in bareHost) "[$bareHost]" else bareHost
    val authority = urlHost + if (input.targetPort == defaultPort) "" else ":${input.targetPort}"
    return buildString {
        appendLine("var vars = new java.util.HashMap<String, String>();")
        input.steps.forEachIndexed { index, step ->
            val number = index + 1
            val url = "$scheme://$authority${step.path}"
            appendLine("var req$number = HttpRequest.httpRequestFromUrl(${javaLiteral(url)}).withMethod(${javaLiteral(step.method.uppercase())});")
            step.inject.forEach { (variable, template) ->
                val parts = template.split(':', limit = 2)
                val injected = "injected${number}_$variable"
                appendLine("if (vars.containsKey(${javaLiteral(variable)})) {")
                appendLine("  var $injected = ${templateExpression(parts[1].trim(), variable)};")
                appendLine(
                    "  if (${safeExtractedValue(injected)}) req$number = req$number.withAddedHeader(" +
                        "${javaLiteral(parts[0].trim())}, $injected);"
                )
                appendLine("}")
            }
            step.headers.forEach { (name, value) ->
                appendLine("req$number = req$number.withAddedHeader(${javaLiteral(name)}, ${javaLiteral(value)});")
            }
            step.body?.let { appendLine("req$number = req$number.withBody(${javaLiteral(it)});") }
            appendLine("var rr$number = api().http().sendRequest(req$number);")
            appendLine("var body$number = rr$number.response() == null ? \"\" : rr$number.response().bodyToString();")
            appendLine("logging().logToOutput(\"[MCP chain $number/${input.steps.size}] response=\" + (rr$number.response() == null ? \"none\" : rr$number.response().statusCode()));")
            step.extract.forEach { (variable, selector) ->
                if (selector.startsWith("$.")) {
                    val pointer = "/" + selector.removePrefix("$.").replace("~", "~0").replace("/", "~1")
                    appendLine("try { var extracted${number}_$variable = utilities().jsonUtils().readString(body$number, ${javaLiteral(pointer)}); if (${safeExtractedValue("extracted${number}_$variable")}) vars.put(${javaLiteral(variable)}, extracted${number}_$variable); } catch (Exception ignored) {}")
                } else {
                    appendLine("var matcher${number}_$variable = java.util.regex.Pattern.compile(${javaLiteral(selector)}).matcher(body$number);")
                    appendLine("if (matcher${number}_$variable.find()) { var extracted${number}_$variable = matcher${number}_$variable.group(1); if (${safeExtractedValue("extracted${number}_$variable")}) vars.put(${javaLiteral(variable)}, extracted${number}_$variable); }")
                }
            }
            appendLine()
        }
        appendLine("logging().logToOutput(\"MCP chain complete: ${javaString(input.name)}\");")
    }.also { require(it.length <= MAX_BAMBDA_SOURCE_CHARS) { "generated Bambda exceeds the size limit" } }
}

private fun validateChainHeader(index: Int, name: String, value: String) {
    require(HTTP_HEADER_TOKEN.matches(name)) { "step ${index + 1} header name is invalid" }
    require(value.length <= 16_384 && value.none(Char::isISOControl)) {
        "step ${index + 1} header value is invalid"
    }
}

private fun validateHeaderTemplate(index: Int, variable: String, template: String) {
    val parts = template.split(':', limit = 2)
    require(parts.size == 2 && HTTP_HEADER_TOKEN.matches(parts[0].trim())) {
        "step ${index + 1} injection must be a valid Header: value template"
    }
    val placeholder = "{{$variable}}"
    require(placeholder in parts[1] && parts[1].replace(placeholder, "").let { "{{" !in it && "}}" !in it }) {
        "step ${index + 1} injection must contain only the matching variable placeholder"
    }
    require(parts[1].length <= 16_384 && parts[1].none(Char::isISOControl)) {
        "step ${index + 1} injection value is invalid"
    }
}

private fun validateExtractionSelector(index: Int, selector: String) {
    if (selector.startsWith("$.")) {
        val key = selector.removePrefix("$.")
        require(key.isNotEmpty() && key.length <= 256 && key.none(Char::isISOControl)) {
            "step ${index + 1} JSON selector is invalid"
        }
    } else {
        val pattern: Pattern = validateSafeRegex(selector)
        require(pattern.matcher("").groupCount() == 1) {
            "step ${index + 1} extraction regex needs exactly one capture group"
        }
    }
}

private fun safeExtractedValue(variable: String): String =
    "$variable != null && $variable.length() <= 16384 && $variable.indexOf('\\r') < 0 && " +
        "$variable.indexOf('\\n') < 0 && $variable.indexOf(0) < 0"

private fun templateExpression(template: String, variable: String): String {
    val placeholder = "{{$variable}}"
    val pieces = template.split(placeholder)
    return pieces.mapIndexed { index, piece ->
        val literal = javaLiteral(piece)
        if (index == pieces.lastIndex) literal else "$literal + vars.getOrDefault(${javaLiteral(variable)}, \"\")"
    }.joinToString(" + ")
}

private fun javaLiteral(value: String): String = "\"${javaString(value)}\""

private fun javaString(value: String): String = buildString(value.length + 16) {
    value.forEach { character ->
        when (character) {
            '\\' -> append("\\\\")
            '"' -> append("\\\"")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            '\b' -> append("\\b")
            '\u000c' -> append("\\f")
            else -> if (character.isISOControl()) append("\\u%04x".format(character.code)) else append(character)
        }
    }
}

private fun ShellTimeoutPolicy.toMontoya(): TimeoutBehavior = TimeoutBehavior.valueOf(name)
private fun ShellStderrPolicy.toMontoya(): StderrBehavior = StderrBehavior.valueOf(name)
private fun ShellExitCodePolicy.toMontoya(): ExitCodeBehavior = ExitCodeBehavior.valueOf(name)
