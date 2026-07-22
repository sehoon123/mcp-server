package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.security.SensitiveActionSecurity
import net.portswigger.mcp.security.safeExceptionSummary
import java.net.IDN
import java.net.URI

private const val MAX_SCOPE_CHECK_TARGETS = 32
private const val MAX_SCOPE_UPDATE_TARGETS = 16
private const val MAX_SCOPE_URL_CHARS = 2_048

@Serializable
data class ScopeTarget(
    @JsonSchemaMetadata(description = "Absolute HTTP(S) URL; supply exactly one of url or ref.", minLength = 1, maxLength = 2048)
    val url: String? = null,
    @JsonSchemaMetadata(description = "Stable message reference; supply exactly one of url or ref.")
    val ref: HttpMessageReference? = null,
)

@Serializable
data class CheckScope(
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "URLs or stable references to check.", minItems = 1, maxItems = 32)
    val targets: List<ScopeTarget>,
)

@Serializable
enum class ScopeUpdateOperation {
    @SerialName("include")
    INCLUDE,

    @SerialName("exclude")
    EXCLUDE,
}

@Serializable
data class UpdateScope(
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Scope mutation to approve and apply.")
    val operation: ScopeUpdateOperation,
    @JsonSchemaMetadata(description = "URLs or stable references to mutate.", minItems = 1, maxItems = 16)
    val targets: List<ScopeTarget>,
)

@Serializable
enum class ScopeToolStatus {
    @SerialName("ok")
    OK,

    @SerialName("access_denied")
    ACCESS_DENIED,

    @SerialName("action_denied")
    ACTION_DENIED,

    @SerialName("invalid_argument")
    INVALID_ARGUMENT,

    @SerialName("invalid_id")
    INVALID_ID,

    @SerialName("project_mismatch")
    PROJECT_MISMATCH,

    @SerialName("not_found")
    NOT_FOUND,

    @SerialName("request_unavailable")
    REQUEST_UNAVAILABLE,

    @SerialName("burp_error")
    BURP_ERROR,

    @SerialName("execution_uncertain")
    EXECUTION_UNCERTAIN,
}

@Serializable
enum class ProjectMutationExecutionState {
    @SerialName("not_started")
    NOT_STARTED,

    @SerialName("completed")
    COMPLETED,

    @SerialName("uncertain")
    UNCERTAIN,
}

@Serializable
data class ScopeTargetResult(
    val index: Int,
    val ref: HttpMessageReference? = null,
    val url: String,
    val inScope: Boolean,
    val changed: Boolean? = null,
)

@Serializable
data class CheckScopeResult(
    val status: ScopeToolStatus,
    val projectId: String?,
    val targets: List<ScopeTargetResult>,
    val errorTargetIndex: Int? = null,
    val error: String? = null,
)

@Serializable
data class UpdateScopeResult(
    val status: ScopeToolStatus,
    val executionState: ProjectMutationExecutionState,
    val projectId: String?,
    val operation: ScopeUpdateOperation,
    val targets: List<ScopeTargetResult>,
    val changedCount: Int,
    val errorTargetIndex: Int? = null,
    val error: String? = null,
)

internal class ScopeToolService(
    private val api: MontoyaApi,
    config: McpConfig,
    private val metadataIndex: HttpMetadataIndex,
) {
    private val resolver = HttpMessageResolver(api, config)

    suspend fun check(input: CheckScope): CheckScopeResult {
        val prepared = when (val result = prepareTargets(input.projectId, input.targets, MAX_SCOPE_CHECK_TARGETS)) {
            is PreparedScopeTargets.Found -> result
            is PreparedScopeTargets.Failed -> return CheckScopeResult(
                status = result.status,
                projectId = result.projectId,
                targets = emptyList(),
                errorTargetIndex = result.index,
                error = result.error,
            )
        }

        val projectBeforeRead = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return CheckScopeResult(
                ScopeToolStatus.BURP_ERROR,
                prepared.projectId,
                emptyList(),
                error = "Burp could not recheck the project before reading scope: ${safeScopeException(e)}",
            )
        }
        if (projectBeforeRead != prepared.projectId) {
            return CheckScopeResult(
                ScopeToolStatus.PROJECT_MISMATCH,
                projectBeforeRead,
                emptyList(),
                error = "Burp project changed before the scope check",
            )
        }

        val results = ArrayList<ScopeTargetResult>(prepared.targets.size)
        return try {
            prepared.targets.forEach { target ->
                currentCoroutineContext().ensureActive()
                results += ScopeTargetResult(
                    index = target.index,
                    ref = target.ref,
                    url = target.url,
                    inScope = api.scope().isInScope(target.url),
                )
            }
            CheckScopeResult(ScopeToolStatus.OK, prepared.projectId, results, error = null)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            CheckScopeResult(
                status = ScopeToolStatus.BURP_ERROR,
                projectId = prepared.projectId,
                targets = results,
                errorTargetIndex = prepared.targets.getOrNull(results.size)?.index,
                error = "Burp could not check Target scope: ${safeScopeException(e)}",
            )
        }
    }

    suspend fun update(input: UpdateScope): UpdateScopeResult {
        val prepared = when (val result = prepareTargets(input.projectId, input.targets, MAX_SCOPE_UPDATE_TARGETS)) {
            is PreparedScopeTargets.Found -> result
            is PreparedScopeTargets.Failed -> return updateFailure(
                input.operation,
                result.status,
                ProjectMutationExecutionState.NOT_STARTED,
                result.projectId,
                result.index,
                result.error,
            )
        }

        val desired = input.operation == ScopeUpdateOperation.INCLUDE
        val before = try {
            prepared.targets.map { target -> api.scope().isInScope(target.url) }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return updateFailure(
                input.operation,
                ScopeToolStatus.BURP_ERROR,
                ProjectMutationExecutionState.NOT_STARTED,
                prepared.projectId,
                null,
                "Burp could not inspect Target scope before changing it: ${safeScopeException(e)}",
            )
        }
        val projectAfterRead = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return updateFailure(
                input.operation,
                ScopeToolStatus.BURP_ERROR,
                ProjectMutationExecutionState.NOT_STARTED,
                prepared.projectId,
                null,
                "Burp could not recheck the project before changing scope: ${safeScopeException(e)}",
            )
        }
        if (projectAfterRead != prepared.projectId) {
            return updateFailure(
                input.operation,
                ScopeToolStatus.PROJECT_MISMATCH,
                ProjectMutationExecutionState.NOT_STARTED,
                projectAfterRead,
                null,
                "Burp project changed before the scope update",
            )
        }
        val indexesToChange = before.indices.filter { before[it] != desired }
        if (indexesToChange.isEmpty()) {
            return UpdateScopeResult(
                status = ScopeToolStatus.OK,
                executionState = ProjectMutationExecutionState.COMPLETED,
                projectId = prepared.projectId,
                operation = input.operation,
                targets = prepared.targets.mapIndexed { index, target ->
                    ScopeTargetResult(target.index, target.ref, target.url, before[index], changed = false)
                },
                changedCount = 0,
            )
        }

        val review = buildString {
            indexesToChange.forEach { index ->
                append(input.operation.name.lowercase())
                append(' ')
                appendLine(prepared.targets[index].url)
            }
        }.trimEnd()
        val approved = try {
            SensitiveActionSecurity.checkPermission(
                action = "${input.operation.name.lowercase()} ${indexesToChange.size} URL(s) ${input.operation.preposition()} Burp Target scope",
                summary = "Project: ${prepared.projectId}\nScope changes: ${indexesToChange.size}",
                reviewContent = review,
                api = api,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return updateFailure(
                input.operation,
                ScopeToolStatus.BURP_ERROR,
                ProjectMutationExecutionState.NOT_STARTED,
                prepared.projectId,
                null,
                "Burp could not request scope-change approval: ${safeScopeException(e)}",
            )
        }
        if (!approved) {
            auditScope(input.operation, indexesToChange.size, 0, "denied")
            return UpdateScopeResult(
                status = ScopeToolStatus.ACTION_DENIED,
                executionState = ProjectMutationExecutionState.NOT_STARTED,
                projectId = prepared.projectId,
                operation = input.operation,
                targets = prepared.targets.mapIndexed { index, target ->
                    ScopeTargetResult(target.index, target.ref, target.url, before[index], changed = false)
                },
                changedCount = 0,
                error = "scope update denied by Burp Suite",
            )
        }

        return metadataIndex.withMutation {
            applyApprovedUpdate(input, prepared, desired, before, indexesToChange)
        }
    }

    private suspend fun applyApprovedUpdate(
        input: UpdateScope,
        prepared: PreparedScopeTargets.Found,
        desired: Boolean,
        before: List<Boolean>,
        indexesToChange: List<Int>,
    ): UpdateScopeResult {
        currentCoroutineContext().ensureActive()
        val after = before.toMutableList()
        val changed = BooleanArray(prepared.targets.size)
        var changedCount = 0
        for (index in indexesToChange) {
            try {
                currentCoroutineContext().ensureActive()
            } catch (e: CancellationException) {
                auditScope(input.operation, indexesToChange.size, changedCount, "cancelled after $changedCount change(s)")
                throw e
            }
            val target = prepared.targets[index]
            var mutationAttempted = false
            try {
                val currentProjectId = api.project().id()
                if (currentProjectId != prepared.projectId) {
                    if (changedCount == 0) {
                        return updateFailure(
                            input.operation,
                            ScopeToolStatus.PROJECT_MISMATCH,
                            ProjectMutationExecutionState.NOT_STARTED,
                            currentProjectId,
                            target.index,
                            "Burp project changed before the scope update executed",
                        )
                    }
                    auditScope(input.operation, indexesToChange.size, changedCount, "project changed; execution uncertain")
                    return uncertainUpdate(
                        input.operation,
                        prepared,
                        after,
                        changed,
                        changedCount,
                        target.index,
                        "Burp project changed while applying scope updates",
                    )
                }
                val currentlyInScope = api.scope().isInScope(target.url)
                if (currentlyInScope == desired) {
                    after[index] = currentlyInScope
                    continue
                }
                mutationAttempted = true
                when (input.operation) {
                    ScopeUpdateOperation.INCLUDE -> api.scope().includeInScope(target.url)
                    ScopeUpdateOperation.EXCLUDE -> api.scope().excludeFromScope(target.url)
                }
                changed[index] = true
                changedCount++
                after[index] = api.scope().isInScope(target.url)
                if (after[index] != desired) {
                    auditScope(input.operation, indexesToChange.size, changedCount, "verification failed; execution uncertain")
                    return uncertainUpdate(
                        input.operation,
                        prepared,
                        after,
                        changed,
                        changedCount,
                        target.index,
                        "Burp did not report the requested scope state after applying the update",
                    )
                }
            } catch (e: Exception) {
                if (!mutationAttempted && changedCount == 0) {
                    return updateFailure(
                        input.operation,
                        ScopeToolStatus.BURP_ERROR,
                        ProjectMutationExecutionState.NOT_STARTED,
                        prepared.projectId,
                        target.index,
                        "Burp could not prepare the scope update: ${safeScopeException(e)}",
                    )
                }
                auditScope(input.operation, indexesToChange.size, changedCount, "execution uncertain")
                return uncertainUpdate(
                    input.operation,
                    prepared,
                    after,
                    changed,
                    changedCount,
                    target.index,
                    "Scope update may have been partially applied: ${safeScopeException(e)}",
                )
            }
        }

        auditScope(input.operation, indexesToChange.size, changedCount, "completed")
        return UpdateScopeResult(
            status = ScopeToolStatus.OK,
            executionState = ProjectMutationExecutionState.COMPLETED,
            projectId = prepared.projectId,
            operation = input.operation,
            targets = prepared.targets.mapIndexed { index, target ->
                ScopeTargetResult(target.index, target.ref, target.url, after[index], changed[index])
            },
            changedCount = changedCount,
        )
    }

    private suspend fun prepareTargets(
        requestedProjectId: String,
        inputs: List<ScopeTarget>,
        maxTargets: Int,
    ): PreparedScopeTargets {
        if (requestedProjectId.isEmpty() || requestedProjectId.length > MAX_HTTP_REFERENCE_PROJECT_ID_CHARS ||
            requestedProjectId.any(Char::isISOControl)
        ) {
            return PreparedScopeTargets.Failed(
                ScopeToolStatus.INVALID_ARGUMENT,
                requestedProjectId.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
                null,
                "projectId is empty, too long, or contains control characters",
            )
        }
        if (inputs.isEmpty() || inputs.size > maxTargets) {
            return PreparedScopeTargets.Failed(
                ScopeToolStatus.INVALID_ARGUMENT,
                requestedProjectId,
                null,
                "targets must contain between 1 and $maxTargets items",
            )
        }

        val currentProjectId = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return PreparedScopeTargets.Failed(
                ScopeToolStatus.BURP_ERROR,
                null,
                null,
                "Burp could not read the current project: ${safeScopeException(e)}",
            )
        }
        if (requestedProjectId != currentProjectId) {
            return PreparedScopeTargets.Failed(
                ScopeToolStatus.PROJECT_MISMATCH,
                currentProjectId,
                null,
                "targets belong to a different Burp project",
            )
        }

        val refInputIndexes = ArrayList<Int>()
        val refs = ArrayList<HttpMessageReference>()
        val prepared = arrayOfNulls<PreparedScopeTarget>(inputs.size)
        inputs.forEachIndexed { index, target ->
            if ((target.url == null) == (target.ref == null)) {
                return PreparedScopeTargets.Failed(
                    ScopeToolStatus.INVALID_ARGUMENT,
                    currentProjectId,
                    index,
                    "each target must contain exactly one of url or ref",
                )
            }
            if (target.url != null) {
                val normalized = try {
                    normalizeScopeUrl(target.url)
                } catch (e: IllegalArgumentException) {
                    return PreparedScopeTargets.Failed(
                        ScopeToolStatus.INVALID_ARGUMENT,
                        currentProjectId,
                        index,
                        e.message ?: "invalid scope URL",
                    )
                }
                prepared[index] = PreparedScopeTarget(index, null, normalized)
            } else {
                refInputIndexes += index
                refs += requireNotNull(target.ref)
            }
        }

        if (refs.isNotEmpty()) {
            when (val resolution = resolver.resolveAll(currentProjectId, refs, maxTargets)) {
                is HttpMessageBatchResolution.Failed -> {
                    val inputIndex = resolution.refIndex?.let(refInputIndexes::getOrNull)
                    return PreparedScopeTargets.Failed(
                        resolution.status.toScopeStatus(),
                        resolution.projectId,
                        inputIndex,
                        resolution.error,
                    )
                }

                is HttpMessageBatchResolution.Found -> resolution.messages.forEachIndexed { refIndex, message ->
                    val inputIndex = refInputIndexes[refIndex]
                    val normalized = try {
                        normalizeScopeUrl(message.request.url())
                    } catch (e: IllegalArgumentException) {
                        return PreparedScopeTargets.Failed(
                            ScopeToolStatus.INVALID_ARGUMENT,
                            currentProjectId,
                            inputIndex,
                            "referenced request has an invalid or oversized URL: ${e.message.orEmpty()}",
                        )
                    }
                    prepared[inputIndex] = PreparedScopeTarget(inputIndex, message.ref, normalized)
                }
            }
        }

        val completed = prepared.map { requireNotNull(it) }
        val duplicateIndex = completed.groupBy { it.url }.values.firstOrNull { it.size > 1 }?.get(1)?.index
        if (duplicateIndex != null) {
            return PreparedScopeTargets.Failed(
                ScopeToolStatus.INVALID_ARGUMENT,
                currentProjectId,
                duplicateIndex,
                "targets contain duplicate normalized URLs",
            )
        }
        return PreparedScopeTargets.Found(currentProjectId, completed)
    }

    private fun uncertainUpdate(
        operation: ScopeUpdateOperation,
        prepared: PreparedScopeTargets.Found,
        after: List<Boolean>,
        changed: BooleanArray,
        changedCount: Int,
        errorIndex: Int,
        error: String,
    ) = UpdateScopeResult(
        status = ScopeToolStatus.EXECUTION_UNCERTAIN,
        executionState = ProjectMutationExecutionState.UNCERTAIN,
        projectId = prepared.projectId,
        operation = operation,
        targets = prepared.targets.mapIndexed { index, target ->
            ScopeTargetResult(target.index, target.ref, target.url, after[index], changed[index])
        },
        changedCount = changedCount,
        errorTargetIndex = errorIndex,
        error = error.take(512),
    )

    private fun auditScope(
        operation: ScopeUpdateOperation,
        requested: Int,
        changed: Int,
        outcome: String,
    ) {
        runCatching {
            api.logging().logToOutput(
                "MCP scope action: operation=${operation.name.lowercase()} requested=$requested changed=$changed outcome=$outcome"
            )
        }
    }
}

private sealed interface PreparedScopeTargets {
    data class Found(
        val projectId: String,
        val targets: List<PreparedScopeTarget>,
    ) : PreparedScopeTargets

    data class Failed(
        val status: ScopeToolStatus,
        val projectId: String?,
        val index: Int?,
        val error: String,
    ) : PreparedScopeTargets
}

private data class PreparedScopeTarget(
    val index: Int,
    val ref: HttpMessageReference?,
    val url: String,
)

internal fun normalizeScopeUrl(value: String): String {
    require(value.length in 1..MAX_SCOPE_URL_CHARS) { "scope URL must contain 1 to $MAX_SCOPE_URL_CHARS characters" }
    require(value == value.trim()) { "scope URL must not contain surrounding whitespace" }
    require(value.none(Char::isISOControl)) { "scope URL contains control characters" }

    val uri = try {
        URI(value)
    } catch (_: Exception) {
        throw IllegalArgumentException("scope URL is not a valid absolute URI")
    }
    val scheme = uri.scheme?.lowercase()
    require(scheme == "http" || scheme == "https") { "scope URL scheme must be http or https" }
    require(uri.rawUserInfo == null) { "scope URL must not contain user information" }
    require(uri.rawFragment == null) { "scope URL must not contain a fragment" }
    val parsedAuthority = parseScopeAuthority(uri)
    val host = parsedAuthority.first
    val asciiHost = if (':' in host) host.lowercase() else try {
        IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).lowercase()
    } catch (_: IllegalArgumentException) {
        throw IllegalArgumentException("scope URL host is invalid")
    }
    require(asciiHost.length in 1..MAX_HTTP_SEARCH_HOST_CHARS) { "scope URL host is too long" }
    val port = parsedAuthority.second
    require(port == -1 || port in 1..65_535) { "scope URL port must be between 1 and 65535" }
    val normalizedPort = when {
        port == -1 -> null
        scheme == "http" && port == 80 -> null
        scheme == "https" && port == 443 -> null
        else -> port
    }
    val authority = if (':' in asciiHost) "[$asciiHost]" else asciiHost
    val path = uri.rawPath?.ifEmpty { "/" } ?: "/"
    val query = uri.rawQuery?.let { "?$it" }.orEmpty()
    val normalized = "$scheme://$authority${normalizedPort?.let { ":$it" }.orEmpty()}$path$query"
    require(normalized.length <= MAX_SCOPE_URL_CHARS) { "normalized scope URL is too long" }
    return normalized
}

private fun parseScopeAuthority(uri: URI): Pair<String, Int> {
    uri.host?.let { return it.removePrefix("[").removeSuffix("]") to uri.port }
    val authority = uri.rawAuthority ?: throw IllegalArgumentException("scope URL must contain a valid host")
    require('@' !in authority && !authority.startsWith('[') && ']' !in authority && '%' !in authority) {
        "scope URL must contain a valid host"
    }
    val separator = authority.lastIndexOf(':')
    val host: String
    val port: Int
    if (separator >= 0) {
        require(authority.indexOf(':') == separator) { "scope URL must contain a valid host" }
        host = authority.substring(0, separator)
        val rawPort = authority.substring(separator + 1)
        require(rawPort.isNotEmpty() && rawPort.all(Char::isDigit)) { "scope URL port is invalid" }
        port = rawPort.toIntOrNull() ?: throw IllegalArgumentException("scope URL port is invalid")
    } else {
        host = authority
        port = -1
    }
    require(host.isNotEmpty()) { "scope URL must contain a valid host" }
    return host to port
}

private fun HttpMessageResolutionStatus.toScopeStatus(): ScopeToolStatus = when (this) {
    HttpMessageResolutionStatus.ACCESS_DENIED -> ScopeToolStatus.ACCESS_DENIED
    HttpMessageResolutionStatus.INVALID_ARGUMENT -> ScopeToolStatus.INVALID_ARGUMENT
    HttpMessageResolutionStatus.INVALID_ID -> ScopeToolStatus.INVALID_ID
    HttpMessageResolutionStatus.PROJECT_MISMATCH -> ScopeToolStatus.PROJECT_MISMATCH
    HttpMessageResolutionStatus.NOT_FOUND -> ScopeToolStatus.NOT_FOUND
    HttpMessageResolutionStatus.REQUEST_UNAVAILABLE -> ScopeToolStatus.REQUEST_UNAVAILABLE
    HttpMessageResolutionStatus.BURP_ERROR -> ScopeToolStatus.BURP_ERROR
}

private fun ScopeUpdateOperation.preposition(): String = when (this) {
    ScopeUpdateOperation.INCLUDE -> "in"
    ScopeUpdateOperation.EXCLUDE -> "from"
}

private fun updateFailure(
    operation: ScopeUpdateOperation,
    status: ScopeToolStatus,
    executionState: ProjectMutationExecutionState,
    projectId: String?,
    errorIndex: Int?,
    error: String,
) = UpdateScopeResult(
    status = status,
    executionState = executionState,
    projectId = projectId,
    operation = operation,
    targets = emptyList(),
    changedCount = 0,
    errorTargetIndex = errorIndex,
    error = error.take(512),
)

private fun safeScopeException(error: Exception): String = safeExceptionSummary(error)
