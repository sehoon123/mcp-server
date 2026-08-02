package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import kotlinx.coroutines.CancellationException
import net.portswigger.mcp.presets.DeleteWorkflowPreset
import net.portswigger.mcp.presets.DeleteWorkflowPresetResult
import net.portswigger.mcp.presets.ExecuteWorkflowPreset
import net.portswigger.mcp.presets.ExecuteWorkflowPresetResult
import net.portswigger.mcp.presets.ListWorkflowPresets
import net.portswigger.mcp.presets.ListWorkflowPresetsResult
import net.portswigger.mcp.presets.MAX_WORKFLOW_PRESET_DESCRIPTION_CHARS
import net.portswigger.mcp.presets.MAX_WORKFLOW_PRESET_NAME_CHARS
import net.portswigger.mcp.presets.SaveWorkflowPreset
import net.portswigger.mcp.presets.SaveWorkflowPresetResult
import net.portswigger.mcp.presets.SavedHttpComparison
import net.portswigger.mcp.presets.SavedHttpSearch
import net.portswigger.mcp.presets.SavedWebSocketSearch
import net.portswigger.mcp.presets.WorkflowPreset
import net.portswigger.mcp.presets.WorkflowPresetAlreadyExistsException
import net.portswigger.mcp.presets.WorkflowPresetStatus
import net.portswigger.mcp.presets.WorkflowPresetStore
import net.portswigger.mcp.presets.WorkflowPresetStoreException
import net.portswigger.mcp.presets.WorkflowPresetStoreFailure
import net.portswigger.mcp.presets.WorkflowPresetType
import net.portswigger.mcp.presets.validateWorkflowPreset
import net.portswigger.mcp.presets.workflowPresetNameKey

internal val WORKFLOW_PRESET_SAVE_ANNOTATIONS = io.modelcontextprotocol.kotlin.sdk.types.ToolAnnotations(
    readOnlyHint = false,
    destructiveHint = true,
    idempotentHint = true,
    openWorldHint = false,
)

internal val WORKFLOW_PRESET_DELETE_ANNOTATIONS = io.modelcontextprotocol.kotlin.sdk.types.ToolAnnotations(
    readOnlyHint = false,
    destructiveHint = true,
    idempotentHint = true,
    openWorldHint = false,
)

private sealed interface WorkflowProjectCheck {
    data class Match(val projectId: String) : WorkflowProjectCheck
    data class Mismatch(val currentProjectId: String) : WorkflowProjectCheck
    data object InvalidRequested : WorkflowProjectCheck
    data object CurrentUnavailable : WorkflowProjectCheck
}

internal class WorkflowPresetService(
    private val api: MontoyaApi,
    private val store: WorkflowPresetStore,
    private val httpSearch: HttpMessageSearchService,
    private val webSocketSearch: WebSocketMessageSearchService,
    private val comparison: HttpMessageComparisonService,
) {
    fun save(input: SaveWorkflowPreset): SaveWorkflowPresetResult {
        val project = when (val check = checkProject(input.projectId)) {
            is WorkflowProjectCheck.Match -> check.projectId
            is WorkflowProjectCheck.Mismatch -> return saveFailure(
                WorkflowPresetStatus.PROJECT_MISMATCH, check.currentProjectId, "The Burp project does not match"
            )
            WorkflowProjectCheck.InvalidRequested -> return saveFailure(
                WorkflowPresetStatus.INVALID_ARGUMENT, null, "projectId is invalid"
            )
            WorkflowProjectCheck.CurrentUnavailable -> return saveFailure(
                WorkflowPresetStatus.BURP_ERROR, null, "The current Burp project is unavailable"
            )
        }
        val preset = try {
            normalizePreset(input.name, input.description, input.definition).also(::validateWorkflowPreset)
        } catch (_: IllegalArgumentException) {
            return saveFailure(WorkflowPresetStatus.INVALID_ARGUMENT, project, "The workflow preset is invalid")
        }
        val outcome = try {
            store.save(preset, input.overwrite)
        } catch (_: WorkflowPresetAlreadyExistsException) {
            return saveFailure(WorkflowPresetStatus.ALREADY_EXISTS, project, "A workflow preset with this name already exists")
        } catch (e: WorkflowPresetStoreException) {
            return if (e.writeAttempted) uncertainSave(project)
            else saveFailure(e.toStatus(), project, e.fixedMessage(), e.retryGuidance())
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return saveFailure(WorkflowPresetStatus.BURP_ERROR, project, "Workflow preset storage is unavailable")
        }
        val projectAfterSave = try {
            checkProject(project)
        } catch (_: CancellationException) {
            return uncertainSave(project)
        }
        when (projectAfterSave) {
            is WorkflowProjectCheck.Match -> Unit
            is WorkflowProjectCheck.Mismatch -> return uncertainSave(
                projectAfterSave.currentProjectId, WorkflowPresetStatus.PROJECT_MISMATCH
            )
            WorkflowProjectCheck.CurrentUnavailable,
            WorkflowProjectCheck.InvalidRequested -> return uncertainSave(null, WorkflowPresetStatus.BURP_ERROR)
        }
        return SaveWorkflowPresetResult(
            status = WorkflowPresetStatus.OK,
            retry = ToolRetryGuidance.NOT_APPLICABLE,
            executionState = StandardExecutionState.COMPLETED,
            projectId = project,
            preset = preset,
            created = outcome.first,
            replaced = outcome.second,
        )
    }

    fun list(input: ListWorkflowPresets): ListWorkflowPresetsResult {
        val project = when (val check = checkProject(input.projectId)) {
            is WorkflowProjectCheck.Match -> check.projectId
            is WorkflowProjectCheck.Mismatch -> return listFailure(
                WorkflowPresetStatus.PROJECT_MISMATCH, check.currentProjectId, "The Burp project does not match"
            )
            WorkflowProjectCheck.InvalidRequested -> return listFailure(
                WorkflowPresetStatus.INVALID_ARGUMENT, null, "projectId is invalid"
            )
            WorkflowProjectCheck.CurrentUnavailable -> return listFailure(
                WorkflowPresetStatus.BURP_ERROR, null, "The current Burp project is unavailable"
            )
        }
        if (input.offset !in 0..64 || input.limit !in 1..64) {
            return listFailure(WorkflowPresetStatus.INVALID_ARGUMENT, project, "List bounds are invalid")
        }
        val all = try {
            store.list().filter { input.type == null || it.definition.kind() == input.type }
        } catch (e: WorkflowPresetStoreException) {
            return listFailure(e.toStatus(), project, e.fixedMessage())
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return listFailure(WorkflowPresetStatus.BURP_ERROR, project, "Workflow preset storage is unavailable")
        }
        when (val after = checkProject(project)) {
            is WorkflowProjectCheck.Match -> Unit
            is WorkflowProjectCheck.Mismatch -> return listFailure(
                WorkflowPresetStatus.PROJECT_MISMATCH,
                after.currentProjectId,
                "The Burp project changed while reading presets",
            )
            WorkflowProjectCheck.CurrentUnavailable,
            WorkflowProjectCheck.InvalidRequested -> return listFailure(
                WorkflowPresetStatus.BURP_ERROR, null, "The current Burp project is unavailable"
            )
        }
        val items = all.drop(input.offset).take(input.limit)
        return ListWorkflowPresetsResult(
            WorkflowPresetStatus.OK, project, items, all.size, items.size, input.offset + items.size < all.size
        )
    }

    fun delete(input: DeleteWorkflowPreset): DeleteWorkflowPresetResult {
        val project = when (val check = checkProject(input.projectId)) {
            is WorkflowProjectCheck.Match -> check.projectId
            is WorkflowProjectCheck.Mismatch -> return deleteFailure(
                WorkflowPresetStatus.PROJECT_MISMATCH, check.currentProjectId, "The Burp project does not match"
            )
            WorkflowProjectCheck.InvalidRequested -> return deleteFailure(
                WorkflowPresetStatus.INVALID_ARGUMENT, null, "projectId is invalid"
            )
            WorkflowProjectCheck.CurrentUnavailable -> return deleteFailure(
                WorkflowPresetStatus.BURP_ERROR, null, "The current Burp project is unavailable"
            )
        }
        val name = try { normalizeName(input.name) } catch (_: IllegalArgumentException) {
            return deleteFailure(WorkflowPresetStatus.INVALID_ARGUMENT, project, "The workflow preset name is invalid")
        }
        val deleted = try {
            store.delete(name)
        } catch (e: WorkflowPresetStoreException) {
            return if (e.writeAttempted) uncertainDelete(project)
            else deleteFailure(e.toStatus(), project, e.fixedMessage(), e.retryGuidance())
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return deleteFailure(WorkflowPresetStatus.BURP_ERROR, project, "Workflow preset storage is unavailable")
        }
        val projectAfterDelete = try {
            checkProject(project)
        } catch (e: CancellationException) {
            if (deleted) return uncertainDelete(project)
            throw e
        }
        when (projectAfterDelete) {
            is WorkflowProjectCheck.Match -> Unit
            is WorkflowProjectCheck.Mismatch -> if (deleted) {
                return uncertainDelete(projectAfterDelete.currentProjectId, WorkflowPresetStatus.PROJECT_MISMATCH)
            } else {
                return deleteFailure(
                    WorkflowPresetStatus.PROJECT_MISMATCH,
                    projectAfterDelete.currentProjectId,
                    "The Burp project changed while reading presets",
                )
            }
            WorkflowProjectCheck.CurrentUnavailable,
            WorkflowProjectCheck.InvalidRequested -> if (deleted) {
                return uncertainDelete(null, WorkflowPresetStatus.BURP_ERROR)
            } else {
                return deleteFailure(
                    WorkflowPresetStatus.BURP_ERROR, null, "The current Burp project is unavailable"
                )
            }
        }
        return DeleteWorkflowPresetResult(
            WorkflowPresetStatus.OK,
            ToolRetryGuidance.NOT_APPLICABLE,
            StandardExecutionState.COMPLETED,
            project,
            deleted,
        )
    }

    suspend fun execute(
        input: ExecuteWorkflowPreset,
        reportProgress: ToolProgressReporter,
    ): ExecuteWorkflowPresetResult {
        val project = when (val check = checkProject(input.projectId)) {
            is WorkflowProjectCheck.Match -> check.projectId
            is WorkflowProjectCheck.Mismatch -> return executeFailure(
                WorkflowPresetStatus.PROJECT_MISMATCH, check.currentProjectId, "The Burp project does not match"
            )
            WorkflowProjectCheck.InvalidRequested -> return executeFailure(
                WorkflowPresetStatus.INVALID_ARGUMENT, null, "projectId is invalid"
            )
            WorkflowProjectCheck.CurrentUnavailable -> return executeFailure(
                WorkflowPresetStatus.BURP_ERROR, null, "The current Burp project is unavailable"
            )
        }
        val name = try { normalizeName(input.name) } catch (_: IllegalArgumentException) {
            return executeFailure(WorkflowPresetStatus.INVALID_ARGUMENT, project, "The workflow preset name is invalid")
        }
        val preset = try {
            val requestedNameKey = workflowPresetNameKey(name)
            store.list().firstOrNull { workflowPresetNameKey(it.name) == requestedNameKey }
        } catch (e: WorkflowPresetStoreException) {
            return executeFailure(e.toStatus(), project, e.fixedMessage())
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return executeFailure(WorkflowPresetStatus.BURP_ERROR, project, "Workflow preset storage is unavailable")
        }
        when (val after = checkProject(project)) {
            is WorkflowProjectCheck.Match -> Unit
            is WorkflowProjectCheck.Mismatch -> return executeFailure(
                WorkflowPresetStatus.PROJECT_MISMATCH,
                after.currentProjectId,
                "The Burp project changed before execution",
            )
            WorkflowProjectCheck.CurrentUnavailable,
            WorkflowProjectCheck.InvalidRequested -> return executeFailure(
                WorkflowPresetStatus.BURP_ERROR, null, "The current Burp project is unavailable"
            )
        }
        if (preset == null) {
            return executeFailure(WorkflowPresetStatus.NOT_FOUND, project, "The workflow preset was not found")
        }

        val kind = preset.definition.kind()
        val runtimeValid = when (kind) {
            WorkflowPresetType.HTTP_SEARCH, WorkflowPresetType.WEBSOCKET_SEARCH -> input.refs == null
            WorkflowPresetType.HTTP_COMPARISON -> input.refs != null && input.limit == null && input.cursor == null
        }
        if (!runtimeValid) return executeFailure(
            WorkflowPresetStatus.INVALID_ARGUMENT, project, "Runtime arguments do not match the workflow preset type",
            preset.name, kind,
        )

        val result = try {
            when (kind) {
                WorkflowPresetType.HTTP_SEARCH -> {
                    val saved = requireNotNull(preset.definition.httpSearch)
                    ExecuteWorkflowPresetResult(
                        WorkflowPresetStatus.OK, project, preset.name, kind,
                        httpSearch = httpSearch.search(saved.toInput(input.limit, input.cursor), reportProgress),
                    )
                }
                WorkflowPresetType.WEBSOCKET_SEARCH -> {
                    val saved = requireNotNull(preset.definition.webSocketSearch)
                    ExecuteWorkflowPresetResult(
                        WorkflowPresetStatus.OK, project, preset.name, kind,
                        webSocketSearch = webSocketSearch.search(saved.toInput(project, input.limit, input.cursor), reportProgress),
                    )
                }
                WorkflowPresetType.HTTP_COMPARISON -> {
                    val saved = requireNotNull(preset.definition.httpComparison)
                    ExecuteWorkflowPresetResult(
                        WorkflowPresetStatus.OK, project, preset.name, kind,
                        httpComparison = comparison.compare(saved.toInput(project, requireNotNull(input.refs))),
                    )
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return executeFailure(WorkflowPresetStatus.BURP_ERROR, project, "The delegated workflow could not be executed")
        }
        when (val after = checkProject(project)) {
            is WorkflowProjectCheck.Match -> Unit
            is WorkflowProjectCheck.Mismatch -> return executeFailure(
                WorkflowPresetStatus.PROJECT_MISMATCH,
                after.currentProjectId,
                "The Burp project changed during execution",
            )
            WorkflowProjectCheck.CurrentUnavailable,
            WorkflowProjectCheck.InvalidRequested -> return executeFailure(
                WorkflowPresetStatus.BURP_ERROR, null, "The current Burp project is unavailable"
            )
        }
        return result
    }

    private fun checkProject(requested: String): WorkflowProjectCheck {
        if (!validWorkflowProjectId(requested)) return WorkflowProjectCheck.InvalidRequested
        val current = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return WorkflowProjectCheck.CurrentUnavailable
        }
        if (!validWorkflowProjectId(current)) return WorkflowProjectCheck.CurrentUnavailable
        return if (current == requested) WorkflowProjectCheck.Match(current)
        else WorkflowProjectCheck.Mismatch(current)
    }
}

private fun validWorkflowProjectId(value: String?): Boolean =
    value != null && value.length in 1..256 && value.isNotBlank() && value.none(Char::isISOControl)

private fun normalizePreset(
    name: String,
    description: String?,
    definition: net.portswigger.mcp.presets.WorkflowPresetDefinition,
): WorkflowPreset {
    val normalizedName = normalizeName(name)
    require(description == null || (description.length <= MAX_WORKFLOW_PRESET_DESCRIPTION_CHARS && description.none(Char::isISOControl)))
    definition.kind()
    return WorkflowPreset(normalizedName, description, definition)
}

private fun normalizeName(name: String): String = name.trim().also {
    require(it.length in 1..MAX_WORKFLOW_PRESET_NAME_CHARS && it.none(Char::isISOControl))
}

private fun SavedHttpSearch.toInput(limit: Int?, cursor: String?) = SearchHttpMessages(
    sources, host, pathContains, methods, statusCodes, mimeTypes, inScopeOnly, hasResponse,
    newestFirst = newestFirst, limit = limit ?: defaultLimit, cursor = cursor,
)

private fun SavedWebSocketSearch.toInput(projectId: String, limit: Int?, cursor: String?) = SearchWebsocketMessages(
    projectId = projectId, cursor = cursor, limit = limit ?: defaultLimit, direction = direction,
    listenerPort = listenerPort, newestFirst = newestFirst,
)

private fun SavedHttpComparison.toInput(projectId: String, refs: List<HttpMessageReference>) = CompareHttpMessages(
    projectId, refs, part, limitBytesPerMessage, excerptEncoding, ignoreHeaders, includeResponseVariations
)

private fun WorkflowPresetStoreException.toStatus(): WorkflowPresetStatus = when (failure) {
    WorkflowPresetStoreFailure.CAPACITY -> WorkflowPresetStatus.CAPACITY_REACHED
    else -> WorkflowPresetStatus.BURP_ERROR
}

private fun WorkflowPresetStoreException.fixedMessage(): String = when (failure) {
    WorkflowPresetStoreFailure.CAPACITY -> "Workflow preset capacity was reached"
    WorkflowPresetStoreFailure.MALFORMED,
    WorkflowPresetStoreFailure.UNKNOWN_VERSION,
    WorkflowPresetStoreFailure.OVERSIZED -> "Stored workflow presets are invalid and require correction; the raw value was preserved"
    WorkflowPresetStoreFailure.STORAGE -> "Workflow preset storage is unavailable"
}

private fun WorkflowPresetStoreException.retryGuidance(): ToolRetryGuidance = when (failure) {
    WorkflowPresetStoreFailure.MALFORMED,
    WorkflowPresetStoreFailure.UNKNOWN_VERSION,
    WorkflowPresetStoreFailure.OVERSIZED -> ToolRetryGuidance.DO_NOT_RETRY
    WorkflowPresetStoreFailure.CAPACITY -> ToolRetryGuidance.AFTER_CORRECTION
    WorkflowPresetStoreFailure.STORAGE -> ToolRetryGuidance.SAFE_TO_RETRY
}

private fun defaultPresetFailureRetry(status: WorkflowPresetStatus): ToolRetryGuidance =
    if (status == WorkflowPresetStatus.BURP_ERROR) ToolRetryGuidance.SAFE_TO_RETRY
    else ToolRetryGuidance.AFTER_CORRECTION

private fun saveFailure(
    status: WorkflowPresetStatus,
    projectId: String?,
    error: String,
    retry: ToolRetryGuidance = defaultPresetFailureRetry(status),
) = SaveWorkflowPresetResult(
    status, retry, StandardExecutionState.NOT_STARTED, projectId,
    created = false, replaced = false, error = error,
)

private fun uncertainSave(projectId: String?, status: WorkflowPresetStatus = WorkflowPresetStatus.BURP_ERROR) =
    SaveWorkflowPresetResult(
        status, ToolRetryGuidance.DO_NOT_RETRY, StandardExecutionState.UNCERTAIN, projectId,
        created = false, replaced = false,
        error = "Preset storage may have changed; do not retry automatically; reconcile Burp state first",
    )

private fun listFailure(status: WorkflowPresetStatus, projectId: String?, error: String) =
    ListWorkflowPresetsResult(status, projectId, emptyList(), 0, 0, false, error)

private fun deleteFailure(
    status: WorkflowPresetStatus,
    projectId: String?,
    error: String,
    retry: ToolRetryGuidance = defaultPresetFailureRetry(status),
) = DeleteWorkflowPresetResult(
    status, retry, StandardExecutionState.NOT_STARTED, projectId, deleted = false, error = error,
)

private fun uncertainDelete(projectId: String?, status: WorkflowPresetStatus = WorkflowPresetStatus.BURP_ERROR) =
    DeleteWorkflowPresetResult(
        status, ToolRetryGuidance.DO_NOT_RETRY, StandardExecutionState.UNCERTAIN, projectId,
        deleted = false,
        error = "Preset storage may have changed; do not retry automatically; reconcile Burp state first",
    )

private fun executeFailure(
    status: WorkflowPresetStatus,
    projectId: String?,
    error: String,
    name: String? = null,
    type: WorkflowPresetType? = null,
) = ExecuteWorkflowPresetResult(status, projectId, name, type, error = error)

internal fun ExecuteWorkflowPresetResult.delegatedSuccess(): Boolean = when {
    status != WorkflowPresetStatus.OK -> false
    httpSearch != null -> httpSearch.status == HttpMessageSearchStatus.OK
    webSocketSearch != null -> webSocketSearch.status == WebSocketSearchStatus.OK
    httpComparison != null -> httpComparison.status == HttpComparisonStatus.OK
    else -> false
}
