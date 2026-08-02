package net.portswigger.mcp.presets

import kotlinx.coroutines.CancellationException

/**
 * SDK-independent native management boundary for project-backed workflow presets.
 *
 * The Swing UI and MCP tool adapter share one [WorkflowPresetStore] instance, so every read-modify-write remains
 * serialized without making the local UI depend on MCP request or transport types. No method executes traffic.
 */
internal interface WorkflowPresetManagement {
    fun list(): LocalWorkflowPresetListResult
    fun save(preset: WorkflowPreset, overwrite: Boolean): LocalWorkflowPresetMutationResult
    fun delete(name: String): LocalWorkflowPresetMutationResult
}

internal class LocalWorkflowPresetManager(
    private val store: WorkflowPresetStore,
    private val projectIdProvider: () -> String,
) : WorkflowPresetManagement {
    override fun list(): LocalWorkflowPresetListResult {
        val projectId = captureProject()
            ?: return LocalWorkflowPresetListResult(LocalWorkflowPresetStatus.PROJECT_UNAVAILABLE)
        val presets = try {
            store.list()
        } catch (e: WorkflowPresetStoreException) {
            return LocalWorkflowPresetListResult(e.localStatus())
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return LocalWorkflowPresetListResult(LocalWorkflowPresetStatus.STORAGE_UNAVAILABLE)
        }
        return when (val after = captureProject()) {
            null -> LocalWorkflowPresetListResult(LocalWorkflowPresetStatus.PROJECT_UNAVAILABLE)
            projectId -> LocalWorkflowPresetListResult(LocalWorkflowPresetStatus.OK, presets)
            else -> LocalWorkflowPresetListResult(LocalWorkflowPresetStatus.PROJECT_CHANGED)
        }
    }

    override fun save(preset: WorkflowPreset, overwrite: Boolean): LocalWorkflowPresetMutationResult {
        val normalized = try {
            preset.copy(
                name = preset.name.trim(),
                description = preset.description?.takeUnless(String::isEmpty),
            ).also(::validateWorkflowPreset)
        } catch (_: IllegalArgumentException) {
            return LocalWorkflowPresetMutationResult(LocalWorkflowPresetStatus.INVALID_ARGUMENT)
        }
        val projectId = captureProject()
            ?: return LocalWorkflowPresetMutationResult(LocalWorkflowPresetStatus.PROJECT_UNAVAILABLE)
        val outcome = try {
            store.save(normalized, overwrite)
        } catch (_: WorkflowPresetAlreadyExistsException) {
            return LocalWorkflowPresetMutationResult(LocalWorkflowPresetStatus.ALREADY_EXISTS)
        } catch (e: WorkflowPresetStoreException) {
            return LocalWorkflowPresetMutationResult(
                if (e.writeAttempted) LocalWorkflowPresetStatus.UNCERTAIN else e.localStatus(),
            )
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return LocalWorkflowPresetMutationResult(LocalWorkflowPresetStatus.STORAGE_UNAVAILABLE)
        }
        val projectAfterWrite = try {
            captureProject()
        } catch (_: CancellationException) {
            return LocalWorkflowPresetMutationResult(LocalWorkflowPresetStatus.UNCERTAIN)
        }
        if (projectAfterWrite != projectId) {
            return LocalWorkflowPresetMutationResult(LocalWorkflowPresetStatus.UNCERTAIN)
        }
        return LocalWorkflowPresetMutationResult(
            status = LocalWorkflowPresetStatus.OK,
            preset = normalized,
            created = outcome.first,
            replaced = outcome.second,
        )
    }

    override fun delete(name: String): LocalWorkflowPresetMutationResult {
        val normalizedName = name.trim()
        if (
            normalizedName.length !in 1..MAX_WORKFLOW_PRESET_NAME_CHARS ||
            normalizedName.any(Char::isISOControl)
        ) {
            return LocalWorkflowPresetMutationResult(LocalWorkflowPresetStatus.INVALID_ARGUMENT)
        }
        val projectId = captureProject()
            ?: return LocalWorkflowPresetMutationResult(LocalWorkflowPresetStatus.PROJECT_UNAVAILABLE)
        val deleted = try {
            store.delete(normalizedName)
        } catch (e: WorkflowPresetStoreException) {
            return LocalWorkflowPresetMutationResult(
                if (e.writeAttempted) LocalWorkflowPresetStatus.UNCERTAIN else e.localStatus(),
            )
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return LocalWorkflowPresetMutationResult(LocalWorkflowPresetStatus.STORAGE_UNAVAILABLE)
        }
        val projectAfterDelete = try {
            captureProject()
        } catch (e: CancellationException) {
            if (deleted) return LocalWorkflowPresetMutationResult(LocalWorkflowPresetStatus.UNCERTAIN)
            throw e
        }
        if (projectAfterDelete != projectId) {
            return LocalWorkflowPresetMutationResult(
                if (deleted) LocalWorkflowPresetStatus.UNCERTAIN
                else if (projectAfterDelete == null) LocalWorkflowPresetStatus.PROJECT_UNAVAILABLE
                else LocalWorkflowPresetStatus.PROJECT_CHANGED,
            )
        }
        return LocalWorkflowPresetMutationResult(
            status = LocalWorkflowPresetStatus.OK,
            deleted = deleted,
        )
    }

    private fun captureProject(): String? {
        val projectId = try {
            projectIdProvider()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return null
        }
        return projectId.takeIf(::validLocalWorkflowProjectId)
    }
}

internal enum class LocalWorkflowPresetStatus {
    OK,
    INVALID_ARGUMENT,
    PROJECT_CHANGED,
    PROJECT_UNAVAILABLE,
    ALREADY_EXISTS,
    CAPACITY_REACHED,
    STORED_DATA_INVALID,
    STORAGE_UNAVAILABLE,
    UNCERTAIN,
}

internal data class LocalWorkflowPresetListResult(
    val status: LocalWorkflowPresetStatus,
    val presets: List<WorkflowPreset> = emptyList(),
)

internal data class LocalWorkflowPresetMutationResult(
    val status: LocalWorkflowPresetStatus,
    val preset: WorkflowPreset? = null,
    val created: Boolean = false,
    val replaced: Boolean = false,
    val deleted: Boolean = false,
)

private fun validLocalWorkflowProjectId(value: String): Boolean =
    value.length in 1..256 && value.isNotBlank() && value.none(Char::isISOControl)

private fun WorkflowPresetStoreException.localStatus(): LocalWorkflowPresetStatus = when (failure) {
    WorkflowPresetStoreFailure.CAPACITY -> LocalWorkflowPresetStatus.CAPACITY_REACHED
    WorkflowPresetStoreFailure.MALFORMED,
    WorkflowPresetStoreFailure.UNKNOWN_VERSION,
    WorkflowPresetStoreFailure.OVERSIZED -> LocalWorkflowPresetStatus.STORED_DATA_INVALID
    WorkflowPresetStoreFailure.STORAGE -> LocalWorkflowPresetStatus.STORAGE_UNAVAILABLE
}
