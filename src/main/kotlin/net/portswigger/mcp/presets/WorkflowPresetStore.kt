package net.portswigger.mcp.presets

import burp.api.montoya.persistence.PersistedObject
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import net.portswigger.mcp.tools.CompareHttpMessages
import net.portswigger.mcp.tools.SearchHttpMessages
import net.portswigger.mcp.tools.SearchWebsocketMessages
import net.portswigger.mcp.tools.validateHttpComparisonSettings
import net.portswigger.mcp.tools.validateHttpMetadataSearchSettings
import net.portswigger.mcp.tools.validateWebSocketMetadataSearchSettings
import java.nio.charset.StandardCharsets
import java.util.Locale

internal const val WORKFLOW_PRESET_STORAGE_KEY = "workflowPresetsV1"
internal fun workflowPresetNameKey(name: String): String = name.lowercase(Locale.ROOT)

internal enum class WorkflowPresetStoreFailure {
    MALFORMED,
    UNKNOWN_VERSION,
    OVERSIZED,
    CAPACITY,
    STORAGE,
}

internal class WorkflowPresetStoreException(
    val failure: WorkflowPresetStoreFailure,
    val writeAttempted: Boolean = false,
    cause: Throwable? = null,
) : Exception(failure.name, cause)

/** Synchronized, decode-on-access repository over Burp's project-backed extensionData object. */
internal class WorkflowPresetStore(private val storage: PersistedObject) {
    private val json = Json {
        encodeDefaults = true
        explicitNulls = false
        ignoreUnknownKeys = false
    }

    @Synchronized
    fun list(): List<WorkflowPreset> = readEnvelope().presets.sortedWith(PRESET_ORDER)

    @Synchronized
    fun save(preset: WorkflowPreset, overwrite: Boolean): Pair<Boolean, Boolean> {
        validateWorkflowPreset(preset)
        val envelope = readEnvelope()
        val requestedKey = workflowPresetNameKey(preset.name)
        val index = envelope.presets.indexOfFirst { workflowPresetNameKey(it.name) == requestedKey }
        if (index >= 0 && !overwrite) throw WorkflowPresetAlreadyExistsException()
        if (index < 0 && envelope.presets.size >= MAX_WORKFLOW_PRESETS) {
            throw WorkflowPresetStoreException(WorkflowPresetStoreFailure.CAPACITY)
        }
        val next = envelope.presets.toMutableList().apply {
            if (index >= 0) set(index, preset) else add(preset)
        }.sortedWith(PRESET_ORDER)
        writeEnvelope(WorkflowPresetEnvelope(presets = next))
        return (index < 0) to (index >= 0)
    }

    @Synchronized
    fun delete(name: String): Boolean {
        val envelope = readEnvelope()
        val requestedKey = workflowPresetNameKey(name)
        val next = envelope.presets.filterNot { workflowPresetNameKey(it.name) == requestedKey }
        if (next.size == envelope.presets.size) return false
        writeEnvelope(WorkflowPresetEnvelope(presets = next.sortedWith(PRESET_ORDER)))
        return true
    }

    private fun readEnvelope(): WorkflowPresetEnvelope {
        val raw = try {
            storage.getString(WORKFLOW_PRESET_STORAGE_KEY)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw WorkflowPresetStoreException(WorkflowPresetStoreFailure.STORAGE, cause = e)
        } ?: return WorkflowPresetEnvelope()
        if (raw.length > MAX_WORKFLOW_PRESET_ENVELOPE_BYTES) {
            throw WorkflowPresetStoreException(WorkflowPresetStoreFailure.OVERSIZED)
        }
        val bytes = raw.toByteArray(StandardCharsets.UTF_8)
        if (bytes.size > MAX_WORKFLOW_PRESET_ENVELOPE_BYTES) {
            throw WorkflowPresetStoreException(WorkflowPresetStoreFailure.OVERSIZED)
        }
        val envelope = try {
            val root = json.parseToJsonElement(raw).jsonObject
            require(root.keys == setOf("version", "presets"))
            json.decodeFromString<WorkflowPresetEnvelope>(raw)
        } catch (e: SerializationException) {
            throw WorkflowPresetStoreException(WorkflowPresetStoreFailure.MALFORMED, cause = e)
        } catch (e: IllegalArgumentException) {
            throw WorkflowPresetStoreException(WorkflowPresetStoreFailure.MALFORMED, cause = e)
        }
        if (envelope.version != 1) {
            throw WorkflowPresetStoreException(WorkflowPresetStoreFailure.UNKNOWN_VERSION)
        }
        if (envelope.presets.size > MAX_WORKFLOW_PRESETS) {
            throw WorkflowPresetStoreException(WorkflowPresetStoreFailure.OVERSIZED)
        }
        try {
            envelope.presets.forEach(::validateWorkflowPreset)
            require(envelope.presets.map { workflowPresetNameKey(it.name) }.distinct().size == envelope.presets.size)
        } catch (e: IllegalArgumentException) {
            throw WorkflowPresetStoreException(WorkflowPresetStoreFailure.MALFORMED, cause = e)
        }
        return envelope
    }

    private fun writeEnvelope(envelope: WorkflowPresetEnvelope) {
        val raw = json.encodeToString(envelope)
        if (raw.length > MAX_WORKFLOW_PRESET_ENVELOPE_BYTES ||
            raw.toByteArray(StandardCharsets.UTF_8).size > MAX_WORKFLOW_PRESET_ENVELOPE_BYTES
        ) {
            throw WorkflowPresetStoreException(WorkflowPresetStoreFailure.CAPACITY)
        }
        try {
            storage.setString(WORKFLOW_PRESET_STORAGE_KEY, raw)
            if (storage.getString(WORKFLOW_PRESET_STORAGE_KEY) != raw) {
                throw WorkflowPresetStoreException(
                    WorkflowPresetStoreFailure.STORAGE,
                    writeAttempted = true,
                )
            }
        } catch (e: WorkflowPresetStoreException) {
            throw e
        } catch (e: Exception) {
            // Invocation has crossed the persistence side-effect boundary, including cancellation-like failures.
            throw WorkflowPresetStoreException(WorkflowPresetStoreFailure.STORAGE, writeAttempted = true, cause = e)
        }
    }

    private companion object {
        val PRESET_ORDER = compareBy<WorkflowPreset>({ workflowPresetNameKey(it.name) }, { it.name })
    }
}

internal fun validateWorkflowPreset(preset: WorkflowPreset) {
    require(preset.name == preset.name.trim())
    require(preset.name.length in 1..MAX_WORKFLOW_PRESET_NAME_CHARS)
    require(preset.name.none(Char::isISOControl))
    require(
        preset.description == null ||
            (preset.description.length <= MAX_WORKFLOW_PRESET_DESCRIPTION_CHARS &&
                preset.description.none(Char::isISOControl)),
    )
    preset.definition.kind()
    preset.definition.httpSearch?.let {
        validateHttpMetadataSearchSettings(SearchHttpMessages(
            sources = it.sources, host = it.host, pathContains = it.pathContains, methods = it.methods,
            statusCodes = it.statusCodes, mimeTypes = it.mimeTypes, inScopeOnly = it.inScopeOnly,
            hasResponse = it.hasResponse, newestFirst = it.newestFirst, limit = it.defaultLimit,
        ))
    }
    preset.definition.webSocketSearch?.let {
        validateWebSocketMetadataSearchSettings(SearchWebsocketMessages(
            projectId = "validation", limit = it.defaultLimit, direction = it.direction,
            listenerPort = it.listenerPort, newestFirst = it.newestFirst,
        ))
    }
    preset.definition.httpComparison?.let {
        validateHttpComparisonSettings(CompareHttpMessages(
            projectId = "validation", refs = emptyList(), part = it.part,
            limitBytesPerMessage = it.limitBytesPerMessage, excerptEncoding = it.excerptEncoding,
            ignoreHeaders = it.ignoreHeaders, includeResponseVariations = it.includeResponseVariations,
        ))
    }
}

internal class WorkflowPresetAlreadyExistsException : Exception()
