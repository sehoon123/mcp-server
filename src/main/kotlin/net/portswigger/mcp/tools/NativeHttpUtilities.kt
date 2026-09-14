package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.utilities.rank.RankingAlgorithm
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
import java.util.Collections
import java.util.IdentityHashMap

private const val MAX_NATIVE_RANK_REFS = 32
private const val MAX_NATIVE_RANK_MESSAGE_BYTES = 2 * 1024 * 1024
private const val MAX_NATIVE_RANK_TOTAL_BYTES = 16 * 1024 * 1024
private const val MAX_ANNOTATION_REFS = 16

@Serializable
enum class NativeRankingAlgorithm {
    @SerialName("anomaly")
    ANOMALY,
}

@Serializable
data class RankHttpMessages(
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(
        description = "Explicit stored HTTP set to rank relative to itself; references must be distinct.",
        minItems = 1,
        maxItems = MAX_NATIVE_RANK_REFS,
    )
    val refs: List<HttpMessageReference>,
    @JsonSchemaMetadata(description = "Native Burp ranking algorithm.", defaultJson = "\"anomaly\"")
    val algorithm: NativeRankingAlgorithm? = null,
)

@Serializable
data class NativeRankedHttpMessage(
    val ref: HttpMessageReference,
    @JsonSchemaMetadata(description = "Burp's relative ordinal for this exact input set; it is not severity or a vulnerability score.")
    val rank: Int,
    @JsonSchemaMetadata(minimum = 0, maximum = 2097152)
    val requestBytes: Int,
    @JsonSchemaMetadata(minimum = 0, maximum = 2097152)
    val responseBytes: Int?,
)

@Serializable
internal data class RankHttpMessagesResult(
    @JsonSchemaMetadata(description = READ_STATUS_RETRY_DESCRIPTION)
    val status: NativeToolStatus,
    @JsonSchemaMetadata(description = TOOL_RETRY_DESCRIPTION)
    val retry: ToolRetryGuidance,
    val projectId: String?,
    val algorithm: NativeRankingAlgorithm,
    @JsonSchemaMetadata(minimum = 0, maximum = 32)
    val considered: Int,
    @JsonSchemaMetadata(maxItems = MAX_NATIVE_RANK_REFS)
    val ranked: List<NativeRankedHttpMessage>,
    @JsonSchemaMetadata(minimum = 0, maximum = 16777216)
    val totalBytes: Int,
    @JsonSchemaMetadata(maxLength = MAX_STANDARD_TOOL_ERROR_CHARS)
    val error: String? = null,
)

internal class NativeHttpRankingService(
    private val api: MontoyaApi,
    private val config: McpConfig,
) {
    private val resolver = HttpMessageResolver(api, config)

    suspend fun rank(input: RankHttpMessages): RankHttpMessagesResult {
        val algorithm = input.algorithm ?: NativeRankingAlgorithm.ANOMALY
        if (!isValidProjectId(input.projectId)) {
            return failure(algorithm, NativeToolStatus.INVALID_ARGUMENT, null, "projectId is invalid")
        }
        if (input.refs.isEmpty() || input.refs.size > MAX_NATIVE_RANK_REFS) {
            return failure(
                algorithm,
                NativeToolStatus.INVALID_ARGUMENT,
                null,
                "refs must contain between 1 and $MAX_NATIVE_RANK_REFS items",
            )
        }
        if (input.refs.hasCanonicalDuplicates()) {
            return failure(algorithm, NativeToolStatus.INVALID_ARGUMENT, null, "refs must identify distinct HTTP records")
        }

        val resolution = resolver.resolveAll(input.projectId, input.refs, MAX_NATIVE_RANK_REFS)
        if (resolution is HttpMessageBatchResolution.Failed) {
            return failure(algorithm, resolution.status.toNativeToolStatus(), resolution.projectId, resolution.error)
        }
        val found = resolution as HttpMessageBatchResolution.Found
        val candidates = ArrayList<HttpRequestResponse>(found.messages.size)
        val refsByCandidate = IdentityHashMap<HttpRequestResponse, NativeRankedHttpMessage>()
        var totalBytes = 0L
        try {
            found.messages.forEach { message ->
                currentCoroutineContext().ensureActive()
                val requestBytes = requestByteLength(message.request)
                val responseBytes = message.response?.messageByteLength()
                if (requestBytes > MAX_NATIVE_RANK_MESSAGE_BYTES ||
                    (responseBytes ?: 0) > MAX_NATIVE_RANK_MESSAGE_BYTES
                ) {
                    return failure(
                        algorithm,
                        NativeToolStatus.LIMIT_EXCEEDED,
                        found.projectId,
                        "each request and response must be at most $MAX_NATIVE_RANK_MESSAGE_BYTES bytes",
                    )
                }
                totalBytes += requestBytes.toLong() + (responseBytes ?: 0)
                if (totalBytes > MAX_NATIVE_RANK_TOTAL_BYTES) {
                    return failure(
                        algorithm,
                        NativeToolStatus.LIMIT_EXCEEDED,
                        found.projectId,
                        "the ranking set exceeds the $MAX_NATIVE_RANK_TOTAL_BYTES-byte aggregate limit",
                    )
                }
                val candidate = message.envelope ?: HttpRequestResponse.httpRequestResponse(
                    message.request,
                    message.response,
                )
                candidates += candidate
                refsByCandidate[candidate] = NativeRankedHttpMessage(
                    ref = message.ref,
                    rank = 0,
                    requestBytes = requestBytes,
                    responseBytes = responseBytes,
                )
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return failure(
                algorithm,
                NativeToolStatus.BURP_ERROR,
                found.projectId,
                "Burp could not prepare the ranking set: ${safeExceptionSummary(e)}",
            )
        }

        val nativeRanks = try {
            api.utilities().rankingUtils().rank(candidates, RankingAlgorithm.ANOMALY)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return failure(
                algorithm,
                NativeToolStatus.BURP_ERROR,
                found.projectId,
                "Burp could not rank the HTTP messages: ${safeExceptionSummary(e)}",
            )
        }
        currentCoroutineContext().ensureActive()
        val currentProject = currentProjectIdOrNull(api) ?: return failure(
            algorithm,
            NativeToolStatus.BURP_ERROR,
            found.projectId,
            "Burp could not recheck the project after ranking",
        )
        if (currentProject != found.projectId) {
            return failure(
                algorithm,
                NativeToolStatus.PROJECT_MISMATCH,
                currentProject,
                "Burp project changed while HTTP messages were ranked",
            )
        }
        if (nativeRanks.size != candidates.size) {
            return failure(
                algorithm,
                NativeToolStatus.BURP_ERROR,
                found.projectId,
                "Burp returned an incomplete ranking set",
            )
        }

        val seen = Collections.newSetFromMap(IdentityHashMap<HttpRequestResponse, Boolean>())
        val ranked = ArrayList<NativeRankedHttpMessage>(nativeRanks.size)
        for (entry in nativeRanks) {
            val requestResponse = try {
                entry.requestResponse()
            } catch (e: Exception) {
                return failure(
                    algorithm,
                    NativeToolStatus.BURP_ERROR,
                    found.projectId,
                    "Burp returned an unreadable ranking entry: ${safeExceptionSummary(e)}",
                )
            }
            val source = refsByCandidate[requestResponse]
            if (source == null || !seen.add(requestResponse)) {
                return failure(
                    algorithm,
                    NativeToolStatus.BURP_ERROR,
                    found.projectId,
                    "Burp returned a ranking entry outside the requested set",
                )
            }
            val rank = try {
                entry.rank()
            } catch (e: Exception) {
                return failure(
                    algorithm,
                    NativeToolStatus.BURP_ERROR,
                    found.projectId,
                    "Burp returned an unreadable rank: ${safeExceptionSummary(e)}",
                )
            }
            ranked += source.copy(rank = rank)
        }
        ranked.sortBy(NativeRankedHttpMessage::rank)
        currentCoroutineContext().ensureActive()
        val projectAfterMapping = currentProjectIdOrNull(api) ?: return failure(
            algorithm,
            NativeToolStatus.BURP_ERROR,
            found.projectId,
            "Burp could not perform the final project check after ranking",
        )
        if (projectAfterMapping != found.projectId) {
            return failure(
                algorithm,
                NativeToolStatus.PROJECT_MISMATCH,
                projectAfterMapping,
                "Burp project changed while ranking output was prepared",
            )
        }
        return RankHttpMessagesResult(
            status = NativeToolStatus.OK,
            retry = ToolRetryGuidance.NOT_APPLICABLE,
            projectId = found.projectId,
            algorithm = algorithm,
            considered = candidates.size,
            ranked = ranked,
            totalBytes = totalBytes.toInt(),
        )
    }

    private fun failure(
        algorithm: NativeRankingAlgorithm,
        status: NativeToolStatus,
        projectId: String?,
        error: String,
    ) = RankHttpMessagesResult(
        status = status,
        retry = status.defaultRetry(),
        projectId = projectId?.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
        algorithm = algorithm,
        considered = 0,
        ranked = emptyList(),
        totalBytes = 0,
        error = nativeToolError(error),
    )
}

@Serializable
enum class HttpAnnotationNotesMode {
    @SerialName("replace")
    REPLACE,

    @SerialName("append")
    APPEND,
}

@Serializable
enum class HttpAnnotationHighlight {
    @SerialName("none")
    NONE,

    @SerialName("red")
    RED,

    @SerialName("orange")
    ORANGE,

    @SerialName("yellow")
    YELLOW,

    @SerialName("green")
    GREEN,

    @SerialName("cyan")
    CYAN,

    @SerialName("blue")
    BLUE,

    @SerialName("pink")
    PINK,

    @SerialName("magenta")
    MAGENTA,

    @SerialName("gray")
    GRAY,
}

@Serializable
data class AnnotateHttpMessages(
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Distinct stored HTTP records to update.", minItems = 1, maxItems = MAX_ANNOTATION_REFS)
    val refs: List<HttpMessageReference>,
    @JsonSchemaMetadata(description = "New note text; an empty value clears notes in replace mode.", maxLength = MAX_NOTES_CHARS)
    val notes: String? = null,
    @JsonSchemaMetadata(description = "Replace notes or append them after one newline.", defaultJson = "\"replace\"")
    val notesMode: HttpAnnotationNotesMode? = null,
    @JsonSchemaMetadata(description = "New highlight color; none clears the highlight.")
    val highlight: HttpAnnotationHighlight? = null,
)

@Serializable
internal data class AnnotateHttpMessagesResult(
    @JsonSchemaMetadata(description = TOOL_STATUS_RETRY_DESCRIPTION)
    val status: NativeToolStatus,
    @JsonSchemaMetadata(description = TOOL_RETRY_DESCRIPTION)
    val retry: ToolRetryGuidance,
    @JsonSchemaMetadata(description = TOOL_EXECUTION_STATE_DESCRIPTION)
    val executionState: StandardExecutionState,
    val projectId: String?,
    @JsonSchemaMetadata(minimum = 0, maximum = 16)
    val requested: Int,
    @JsonSchemaMetadata(minimum = 0, maximum = 16)
    val updated: Int,
    @JsonSchemaMetadata(maxLength = MAX_STANDARD_TOOL_ERROR_CHARS)
    val error: String? = null,
)

private class AnnotationPreconditionException(
    val status: NativeToolStatus,
    val projectId: String?,
    message: String,
) : IllegalStateException(message)

private class AnnotationStaleStateException : IllegalStateException("annotation state changed")
private class AnnotationEmergencyReadOnlyException : IllegalStateException("Emergency read-only mode enabled")
private class AnnotationProjectBoundaryException : IllegalStateException("Burp project changed")

private data class PreparedAnnotation(
    val annotations: Annotations,
    val previousNotes: String,
    val previousHighlight: HighlightColor,
    val newNotes: String?,
    val newHighlight: HighlightColor?,
) {
    val changed: Boolean
        get() = (newNotes != null && newNotes != previousNotes) ||
            (newHighlight != null && newHighlight != previousHighlight)
}

internal class HttpAnnotationService(
    private val api: MontoyaApi,
    private val config: McpConfig,
    private val withMutation: suspend (String, suspend () -> Unit) -> Unit,
) {
    private val resolver = HttpMessageResolver(api, config)

    suspend fun annotate(input: AnnotateHttpMessages): AnnotateHttpMessagesResult {
        val validationError = validate(input)
        if (validationError != null) {
            return failure(NativeToolStatus.INVALID_ARGUMENT, null, input.refs.size, 0, validationError)
        }
        val resolution = resolver.resolveAll(
            input.projectId,
            input.refs,
            MAX_ANNOTATION_REFS,
            HttpSourceMetadataSelection.ANNOTATIONS,
        )
        if (resolution is HttpMessageBatchResolution.Failed) {
            return failure(
                resolution.status.toNativeToolStatus(),
                resolution.projectId,
                input.refs.size,
                0,
                resolution.error,
            )
        }
        val found = resolution as HttpMessageBatchResolution.Found
        val prepared = try {
            found.messages.map { message -> prepareAnnotation(requireNotNull(message.annotations), input) }
        } catch (e: CancellationException) {
            throw e
        } catch (e: IllegalArgumentException) {
            return failure(NativeToolStatus.INVALID_ARGUMENT, found.projectId, input.refs.size, 0, e.message.orEmpty())
        } catch (e: Exception) {
            return failure(
                NativeToolStatus.BURP_ERROR,
                found.projectId,
                input.refs.size,
                0,
                "Burp could not read current annotations: ${safeExceptionSummary(e)}",
            )
        }
        val changed = prepared.count(PreparedAnnotation::changed)
        if (changed == 0) {
            return success(found.projectId, input.refs.size, 0)
        }

        val approved = try {
            SensitiveActionSecurity.checkPermission(
                action = "update annotations on $changed HTTP message(s)",
                summary = buildString {
                    append("Update notes=")
                    append(if (input.notes == null) "unchanged" else (input.notesMode ?: HttpAnnotationNotesMode.REPLACE).name.lowercase())
                    append(", highlight=")
                    append(input.highlight?.name?.lowercase() ?: "unchanged")
                    append(" on $changed of ${input.refs.size} selected records; refs=")
                    append(input.refs.joinToString(",") { "${it.source.name.lowercase()}:${it.id}" })
                },
                reviewContent = input.notes,
                api = api,
                config = config,
                auditOperation = SensitiveActionAuditOperation.HTTP_ANNOTATION,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return failure(
                NativeToolStatus.BURP_ERROR,
                found.projectId,
                input.refs.size,
                0,
                "Burp could not request annotation approval: ${safeExceptionSummary(e)}",
            )
        }
        val projectAfterApproval = currentProjectIdOrNull(api) ?: return failure(
            NativeToolStatus.BURP_ERROR,
            found.projectId,
            input.refs.size,
            0,
            "Burp could not recheck the project after annotation approval",
        )
        if (projectAfterApproval != found.projectId) {
            return failure(
                NativeToolStatus.PROJECT_MISMATCH,
                projectAfterApproval,
                input.refs.size,
                0,
                "Burp project changed during annotation approval",
            )
        }
        if (!approved) {
            return failure(
                NativeToolStatus.ACCESS_DENIED,
                found.projectId,
                input.refs.size,
                0,
                "annotation update denied by Burp Suite",
            )
        }
        var attempted = false
        var completed = 0
        try {
            withMutation(found.projectId) {
                if (config.emergencyReadOnlyMode) throw AnnotationEmergencyReadOnlyException()
                val refreshed = when (val outcome = resolver.resolveAllAuthorized(
                    found.projectId,
                    input.refs,
                    found.authorization,
                    MAX_ANNOTATION_REFS,
                    HttpSourceMetadataSelection.ANNOTATIONS,
                )) {
                    is HttpMessageBatchResolution.Failed -> throw AnnotationPreconditionException(
                        outcome.status.toNativeToolStatus(),
                        outcome.projectId,
                        outcome.error,
                    )
                    is HttpMessageBatchResolution.Found -> outcome.messages.map { message ->
                        val annotations = message.annotations ?: throw AnnotationPreconditionException(
                            NativeToolStatus.NOT_AVAILABLE,
                            found.projectId,
                            "one selected HTTP source does not expose mutable annotations",
                        )
                        prepareAnnotation(annotations, input)
                    }
                }
                val stale = refreshed.zip(prepared).any { (current, approvedState) ->
                    current.previousNotes != approvedState.previousNotes ||
                        current.previousHighlight != approvedState.previousHighlight
                }
                if (stale) throw AnnotationStaleStateException()

                for (change in refreshed) {
                    currentCoroutineContext().ensureActive()
                    if (config.emergencyReadOnlyMode) throw AnnotationEmergencyReadOnlyException()
                    if (currentProjectIdOrNull(api) != found.projectId) throw AnnotationProjectBoundaryException()
                    if (!change.changed) continue
                    if (change.newNotes != null && change.newNotes != change.previousNotes) {
                        attempted = true
                        change.annotations.setNotes(change.newNotes)
                    }
                    if (change.newHighlight != null && change.newHighlight != change.previousHighlight) {
                        attempted = true
                        change.annotations.setHighlightColor(change.newHighlight)
                    }
                    completed++
                }
                val verified = refreshed.all { change ->
                    (change.newNotes == null || change.annotations.notes().orEmpty() == change.newNotes) &&
                        (change.newHighlight == null || change.annotations.currentHighlight() == change.newHighlight)
                }
                if (!verified) throw IllegalStateException("Burp did not retain every requested annotation value")
                if (currentProjectIdOrNull(api) != found.projectId) throw AnnotationProjectBoundaryException()
            }
        } catch (e: AnnotationPreconditionException) {
            return failure(e.status, e.projectId, input.refs.size, 0, e.message.orEmpty())
        } catch (_: AnnotationStaleStateException) {
            return failure(
                NativeToolStatus.STALE_STATE,
                found.projectId,
                input.refs.size,
                0,
                "the selected records or annotations changed while approval was pending",
            )
        } catch (e: AnnotationEmergencyReadOnlyException) {
            if (attempted) return uncertain(found.projectId, input.refs.size, completed, e)
            return failure(
                NativeToolStatus.DISABLED,
                found.projectId,
                input.refs.size,
                0,
                "Emergency read-only mode was enabled before annotations were updated",
            )
        } catch (e: AnnotationProjectBoundaryException) {
            if (attempted) return uncertain(found.projectId, input.refs.size, completed, e)
            return failure(
                NativeToolStatus.PROJECT_MISMATCH,
                currentProjectIdOrNull(api),
                input.refs.size,
                0,
                "Burp project changed before annotations were updated",
            )
        } catch (e: OrganizerProjectMismatchBeforeMutationException) {
            return failure(
                NativeToolStatus.PROJECT_MISMATCH,
                e.currentProjectId,
                input.refs.size,
                0,
                "Burp project changed before annotations were updated",
            )
        } catch (e: OrganizerMutationNotStartedException) {
            return failure(
                NativeToolStatus.BURP_ERROR,
                found.projectId,
                input.refs.size,
                0,
                "Burp could not start the annotation update: ${safeExceptionSummary(e)}",
            )
        } catch (e: CancellationException) {
            if (!currentCoroutineContext().isActive || !attempted) throw e
            return uncertain(found.projectId, input.refs.size, completed, e)
        } catch (e: Exception) {
            if (!attempted) {
                return failure(
                    NativeToolStatus.BURP_ERROR,
                    found.projectId,
                    input.refs.size,
                    0,
                    "Burp could not start the annotation update: ${safeExceptionSummary(e)}",
                )
            }
            return uncertain(found.projectId, input.refs.size, completed, e)
        }
        val projectAfterMutation = currentProjectIdOrNull(api)
        if (projectAfterMutation != found.projectId) {
            return uncertain(
                found.projectId,
                input.refs.size,
                completed,
                IllegalStateException("Burp project changed while annotations were updated"),
            )
        }
        return success(found.projectId, input.refs.size, completed)
    }

    private fun validate(input: AnnotateHttpMessages): String? = when {
        !isValidProjectId(input.projectId) -> "projectId is invalid"
        input.refs.isEmpty() || input.refs.size > MAX_ANNOTATION_REFS ->
            "refs must contain between 1 and $MAX_ANNOTATION_REFS items"
        input.refs.hasCanonicalDuplicates() -> "refs must identify distinct HTTP records"
        input.notes == null && input.highlight == null -> "notes or highlight must be provided"
        input.notes == null && input.notesMode != null -> "notesMode is supported only when notes is provided"
        input.notes != null && input.notes.length > MAX_NOTES_CHARS -> "notes exceeds the $MAX_NOTES_CHARS-character limit"
        input.notes != null && input.notes.any { it == '\u0000' } -> "notes must not contain NUL characters"
        input.notesMode == HttpAnnotationNotesMode.APPEND && input.notes.isNullOrEmpty() ->
            "append mode requires non-empty notes"
        else -> null
    }

    private fun prepareAnnotation(annotations: Annotations, input: AnnotateHttpMessages): PreparedAnnotation {
        val previousNotes = annotations.notes().orEmpty()
        val previousHighlight = annotations.currentHighlight()
        val newNotes = input.notes?.let { notes ->
            when (input.notesMode ?: HttpAnnotationNotesMode.REPLACE) {
                HttpAnnotationNotesMode.REPLACE -> notes
                HttpAnnotationNotesMode.APPEND -> if (previousNotes.isEmpty()) notes else "$previousNotes\n$notes"
            }.also { require(it.length <= MAX_NOTES_CHARS) { "resulting notes exceed the $MAX_NOTES_CHARS-character limit" } }
        }
        return PreparedAnnotation(
            annotations,
            previousNotes,
            previousHighlight,
            newNotes,
            input.highlight?.toMontoya(),
        )
    }

    private fun success(projectId: String, requested: Int, updated: Int) = AnnotateHttpMessagesResult(
        status = NativeToolStatus.OK,
        retry = ToolRetryGuidance.NOT_APPLICABLE,
        executionState = StandardExecutionState.COMPLETED,
        projectId = projectId,
        requested = requested,
        updated = updated,
    )

    private fun failure(
        status: NativeToolStatus,
        projectId: String?,
        requested: Int,
        updated: Int,
        error: String,
    ) = AnnotateHttpMessagesResult(
        status = status,
        retry = status.defaultRetry(),
        executionState = StandardExecutionState.NOT_STARTED,
        projectId = projectId?.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
        requested = requested.coerceIn(0, MAX_ANNOTATION_REFS),
        updated = updated.coerceIn(0, MAX_ANNOTATION_REFS),
        error = nativeToolError(error),
    )

    private fun uncertain(
        projectId: String,
        requested: Int,
        updated: Int,
        error: Exception,
    ) = AnnotateHttpMessagesResult(
        status = NativeToolStatus.EXECUTION_UNCERTAIN,
        retry = ToolRetryGuidance.DO_NOT_RETRY,
        executionState = StandardExecutionState.UNCERTAIN,
        projectId = projectId,
        requested = requested,
        updated = updated.coerceIn(0, MAX_ANNOTATION_REFS),
        error = uncertainExecutionError(
            "Burp may have partially updated HTTP annotations",
            error,
            preserveCancellation = false,
            maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
        ),
    )
}

private fun HttpResponse.messageByteLength(): Int {
    val headerBytes = bodyOffset()
    val bodyBytes = body().length()
    require(headerBytes >= 0 && bodyBytes >= 0) { "response reported an invalid byte length" }
    return (headerBytes.toLong() + bodyBytes).also {
        require(it <= Int.MAX_VALUE) { "response is too large" }
    }.toInt()
}

private fun Annotations.currentHighlight(): HighlightColor =
    if (hasHighlightColor()) highlightColor() else HighlightColor.NONE

private fun HttpAnnotationHighlight.toMontoya(): HighlightColor = HighlightColor.valueOf(name)

private fun List<HttpMessageReference>.hasCanonicalDuplicates(): Boolean {
    val identities = mapNotNull(::canonicalHttpReferenceIdentity)
    return identities.size == size && identities.distinct().size != identities.size
}

internal fun currentProjectIdOrNull(api: MontoyaApi): String? = try {
    api.project().id()
} catch (e: CancellationException) {
    throw e
} catch (_: Exception) {
    null
}
