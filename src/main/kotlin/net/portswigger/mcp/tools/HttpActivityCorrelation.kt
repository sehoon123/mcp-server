package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.JsonSchemaMetadata

private const val MAX_CORRELATION_REFS_PER_COHORT = 16
private const val MAX_CORRELATION_REFS = 32
private const val DEFAULT_CORRELATION_PATH_DEPTH = 2

@Serializable
data class CorrelateHttpActivity(
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(
        description = "One to 16 stored HTTP references in the baseline cohort; references must be globally distinct across both cohorts.",
        minItems = 1,
        maxItems = 16,
    )
    val baselineRefs: List<HttpMessageReference>,
    @JsonSchemaMetadata(
        description = "One to 16 stored HTTP references in the comparison cohort; references must be globally distinct across both cohorts.",
        minItems = 1,
        maxItems = 16,
    )
    val comparisonRefs: List<HttpMessageReference>,
    @JsonSchemaMetadata(
        description = "Number of bounded path segments retained in delta prefixes.",
        minimum = 1,
        maximum = 4,
        defaultJson = "2",
    )
    val pathDepth: Int? = null,
)

@Serializable
enum class HttpActivityCorrelationStatus {
    @SerialName("ok")
    OK,

    @SerialName("access_denied")
    ACCESS_DENIED,

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
}

@Serializable
enum class HttpActivityCohort {
    @SerialName("baseline")
    BASELINE,

    @SerialName("comparison")
    COMPARISON,
}

@Serializable
enum class HttpActivityTimestampKind {
    @SerialName("proxy_captured")
    PROXY_CAPTURED,

    @SerialName("unavailable")
    UNAVAILABLE,
}

@Serializable
data class HttpActivityEvent(
    val index: Int,
    val cohort: HttpActivityCohort,
    val cohortIndex: Int,
    val ref: HttpMessageReference,
    val observedAtEpochMillis: Long?,
    val timestampKind: HttpActivityTimestampKind,
    val scheme: String,
    val host: String,
    val port: Int,
    val method: String,
    val pathPrefix: String,
    val pathInputTruncated: Boolean,
    val statusCode: Int?,
    val statusClass: String?,
    val mimeType: String?,
    val hasResponse: Boolean,
    val inScope: Boolean,
    val similarityGroupId: String?,
)

@Serializable
data class HttpActivitySimilarityGroup(
    val id: String,
    val eventIndices: List<Int>,
    val sources: List<HttpMessageSource>,
    val basis: String = "same_bounded_http_metadata",
    val identityEstablished: Boolean = false,
)

@Serializable
data class ValueCountDelta(
    val value: String,
    val baselineCount: Int,
    val comparisonCount: Int,
    val delta: Int,
)

@Serializable
data class ServiceCountDelta(
    val scheme: String,
    val host: String,
    val port: Int,
    val baselineCount: Int,
    val comparisonCount: Int,
    val delta: Int,
)

@Serializable
data class PathCountDelta(
    val scheme: String,
    val host: String,
    val port: Int,
    val pathPrefix: String,
    val baselineCount: Int,
    val comparisonCount: Int,
    val delta: Int,
)

@Serializable
data class HttpAttackSurfaceDelta(
    val baselineRecords: Int,
    val comparisonRecords: Int,
    val services: List<ServiceCountDelta>,
    val pathPrefixes: List<PathCountDelta>,
    val methods: List<ValueCountDelta>,
    val statusClasses: List<ValueCountDelta>,
    val mimeTypes: List<ValueCountDelta>,
    val extensions: List<ValueCountDelta>,
    val unchangedServiceKeys: Int,
    val unchangedPathPrefixKeys: Int,
)

@Serializable
data class HttpActivityEvidenceBounds(
    val ordering: String = "caller_supplied",
    val chronologyEstablished: Boolean = false,
    val cohortBoundaryEstablishesTime: Boolean = false,
    val exactCrossSourceIdentityEstablished: Boolean = false,
    val probableDuplicatesDeduplicated: Boolean = false,
    val selectedReferences: Int,
    val timestampedEvents: Int,
    val similarityGroupCount: Int,
    val maxReferences: Int = MAX_CORRELATION_REFS,
    val maxReferencesPerCohort: Int = MAX_CORRELATION_REFS_PER_COHORT,
    val pathDepth: Int,
    val maxPathDepth: Int = MAX_ATTACK_SURFACE_PATH_DEPTH,
    val maxIndexedPathChars: Int = MAX_INDEXED_HTTP_PATH_CHARS,
    val limitations: List<String> = CORRELATION_LIMITATIONS,
)

@Serializable
data class CorrelateHttpActivityResult(
    val status: HttpActivityCorrelationStatus,
    val projectId: String?,
    val timeline: List<HttpActivityEvent>,
    val similarityGroups: List<HttpActivitySimilarityGroup>,
    val delta: HttpAttackSurfaceDelta?,
    val evidence: HttpActivityEvidenceBounds,
    val errorRefIndex: Int? = null,
    val error: String? = null,
)

private val CORRELATION_LIMITATIONS = listOf(
    "Timeline order is caller supplied and does not establish chronology or causality.",
    "Only Proxy references can expose capture time; Site Map and Organizer timestamps are unavailable.",
    "Matching bounded metadata across sources is similarity, not exact identity, and records are never deduplicated.",
    "Correlation metadata does not retain or return query strings, fragments, headers, bodies, notes, or raw message bytes.",
    "Site Map stable-ID resolution may inspect bounded private identity samples before metadata materialization.",
)

private enum class CorrelationProgressStage(val message: String) {
    VALIDATING("Validating HTTP activity cohorts"),
    RESOLVING("Resolving and authorizing HTTP references"),
    MATERIALIZING("Materializing bounded HTTP metadata"),
    CORRELATING("Computing similarity and attack-surface delta"),
    VERIFYING("Verifying the current Burp project"),
    COMPLETED("HTTP activity correlation completed"),
}

private val CORRELATION_PROGRESS_MESSAGES = CorrelationProgressStage.entries.map(CorrelationProgressStage::message)

internal class HttpActivityCorrelationService(
    private val api: MontoyaApi,
    private val config: McpConfig,
) {
    private val resolver = HttpMessageResolver(api, config)

    suspend fun correlate(
        input: CorrelateHttpActivity,
        reportProgress: ToolProgressReporter = NO_TOOL_PROGRESS_REPORTER,
    ): CorrelateHttpActivityResult {
        val progress = FixedStageProgress(CORRELATION_PROGRESS_MESSAGES, reportProgress)
        progress.report(CorrelationProgressStage.VALIDATING.ordinal)
        val pathDepth = input.pathDepth ?: DEFAULT_CORRELATION_PATH_DEPTH
        val invalid = validate(input, pathDepth)
        if (invalid != null) return invalid
        val refs = input.baselineRefs + input.comparisonRefs

        progress.report(CorrelationProgressStage.RESOLVING.ordinal)
        val found = when (
            val resolution = resolver.resolveAll(
                projectId = input.projectId,
                refs = refs,
                maxRefs = MAX_CORRELATION_REFS,
                sourceMetadata = HttpSourceMetadataSelection.PROXY_CAPTURE_TIME,
            )
        ) {
            is HttpMessageBatchResolution.Found -> resolution
            is HttpMessageBatchResolution.Failed -> return errorResult(
                status = resolution.status.toCorrelationStatus(),
                projectId = resolution.projectId,
                pathDepth = pathDepth,
                errorRefIndex = resolution.refIndex,
                error = if (resolution.status == HttpMessageResolutionStatus.BURP_ERROR) {
                    "Burp could not resolve one or more HTTP references"
                } else {
                    resolution.error
                },
            )
        }

        progress.report(CorrelationProgressStage.MATERIALIZING.ordinal)
        val prepared = try {
            materialize(found.messages, input.baselineRefs.size, pathDepth)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return errorResult(
                status = HttpActivityCorrelationStatus.BURP_ERROR,
                projectId = input.projectId,
                pathDepth = pathDepth,
                error = "Burp could not read bounded HTTP activity metadata",
            )
        }

        currentCoroutineContext().ensureActive()
        progress.report(CorrelationProgressStage.CORRELATING.ordinal)
        val correlated = correlatePrepared(prepared)
        val delta = buildDelta(prepared)

        currentCoroutineContext().ensureActive()
        progress.report(CorrelationProgressStage.VERIFYING.ordinal)
        val currentProjectId = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return errorResult(
                status = HttpActivityCorrelationStatus.BURP_ERROR,
                projectId = input.projectId,
                pathDepth = pathDepth,
                error = "Burp could not verify the current project after correlation",
            )
        }
        if (currentProjectId != input.projectId) {
            return errorResult(
                status = HttpActivityCorrelationStatus.PROJECT_MISMATCH,
                projectId = currentProjectId,
                pathDepth = pathDepth,
                error = "Burp project changed before the HTTP activity correlation was returned",
            )
        }

        progress.report(CorrelationProgressStage.COMPLETED.ordinal)
        currentCoroutineContext().ensureActive()
        val projectAfterCompletionProgress = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return errorResult(
                status = HttpActivityCorrelationStatus.BURP_ERROR,
                projectId = input.projectId,
                pathDepth = pathDepth,
                error = "Burp could not verify the current project after completion progress",
            )
        }
        if (projectAfterCompletionProgress != input.projectId) {
            return errorResult(
                status = HttpActivityCorrelationStatus.PROJECT_MISMATCH,
                projectId = projectAfterCompletionProgress,
                pathDepth = pathDepth,
                error = "Burp project changed before the HTTP activity correlation was returned",
            )
        }
        return CorrelateHttpActivityResult(
            status = HttpActivityCorrelationStatus.OK,
            projectId = input.projectId,
            timeline = correlated.events,
            similarityGroups = correlated.groups,
            delta = delta,
            evidence = evidence(
                pathDepth = pathDepth,
                selectedReferences = correlated.events.size,
                timestampedEvents = correlated.events.count { it.timestampKind == HttpActivityTimestampKind.PROXY_CAPTURED },
                similarityGroupCount = correlated.groups.size,
            ),
        )
    }

    private fun validate(input: CorrelateHttpActivity, pathDepth: Int): CorrelateHttpActivityResult? {
        if (
            input.projectId.isEmpty() || input.projectId.length > MAX_HTTP_REFERENCE_PROJECT_ID_CHARS ||
            input.projectId.any(Char::isISOControl)
        ) {
            return errorResult(
                HttpActivityCorrelationStatus.INVALID_ARGUMENT,
                null,
                pathDepth.coerceIn(1, MAX_ATTACK_SURFACE_PATH_DEPTH),
                error = "projectId is empty, too long, or contains control characters",
            )
        }
        if (
            input.baselineRefs.size !in 1..MAX_CORRELATION_REFS_PER_COHORT ||
            input.comparisonRefs.size !in 1..MAX_CORRELATION_REFS_PER_COHORT ||
            input.baselineRefs.size + input.comparisonRefs.size > MAX_CORRELATION_REFS ||
            pathDepth !in 1..MAX_ATTACK_SURFACE_PATH_DEPTH
        ) {
            return errorResult(
                HttpActivityCorrelationStatus.INVALID_ARGUMENT,
                input.projectId,
                pathDepth.coerceIn(1, MAX_ATTACK_SURFACE_PATH_DEPTH),
                error = "cohorts or pathDepth are out of range",
            )
        }
        val identities = ArrayList<CanonicalHttpReferenceIdentity>(input.baselineRefs.size + input.comparisonRefs.size)
        for ((index, ref) in (input.baselineRefs + input.comparisonRefs).withIndex()) {
            val identity = canonicalHttpReferenceIdentity(ref) ?: return errorResult(
                HttpActivityCorrelationStatus.INVALID_ID,
                input.projectId,
                pathDepth,
                errorRefIndex = index,
                error = "HTTP reference ID is invalid for its source",
            )
            val duplicateIndex = identities.indexOf(identity)
            if (duplicateIndex >= 0) {
                return errorResult(
                    HttpActivityCorrelationStatus.INVALID_ARGUMENT,
                    input.projectId,
                    pathDepth,
                    errorRefIndex = index,
                    error = "baselineRefs and comparisonRefs must be globally distinct",
                )
            }
            identities += identity
        }
        return null
    }

    private suspend fun materialize(
        messages: List<ResolvedHttpMessage>,
        baselineSize: Int,
        pathDepth: Int,
    ): List<PreparedCorrelationEvent> {
        val prepared = ArrayList<PreparedCorrelationEvent>(messages.size)
        val coroutineContext = currentCoroutineContext()
        messages.forEachIndexed { index, message ->
            coroutineContext.ensureActive()
            val request = message.request
            val response = message.response
            val service = request.httpService()
            val host = service.host().trim().trimEnd('.').lowercase()
            require(host.isNotEmpty() && host.length <= MAX_HTTP_SEARCH_HOST_CHARS && host.none(Char::isISOControl))
            val port = service.port()
            require(port in 1..65_535)
            val method = request.method().trim().uppercase()
            require(method.isNotEmpty() && method.length <= 32 && method.none(Char::isISOControl))
            val path = normalizeHttpPath(request.path())
            val statusCode = response?.statusCode()?.toInt()
            val mimeType = normalizeHttpMimeType(response?.mimeType())
            val observedAt = message.sourceMetadata?.proxyCaptureTimeEpochMillis
                ?.takeIf { message.ref.source == HttpMessageSource.PROXY }
            val cohort = if (index < baselineSize) HttpActivityCohort.BASELINE else HttpActivityCohort.COMPARISON
            val cohortIndex = if (cohort == HttpActivityCohort.BASELINE) index else index - baselineSize
            prepared += PreparedCorrelationEvent(
                event = HttpActivityEvent(
                    index = index,
                    cohort = cohort,
                    cohortIndex = cohortIndex,
                    ref = message.ref,
                    observedAtEpochMillis = observedAt,
                    timestampKind = if (observedAt == null) {
                        HttpActivityTimestampKind.UNAVAILABLE
                    } else {
                        HttpActivityTimestampKind.PROXY_CAPTURED
                    },
                    scheme = if (service.secure()) "https" else "http",
                    host = host,
                    port = port,
                    method = method,
                    pathPrefix = normalizedHttpPathPrefix(path.value, pathDepth),
                    pathInputTruncated = path.truncated,
                    statusCode = statusCode,
                    statusClass = statusCode?.let(::httpStatusClass),
                    mimeType = mimeType,
                    hasResponse = response != null,
                    inScope = request.isInScope(),
                    similarityGroupId = null,
                ),
                boundedPath = path.value,
                extension = httpFileExtension(path.value, path.truncated),
            )
        }
        return prepared
    }

    private fun correlatePrepared(prepared: List<PreparedCorrelationEvent>): CorrelatedEvents {
        val candidates = prepared.indices.groupBy { index -> prepared[index].similarityKey() }
            .values
            .filter { indices -> indices.map { prepared[it].event.ref.source }.distinct().size >= 2 }
            .sortedBy { indices -> indices.minOf { prepared[it].event.index } }
        val groupIds = HashMap<Int, String>()
        val groups = candidates.mapIndexed { groupIndex, indices ->
            val id = "similarity-${groupIndex + 1}"
            val eventIndices = indices.map { prepared[it].event.index }.sorted()
            eventIndices.forEach { eventIndex -> groupIds[eventIndex] = id }
            HttpActivitySimilarityGroup(
                id = id,
                eventIndices = eventIndices,
                sources = indices.map { prepared[it].event.ref.source }.distinct().sortedBy { it.ordinal },
            )
        }
        return CorrelatedEvents(
            events = prepared.map { item -> item.event.copy(similarityGroupId = groupIds[item.event.index]) },
            groups = groups,
        )
    }

    private fun buildDelta(prepared: List<PreparedCorrelationEvent>): HttpAttackSurfaceDelta {
        val baseline = prepared.filter { it.event.cohort == HttpActivityCohort.BASELINE }
        val comparison = prepared.filter { it.event.cohort == HttpActivityCohort.COMPARISON }
        val baselineServices = baseline.countBy { it.serviceKey() }
        val comparisonServices = comparison.countBy { it.serviceKey() }
        val baselinePaths = baseline.countBy { it.pathKey() }
        val comparisonPaths = comparison.countBy { it.pathKey() }
        return HttpAttackSurfaceDelta(
            baselineRecords = baseline.size,
            comparisonRecords = comparison.size,
            services = changedDeltas(baselineServices, comparisonServices)
                .sortedWith(compareBy({ it.key.host }, { it.key.port }, { it.key.scheme }))
                .map { (key, counts) ->
                    ServiceCountDelta(key.scheme, key.host, key.port, counts.first, counts.second, counts.second - counts.first)
                },
            pathPrefixes = changedDeltas(baselinePaths, comparisonPaths)
                .sortedWith(compareBy({ it.key.service.host }, { it.key.service.port }, { it.key.service.scheme }, { it.key.path }))
                .map { (key, counts) ->
                    PathCountDelta(
                        key.service.scheme,
                        key.service.host,
                        key.service.port,
                        key.path,
                        counts.first,
                        counts.second,
                        counts.second - counts.first,
                    )
                },
            methods = valueDeltas(baseline, comparison) { it.event.method },
            statusClasses = valueDeltas(baseline, comparison) { it.event.statusClass },
            mimeTypes = valueDeltas(baseline, comparison) { it.event.mimeType },
            extensions = valueDeltas(baseline, comparison) { it.extension },
            unchangedServiceKeys = unchangedNonzeroKeys(baselineServices, comparisonServices),
            unchangedPathPrefixKeys = unchangedNonzeroKeys(baselinePaths, comparisonPaths),
        )
    }

    private fun valueDeltas(
        baseline: List<PreparedCorrelationEvent>,
        comparison: List<PreparedCorrelationEvent>,
        value: (PreparedCorrelationEvent) -> String?,
    ): List<ValueCountDelta> {
        val baselineCounts = baseline.mapNotNull(value).groupingBy { it }.eachCount()
        val comparisonCounts = comparison.mapNotNull(value).groupingBy { it }.eachCount()
        return changedDeltas(baselineCounts, comparisonCounts)
            .sortedBy { it.key }
            .map { (key, counts) -> ValueCountDelta(key, counts.first, counts.second, counts.second - counts.first) }
    }
}

private data class PreparedCorrelationEvent(
    val event: HttpActivityEvent,
    val boundedPath: String,
    val extension: String?,
) {
    fun serviceKey() = CorrelationServiceKey(event.scheme, event.host, event.port)
    fun pathKey() = CorrelationPathKey(serviceKey(), event.pathPrefix)
    fun similarityKey() = CorrelationSimilarityKey(
        event.scheme,
        event.host,
        event.port,
        event.method,
        boundedPath,
        event.pathInputTruncated,
        event.statusCode,
        event.mimeType,
        event.hasResponse,
    )
}

private data class CorrelationServiceKey(val scheme: String, val host: String, val port: Int)
private data class CorrelationPathKey(val service: CorrelationServiceKey, val path: String)
private data class CorrelationSimilarityKey(
    val scheme: String,
    val host: String,
    val port: Int,
    val method: String,
    val path: String,
    val pathTruncated: Boolean,
    val statusCode: Int?,
    val mimeType: String?,
    val hasResponse: Boolean,
)
private data class CorrelatedEvents(
    val events: List<HttpActivityEvent>,
    val groups: List<HttpActivitySimilarityGroup>,
)
private data class DeltaEntry<K>(val key: K, val counts: Pair<Int, Int>)

private fun <K> List<PreparedCorrelationEvent>.countBy(key: (PreparedCorrelationEvent) -> K): Map<K, Int> =
    groupingBy(key).eachCount()

private fun <K> changedDeltas(baseline: Map<K, Int>, comparison: Map<K, Int>): List<DeltaEntry<K>> =
    (baseline.keys + comparison.keys).mapNotNull { key ->
        val counts = (baseline[key] ?: 0) to (comparison[key] ?: 0)
        if (counts.first == counts.second) null else DeltaEntry(key, counts)
    }

private fun <K> unchangedNonzeroKeys(baseline: Map<K, Int>, comparison: Map<K, Int>): Int =
    (baseline.keys + comparison.keys).count { key ->
        val baselineCount = baseline[key] ?: 0
        baselineCount > 0 && baselineCount == (comparison[key] ?: 0)
    }

private fun HttpMessageResolutionStatus.toCorrelationStatus(): HttpActivityCorrelationStatus = when (this) {
    HttpMessageResolutionStatus.ACCESS_DENIED -> HttpActivityCorrelationStatus.ACCESS_DENIED
    HttpMessageResolutionStatus.INVALID_ARGUMENT -> HttpActivityCorrelationStatus.INVALID_ARGUMENT
    HttpMessageResolutionStatus.INVALID_ID -> HttpActivityCorrelationStatus.INVALID_ID
    HttpMessageResolutionStatus.PROJECT_MISMATCH -> HttpActivityCorrelationStatus.PROJECT_MISMATCH
    HttpMessageResolutionStatus.NOT_FOUND -> HttpActivityCorrelationStatus.NOT_FOUND
    HttpMessageResolutionStatus.REQUEST_UNAVAILABLE -> HttpActivityCorrelationStatus.REQUEST_UNAVAILABLE
    HttpMessageResolutionStatus.BURP_ERROR -> HttpActivityCorrelationStatus.BURP_ERROR
}

private fun evidence(
    pathDepth: Int,
    selectedReferences: Int = 0,
    timestampedEvents: Int = 0,
    similarityGroupCount: Int = 0,
) = HttpActivityEvidenceBounds(
    selectedReferences = selectedReferences,
    timestampedEvents = timestampedEvents,
    similarityGroupCount = similarityGroupCount,
    pathDepth = pathDepth,
)

private fun errorResult(
    status: HttpActivityCorrelationStatus,
    projectId: String?,
    pathDepth: Int,
    errorRefIndex: Int? = null,
    error: String,
) = CorrelateHttpActivityResult(
    status = status,
    projectId = projectId,
    timeline = emptyList(),
    similarityGroups = emptyList(),
    delta = null,
    evidence = evidence(pathDepth),
    errorRefIndex = errorRefIndex,
    error = error.take(512),
)
