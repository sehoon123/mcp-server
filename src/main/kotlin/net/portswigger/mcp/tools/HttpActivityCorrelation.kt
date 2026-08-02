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
internal const val MAX_RELATED_TRAFFIC_SEEDS = 4
private const val MAX_RELATED_TRAFFIC_SOURCES = 3
private const val MAX_RELATED_TRAFFIC_REFS = 16
private const val MAX_RELATED_TRAFFIC_QUERY_RESULTS = 50
private const val MAX_CORRELATION_OUTPUT_REFS = MAX_CORRELATION_REFS + MAX_RELATED_TRAFFIC_REFS
private const val DEFAULT_CORRELATION_PATH_DEPTH = 2
private const val DEFAULT_RELATED_TRAFFIC_LIMIT = 8
private val RELATED_RESOLUTION_ATTRIBUTION = HttpMessageResolutionPerformanceAttribution(
    acquisitionMetric = HistoryPerformanceMetric.RELATED_CORRELATION_MONTOYA_ACQUISITION,
    processingMetric = HistoryPerformanceMetric.RELATED_CORRELATION_EXTENSION_PROCESSING,
)

@Serializable
data class RelatedHttpTrafficDiscovery(
    @JsonSchemaMetadata(
        description = "One to four zero-based indices into baselineRefs followed by comparisonRefs. These explicit events seed bounded related-traffic discovery.",
        minItems = 1,
        maxItems = 4,
    )
    val seedEventIndices: List<Int>,
    @JsonSchemaMetadata(
        description = "Sources searched for related traffic. Defaults to the distinct sources of the selected seed events.",
        minItems = 1,
        maxItems = MAX_RELATED_TRAFFIC_SOURCES,
    )
    val sources: List<HttpMessageSource>? = null,
    @JsonSchemaMetadata(description = "Restrict discovery candidates to Burp Scope when true.")
    val inScopeOnly: Boolean? = null,
    @JsonSchemaMetadata(
        description = "Maximum related events appended after the two explicit cohorts.",
        minimum = 1,
        maximum = 16,
        defaultJson = "8",
    )
    val limit: Int? = null,
)

@Serializable
data class CorrelateHttpActivity(
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256)
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
    @JsonSchemaMetadata(
        description = "Optional bounded discovery appended after the explicit cohorts. Explicit and extra discovery sources are authorized together once; no content is returned and the explicit delta never changes.",
    )
    val relatedTraffic: RelatedHttpTrafficDiscovery? = null,
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

    @SerialName("related")
    RELATED,
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
    @JsonSchemaMetadata(description = "Fixed value describing the bounded metadata similarity basis.")
    val basis: String,
    @JsonSchemaMetadata(description = "Always false: similarity groups do not establish record identity.")
    val identityEstablished: Boolean,
)

@Serializable
enum class RelatedHttpTrafficSignal {
    @SerialName("same_service")
    SAME_SERVICE,

    @SerialName("same_path_prefix")
    SAME_PATH_PREFIX,

    @SerialName("same_method")
    SAME_METHOD,

    @SerialName("same_status_class")
    SAME_STATUS_CLASS,

    @SerialName("same_mime_type")
    SAME_MIME_TYPE,
}

@Serializable
data class RelatedHttpTrafficSeedMatch(
    @JsonSchemaMetadata(minimum = 0, maximum = 31)
    val seedEventIndex: Int,
    @JsonSchemaMetadata(
        description = "Deterministic metadata score for this seed; it is not probability, confidence, identity, causality, or vulnerability evidence.",
        minimum = 0,
        maximum = 12,
    )
    val score: Int,
    @JsonSchemaMetadata(minItems = 1, maxItems = 5)
    val signals: List<RelatedHttpTrafficSignal>,
)

@Serializable
data class RelatedHttpTrafficMatch(
    @JsonSchemaMetadata(minimum = 2, maximum = 47)
    val eventIndex: Int,
    @JsonSchemaMetadata(
        description = "Maximum deterministic seed score for this event; it is not probability, confidence, identity, causality, or vulnerability evidence.",
        minimum = 0,
        maximum = 12,
    )
    val score: Int,
    @JsonSchemaMetadata(minItems = 1, maxItems = 4)
    val seedMatches: List<RelatedHttpTrafficSeedMatch>,
)

@Serializable
data class RelatedHttpTrafficResult(
    @JsonSchemaMetadata(minItems = 1, maxItems = 4)
    val seedEventIndices: List<Int>,
    @JsonSchemaMetadata(minItems = 1, maxItems = MAX_RELATED_TRAFFIC_SOURCES)
    val sources: List<HttpMessageSource>,
    @JsonSchemaMetadata(minimum = 1, maximum = 16)
    val requestedLimit: Int,
    @JsonSchemaMetadata(minimum = 1, maximum = 4)
    val queryCount: Int,
    @JsonSchemaMetadata(minimum = 0, maximum = 200)
    val candidateSummariesExamined: Int,
    @JsonSchemaMetadata(
        description = "Search summaries qualified before bounded selected-reference revalidation.",
        minimum = 0,
        maximum = 200,
    )
    val qualifiedCandidates: Int,
    @JsonSchemaMetadata(minimum = 0, maximum = 16)
    val returned: Int,
    val truncated: Boolean,
    @JsonSchemaMetadata(description = "Fixed value describing the discovery relation basis.")
    val basis: String,
    @JsonSchemaMetadata(description = "Always false: related metadata does not establish record identity.")
    val identityEstablished: Boolean,
    @JsonSchemaMetadata(maxItems = 16)
    val matches: List<RelatedHttpTrafficMatch>,
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
    @JsonSchemaMetadata(description = "caller_supplied without discovery; caller_supplied_then_related_score when related events are appended.")
    val ordering: String,
    @JsonSchemaMetadata(description = "Always false: this analysis does not establish chronology.")
    val chronologyEstablished: Boolean,
    @JsonSchemaMetadata(description = "Always false: cohort membership does not establish a time boundary.")
    val cohortBoundaryEstablishesTime: Boolean,
    @JsonSchemaMetadata(description = "Always false: bounded cross-source similarity is not exact identity.")
    val exactCrossSourceIdentityEstablished: Boolean,
    @JsonSchemaMetadata(description = "Always false: probable duplicates are never removed.")
    val probableDuplicatesDeduplicated: Boolean,
    @JsonSchemaMetadata(description = "Number of caller-supplied baseline and comparison references.")
    val selectedReferences: Int,
    @JsonSchemaMetadata(description = "Number of appended related events.")
    val relatedReferences: Int,
    @JsonSchemaMetadata(description = "Total explicit and related timeline events.")
    val timelineEvents: Int,
    val timestampedEvents: Int,
    val similarityGroupCount: Int,
    @JsonSchemaMetadata(description = "Maximum accepted caller-supplied references across both explicit cohorts.")
    val maxReferences: Int,
    val maxReferencesPerCohort: Int,
    val maxRelatedReferences: Int,
    val maxTimelineEvents: Int,
    val pathDepth: Int,
    val maxPathDepth: Int,
    val maxIndexedPathChars: Int,
    @JsonSchemaMetadata(description = "Authoritative interpretation limits; always present.")
    val limitations: List<String>,
)

@Serializable
data class CorrelateHttpActivityResult(
    @JsonSchemaMetadata(description = READ_ONLY_TOOL_STATUS_DESCRIPTION)
    val status: HttpActivityCorrelationStatus,
    val projectId: String?,
    @JsonSchemaMetadata(maxItems = MAX_CORRELATION_OUTPUT_REFS)
    val timeline: List<HttpActivityEvent>,
    @JsonSchemaMetadata(maxItems = MAX_CORRELATION_REFS / 2)
    val similarityGroups: List<HttpActivitySimilarityGroup>,
    val delta: HttpAttackSurfaceDelta?,
    val relatedTraffic: RelatedHttpTrafficResult?,
    val evidence: HttpActivityEvidenceBounds,
    val errorRefIndex: Int? = null,
    val error: String? = null,
)

private val CORRELATION_LIMITATIONS = listOf(
    "Explicit event order is caller supplied; appended related order is metadata-score ranked; neither establishes chronology or causality.",
    "Only Proxy references can expose capture time; Site Map and Organizer timestamps are unavailable.",
    "Matching bounded metadata across explicit sources is similarity, not exact identity, and records are never deduplicated.",
    "Correlation metadata does not retain or return query strings, fragments, headers, bodies, notes, or raw message bytes.",
    "Site Map stable-ID generation may inspect bounded private identity samples for examined candidates and selected-reference revalidation.",
    "Related discovery is bounded metadata ranking, not semantic dependence, record identity, or complete project enumeration.",
    "Candidate summaries count returned search matches, not all source records inspected under each search scan bound.",
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
    private val searchService: HttpMessageSearchService? = null,
    private val performanceDiagnostics: HistoryPerformanceDiagnostics = HistoryPerformanceDiagnostics.NO_OP,
) {
    private val resolver = HttpMessageResolver(api, config, performanceDiagnostics)

    suspend fun correlate(
        input: CorrelateHttpActivity,
        reportProgress: ToolProgressReporter = NO_TOOL_PROGRESS_REPORTER,
    ): CorrelateHttpActivityResult {
        val progress = FixedStageProgress(CORRELATION_PROGRESS_MESSAGES, reportProgress)
        progress.report(CorrelationProgressStage.VALIDATING.ordinal)
        val pathDepth = input.pathDepth ?: DEFAULT_CORRELATION_PATH_DEPTH
        val invalid = validate(input, pathDepth)
        if (invalid != null) return invalid
        if (input.relatedTraffic != null && searchService == null) {
            return errorResult(
                status = HttpActivityCorrelationStatus.BURP_ERROR,
                projectId = null,
                pathDepth = pathDepth,
                error = "Related HTTP discovery is unavailable",
            )
        }
        val explicitRefs = input.baselineRefs + input.comparisonRefs
        val relatedSources = input.relatedTraffic?.let { discovery ->
            (discovery.sources ?: discovery.seedEventIndices.map { explicitRefs[it].source })
                .distinct()
                .sortedBy(HttpMessageSource::ordinal)
        }.orEmpty()

        progress.report(CorrelationProgressStage.RESOLVING.ordinal)
        val found = when (
            val resolution = resolver.resolveAll(
                projectId = input.projectId,
                refs = explicitRefs,
                maxRefs = MAX_CORRELATION_REFS,
                sourceMetadata = HttpSourceMetadataSelection.PROXY_CAPTURE_TIME,
                additionalAuthorizationSources = relatedSources,
                performanceAttribution = input.relatedTraffic?.let { RELATED_RESOLUTION_ATTRIBUTION },
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
        val explicitPrepared = try {
            measureRelatedProcessing(input.relatedTraffic != null) {
                materialize(
                    found.messages,
                    baselineSize = input.baselineRefs.size,
                    comparisonSize = input.comparisonRefs.size,
                    pathDepth = pathDepth,
                )
            }
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

        var prepared = explicitPrepared
        var relatedTrafficResult: RelatedHttpTrafficResult? = null
        input.relatedTraffic?.let { discovery ->
            val plan = when (
                val outcome = discoverRelatedCandidateRefs(
                    input = input,
                    discovery = discovery,
                    explicitPrepared = explicitPrepared,
                    pathDepth = pathDepth,
                    authorizedSources = relatedSources.toSet(),
                    authorization = found.authorization,
                )
            ) {
                is RelatedCandidateSearchOutcome.Found -> outcome.plan
                is RelatedCandidateSearchOutcome.Failed -> return errorResult(
                    status = outcome.status,
                    projectId = outcome.projectId,
                    pathDepth = pathDepth,
                    error = outcome.error,
                )
            }
            val assembled = performanceDiagnostics.measure(
                HistoryPerformanceMetric.RELATED_CORRELATION_EXTENSION_PROCESSING,
            ) {
                val combined = explicitPrepared + plan.candidates.mapIndexed { relatedIndex, candidate ->
                    candidate.prepared.copy(
                        event = candidate.prepared.event.copy(
                            index = explicitPrepared.size + relatedIndex,
                            cohort = HttpActivityCohort.RELATED,
                            cohortIndex = relatedIndex,
                        ),
                    )
                }
                combined to plan.toResult(explicitPrepared.size)
            }
            prepared = assembled.first
            relatedTrafficResult = assembled.second
        }

        currentCoroutineContext().ensureActive()
        progress.report(CorrelationProgressStage.CORRELATING.ordinal)
        val correlationOutput = measureRelatedProcessing(input.relatedTraffic != null) {
            val explicitCorrelated = correlatePrepared(explicitPrepared)
            val correlated = CorrelatedEvents(
                events = explicitCorrelated.events + prepared.drop(explicitPrepared.size)
                    .map(PreparedCorrelationEvent::event),
                groups = explicitCorrelated.groups,
            )
            correlated to buildDelta(explicitPrepared)
        }
        val correlated = correlationOutput.first
        val delta = correlationOutput.second

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
        return measureRelatedProcessing(input.relatedTraffic != null) {
            CorrelateHttpActivityResult(
                status = HttpActivityCorrelationStatus.OK,
                projectId = input.projectId,
                timeline = correlated.events,
                similarityGroups = correlated.groups,
                delta = delta,
                relatedTraffic = relatedTrafficResult,
                evidence = evidence(
                    pathDepth = pathDepth,
                    ordering = if (relatedTrafficResult == null) "caller_supplied" else "caller_supplied_then_related_score",
                    selectedReferences = explicitPrepared.size,
                    relatedReferences = correlated.events.size - explicitPrepared.size,
                    timelineEvents = correlated.events.size,
                    timestampedEvents = correlated.events.count {
                        it.timestampKind == HttpActivityTimestampKind.PROXY_CAPTURED
                    },
                    similarityGroupCount = correlated.groups.size,
                ),
            )
        }
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
                null,
                pathDepth.coerceIn(1, MAX_ATTACK_SURFACE_PATH_DEPTH),
                error = "cohorts or pathDepth are out of range",
            )
        }
        input.relatedTraffic?.let { discovery ->
            val explicitSize = input.baselineRefs.size + input.comparisonRefs.size
            val limit = discovery.limit ?: DEFAULT_RELATED_TRAFFIC_LIMIT
            if (
                discovery.seedEventIndices.size !in 1..MAX_RELATED_TRAFFIC_SEEDS ||
                discovery.seedEventIndices.distinct().size != discovery.seedEventIndices.size ||
                discovery.seedEventIndices.any { it !in 0 until explicitSize } ||
                discovery.sources?.let {
            it.isEmpty() || it.size > MAX_RELATED_TRAFFIC_SOURCES || it.distinct().size != it.size
        } == true ||
                limit !in 1..MAX_RELATED_TRAFFIC_REFS
            ) {
                return errorResult(
                    HttpActivityCorrelationStatus.INVALID_ARGUMENT,
                    null,
                    pathDepth,
                    error = "relatedTraffic bounds, seed indices, or sources are invalid",
                )
            }
        }
        val identities = ArrayList<CanonicalHttpReferenceIdentity>(input.baselineRefs.size + input.comparisonRefs.size)
        for ((index, ref) in (input.baselineRefs + input.comparisonRefs).withIndex()) {
            val identity = canonicalHttpReferenceIdentity(ref) ?: return errorResult(
                HttpActivityCorrelationStatus.INVALID_ID,
                null,
                pathDepth,
                errorRefIndex = index,
                error = "HTTP reference ID is invalid for its source",
            )
            val duplicateIndex = identities.indexOf(identity)
            if (duplicateIndex >= 0) {
                return errorResult(
                    HttpActivityCorrelationStatus.INVALID_ARGUMENT,
                    null,
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
        comparisonSize: Int,
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
            val cohort = when {
                index < baselineSize -> HttpActivityCohort.BASELINE
                index < baselineSize + comparisonSize -> HttpActivityCohort.COMPARISON
                else -> HttpActivityCohort.RELATED
            }
            val cohortIndex = when (cohort) {
                HttpActivityCohort.BASELINE -> index
                HttpActivityCohort.COMPARISON -> index - baselineSize
                HttpActivityCohort.RELATED -> index - baselineSize - comparisonSize
            }
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

    private suspend fun discoverRelatedCandidateRefs(
        input: CorrelateHttpActivity,
        discovery: RelatedHttpTrafficDiscovery,
        explicitPrepared: List<PreparedCorrelationEvent>,
        pathDepth: Int,
        authorizedSources: Set<HttpMessageSource>,
        authorization: HttpMessageResolutionAuthorization,
    ): RelatedCandidateSearchOutcome {
        val search = searchService ?: return RelatedCandidateSearchOutcome.Failed(
            HttpActivityCorrelationStatus.BURP_ERROR,
            input.projectId,
            "Related HTTP discovery is unavailable",
        )
        val setup = performanceDiagnostics.measure(
            HistoryPerformanceMetric.RELATED_CORRELATION_EXTENSION_PROCESSING,
        ) {
            val seedEvents = discovery.seedEventIndices.map { explicitPrepared[it] }
            val sources = authorizedSources.sortedBy(HttpMessageSource::ordinal)
            val excluded = (input.baselineRefs + input.comparisonRefs)
                .mapNotNull(::canonicalHttpReferenceIdentity)
                .toSet()
            val queryKeys = seedEvents.map { seed ->
                val firstPrefix = normalizedHttpPathPrefix(seed.boundedPath, 1)
                    .takeIf { it != "/" && !it.contains('{') }
                RelatedSearchKey(seed.event.host, firstPrefix)
            }.distinct()
            RelatedDiscoverySetup(seedEvents, sources, excluded, queryKeys)
        }
        val seedEvents = setup.seedEvents
        val sources = setup.sources
        val excluded = setup.excluded
        val queryKeys = setup.queryKeys
        val requestedLimit = discovery.limit ?: DEFAULT_RELATED_TRAFFIC_LIMIT
        val candidates = LinkedHashMap<CanonicalHttpReferenceIdentity, RankedRelatedCandidate>()
        var candidateSummariesExamined = 0
        var encounterIndex = 0
        var searchTruncated = false

        val searchResults = search.searchReferenceMetadataBatch(
            inputs = queryKeys.map { query ->
                SearchHttpMessages(
                    sources = sources,
                    host = query.host,
                    pathContains = query.pathContains,
                    inScopeOnly = discovery.inScopeOnly,
                    newestFirst = true,
                    limit = MAX_RELATED_TRAFFIC_QUERY_RESULTS,
                )
            },
            authorization = authorization,
            authorizationVerifier = resolver,
        )
        for (result in searchResults) {
            currentCoroutineContext().ensureActive()
            if (result.status != HttpMessageSearchStatus.OK) {
                return RelatedCandidateSearchOutcome.Failed(
                    result.status.toCorrelationStatus(),
                    result.projectId,
                    if (result.status == HttpMessageSearchStatus.ACCESS_DENIED) {
                        "Related HTTP source access was denied"
                    } else {
                        "Burp could not search bounded related HTTP metadata"
                    },
                )
            }
            if (result.projectId != input.projectId) {
                return RelatedCandidateSearchOutcome.Failed(
                    HttpActivityCorrelationStatus.PROJECT_MISMATCH,
                    result.projectId,
                    "Burp project changed during related HTTP discovery",
                )
            }
            performanceDiagnostics.measure(HistoryPerformanceMetric.RELATED_CORRELATION_EXTENSION_PROCESSING) {
                searchTruncated = searchTruncated || result.hasMore || result.scanLimitReached
                candidateSummariesExamined += result.items.size
                for (item in result.items) {
                    val currentEncounter = encounterIndex++
                    val identity = canonicalHttpReferenceIdentity(item.ref) ?: continue
                    if (identity in excluded) continue
                    val prepared = item.toPreparedRelated(pathDepth) ?: continue
                    val seedMatches = relatedSeedMatches(prepared.toRelatedMetadata(), seedEvents)
                    if (seedMatches.isEmpty()) continue
                    val ranked = RankedRelatedCandidate(
                        prepared = prepared,
                        score = seedMatches.maxOf(RelatedSeedRelation::score),
                        seedMatches = seedMatches,
                        encounterIndex = currentEncounter,
                    )
                    val existing = candidates[identity]
                    if (existing == null || ranked.score > existing.score) candidates[identity] = ranked
                }
            }
        }

        val selection = performanceDiagnostics.measure(
            HistoryPerformanceMetric.RELATED_CORRELATION_EXTENSION_PROCESSING,
        ) {
            val qualified = candidates.size
            qualified to candidates.values.sortedWith(RELATED_CANDIDATE_ORDER).take(requestedLimit)
        }
        val qualified = selection.first
        val preliminarySelection = selection.second
        val selected = if (preliminarySelection.isEmpty()) {
            emptyList()
        } else {
            val resolved = when (
                val resolution = resolver.resolveAllAuthorized(
                    projectId = input.projectId,
                    refs = preliminarySelection.map { it.prepared.event.ref },
                    authorization = authorization,
                    maxRefs = MAX_RELATED_TRAFFIC_REFS,
                    sourceMetadata = HttpSourceMetadataSelection.PROXY_CAPTURE_TIME,
                    performanceAttribution = RELATED_RESOLUTION_ATTRIBUTION,
                )
            ) {
                is HttpMessageBatchResolution.Found -> resolution.messages
                is HttpMessageBatchResolution.Failed -> return RelatedCandidateSearchOutcome.Failed(
                    status = resolution.status.toCorrelationStatus(),
                    projectId = resolution.projectId,
                    error = when (resolution.status) {
                        HttpMessageResolutionStatus.NOT_FOUND,
                        HttpMessageResolutionStatus.REQUEST_UNAVAILABLE,
                        -> "A related HTTP candidate was no longer available"

                        else -> "Burp could not resolve one or more related HTTP references"
                    },
                )
            }
            val materialized = try {
                performanceDiagnostics.measure(HistoryPerformanceMetric.RELATED_CORRELATION_EXTENSION_PROCESSING) {
                    materialize(
                        messages = resolved,
                        baselineSize = 0,
                        comparisonSize = 0,
                        pathDepth = pathDepth,
                    )
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                return RelatedCandidateSearchOutcome.Failed(
                    status = HttpActivityCorrelationStatus.BURP_ERROR,
                    projectId = input.projectId,
                    error = "Burp could not read bounded related HTTP metadata",
                )
            }
            if (materialized.size != preliminarySelection.size) {
                return RelatedCandidateSearchOutcome.Failed(
                    status = HttpActivityCorrelationStatus.BURP_ERROR,
                    projectId = input.projectId,
                    error = "Burp could not resolve one or more related HTTP references",
                )
            }
            val reranked = performanceDiagnostics.measure(
                HistoryPerformanceMetric.RELATED_CORRELATION_EXTENSION_PROCESSING,
            ) {
                var invalidReference = false
                val candidates = materialized.mapIndexedNotNull { index, prepared ->
                    val preliminary = preliminarySelection[index]
                    if (canonicalHttpReferenceIdentity(prepared.event.ref) !=
                        canonicalHttpReferenceIdentity(preliminary.prepared.event.ref)
                    ) {
                        invalidReference = true
                        null
                    } else {
                        val seedMatches = relatedSeedMatches(prepared.toRelatedMetadata(), seedEvents)
                        if (seedMatches.isEmpty()) {
                            null
                        } else {
                            RankedRelatedCandidate(
                                prepared = prepared,
                                score = seedMatches.maxOf(RelatedSeedRelation::score),
                                seedMatches = seedMatches,
                                encounterIndex = preliminary.encounterIndex,
                            )
                        }
                    }
                }.sortedWith(RELATED_CANDIDATE_ORDER)
                RerankedRelatedCandidates(candidates, invalidReference)
            }
            if (reranked.invalidReference) {
                return RelatedCandidateSearchOutcome.Failed(
                    status = HttpActivityCorrelationStatus.BURP_ERROR,
                    projectId = input.projectId,
                    error = "Burp could not resolve one or more related HTTP references",
                )
            }
            reranked.candidates
        }
        return performanceDiagnostics.measure(
            HistoryPerformanceMetric.RELATED_CORRELATION_EXTENSION_PROCESSING,
        ) {
            RelatedCandidateSearchOutcome.Found(
                RelatedCandidatePlan(
                    candidates = selected,
                    seedEventIndices = discovery.seedEventIndices.toList(),
                    sources = sources,
                    requestedLimit = requestedLimit,
                    queryCount = queryKeys.size,
                    candidateSummariesExamined = candidateSummariesExamined,
                    qualifiedCandidates = qualified,
                    truncated = searchTruncated || qualified > requestedLimit,
                ),
            )
        }
    }

    private suspend fun <T> measureRelatedProcessing(
        enabled: Boolean,
        block: suspend () -> T,
    ): T = if (enabled) {
        performanceDiagnostics.measure(HistoryPerformanceMetric.RELATED_CORRELATION_EXTENSION_PROCESSING, block)
    } else {
        block()
    }

    private fun relatedSeedMatches(
        candidate: RelatedMetadata,
        seeds: List<PreparedCorrelationEvent>,
    ): List<RelatedSeedRelation> = seeds.mapNotNull { seed ->
        val seedMetadata = seed.toRelatedMetadata()
        if (
            candidate.scheme != seedMetadata.scheme ||
            candidate.host != seedMetadata.host ||
            candidate.port != seedMetadata.port
        ) {
            return@mapNotNull null
        }
        val samePath = candidate.pathPrefix != "/" && candidate.pathPrefix == seedMetadata.pathPrefix
        val sameMethod = candidate.method == seedMetadata.method
        val sameStatus = candidate.statusClass != null && candidate.statusClass == seedMetadata.statusClass
        val sameMime = candidate.mimeType != null && candidate.mimeType == seedMetadata.mimeType
        if (!samePath && listOf(sameMethod, sameStatus, sameMime).count { it } < 2) return@mapNotNull null

        val signals = buildList {
            add(RelatedHttpTrafficSignal.SAME_SERVICE)
            if (samePath) add(RelatedHttpTrafficSignal.SAME_PATH_PREFIX)
            if (sameMethod) add(RelatedHttpTrafficSignal.SAME_METHOD)
            if (sameStatus) add(RelatedHttpTrafficSignal.SAME_STATUS_CLASS)
            if (sameMime) add(RelatedHttpTrafficSignal.SAME_MIME_TYPE)
        }
        RelatedSeedRelation(
            seedEventIndex = seed.event.index,
            score = 4 + (if (samePath) 4 else 0) + (if (sameMethod) 2 else 0) +
                (if (sameStatus) 1 else 0) + (if (sameMime) 1 else 0),
            signals = signals,
        )
    }.sortedBy(RelatedSeedRelation::seedEventIndex)

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
                basis = "same_bounded_http_metadata",
                identityEstablished = false,
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
    fun toRelatedMetadata() = RelatedMetadata(
        scheme = event.scheme,
        host = event.host,
        port = event.port,
        method = event.method,
        pathPrefix = event.pathPrefix,
        statusClass = event.statusClass,
        mimeType = event.mimeType,
    )
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

private sealed interface RelatedCandidateSearchOutcome {
    data class Found(val plan: RelatedCandidatePlan) : RelatedCandidateSearchOutcome
    data class Failed(
        val status: HttpActivityCorrelationStatus,
        val projectId: String?,
        val error: String,
    ) : RelatedCandidateSearchOutcome
}

private data class RelatedDiscoverySetup(
    val seedEvents: List<PreparedCorrelationEvent>,
    val sources: List<HttpMessageSource>,
    val excluded: Set<CanonicalHttpReferenceIdentity>,
    val queryKeys: List<RelatedSearchKey>,
)

private data class RerankedRelatedCandidates(
    val candidates: List<RankedRelatedCandidate>,
    val invalidReference: Boolean,
)

private data class RelatedCandidatePlan(
    val candidates: List<RankedRelatedCandidate>,
    val seedEventIndices: List<Int>,
    val sources: List<HttpMessageSource>,
    val requestedLimit: Int,
    val queryCount: Int,
    val candidateSummariesExamined: Int,
    val qualifiedCandidates: Int,
    val truncated: Boolean,
) {
    fun toResult(explicitSize: Int) = RelatedHttpTrafficResult(
        seedEventIndices = seedEventIndices,
        sources = sources,
        requestedLimit = requestedLimit,
        queryCount = queryCount,
        candidateSummariesExamined = candidateSummariesExamined,
        qualifiedCandidates = qualifiedCandidates,
        returned = candidates.size,
        truncated = truncated,
        basis = "same_service_and_bounded_metadata",
        identityEstablished = false,
        matches = candidates.mapIndexed { relatedIndex, selected ->
            RelatedHttpTrafficMatch(
                eventIndex = explicitSize + relatedIndex,
                score = selected.score,
                seedMatches = selected.seedMatches.map { relation ->
                    RelatedHttpTrafficSeedMatch(
                        seedEventIndex = relation.seedEventIndex,
                        score = relation.score,
                        signals = relation.signals,
                    )
                },
            )
        },
    )
}

private data class RelatedSeedRelation(
    val seedEventIndex: Int,
    val score: Int,
    val signals: List<RelatedHttpTrafficSignal>,
)

private data class RelatedMetadata(
    val scheme: String,
    val host: String,
    val port: Int,
    val method: String,
    val pathPrefix: String,
    val statusClass: String?,
    val mimeType: String?,
)

private data class RelatedSearchKey(val host: String, val pathContains: String?)
private data class RankedRelatedCandidate(
    val prepared: PreparedCorrelationEvent,
    val score: Int,
    val seedMatches: List<RelatedSeedRelation>,
    val encounterIndex: Int,
)

private val RELATED_CANDIDATE_ORDER = compareByDescending<RankedRelatedCandidate>(RankedRelatedCandidate::score)
    .thenBy { it.prepared.event.ref.source.ordinal }
    .thenBy(RankedRelatedCandidate::encounterIndex)

private fun HttpMessageSearchItem.toPreparedRelated(pathDepth: Int): PreparedCorrelationEvent? {
    val normalizedHost = host.trim().trimEnd('.').lowercase()
    if (normalizedHost.isEmpty() || normalizedHost.length > MAX_HTTP_SEARCH_HOST_CHARS ||
        normalizedHost.any(Char::isISOControl) || port !in 1..65_535
    ) {
        return null
    }
    val normalizedMethod = method.trim().uppercase()
    if (normalizedMethod.isEmpty() || normalizedMethod.length > 32 || normalizedMethod.any(Char::isISOControl)) {
        return null
    }
    val path = normalizeHttpPath(url)
    val pathWasTruncated = urlTruncated || path.truncated
    val normalizedMimeType = mimeType?.trim()?.lowercase()
        ?.takeIf { it.isNotEmpty() && it.length <= 64 && it.none(Char::isISOControl) }
    val observedAt = time?.toLongOrNull()?.takeIf { ref.source == HttpMessageSource.PROXY }
    return PreparedCorrelationEvent(
        event = HttpActivityEvent(
            index = 0,
            cohort = HttpActivityCohort.RELATED,
            cohortIndex = 0,
            ref = ref,
            observedAtEpochMillis = observedAt,
            timestampKind = if (observedAt == null) {
                HttpActivityTimestampKind.UNAVAILABLE
            } else {
                HttpActivityTimestampKind.PROXY_CAPTURED
            },
            scheme = if (secure) "https" else "http",
            host = normalizedHost,
            port = port,
            method = normalizedMethod,
            pathPrefix = normalizedHttpPathPrefix(path.value, pathDepth),
            pathInputTruncated = pathWasTruncated,
            statusCode = statusCode,
            statusClass = statusCode?.let(::httpStatusClass),
            mimeType = normalizedMimeType,
            hasResponse = hasResponse,
            inScope = inScope,
            similarityGroupId = null,
        ),
        boundedPath = path.value,
        extension = httpFileExtension(path.value, pathWasTruncated),
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

private fun HttpMessageSearchStatus.toCorrelationStatus(): HttpActivityCorrelationStatus = when (this) {
    HttpMessageSearchStatus.OK -> HttpActivityCorrelationStatus.OK
    HttpMessageSearchStatus.ACCESS_DENIED -> HttpActivityCorrelationStatus.ACCESS_DENIED
    HttpMessageSearchStatus.PROJECT_MISMATCH -> HttpActivityCorrelationStatus.PROJECT_MISMATCH
    HttpMessageSearchStatus.INVALID_ARGUMENT,
    HttpMessageSearchStatus.INVALID_CURSOR,
    HttpMessageSearchStatus.STALE_CURSOR,
    HttpMessageSearchStatus.BURP_ERROR -> HttpActivityCorrelationStatus.BURP_ERROR
}

private fun evidence(
    pathDepth: Int,
    ordering: String = "caller_supplied",
    selectedReferences: Int = 0,
    relatedReferences: Int = 0,
    timelineEvents: Int = 0,
    timestampedEvents: Int = 0,
    similarityGroupCount: Int = 0,
) = HttpActivityEvidenceBounds(
    ordering = ordering,
    chronologyEstablished = false,
    cohortBoundaryEstablishesTime = false,
    exactCrossSourceIdentityEstablished = false,
    probableDuplicatesDeduplicated = false,
    selectedReferences = selectedReferences,
    relatedReferences = relatedReferences,
    timelineEvents = timelineEvents,
    timestampedEvents = timestampedEvents,
    similarityGroupCount = similarityGroupCount,
    maxReferences = MAX_CORRELATION_REFS,
    maxReferencesPerCohort = MAX_CORRELATION_REFS_PER_COHORT,
    maxRelatedReferences = MAX_RELATED_TRAFFIC_REFS,
    maxTimelineEvents = MAX_CORRELATION_OUTPUT_REFS,
    pathDepth = pathDepth,
    maxPathDepth = MAX_ATTACK_SURFACE_PATH_DEPTH,
    maxIndexedPathChars = MAX_INDEXED_HTTP_PATH_CHARS,
    limitations = CORRELATION_LIMITATIONS,
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
    relatedTraffic = null,
    evidence = evidence(pathDepth),
    errorRefIndex = errorRefIndex,
    error = error.take(512),
)
