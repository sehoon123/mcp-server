package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse as MontoyaHttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.safeExceptionSummary

internal const val MAX_HTTP_REFERENCE_PROJECT_ID_CHARS = 256
internal const val MAX_HTTP_REFERENCE_ID_CHARS = 128
internal const val MAX_HTTP_REFERENCES_PER_BATCH = 32

internal enum class HttpMessageResolutionStatus {
    ACCESS_DENIED,
    INVALID_ARGUMENT,
    INVALID_ID,
    PROJECT_MISMATCH,
    NOT_FOUND,
    REQUEST_UNAVAILABLE,
    BURP_ERROR,
}

internal enum class HttpSourceMetadataSelection {
    NONE,
    FULL,
    PROXY_CAPTURE_TIME,
}

internal data class ResolvedHttpMessage(
    val ref: HttpMessageReference,
    val request: HttpRequest,
    val response: HttpResponse?,
    val envelope: MontoyaHttpRequestResponse?,
    val sourceMetadata: ResolvedHttpSourceMetadata? = null,
)

internal data class ResolvedHttpSourceMetadata(
    val time: String? = null,
    val proxyCaptureTimeEpochMillis: Long? = null,
    val listenerPort: Int? = null,
    val edited: Boolean? = null,
    val inScope: Boolean? = null,
    val notes: String? = null,
    val notesTruncated: Boolean = false,
)

internal data class HttpMessageResolutionPerformanceAttribution(
    val acquisitionMetric: HistoryPerformanceMetric,
    val processingMetric: HistoryPerformanceMetric,
)

internal class HttpMessageResolutionAuthorization internal constructor(
    val projectId: String,
    private val sources: Set<HttpMessageSource>,
    private val issuer: Any,
) {
    internal fun wasIssuedBy(expectedIssuer: Any): Boolean = issuer === expectedIssuer

    internal fun permits(projectId: String, requestedSources: Collection<HttpMessageSource>): Boolean =
        this.projectId == projectId && sources.containsAll(requestedSources)
}

internal sealed interface HttpMessageBatchResolution {
    data class Found(
        val projectId: String,
        val messages: List<ResolvedHttpMessage>,
        val authorization: HttpMessageResolutionAuthorization,
    ) : HttpMessageBatchResolution

    data class Failed(
        val status: HttpMessageResolutionStatus,
        val projectId: String?,
        val ref: HttpMessageReference?,
        val refIndex: Int?,
        val error: String,
    ) : HttpMessageBatchResolution
}

/**
 * Resolves project-scoped HTTP references through Montoya's filtered lookup APIs.
 *
 * Batch resolution checks project and data-access policy once, including an optional additional source set for a
 * compound read, performs at most one bounded filtered Proxy/Organizer lookup per represented reference source, and
 * snapshots Site Map at most once. This avoids repeated approval prompts and per-reference source acquisitions while
 * preserving caller-order resolution and Site Map positional identity checks. A successful compound read carries an
 * instance-bound authorization handle that can revalidate a later bounded reference set without a second prompt.
 */
internal class HttpMessageResolver(
    private val api: MontoyaApi,
    private val config: McpConfig,
    private val performanceDiagnostics: HistoryPerformanceDiagnostics = HistoryPerformanceDiagnostics.NO_OP,
) {
    private val authorizationIssuer = Any()

    internal fun authorizes(
        authorization: HttpMessageResolutionAuthorization,
        projectId: String,
        requestedSources: Collection<HttpMessageSource>,
    ): Boolean = authorization.wasIssuedBy(authorizationIssuer) &&
        authorization.permits(projectId, requestedSources)

    suspend fun resolve(
        projectId: String,
        ref: HttpMessageReference,
        sourceMetadata: HttpSourceMetadataSelection = HttpSourceMetadataSelection.NONE,
    ): HttpMessageBatchResolution = resolveAll(projectId, listOf(ref), 1, sourceMetadata)

    suspend fun resolveAll(
        projectId: String,
        refs: List<HttpMessageReference>,
        maxRefs: Int = MAX_HTTP_REFERENCES_PER_BATCH,
        sourceMetadata: HttpSourceMetadataSelection = HttpSourceMetadataSelection.NONE,
        additionalAuthorizationSources: List<HttpMessageSource> = emptyList(),
        performanceAttribution: HttpMessageResolutionPerformanceAttribution? = null,
    ): HttpMessageBatchResolution = resolveAllInternal(
        projectId = projectId,
        refs = refs,
        maxRefs = maxRefs,
        sourceMetadata = sourceMetadata,
        additionalAuthorizationSources = additionalAuthorizationSources,
        authorization = null,
        performanceAttribution = performanceAttribution,
    )

    suspend fun resolveAllAuthorized(
        projectId: String,
        refs: List<HttpMessageReference>,
        authorization: HttpMessageResolutionAuthorization,
        maxRefs: Int = MAX_HTTP_REFERENCES_PER_BATCH,
        sourceMetadata: HttpSourceMetadataSelection = HttpSourceMetadataSelection.NONE,
        performanceAttribution: HttpMessageResolutionPerformanceAttribution? = null,
    ): HttpMessageBatchResolution = resolveAllInternal(
        projectId = projectId,
        refs = refs,
        maxRefs = maxRefs,
        sourceMetadata = sourceMetadata,
        additionalAuthorizationSources = emptyList(),
        authorization = authorization,
        performanceAttribution = performanceAttribution,
    )

    private suspend fun resolveAllInternal(
        projectId: String,
        refs: List<HttpMessageReference>,
        maxRefs: Int,
        sourceMetadata: HttpSourceMetadataSelection,
        additionalAuthorizationSources: List<HttpMessageSource>,
        authorization: HttpMessageResolutionAuthorization?,
        performanceAttribution: HttpMessageResolutionPerformanceAttribution?,
    ): HttpMessageBatchResolution {
        if (!isValidProjectId(projectId)) {
            return failure(
                HttpMessageResolutionStatus.INVALID_ARGUMENT,
                null,
                refs.firstOrNull(),
                refs.indices.firstOrNull(),
                "projectId is empty, too long, or contains control characters",
            )
        }
        if (refs.isEmpty() || refs.size > maxRefs.coerceAtMost(MAX_HTTP_REFERENCES_PER_BATCH)) {
            return failure(
                HttpMessageResolutionStatus.INVALID_ARGUMENT,
                null,
                refs.firstOrNull(),
                refs.indices.firstOrNull(),
                "refs must contain between 1 and ${maxRefs.coerceAtMost(MAX_HTTP_REFERENCES_PER_BATCH)} items",
            )
        }
        if (
            additionalAuthorizationSources.size > HttpMessageSource.entries.size ||
            additionalAuthorizationSources.distinct().size != additionalAuthorizationSources.size
        ) {
            return failure(
                HttpMessageResolutionStatus.INVALID_ARGUMENT,
                null,
                refs.firstOrNull(),
                refs.indices.firstOrNull(),
                "additionalAuthorizationSources must be distinct supported HTTP sources",
            )
        }

        val validated = ArrayList<ValidatedHttpReference>(refs.size)
        refs.forEachIndexed { index, ref ->
            val result = validateReference(ref)
            if (result == null) {
                return failure(
                    HttpMessageResolutionStatus.INVALID_ID,
                    null,
                    ref,
                    index,
                    invalidIdMessage(ref.source),
                )
            }
            validated += result
        }

        val currentProjectId = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return failure(
                HttpMessageResolutionStatus.BURP_ERROR,
                null,
                refs.first(),
                0,
                "Burp could not read the current project: ${safeResolverException(e)}",
            )
        }
        if (projectId != currentProjectId) {
            return failure(
                HttpMessageResolutionStatus.PROJECT_MISMATCH,
                currentProjectId,
                refs.first(),
                0,
                "reference belongs to a different Burp project",
            )
        }

        val authorizationSources = (
            validated.asSequence().map { it.ref.source }.toList() + additionalAuthorizationSources
        ).distinct().sortedBy(HttpMessageSource::ordinal)
        val grantedAuthorization = if (authorization != null) {
            if (!authorizes(authorization, currentProjectId, authorizationSources)) {
                return failure(
                    HttpMessageResolutionStatus.BURP_ERROR,
                    currentProjectId,
                    refs.first(),
                    0,
                    "HTTP source preauthorization was invalid",
                )
            }
            authorization
        } else {
            for (source in authorizationSources) {
                val sourceRefIndex = validated.indexOfFirst { it.ref.source == source }
                val sourceRef = validated.getOrNull(sourceRefIndex)?.ref
                val allowed = try {
                    DataAccessSecurity.checkDataAccessPermission(source.dataAccessType(), config)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    return failure(
                        HttpMessageResolutionStatus.BURP_ERROR,
                        currentProjectId,
                        sourceRef,
                        sourceRefIndex.takeIf { it >= 0 },
                        "Burp could not check ${source.displayNameForResolution()} access: ${safeResolverException(e)}",
                    )
                }
                runCatching {
                    api.logging().logToOutput(
                        "MCP ${source.displayNameForResolution()} access ${if (allowed) "granted" else "denied"}"
                    )
                }
                val projectAfterSourceApproval = try {
                    api.project().id()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    return failure(
                        HttpMessageResolutionStatus.BURP_ERROR,
                        currentProjectId,
                        sourceRef,
                        sourceRefIndex.takeIf { it >= 0 },
                        "Burp could not recheck the project after HTTP data approval: ${safeResolverException(e)}",
                    )
                }
                if (projectAfterSourceApproval != currentProjectId) {
                    return failure(
                        HttpMessageResolutionStatus.PROJECT_MISMATCH,
                        projectAfterSourceApproval,
                        sourceRef,
                        sourceRefIndex.takeIf { it >= 0 },
                        "Burp project changed during HTTP data approval",
                    )
                }
                if (!allowed) {
                    return failure(
                        HttpMessageResolutionStatus.ACCESS_DENIED,
                        currentProjectId,
                        sourceRef,
                        sourceRefIndex.takeIf { it >= 0 },
                        "${source.displayNameForResolution()} access denied by Burp Suite",
                    )
                }
            }
            HttpMessageResolutionAuthorization(
                projectId = currentProjectId,
                sources = authorizationSources.toSet(),
                issuer = authorizationIssuer,
            )
        }

        val resolution = try {
            resolveValidated(
                currentProjectId,
                validated,
                sourceMetadata,
                grantedAuthorization,
                performanceAttribution,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return failure(
                HttpMessageResolutionStatus.BURP_ERROR,
                currentProjectId,
                refs.first(),
                0,
                "Burp could not resolve the HTTP message: ${safeResolverException(e)}",
            )
        }
        val projectAfterResolution = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return failure(
                HttpMessageResolutionStatus.BURP_ERROR,
                currentProjectId,
                refs.first(),
                0,
                "Burp could not recheck the project after resolving HTTP data: ${safeResolverException(e)}",
            )
        }
        if (projectAfterResolution != currentProjectId) {
            return failure(
                HttpMessageResolutionStatus.PROJECT_MISMATCH,
                projectAfterResolution,
                refs.first(),
                0,
                "Burp project changed while HTTP data was resolved",
            )
        }
        return resolution
    }

    private suspend fun resolveValidated(
        projectId: String,
        refs: List<ValidatedHttpReference>,
        sourceMetadataSelection: HttpSourceMetadataSelection,
        authorization: HttpMessageResolutionAuthorization,
        performanceAttribution: HttpMessageResolutionPerformanceAttribution?,
    ): HttpMessageBatchResolution {
        var proxyItems: Map<Int, ProxyHttpRequestResponse>? = null
        var organizerItems: Map<Int, OrganizerItem>? = null
        var siteMapItems: List<MontoyaHttpRequestResponse>? = null
        val resolved = ArrayList<ResolvedHttpMessage>(refs.size)

        refs.forEachIndexed { index, validated ->
            currentCoroutineContext().ensureActive()
            val outcome = when (validated.ref.source) {
                HttpMessageSource.PROXY -> {
                    val items = proxyItems ?: acquireProxyItems(refs, performanceAttribution).also { proxyItems = it }
                    val item = items[validated.numericId]
                        ?: return notFound(projectId, validated.ref, index)
                    measureProcessing(performanceAttribution) processing@{
                        val request = item.request()
                            ?: return@processing ResolvedItemOutcome.RequestUnavailable
                        val sourceMetadata = when (sourceMetadataSelection) {
                            HttpSourceMetadataSelection.NONE -> null
                            HttpSourceMetadataSelection.FULL -> {
                                val notes = item.annotations().notes().boundedResolvedNotes()
                                ResolvedHttpSourceMetadata(
                                    time = item.time().toString(),
                                    listenerPort = item.listenerPort(),
                                    edited = item.edited(),
                                    notes = notes.first,
                                    notesTruncated = notes.second,
                                )
                            }
                            HttpSourceMetadataSelection.PROXY_CAPTURE_TIME -> ResolvedHttpSourceMetadata(
                                proxyCaptureTimeEpochMillis = item.time().toInstant().toEpochMilli(),
                            )
                        }
                        ResolvedItemOutcome.Found(
                            ResolvedHttpMessage(validated.ref, request, item.response(), null, sourceMetadata),
                        )
                    }
                }

                HttpMessageSource.ORGANIZER -> {
                    val items = organizerItems ?: acquireOrganizerItems(refs, performanceAttribution).also { organizerItems = it }
                    val item = items[validated.numericId]
                        ?: return notFound(projectId, validated.ref, index)
                    measureProcessing(performanceAttribution) processing@{
                        val request = item.request()
                            ?: return@processing ResolvedItemOutcome.RequestUnavailable
                        val sourceMetadata = if (sourceMetadataSelection == HttpSourceMetadataSelection.FULL) {
                            val notes = item.annotations().notes().boundedResolvedNotes()
                            ResolvedHttpSourceMetadata(notes = notes.first, notesTruncated = notes.second)
                        } else null
                        ResolvedItemOutcome.Found(
                            ResolvedHttpMessage(validated.ref, request, item.response(), item, sourceMetadata),
                        )
                    }
                }

                HttpMessageSource.SITE_MAP -> {
                    val parsed = requireNotNull(validated.siteMapId)
                    val items = siteMapItems ?: acquireSiteMapItems(performanceAttribution).also { siteMapItems = it }
                    val item = items.getOrNull(parsed.index)
                        ?: return notFound(projectId, validated.ref, index)
                    measureProcessing(performanceAttribution) processing@{
                        if (stableSiteMapId(projectId, parsed.index, item) != validated.ref.id) {
                            return@processing ResolvedItemOutcome.NotFound
                        }
                        val request = item.request()
                            ?: return@processing ResolvedItemOutcome.RequestUnavailable
                        val sourceMetadata = if (sourceMetadataSelection == HttpSourceMetadataSelection.FULL) {
                            val notes = item.annotations().notes().boundedResolvedNotes()
                            ResolvedHttpSourceMetadata(
                                inScope = request.isInScope(),
                                notes = notes.first,
                                notesTruncated = notes.second,
                            )
                        } else null
                        ResolvedItemOutcome.Found(
                            ResolvedHttpMessage(validated.ref, request, item.response(), item, sourceMetadata),
                        )
                    }
                }
            }
            when (outcome) {
                is ResolvedItemOutcome.Found -> resolved += outcome.message
                ResolvedItemOutcome.NotFound -> return notFound(projectId, validated.ref, index)
                ResolvedItemOutcome.RequestUnavailable -> return requestUnavailable(projectId, validated.ref, index)
            }
        }

        return HttpMessageBatchResolution.Found(projectId, resolved, authorization)
    }

    private suspend fun acquireProxyItems(
        refs: List<ValidatedHttpReference>,
        performanceAttribution: HttpMessageResolutionPerformanceAttribution?,
    ): Map<Int, ProxyHttpRequestResponse> {
        val requestedIds = refs.asSequence()
            .filter { it.ref.source == HttpMessageSource.PROXY }
            .map { requireNotNull(it.numericId) }
            .toSet()
        currentCoroutineContext().ensureActive()
        val items = measureAcquisition(performanceAttribution) { api.proxy().history { it.id() in requestedIds } }
        currentCoroutineContext().ensureActive()
        return measureProcessing(performanceAttribution) {
            indexFilteredItems(items, requestedIds, ProxyHttpRequestResponse::id)
        }
    }

    private suspend fun acquireOrganizerItems(
        refs: List<ValidatedHttpReference>,
        performanceAttribution: HttpMessageResolutionPerformanceAttribution?,
    ): Map<Int, OrganizerItem> {
        val requestedIds = refs.asSequence()
            .filter { it.ref.source == HttpMessageSource.ORGANIZER }
            .map { requireNotNull(it.numericId) }
            .toSet()
        currentCoroutineContext().ensureActive()
        val items = measureAcquisition(performanceAttribution) { api.organizer().items { it.id() in requestedIds } }
        currentCoroutineContext().ensureActive()
        return measureProcessing(performanceAttribution) {
            indexFilteredItems(items, requestedIds, OrganizerItem::id)
        }
    }

    private suspend fun acquireSiteMapItems(
        performanceAttribution: HttpMessageResolutionPerformanceAttribution?,
    ): List<MontoyaHttpRequestResponse> {
        currentCoroutineContext().ensureActive()
        val items = measureAcquisition(performanceAttribution) { api.siteMap().requestResponses() }
        currentCoroutineContext().ensureActive()
        return items
    }

    private suspend fun <T> measureAcquisition(
        attribution: HttpMessageResolutionPerformanceAttribution?,
        block: suspend () -> T,
    ): T = if (attribution == null) block() else {
        performanceDiagnostics.measure(attribution.acquisitionMetric, block)
    }

    private suspend fun <T> measureProcessing(
        attribution: HttpMessageResolutionPerformanceAttribution?,
        block: suspend () -> T,
    ): T = if (attribution == null) block() else {
        performanceDiagnostics.measure(attribution.processingMetric, block)
    }
}

private sealed interface ResolvedItemOutcome {
    data class Found(val message: ResolvedHttpMessage) : ResolvedItemOutcome
    data object NotFound : ResolvedItemOutcome
    data object RequestUnavailable : ResolvedItemOutcome
}

private fun <T> indexFilteredItems(
    items: List<T>,
    requestedIds: Set<Int>,
    id: (T) -> Int,
): Map<Int, T> {
    check(items.size <= requestedIds.size) { "filtered lookup returned too many records" }
    val indexed = HashMap<Int, T>(requestedIds.size)
    for (item in items) {
        val itemId = id(item)
        check(itemId in requestedIds) { "filtered lookup returned an unexpected record" }
        check(indexed.put(itemId, item) == null) { "filtered lookup returned duplicate records" }
    }
    return indexed
}

internal data class CanonicalHttpReferenceIdentity(
    val source: HttpMessageSource,
    val id: String,
)

internal fun canonicalHttpReferenceIdentity(ref: HttpMessageReference): CanonicalHttpReferenceIdentity? {
    if (ref.id.isEmpty() || ref.id.length > MAX_HTTP_REFERENCE_ID_CHARS || ref.id.any(Char::isISOControl)) return null
    return if (ref.source == HttpMessageSource.SITE_MAP) {
        if (parseSiteMapId(ref.id) == null) null else CanonicalHttpReferenceIdentity(ref.source, ref.id)
    } else {
        val numeric = ref.id.toIntOrNull()?.takeIf { it >= 0 } ?: return null
        CanonicalHttpReferenceIdentity(ref.source, numeric.toString())
    }
}

private data class ValidatedHttpReference(
    val ref: HttpMessageReference,
    val numericId: Int?,
    val siteMapId: ParsedSiteMapId?,
)

private fun validateReference(ref: HttpMessageReference): ValidatedHttpReference? {
    val canonical = canonicalHttpReferenceIdentity(ref) ?: return null
    return if (ref.source == HttpMessageSource.SITE_MAP) {
        val parsed = parseSiteMapId(canonical.id) ?: return null
        ValidatedHttpReference(ref, null, parsed)
    } else {
        ValidatedHttpReference(ref, canonical.id.toInt(), null)
    }
}

private fun isValidProjectId(projectId: String): Boolean =
    projectId.isNotEmpty() && projectId.length <= MAX_HTTP_REFERENCE_PROJECT_ID_CHARS && projectId.none(Char::isISOControl)

private fun invalidIdMessage(source: HttpMessageSource): String = when (source) {
    HttpMessageSource.SITE_MAP -> "Site Map reference ID must come from search_http_messages"
    HttpMessageSource.PROXY -> "Proxy history reference ID must be a non-negative integer"
    HttpMessageSource.ORGANIZER -> "Organizer reference ID must be a non-negative integer"
}

private fun HttpMessageSource.dataAccessType(): DataAccessType = when (this) {
    HttpMessageSource.PROXY -> DataAccessType.HTTP_HISTORY
    HttpMessageSource.SITE_MAP -> DataAccessType.SITE_MAP
    HttpMessageSource.ORGANIZER -> DataAccessType.ORGANIZER
}

internal fun HttpMessageSource.displayNameForResolution(): String = when (this) {
    HttpMessageSource.PROXY -> "Proxy history"
    HttpMessageSource.SITE_MAP -> "Site Map"
    HttpMessageSource.ORGANIZER -> "Organizer"
}

private fun notFound(
    projectId: String,
    ref: HttpMessageReference,
    index: Int,
) = failure(
    HttpMessageResolutionStatus.NOT_FOUND,
    projectId,
    ref,
    index,
    "HTTP message reference was not found or changed after it was issued",
)

private fun requestUnavailable(
    projectId: String,
    ref: HttpMessageReference,
    index: Int,
) = failure(
    HttpMessageResolutionStatus.REQUEST_UNAVAILABLE,
    projectId,
    ref,
    index,
    "HTTP message exists but its request is unavailable",
)

private fun failure(
    status: HttpMessageResolutionStatus,
    projectId: String?,
    ref: HttpMessageReference?,
    refIndex: Int?,
    error: String,
) = HttpMessageBatchResolution.Failed(
    status = status,
    projectId = projectId,
    ref = ref?.let { HttpMessageReference(it.source, it.id.take(MAX_HTTP_REFERENCE_ID_CHARS)) },
    refIndex = refIndex,
    error = error.take(512),
)

private fun String?.boundedResolvedNotes(): Pair<String?, Boolean> {
    if (this == null || length <= MAX_NOTES_CHARS) return this to false
    return take(MAX_NOTES_CHARS) to true
}

private fun safeResolverException(error: Exception): String = safeExceptionSummary(error)
