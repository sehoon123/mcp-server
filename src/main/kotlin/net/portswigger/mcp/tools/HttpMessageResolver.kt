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

internal sealed interface HttpMessageBatchResolution {
    data class Found(
        val projectId: String,
        val messages: List<ResolvedHttpMessage>,
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
 * Batch resolution checks project and data-access policy once, performs at most one bounded filtered Proxy/Organizer
 * lookup per source, and snapshots Site Map at most once. This avoids repeated approval prompts and per-reference source
 * acquisitions while preserving caller-order resolution and Site Map positional identity checks.
 */
internal class HttpMessageResolver(
    private val api: MontoyaApi,
    private val config: McpConfig,
) {
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

        for (source in validated.asSequence().map { it.ref.source }.distinct().sortedBy { it.ordinal }) {
            val allowed = try {
                DataAccessSecurity.checkDataAccessPermission(source.dataAccessType(), config)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return failure(
                    HttpMessageResolutionStatus.BURP_ERROR,
                    currentProjectId,
                    validated.first { it.ref.source == source }.ref,
                    validated.indexOfFirst { it.ref.source == source },
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
                    validated.first { it.ref.source == source }.ref,
                    validated.indexOfFirst { it.ref.source == source },
                    "Burp could not recheck the project after HTTP data approval: ${safeResolverException(e)}",
                )
            }
            if (projectAfterSourceApproval != currentProjectId) {
                val changedIndex = validated.indexOfFirst { it.ref.source == source }
                return failure(
                    HttpMessageResolutionStatus.PROJECT_MISMATCH,
                    projectAfterSourceApproval,
                    validated[changedIndex].ref,
                    changedIndex,
                    "Burp project changed during HTTP data approval",
                )
            }
            if (!allowed) {
                val deniedIndex = validated.indexOfFirst { it.ref.source == source }
                return failure(
                    HttpMessageResolutionStatus.ACCESS_DENIED,
                    currentProjectId,
                    validated[deniedIndex].ref,
                    deniedIndex,
                    "${source.displayNameForResolution()} access denied by Burp Suite",
                )
            }
        }

        val resolution = try {
            resolveValidated(currentProjectId, validated, sourceMetadata)
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
    ): HttpMessageBatchResolution {
        var proxyItems: Map<Int, ProxyHttpRequestResponse>? = null
        var organizerItems: Map<Int, OrganizerItem>? = null
        var siteMapItems: List<MontoyaHttpRequestResponse>? = null
        val resolved = ArrayList<ResolvedHttpMessage>(refs.size)

        refs.forEachIndexed { index, validated ->
            currentCoroutineContext().ensureActive()
            val message = when (validated.ref.source) {
                HttpMessageSource.PROXY -> {
                    val items = proxyItems ?: acquireProxyItems(refs).also { proxyItems = it }
                    val item = items[validated.numericId]
                        ?: return notFound(projectId, validated.ref, index)
                    val request = item.request()
                        ?: return requestUnavailable(projectId, validated.ref, index)
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
                    ResolvedHttpMessage(validated.ref, request, item.response(), null, sourceMetadata)
                }

                HttpMessageSource.ORGANIZER -> {
                    val items = organizerItems ?: acquireOrganizerItems(refs).also { organizerItems = it }
                    val item = items[validated.numericId]
                        ?: return notFound(projectId, validated.ref, index)
                    val request = item.request()
                        ?: return requestUnavailable(projectId, validated.ref, index)
                    val sourceMetadata = if (sourceMetadataSelection == HttpSourceMetadataSelection.FULL) {
                        val notes = item.annotations().notes().boundedResolvedNotes()
                        ResolvedHttpSourceMetadata(notes = notes.first, notesTruncated = notes.second)
                    } else null
                    ResolvedHttpMessage(validated.ref, request, item.response(), item, sourceMetadata)
                }

                HttpMessageSource.SITE_MAP -> {
                    val parsed = requireNotNull(validated.siteMapId)
                    val items = siteMapItems ?: acquireSiteMapItems().also { siteMapItems = it }
                    val item = items.getOrNull(parsed.index)
                        ?: return notFound(projectId, validated.ref, index)
                    if (stableSiteMapId(projectId, parsed.index, item) != validated.ref.id) {
                        return notFound(projectId, validated.ref, index)
                    }
                    val request = item.request()
                        ?: return requestUnavailable(projectId, validated.ref, index)
                    val sourceMetadata = if (sourceMetadataSelection == HttpSourceMetadataSelection.FULL) {
                        val notes = item.annotations().notes().boundedResolvedNotes()
                        ResolvedHttpSourceMetadata(
                            inScope = request.isInScope(),
                            notes = notes.first,
                            notesTruncated = notes.second,
                        )
                    } else null
                    ResolvedHttpMessage(validated.ref, request, item.response(), item, sourceMetadata)
                }
            }
            resolved += message
        }

        return HttpMessageBatchResolution.Found(projectId, resolved)
    }

    private suspend fun acquireProxyItems(refs: List<ValidatedHttpReference>): Map<Int, ProxyHttpRequestResponse> {
        val requestedIds = refs.asSequence()
            .filter { it.ref.source == HttpMessageSource.PROXY }
            .map { requireNotNull(it.numericId) }
            .toSet()
        currentCoroutineContext().ensureActive()
        val items = api.proxy().history { it.id() in requestedIds }
        currentCoroutineContext().ensureActive()
        return indexFilteredItems(items, requestedIds, ProxyHttpRequestResponse::id)
    }

    private suspend fun acquireOrganizerItems(refs: List<ValidatedHttpReference>): Map<Int, OrganizerItem> {
        val requestedIds = refs.asSequence()
            .filter { it.ref.source == HttpMessageSource.ORGANIZER }
            .map { requireNotNull(it.numericId) }
            .toSet()
        currentCoroutineContext().ensureActive()
        val items = api.organizer().items { it.id() in requestedIds }
        currentCoroutineContext().ensureActive()
        return indexFilteredItems(items, requestedIds, OrganizerItem::id)
    }

    private suspend fun acquireSiteMapItems(): List<MontoyaHttpRequestResponse> {
        currentCoroutineContext().ensureActive()
        val items = api.siteMap().requestResponses()
        currentCoroutineContext().ensureActive()
        return items
    }
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
