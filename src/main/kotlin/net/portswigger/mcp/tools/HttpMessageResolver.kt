package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse as MontoyaHttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType

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

internal data class ResolvedHttpMessage(
    val ref: HttpMessageReference,
    val request: HttpRequest,
    val response: HttpResponse?,
    val envelope: MontoyaHttpRequestResponse?,
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
 * Batch resolution checks project and data-access policy once, and snapshots Site Map at most once.
 * This avoids repeated approval prompts and O(reference count × Site Map size) lookups.
 */
internal class HttpMessageResolver(
    private val api: MontoyaApi,
    private val config: McpConfig,
) {
    suspend fun resolve(
        projectId: String,
        ref: HttpMessageReference,
    ): HttpMessageBatchResolution = resolveAll(projectId, listOf(ref), 1)

    suspend fun resolveAll(
        projectId: String,
        refs: List<HttpMessageReference>,
        maxRefs: Int = MAX_HTTP_REFERENCES_PER_BATCH,
    ): HttpMessageBatchResolution {
        if (!isValidProjectId(projectId)) {
            return failure(
                HttpMessageResolutionStatus.INVALID_ARGUMENT,
                projectId.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
                refs.firstOrNull(),
                refs.indices.firstOrNull(),
                "projectId is empty, too long, or contains control characters",
            )
        }
        if (refs.isEmpty() || refs.size > maxRefs.coerceAtMost(MAX_HTTP_REFERENCES_PER_BATCH)) {
            return failure(
                HttpMessageResolutionStatus.INVALID_ARGUMENT,
                projectId,
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
                    projectId,
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

        return try {
            resolveValidated(currentProjectId, validated)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            failure(
                HttpMessageResolutionStatus.BURP_ERROR,
                currentProjectId,
                refs.first(),
                0,
                "Burp could not resolve the HTTP message: ${safeResolverException(e)}",
            )
        }
    }

    private suspend fun resolveValidated(
        projectId: String,
        refs: List<ValidatedHttpReference>,
    ): HttpMessageBatchResolution {
        val siteMapItems by lazy(LazyThreadSafetyMode.NONE) { api.siteMap().requestResponses() }
        val resolved = ArrayList<ResolvedHttpMessage>(refs.size)

        refs.forEachIndexed { index, validated ->
            currentCoroutineContext().ensureActive()
            val message = when (validated.ref.source) {
                HttpMessageSource.PROXY -> {
                    val item = api.proxy().history { it.id() == validated.numericId }.firstOrNull()
                        ?: return notFound(projectId, validated.ref, index)
                    val request = item.request()
                        ?: return requestUnavailable(projectId, validated.ref, index)
                    ResolvedHttpMessage(validated.ref, request, item.response(), null)
                }

                HttpMessageSource.ORGANIZER -> {
                    val item = api.organizer().items { it.id() == validated.numericId }.firstOrNull()
                        ?: return notFound(projectId, validated.ref, index)
                    val request = item.request()
                        ?: return requestUnavailable(projectId, validated.ref, index)
                    ResolvedHttpMessage(validated.ref, request, item.response(), item)
                }

                HttpMessageSource.SITE_MAP -> {
                    val parsed = requireNotNull(validated.siteMapId)
                    val item = siteMapItems.getOrNull(parsed.index)
                        ?: return notFound(projectId, validated.ref, index)
                    if (stableSiteMapId(projectId, parsed.index, item) != validated.ref.id) {
                        return notFound(projectId, validated.ref, index)
                    }
                    val request = item.request()
                        ?: return requestUnavailable(projectId, validated.ref, index)
                    ResolvedHttpMessage(validated.ref, request, item.response(), item)
                }
            }
            resolved += message
        }

        return HttpMessageBatchResolution.Found(projectId, resolved)
    }
}

private data class ValidatedHttpReference(
    val ref: HttpMessageReference,
    val numericId: Int?,
    val siteMapId: ParsedSiteMapId?,
)

private fun validateReference(ref: HttpMessageReference): ValidatedHttpReference? {
    if (ref.id.isEmpty() || ref.id.length > MAX_HTTP_REFERENCE_ID_CHARS || ref.id.any(Char::isISOControl)) return null
    return if (ref.source == HttpMessageSource.SITE_MAP) {
        val parsed = parseSiteMapId(ref.id) ?: return null
        ValidatedHttpReference(ref, null, parsed)
    } else {
        val numeric = ref.id.toIntOrNull()?.takeIf { it >= 0 } ?: return null
        ValidatedHttpReference(ref, numeric, null)
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

private fun safeResolverException(error: Exception): String =
    "${error::class.simpleName ?: "Exception"}: ${error.message.orEmpty()}".take(512)
