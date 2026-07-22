package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse as MontoyaHttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal const val DEFAULT_HTTP_SEARCH_LIMIT = 25
internal const val MAX_HTTP_SEARCH_LIMIT = 50
internal const val MAX_HTTP_SEARCH_SCANNED_ITEMS = 10_000
internal const val MAX_HTTP_SEARCH_TEXT_BYTES = 32L * 1024 * 1024
private const val MAX_HTTP_SEARCH_CURSOR_CHARS = 32_768
internal const val MAX_HTTP_SEARCH_HOST_CHARS = 253
private const val MAX_HTTP_SEARCH_PATH_CHARS = 2_048
private const val MAX_HTTP_SEARCH_TEXT_CHARS = 512
private const val MAX_HTTP_SEARCH_FILTER_VALUES = 32
internal const val MAX_HTTP_SEARCH_URL_CHARS = 2_048
private const val MAX_HTTP_SEARCH_NOTES_CHARS = 512
private const val CURSOR_VERSION = 2
private const val CURSOR_HMAC_ALGORITHM = "HmacSHA256"
private val HTTP_METHOD_PATTERN = Regex("[A-Z!#$%&'*+.^_`|~-]{1,32}")
private val MIME_TYPE_PATTERN = Regex("[A-Z0-9_+.-]{1,64}")

@Serializable
enum class HttpMessageSource {
    @SerialName("proxy")
    PROXY,

    @SerialName("site_map")
    SITE_MAP,

    @SerialName("organizer")
    ORGANIZER,
}

@Serializable
enum class HttpSearchLocation {
    @SerialName("request")
    REQUEST,

    @SerialName("response")
    RESPONSE,

    @SerialName("both")
    BOTH,
}

@Serializable
data class SearchHttpMessages(
    @JsonSchemaMetadata(description = "History sources to search.", minItems = 1, maxItems = 3)
    val sources: List<HttpMessageSource>? = null,
    @JsonSchemaMetadata(description = "Exact canonical host filter.", minLength = 1, maxLength = 253)
    val host: String? = null,
    @JsonSchemaMetadata(description = "Case-sensitive URL path substring.", minLength = 1, maxLength = 2048)
    val pathContains: String? = null,
    @JsonSchemaMetadata(description = "HTTP methods to include.", minItems = 1, maxItems = 32)
    val methods: List<String>? = null,
    @JsonSchemaMetadata(description = "HTTP response status codes to include.", minItems = 1, maxItems = 32)
    val statusCodes: List<Int>? = null,
    @JsonSchemaMetadata(description = "MIME types to include.", minItems = 1, maxItems = 32)
    val mimeTypes: List<String>? = null,
    @JsonSchemaMetadata(description = "Restrict results to Burp Scope.", defaultJson = "false")
    val inScopeOnly: Boolean? = null,
    @JsonSchemaMetadata(description = "Filter by response presence when supplied.")
    val hasResponse: Boolean? = null,
    @JsonSchemaMetadata(description = "Bounded literal request or response text to search for; mutually exclusive with regex.", maxLength = 512)
    val text: String? = null,
    @JsonSchemaMetadata(description = "Conservatively safe request or response regex; mutually exclusive with text.", minLength = 1, maxLength = 512)
    val regex: String? = null,
    @JsonSchemaMetadata(description = "Message part searched by text or regex.", defaultJson = "\"both\"")
    val searchIn: HttpSearchLocation? = null,
    @JsonSchemaMetadata(description = "Use case-sensitive matching. Defaults to false for text and true for regex.")
    val caseSensitive: Boolean? = null,
    @JsonSchemaMetadata(description = "Return newest matches first.", defaultJson = "true")
    val newestFirst: Boolean? = null,
    @JsonSchemaMetadata(description = "Maximum results in this page.", minimum = 1, maximum = 50, defaultJson = "25")
    val limit: Int? = null,
    @JsonSchemaMetadata(description = "Opaque signed continuation cursor.", maxLength = 32768)
    val cursor: String? = null,
)

@Serializable
enum class HttpMessageSearchStatus {
    @SerialName("ok")
    OK,

    @SerialName("access_denied")
    ACCESS_DENIED,

    @SerialName("invalid_argument")
    INVALID_ARGUMENT,

    @SerialName("invalid_cursor")
    INVALID_CURSOR,

    @SerialName("stale_cursor")
    STALE_CURSOR,

    @SerialName("project_mismatch")
    PROJECT_MISMATCH,
}

@Serializable
data class HttpMessageReference(
    @JsonSchemaMetadata(description = "Burp history source.")
    val source: HttpMessageSource,
    @JsonSchemaMetadata(description = "Stable source-specific message ID.", minLength = 1, maxLength = 128)
    val id: String,
)

@Serializable
data class HttpMessageSearchItem(
    val ref: HttpMessageReference,
    val method: String,
    val url: String,
    val urlTruncated: Boolean,
    val host: String,
    val port: Int,
    val secure: Boolean,
    val statusCode: Int?,
    val mimeType: String?,
    val hasResponse: Boolean,
    val inScope: Boolean,
    val requestBodyBytes: Int,
    val responseBodyBytes: Int?,
    val time: String?,
    val listenerPort: Int?,
    val edited: Boolean?,
    val organizerStatus: String?,
    val notes: String?,
    val notesTruncated: Boolean,
)

@Serializable
data class SearchHttpMessagesResult(
    val status: HttpMessageSearchStatus,
    val projectId: String?,
    val items: List<HttpMessageSearchItem>,
    val returned: Int,
    val scanned: Int,
    val scannedContentBytes: Long,
    val oversizedContentSkipped: Int,
    val scanLimitReached: Boolean,
    val hasMore: Boolean,
    val nextCursor: String?,
    val error: String?,
)

@Serializable
private data class NormalizedHttpSearchQuery(
    val sources: List<HttpMessageSource>,
    val host: String?,
    val pathContains: String?,
    val methods: List<String>?,
    val statusCodes: List<Int>?,
    val mimeTypes: List<String>?,
    val inScopeOnly: Boolean,
    val hasResponse: Boolean?,
    val text: String?,
    val regex: String?,
    val searchIn: HttpSearchLocation,
    val caseSensitive: Boolean,
    val newestFirst: Boolean,
)

@Serializable
private data class CursorSourceSnapshot(
    val source: HttpMessageSource,
    val size: Int,
    val firstAnchor: String?,
    val lastAnchor: String?,
)

@Serializable
private data class HttpSearchCursor(
    val version: Int,
    val projectId: String,
    val query: NormalizedHttpSearchQuery,
    val snapshots: List<CursorSourceSnapshot>,
    val sourceIndex: Int,
    val itemIndex: Int,
)

private data class SearchPosition(var sourceIndex: Int, var itemIndex: Int)

private class ExpectedSearchError(
    val status: HttpMessageSearchStatus,
    override val message: String,
) : Exception(message)

internal class HttpMessageSearchService(
    private val api: MontoyaApi,
    private val config: McpConfig,
    private val metadataIndex: HttpMetadataIndex? = null,
    cursorSecret: ByteArray = ByteArray(32).also(SecureRandom()::nextBytes),
    private val maxScannedItems: Int = MAX_HTTP_SEARCH_SCANNED_ITEMS,
    private val maxTextBytes: Long = MAX_HTTP_SEARCH_TEXT_BYTES,
) {
    private val cursorKey = SecretKeySpec(
        cursorSecret.copyOf().also { require(it.size >= 32) { "cursorSecret must contain at least 32 bytes" } },
        CURSOR_HMAC_ALGORITHM,
    )
    private val cursorJson = Json { encodeDefaults = true }

    init {
        require(maxScannedItems > 0) { "maxScannedItems must be positive" }
        require(maxTextBytes > 0) { "maxTextBytes must be positive" }
    }

    suspend fun search(input: SearchHttpMessages): SearchHttpMessagesResult {
        val cursor = try {
            input.cursor?.let(::decodeCursor)
        } catch (e: ExpectedSearchError) {
            return searchError(e.status, e.message)
        }

        val query = try {
            when {
                cursor == null -> normalizeQuery(input)
                input.hasExplicitQuery() -> {
                    val supplied = normalizeQuery(input)
                    if (supplied != cursor.query) {
                        throw ExpectedSearchError(
                            HttpMessageSearchStatus.INVALID_CURSOR,
                            "cursor does not match the supplied search filters",
                        )
                    }
                    supplied
                }
                else -> cursor.query
            }
        } catch (e: IllegalArgumentException) {
            return searchError(HttpMessageSearchStatus.INVALID_ARGUMENT, e.message ?: "invalid search arguments")
        } catch (e: ExpectedSearchError) {
            return searchError(e.status, e.message)
        }

        val limit = input.limit ?: DEFAULT_HTTP_SEARCH_LIMIT
        if (limit !in 1..MAX_HTTP_SEARCH_LIMIT) {
            return searchError(
                HttpMessageSearchStatus.INVALID_ARGUMENT,
                "limit must be between 1 and $MAX_HTTP_SEARCH_LIMIT",
            )
        }

        for (source in query.sources) {
            if (!checkAccess(source)) {
                return searchError(
                    HttpMessageSearchStatus.ACCESS_DENIED,
                    "${source.displayName()} access denied by Burp Suite",
                )
            }
        }

        val projectId = currentProjectId()
        if (cursor != null && cursor.projectId != projectId) {
            return searchError(
                HttpMessageSearchStatus.PROJECT_MISMATCH,
                "cursor belongs to a different Burp project",
                projectId,
            )
        }

        val indexSources = query.metadataIndexSources()
        val indexSnapshot = if (metadataIndex != null && indexSources.isNotEmpty()) {
            try {
                metadataIndex.searchHintsSnapshot(projectId, indexSources)
            } catch (e: HttpMetadataProjectMismatchException) {
                return searchError(
                    HttpMessageSearchStatus.PROJECT_MISMATCH,
                    "Burp project changed while preparing the search",
                    e.currentProjectId,
                )
            } catch (_: HttpMetadataIndexChangingException) {
                null
            }
        } else {
            null
        }

        var result = try {
            executeSearch(query, cursor, limit, projectId, indexSnapshot?.let(::IndexedSearchHints))
        } catch (e: ExpectedSearchError) {
            return searchError(e.status, e.message, projectId)
        }

        if (indexSnapshot != null) {
            val indexStillCurrent = try {
                requireNotNull(metadataIndex).areSearchHintsCurrent(indexSnapshot)
            } catch (e: HttpMetadataProjectMismatchException) {
                return searchError(
                    HttpMessageSearchStatus.PROJECT_MISMATCH,
                    "Burp project changed while searching HTTP messages",
                    e.currentProjectId,
                )
            } catch (_: HttpMetadataIndexChangingException) {
                false
            }
            if (!indexStillCurrent) {
                result = try {
                    executeSearch(query, cursor, limit, projectId, hints = null)
                } catch (e: ExpectedSearchError) {
                    return searchError(e.status, e.message, projectId)
                }
            }
        }

        val finalProjectId = currentProjectId()
        if (finalProjectId != projectId) {
            return searchError(
                HttpMessageSearchStatus.PROJECT_MISMATCH,
                "Burp project changed while searching HTTP messages",
                finalProjectId,
            )
        }
        return result
    }

    private suspend fun executeSearch(
        query: NormalizedHttpSearchQuery,
        cursor: HttpSearchCursor?,
        limit: Int,
        projectId: String,
        hints: IndexedSearchHints?,
    ): SearchHttpMessagesResult {
        val views = query.sources.map(::loadView)
        val snapshots = if (cursor == null) {
            views.map { it.snapshot() }
        } else {
            validateCursor(cursor, views)
            cursor.snapshots
        }

        val position = if (cursor == null) {
            SearchPosition(0, initialItemIndex(snapshots.firstOrNull()?.size ?: 0, query.newestFirst))
        } else {
            SearchPosition(cursor.sourceIndex, cursor.itemIndex)
        }
        normalizePosition(position, snapshots, query.newestFirst)

        val matcher = CompiledHttpSearchQuery(query)
        val results = ArrayList<HttpMessageSearchItem>(limit)
        var scanned = 0
        var scannedContentBytes = 0L
        var oversizedContentSkipped = 0
        var stoppedByScanBudget = false

        while (position.sourceIndex < views.size && results.size < limit) {
            if (scanned and 63 == 0) currentCoroutineContext().ensureActive()
            if (scanned >= maxScannedItems) {
                stoppedByScanBudget = true
                break
            }

            val view = views[position.sourceIndex]
            val itemIndex = position.itemIndex
            scanned++
            val indexedRecord = hints?.record(view.source, itemIndex)
            val predictedRejection = indexedRecord?.predictedRejection(matcher)
            if (predictedRejection != null &&
                view.currentRecordStillRejects(itemIndex, indexedRecord, predictedRejection, matcher)
            ) {
                advancePosition(position, snapshots, query.newestFirst)
                continue
            }

            val candidate = view.candidate(itemIndex)
            if (candidate == null || !candidate.matchesMetadata(matcher)) {
                advancePosition(position, snapshots, query.newestFirst)
                continue
            }

            if (query.hasContentPredicate()) {
                val candidateBytes = candidate.approximateContentBytes()
                if (candidateBytes > maxTextBytes) {
                    oversizedContentSkipped++
                    advancePosition(position, snapshots, query.newestFirst)
                    continue
                }
                if (scannedContentBytes + candidateBytes > maxTextBytes) {
                    stoppedByScanBudget = true
                    break
                }
                scannedContentBytes += candidateBytes
                if (!candidate.matchesContent(matcher)) {
                    advancePosition(position, snapshots, query.newestFirst)
                    continue
                }
            }

            results += candidate.toSummary(projectId, itemIndex)
            advancePosition(position, snapshots, query.newestFirst)
        }

        normalizePosition(position, snapshots, query.newestFirst)
        val hasMore = position.sourceIndex < snapshots.size
        val nextCursor = if (hasMore) {
            encodeCursor(
                HttpSearchCursor(
                    version = CURSOR_VERSION,
                    projectId = projectId,
                    query = query,
                    snapshots = snapshots,
                    sourceIndex = position.sourceIndex,
                    itemIndex = position.itemIndex,
                )
            )
        } else {
            null
        }

        return SearchHttpMessagesResult(
            status = HttpMessageSearchStatus.OK,
            projectId = projectId,
            items = results,
            returned = results.size,
            scanned = scanned,
            scannedContentBytes = scannedContentBytes,
            oversizedContentSkipped = oversizedContentSkipped,
            scanLimitReached = stoppedByScanBudget,
            hasMore = hasMore,
            nextCursor = nextCursor,
            error = null,
        )
    }

    suspend fun readSiteMapMessage(input: GetSitemapMessageById): SiteMapMessageReadResult {
        val safeProjectId = input.projectId.take(256)
        val safeId = input.id.take(128)
        val safePart = input.part?.take(64) ?: "metadata"
        if (input.projectId.length > 256 || input.id.length > 128 || (input.part?.length ?: 0) > 64) {
            return siteMapReadError(
                SiteMapReadStatus.INVALID_ARGUMENT,
                safeProjectId,
                safeId,
                safePart,
                "projectId, id, or part is too long",
            )
        }

        val part: String
        val offset: Int
        val limit: Int
        val encoding: String
        try {
            part = normalizeHttpPart(input.part)
            offset = normalizeHistoryOffset(input.offset)
            limit = normalizeHistoryLimit(input.limit)
            encoding = normalizeHistoryEncoding(input.encoding)
        } catch (e: IllegalArgumentException) {
            return siteMapReadError(
                SiteMapReadStatus.INVALID_ARGUMENT,
                safeProjectId,
                safeId,
                safePart,
                e.message ?: "invalid read arguments",
            )
        }

        val parsedId = parseSiteMapId(input.id) ?: return siteMapReadError(
            SiteMapReadStatus.INVALID_ID,
            input.projectId,
            input.id,
            part,
            "id must be a Site Map ID returned by search_http_messages",
        )

        if (!checkAccess(HttpMessageSource.SITE_MAP)) {
            return siteMapReadError(
                SiteMapReadStatus.ACCESS_DENIED,
                input.projectId,
                input.id,
                part,
                "Site Map access denied by Burp Suite",
            )
        }

        val projectId = currentProjectId()
        if (input.projectId != projectId) {
            return siteMapReadError(
                SiteMapReadStatus.PROJECT_MISMATCH,
                projectId,
                input.id,
                part,
                "ID belongs to a different Burp project",
            )
        }

        val items = api.siteMap().requestResponses()
        val item = items.getOrNull(parsedId.index) ?: return siteMapReadError(
            SiteMapReadStatus.NOT_FOUND,
            projectId,
            input.id,
            part,
            "Site Map item was removed or is no longer at its original position",
        )
        if (stableSiteMapId(projectId, parsedId.index, item) != input.id) {
            return siteMapReadError(
                SiteMapReadStatus.NOT_FOUND,
                projectId,
                input.id,
                part,
                "Site Map item changed after the ID was issued",
            )
        }

        return try {
            item.readSiteMapPart(projectId, input.id, part, offset, limit, encoding)
        } catch (e: IllegalArgumentException) {
            siteMapReadError(
                SiteMapReadStatus.INVALID_ARGUMENT,
                projectId,
                input.id,
                part,
                e.message ?: "invalid read arguments",
            )
        }
    }

    private suspend fun checkAccess(source: HttpMessageSource): Boolean {
        val accessType = when (source) {
            HttpMessageSource.PROXY -> DataAccessType.HTTP_HISTORY
            HttpMessageSource.SITE_MAP -> DataAccessType.SITE_MAP
            HttpMessageSource.ORGANIZER -> DataAccessType.ORGANIZER
        }
        val allowed = DataAccessSecurity.checkDataAccessPermission(accessType, config)
        api.logging().logToOutput(
            "MCP ${source.displayName()} access ${if (allowed) "granted" else "denied"}"
        )
        return allowed
    }

    private fun loadView(source: HttpMessageSource): SourceView = when (source) {
        HttpMessageSource.PROXY -> ProxySourceView(api.proxy().history())
        HttpMessageSource.SITE_MAP -> SiteMapSourceView(api.siteMap().requestResponses())
        HttpMessageSource.ORGANIZER -> OrganizerSourceView(api.organizer().items())
    }

    private fun validateCursor(cursor: HttpSearchCursor, views: List<SourceView>) {
        if (cursor.version != CURSOR_VERSION) {
            throw ExpectedSearchError(HttpMessageSearchStatus.INVALID_CURSOR, "unsupported cursor version")
        }
        if (cursor.snapshots.size != views.size ||
            cursor.snapshots.map { it.source } != views.map { it.source }
        ) {
            throw ExpectedSearchError(HttpMessageSearchStatus.INVALID_CURSOR, "cursor source set is invalid")
        }
        if (cursor.sourceIndex !in 0..views.size) {
            throw ExpectedSearchError(HttpMessageSearchStatus.INVALID_CURSOR, "cursor position is invalid")
        }

        cursor.snapshots.zip(views).forEach { (snapshot, view) ->
            if (view.size < snapshot.size) {
                throw ExpectedSearchError(
                    HttpMessageSearchStatus.STALE_CURSOR,
                    "${snapshot.source.displayName()} changed while paging; start a new search",
                )
            }
            if (snapshot.size > 0 &&
                (view.anchor(0) != snapshot.firstAnchor || view.anchor(snapshot.size - 1) != snapshot.lastAnchor)
            ) {
                throw ExpectedSearchError(
                    HttpMessageSearchStatus.STALE_CURSOR,
                    "${snapshot.source.displayName()} ordering changed while paging; start a new search",
                )
            }
        }
    }

    private fun encodeCursor(cursor: HttpSearchCursor): String {
        val payload = cursorJson.encodeToString(cursor).toByteArray(StandardCharsets.UTF_8)
        val signature = hmac(payload)
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(payload) + "." +
            Base64.getUrlEncoder().withoutPadding().encodeToString(signature)
        check(encoded.length <= MAX_HTTP_SEARCH_CURSOR_CHARS) { "generated cursor exceeded its size bound" }
        return encoded
    }

    private fun decodeCursor(value: String): HttpSearchCursor {
        if (value.length !in 1..MAX_HTTP_SEARCH_CURSOR_CHARS) {
            throw ExpectedSearchError(HttpMessageSearchStatus.INVALID_CURSOR, "cursor is too large or empty")
        }
        val separator = value.indexOf('.')
        if (separator <= 0 || separator != value.lastIndexOf('.') || separator == value.lastIndex) {
            throw ExpectedSearchError(HttpMessageSearchStatus.INVALID_CURSOR, "cursor format is invalid")
        }
        val payload: ByteArray
        val suppliedSignature: ByteArray
        try {
            payload = Base64.getUrlDecoder().decode(value.substring(0, separator))
            suppliedSignature = Base64.getUrlDecoder().decode(value.substring(separator + 1))
        } catch (_: IllegalArgumentException) {
            throw ExpectedSearchError(HttpMessageSearchStatus.INVALID_CURSOR, "cursor encoding is invalid")
        }
        if (!MessageDigest.isEqual(hmac(payload), suppliedSignature)) {
            throw ExpectedSearchError(HttpMessageSearchStatus.INVALID_CURSOR, "cursor signature is invalid")
        }
        return try {
            cursorJson.decodeFromString<HttpSearchCursor>(payload.toString(StandardCharsets.UTF_8))
        } catch (_: Exception) {
            throw ExpectedSearchError(HttpMessageSearchStatus.INVALID_CURSOR, "cursor payload is invalid")
        }
    }

    private fun hmac(payload: ByteArray): ByteArray = Mac.getInstance(CURSOR_HMAC_ALGORITHM).run {
        init(cursorKey)
        doFinal(payload)
    }

    private fun currentProjectId(): String = api.project().id()
}

private interface SourceView {
    val source: HttpMessageSource
    val size: Int
    fun candidate(index: Int): SearchCandidate?
    fun anchor(index: Int): String?
    fun currentRecordStillRejects(
        index: Int,
        indexedRecord: HttpMetadataRecord,
        predicted: MetadataRejectionReason,
        matcher: CompiledHttpSearchQuery,
    ): Boolean = false

    fun snapshot(): CursorSourceSnapshot = CursorSourceSnapshot(
        source = source,
        size = size,
        firstAnchor = if (size == 0) null else anchor(0),
        lastAnchor = if (size == 0) null else anchor(size - 1),
    )
}

private class ProxySourceView(private val items: List<ProxyHttpRequestResponse>) : SourceView {
    override val source = HttpMessageSource.PROXY
    override val size get() = items.size

    override fun candidate(index: Int): SearchCandidate? {
        val item = items.getOrNull(index) ?: return null
        val request = item.request() ?: return null
        val response = item.response()
        return SearchCandidate(
            source = source,
            request = request,
            response = response,
            service = item.httpService(),
            proxyItem = item,
        )
    }

    override fun anchor(index: Int): String? = items.getOrNull(index)?.id()?.toString()

    override fun currentRecordStillRejects(
        index: Int,
        indexedRecord: HttpMetadataRecord,
        predicted: MetadataRejectionReason,
        matcher: CompiledHttpSearchQuery,
    ): Boolean = currentProxyRecordStillRejects(
        items.getOrNull(index),
        indexedRecord.numericSourceId,
        predicted,
        matcher,
    )
}

private class SiteMapSourceView(private val items: List<MontoyaHttpRequestResponse>) : SourceView {
    override val source = HttpMessageSource.SITE_MAP
    override val size get() = items.size

    override fun candidate(index: Int): SearchCandidate? {
        val item = items.getOrNull(index) ?: return null
        val request = item.request() ?: return null
        return SearchCandidate(
            source = source,
            request = request,
            response = item.response(),
            service = item.httpService(),
            siteMapItem = item,
        )
    }

    override fun anchor(index: Int): String? = items.getOrNull(index)?.let(::siteMapBoundaryAnchor)
}

private class OrganizerSourceView(private val items: List<OrganizerItem>) : SourceView {
    override val source = HttpMessageSource.ORGANIZER
    override val size get() = items.size

    override fun candidate(index: Int): SearchCandidate? {
        val item = items.getOrNull(index) ?: return null
        val request = item.request() ?: return null
        return SearchCandidate(
            source = source,
            request = request,
            response = item.response(),
            service = item.httpService(),
            organizerItem = item,
        )
    }

    override fun anchor(index: Int): String? = items.getOrNull(index)?.id()?.toString()

    override fun currentRecordStillRejects(
        index: Int,
        indexedRecord: HttpMetadataRecord,
        predicted: MetadataRejectionReason,
        matcher: CompiledHttpSearchQuery,
    ): Boolean = currentOrganizerRecordStillRejects(
        items.getOrNull(index),
        indexedRecord.numericSourceId,
        predicted,
        matcher,
    )
}

private fun currentProxyRecordStillRejects(
    item: ProxyHttpRequestResponse?,
    expectedSourceId: Int?,
    predicted: MetadataRejectionReason,
    matcher: CompiledHttpSearchQuery,
): Boolean = currentRejectionOrFallback {
    if (item == null) return@currentRejectionOrFallback true
    if (expectedSourceId == null || item.id() != expectedSourceId) return@currentRejectionOrFallback false
    currentFieldStillRejects(
        predicted,
        matcher,
        currentService = { item.httpService() },
        currentRequest = { item.request() },
        currentResponse = { item.response() },
    )
}

private fun currentOrganizerRecordStillRejects(
    item: OrganizerItem?,
    expectedSourceId: Int?,
    predicted: MetadataRejectionReason,
    matcher: CompiledHttpSearchQuery,
): Boolean = currentRejectionOrFallback {
    if (item == null) return@currentRejectionOrFallback true
    if (expectedSourceId == null || item.id() != expectedSourceId) return@currentRejectionOrFallback false
    currentFieldStillRejects(
        predicted,
        matcher,
        currentService = { item.httpService() },
        currentRequest = { item.request() },
        currentResponse = { item.response() },
    )
}

private inline fun currentFieldStillRejects(
    predicted: MetadataRejectionReason,
    matcher: CompiledHttpSearchQuery,
    currentService: () -> HttpService,
    currentRequest: () -> HttpRequest?,
    currentResponse: () -> HttpResponse?,
): Boolean = when (predicted) {
    MetadataRejectionReason.HOST ->
        !hostMatches(currentService().host(), requireNotNull(matcher.query.host))
    MetadataRejectionReason.PATH -> currentRequest()?.let {
        !pathMatches(it.path(), requireNotNull(matcher.query.pathContains), matcher.query.caseSensitive)
    } ?: true
    MetadataRejectionReason.METHOD -> currentRequest()?.let {
        !methodMatches(it.method(), requireNotNull(matcher.methods))
    } ?: true
    MetadataRejectionReason.STATUS_CODE ->
        currentResponse()?.statusCode()?.toInt() !in requireNotNull(matcher.statusCodes)
    MetadataRejectionReason.MIME_TYPE ->
        currentResponse()?.mimeType()?.name !in requireNotNull(matcher.mimeTypes)
    MetadataRejectionReason.SCOPE -> currentRequest()?.let { !it.isInScope() } ?: true
    MetadataRejectionReason.HAS_RESPONSE ->
        (currentResponse() != null) != requireNotNull(matcher.query.hasResponse)
}

private class CompiledHttpSearchQuery(val query: NormalizedHttpSearchQuery) {
    val methods = query.methods?.toHashSet()
    val statusCodes = query.statusCodes?.toHashSet()
    val mimeTypes = query.mimeTypes?.toHashSet()
    val indexedMimeTypes = query.mimeTypes?.mapTo(HashSet()) { it.lowercase() }
    val regex = query.regex?.let { validateSafeRegex(it, query.caseSensitive) }
}

private enum class MetadataRejectionReason {
    HOST,
    PATH,
    METHOD,
    STATUS_CODE,
    MIME_TYPE,
    SCOPE,
    HAS_RESPONSE,
}

/**
 * Uses cached metadata only to predict which current field can reject a record cheaply.
 *
 * The source view always re-reads that field from the current Burp record and verifies the numeric Proxy/Organizer ID
 * before skipping anything. A stale prediction therefore falls back to the original raw matcher and cannot alter
 * search or cursor semantics.
 */
private class IndexedSearchHints(snapshot: HttpMetadataIndexSnapshot) {
    private val sources = arrayOfNulls<HttpMetadataSourceSnapshot>(HttpMessageSource.entries.size).also { indexed ->
        snapshot.sources.forEach { indexed[it.source.ordinal] = it }
    }

    fun record(source: HttpMessageSource, sourceIndex: Int): HttpMetadataRecord? {
        val sourceSnapshot = sources[source.ordinal] ?: return null
        val record = sourceSnapshot.slots.getOrNull(sourceIndex - sourceSnapshot.indexedFrom) ?: return null
        return record.takeIf { it.sourceIndex == sourceIndex }
    }
}

private fun HttpMetadataRecord.predictedRejection(matcher: CompiledHttpSearchQuery): MetadataRejectionReason? {
    val query = matcher.query
    return when {
        query.host != null && !host.equals(query.host, ignoreCase = true) -> MetadataRejectionReason.HOST
        query.pathContains != null && !pathTruncated &&
            !pathMatches(path, query.pathContains, query.caseSensitive) -> MetadataRejectionReason.PATH
        matcher.methods != null && method !in matcher.methods -> MetadataRejectionReason.METHOD
        matcher.statusCodes != null && statusCode !in matcher.statusCodes -> MetadataRejectionReason.STATUS_CODE
        matcher.indexedMimeTypes != null && mimeType !in matcher.indexedMimeTypes -> MetadataRejectionReason.MIME_TYPE
        query.inScopeOnly && !inScope -> MetadataRejectionReason.SCOPE
        query.hasResponse != null && hasResponse != query.hasResponse -> MetadataRejectionReason.HAS_RESPONSE
        else -> null
    }
}

private data class SearchCandidate(
    val source: HttpMessageSource,
    val request: HttpRequest,
    val response: HttpResponse?,
    val service: HttpService,
    val proxyItem: ProxyHttpRequestResponse? = null,
    val siteMapItem: MontoyaHttpRequestResponse? = null,
    val organizerItem: OrganizerItem? = null,
) {
    fun approximateContentBytes(): Long = messageBytes(request) + (response?.let(::messageBytes) ?: 0L)

    fun matchesMetadata(matcher: CompiledHttpSearchQuery): Boolean {
        val query = matcher.query
        if (query.host != null && !hostMatches(service.host(), query.host)) return false
        if (query.pathContains != null && !pathMatches(request.path(), query.pathContains, query.caseSensitive)) return false
        if (matcher.methods != null && !methodMatches(request.method(), matcher.methods)) return false
        if (matcher.statusCodes != null && response?.statusCode()?.toInt() !in matcher.statusCodes) return false
        if (matcher.mimeTypes != null && response?.mimeType()?.name !in matcher.mimeTypes) return false
        if (query.inScopeOnly && !request.isInScope()) return false
        if (query.hasResponse != null && (response != null) != query.hasResponse) return false
        return true
    }

    fun matchesContent(matcher: CompiledHttpSearchQuery): Boolean {
        val query = matcher.query
        val requestMatches = query.searchIn != HttpSearchLocation.RESPONSE && when {
            query.text != null -> request.contains(query.text, query.caseSensitive)
            matcher.regex != null -> request.contains(matcher.regex)
            else -> true
        }
        if (requestMatches) return true
        return query.searchIn != HttpSearchLocation.REQUEST && when {
            query.text != null -> response?.contains(query.text, query.caseSensitive) == true
            matcher.regex != null -> response?.contains(matcher.regex) == true
            else -> true
        }
    }

    fun toSummary(projectId: String, sourceIndex: Int): HttpMessageSearchItem {
        val notes = when (source) {
            HttpMessageSource.PROXY -> requireNotNull(proxyItem).annotations().notes()
            HttpMessageSource.SITE_MAP -> requireNotNull(siteMapItem).annotations().notes()
            HttpMessageSource.ORGANIZER -> requireNotNull(organizerItem).annotations().notes()
        }
        val boundedNotes = notes.bounded(MAX_HTTP_SEARCH_NOTES_CHARS)
        val id = when (source) {
            HttpMessageSource.PROXY -> requireNotNull(proxyItem).id().toString()
            HttpMessageSource.ORGANIZER -> requireNotNull(organizerItem).id().toString()
            HttpMessageSource.SITE_MAP -> stableSiteMapId(projectId, sourceIndex, requireNotNull(siteMapItem))
        }
        val boundedUrl = request.url().bounded(MAX_HTTP_SEARCH_URL_CHARS)
        return HttpMessageSearchItem(
            ref = HttpMessageReference(source, id),
            method = request.method().bounded(32).first.orEmpty(),
            url = boundedUrl.first.orEmpty(),
            urlTruncated = boundedUrl.second,
            host = service.host().bounded(MAX_HTTP_SEARCH_HOST_CHARS).first.orEmpty(),
            port = service.port(),
            secure = service.secure(),
            statusCode = response?.statusCode()?.toInt(),
            mimeType = response?.mimeType()?.name,
            hasResponse = response != null,
            inScope = request.isInScope(),
            requestBodyBytes = request.body().length(),
            responseBodyBytes = response?.body()?.length(),
            time = proxyItem?.time()?.toString(),
            listenerPort = proxyItem?.listenerPort(),
            edited = proxyItem?.edited(),
            organizerStatus = organizerItem?.status()?.displayName(),
            notes = boundedNotes.first,
            notesTruncated = boundedNotes.second,
        )
    }
}

private inline fun currentRejectionOrFallback(block: () -> Boolean): Boolean = try {
    block()
} catch (e: kotlinx.coroutines.CancellationException) {
    throw e
} catch (_: Exception) {
    false
}

private fun hostMatches(actual: String, expected: String): Boolean =
    actual.trimEnd('.').equals(expected, ignoreCase = true)

private fun pathMatches(actual: String, expected: String, caseSensitive: Boolean): Boolean =
    actual.contains(expected, ignoreCase = !caseSensitive)

private fun methodMatches(actual: String, expected: Set<String>): Boolean =
    actual in expected || actual.uppercase() in expected

private fun NormalizedHttpSearchQuery.hasContentPredicate(): Boolean = text != null || regex != null

private fun NormalizedHttpSearchQuery.metadataIndexSources(): List<HttpMessageSource> {
    val hasMetadataPredicate = host != null || pathContains != null || methods != null || statusCodes != null ||
        mimeTypes != null || inScopeOnly || hasResponse != null
    if (hasContentPredicate() || !newestFirst || !hasMetadataPredicate) return emptyList()
    return sources.filter { it == HttpMessageSource.PROXY || it == HttpMessageSource.ORGANIZER }
}

private fun normalizeQuery(input: SearchHttpMessages): NormalizedHttpSearchQuery {
    require((input.sources?.size ?: 0) <= HttpMessageSource.entries.size) { "too many sources" }
    require((input.methods?.size ?: 0) <= MAX_HTTP_SEARCH_FILTER_VALUES) { "too many methods" }
    require((input.statusCodes?.size ?: 0) <= MAX_HTTP_SEARCH_FILTER_VALUES) { "too many status codes" }
    require((input.mimeTypes?.size ?: 0) <= MAX_HTTP_SEARCH_FILTER_VALUES) { "too many MIME types" }

    val sources = (input.sources ?: listOf(HttpMessageSource.PROXY))
        .distinct()
        .sortedBy(HttpMessageSource::ordinal)
    require(sources.isNotEmpty()) { "sources must contain at least one source" }

    require((input.host?.length ?: 0) <= MAX_HTTP_SEARCH_HOST_CHARS + 1) { "host is too long" }
    val host = input.host?.trim()?.trimEnd('.')?.lowercase()?.also {
        require(it.isNotEmpty()) { "host must not be empty" }
        require(it.length <= MAX_HTTP_SEARCH_HOST_CHARS) { "host is too long" }
        require(it.none(Char::isISOControl)) { "host contains control characters" }
    }
    val pathContains = input.pathContains?.also {
        require(it.isNotEmpty()) { "pathContains must not be empty" }
        require(it.length <= MAX_HTTP_SEARCH_PATH_CHARS) { "pathContains is too long" }
    }
    val methods = input.methods?.map { method ->
        require(method.length <= 64) { "HTTP method is too long" }
        method.trim().uppercase().also {
            require(it.matches(HTTP_METHOD_PATTERN)) { "invalid HTTP method: $method" }
        }
    }?.distinct()?.sorted()?.also {
        require(it.isNotEmpty()) { "methods must not be empty" }
        require(it.size <= MAX_HTTP_SEARCH_FILTER_VALUES) { "too many methods" }
    }
    val statusCodes = input.statusCodes?.distinct()?.sorted()?.also {
        require(it.isNotEmpty()) { "statusCodes must not be empty" }
        require(it.size <= MAX_HTTP_SEARCH_FILTER_VALUES) { "too many status codes" }
        require(it.all { code -> code in 100..599 }) { "statusCodes must be between 100 and 599" }
    }
    val mimeTypes = input.mimeTypes?.map { value ->
        require(value.length <= 64) { "MIME type is too long" }
        value.trim().uppercase().also {
            require(it.isNotEmpty()) { "MIME type must not be empty" }
            require(it.matches(MIME_TYPE_PATTERN)) { "invalid MIME type" }
        }
    }?.distinct()?.sorted()?.also {
        require(it.isNotEmpty()) { "mimeTypes must not be empty" }
        require(it.size <= MAX_HTTP_SEARCH_FILTER_VALUES) { "too many MIME types" }
    }
    require(input.text == null || input.regex == null) { "text and regex are mutually exclusive" }
    val text = input.text?.also {
        require(it.isNotEmpty()) { "text must not be empty" }
        require(it.length <= MAX_HTTP_SEARCH_TEXT_CHARS) { "text is too long" }
    }
    val regex = input.regex?.also {
        require(it.length <= MAX_HTTP_SEARCH_TEXT_CHARS) { "regex is too long" }
        validateSafeRegex(it, input.caseSensitive ?: true)
    }

    return NormalizedHttpSearchQuery(
        sources = sources,
        host = host,
        pathContains = pathContains,
        methods = methods,
        statusCodes = statusCodes,
        mimeTypes = mimeTypes,
        inScopeOnly = input.inScopeOnly ?: false,
        hasResponse = input.hasResponse,
        text = text,
        regex = regex,
        searchIn = input.searchIn ?: HttpSearchLocation.BOTH,
        caseSensitive = input.caseSensitive ?: (regex != null),
        newestFirst = input.newestFirst ?: true,
    )
}

private fun SearchHttpMessages.hasExplicitQuery(): Boolean =
    sources != null || host != null || pathContains != null || methods != null || statusCodes != null ||
        mimeTypes != null || inScopeOnly != null || hasResponse != null || text != null || regex != null ||
        searchIn != null || caseSensitive != null || newestFirst != null

private fun initialItemIndex(size: Int, newestFirst: Boolean): Int = if (newestFirst) size - 1 else 0

private fun normalizePosition(
    position: SearchPosition,
    snapshots: List<CursorSourceSnapshot>,
    newestFirst: Boolean,
) {
    while (position.sourceIndex < snapshots.size) {
        val size = snapshots[position.sourceIndex].size
        val valid = position.itemIndex in 0 until size
        if (valid) return
        position.sourceIndex++
        if (position.sourceIndex < snapshots.size) {
            position.itemIndex = initialItemIndex(snapshots[position.sourceIndex].size, newestFirst)
        }
    }
    position.itemIndex = 0
}

private fun advancePosition(
    position: SearchPosition,
    snapshots: List<CursorSourceSnapshot>,
    newestFirst: Boolean,
) {
    position.itemIndex += if (newestFirst) -1 else 1
    normalizePosition(position, snapshots, newestFirst)
}

private fun HttpMessageSearchService.searchError(
    status: HttpMessageSearchStatus,
    message: String,
    projectId: String? = null,
) = SearchHttpMessagesResult(
    status = status,
    projectId = projectId,
    items = emptyList(),
    returned = 0,
    scanned = 0,
    scannedContentBytes = 0,
    oversizedContentSkipped = 0,
    scanLimitReached = false,
    hasMore = false,
    nextCursor = null,
    error = message,
)

private fun siteMapReadError(
    status: SiteMapReadStatus,
    projectId: String,
    id: String,
    part: String,
    message: String,
) = SiteMapMessageReadResult(
    status = status,
    projectId = projectId,
    id = id,
    part = part,
    error = message,
)

private fun HttpMessageSource.displayName(): String = when (this) {
    HttpMessageSource.PROXY -> "HTTP history"
    HttpMessageSource.SITE_MAP -> "Site Map"
    HttpMessageSource.ORGANIZER -> "Organizer"
}

private fun messageBytes(request: HttpRequest): Long =
    request.bodyOffset().toLong().coerceAtLeast(0) + request.body().length().toLong().coerceAtLeast(0)

private fun messageBytes(response: HttpResponse): Long =
    response.bodyOffset().toLong().coerceAtLeast(0) + response.body().length().toLong().coerceAtLeast(0)

private fun String?.bounded(maxChars: Int): Pair<String?, Boolean> {
    if (this == null || length <= maxChars) return this to false
    return take(maxChars) to true
}
