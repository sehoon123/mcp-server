package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse as MontoyaHttpRequestResponse
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.security.MessageDigest
import java.util.HexFormat
import java.util.concurrent.TimeUnit

internal const val MAX_METADATA_INDEX_RECORDS_PER_SOURCE = 5_000
internal const val MAX_METADATA_INDEX_PATH_CHARS = 512
private const val MAX_METADATA_INDEX_ANCHORS = 16
private const val DEFAULT_METADATA_INDEX_REUSE_MILLIS = 30_000L
private const val METADATA_FINGERPRINT_HEX_CHARS = 32
private val METADATA_HEX_FORMAT = HexFormat.of()
private val NORMALIZED_METADATA_MIME_TYPES = MimeType.entries.associate { it.name to it.name.take(64).lowercase() }

/** Describes whether a source snapshot was reused, incrementally updated, or rebuilt. */
@Serializable
enum class MetadataIndexRefresh {
    @SerialName("reused")
    REUSED,

    @SerialName("updated")
    UPDATED,

    @SerialName("rebuilt")
    REBUILT,
}

/**
 * Body-free metadata retained by the extension-lifetime index.
 *
 * This type deliberately contains no Montoya object, header, note, URL query, or message body reference. A selected
 * source record must still be re-resolved from Burp and fingerprint-checked before any future detail/action use.
 */
internal data class HttpMetadataRecord(
    val source: HttpMessageSource,
    val sourceIndex: Int,
    val sourceId: String?,
    val fingerprint: String,
    val scheme: String,
    val host: String,
    val port: Int,
    val method: String,
    val path: String,
    val pathTruncated: Boolean,
    val statusCode: Int?,
    val mimeType: String?,
    val timestampEpochMillis: Long?,
    val hasResponse: Boolean,
    val inScope: Boolean,
)

internal data class HttpMetadataSourceSnapshot(
    val source: HttpMessageSource,
    val totalRecords: Int,
    val indexedFrom: Int,
    val slots: List<HttpMetadataRecord?>,
    val refresh: MetadataIndexRefresh,
) {
    val availableRecords: List<HttpMetadataRecord> get() = slots.filterNotNull()
    val unavailableRecords: Int get() = slots.count { it == null }
    val omittedRecords: Int get() = indexedFrom
}

internal data class HttpMetadataIndexSnapshot(
    val projectId: String,
    val sources: List<HttpMetadataSourceSnapshot>,
)

internal class HttpMetadataProjectMismatchException(val currentProjectId: String) : Exception()

/**
 * Lazily caches bounded metadata for the current project only.
 *
 * Source lists are local to a refresh and are never retained. Cache reuse validates bounded metadata anchors and is
 * time-limited so same-size edits outside sampled anchors cannot remain indefinitely stale. Project changes discard all
 * records before another result can be returned.
 */
internal class HttpMetadataIndex(
    private val api: MontoyaApi,
    private val maxRecordsPerSource: Int = MAX_METADATA_INDEX_RECORDS_PER_SOURCE,
    reuseMillis: Long = DEFAULT_METADATA_INDEX_REUSE_MILLIS,
    private val nanoTime: () -> Long = System::nanoTime,
) : AutoCloseable {
    private val lock = Mutex()
    // snapshot() serializes all source reads, so one digest can be safely reused without a ThreadLocal or per-record
    // provider lookup. Keeping it on this closeable index also avoids retaining the extension class loader in workers.
    private val fingerprinter = MetadataFingerprinter()
    private val entries = mutableMapOf<HttpMessageSource, CachedMetadataSource>()
    private val maxReuseNanos = TimeUnit.MILLISECONDS.toNanos(reuseMillis)
    private var observedProjectId: String? = null
    private var closed = false

    init {
        require(maxRecordsPerSource > 0) { "maxRecordsPerSource must be positive" }
        require(reuseMillis >= 0) { "reuseMillis must not be negative" }
    }

    suspend fun observeCurrentProject(): String = lock.withLock {
        check(!closed) { "HTTP metadata index is closed" }
        api.project().id().also(::observeProjectLocked)
    }

    suspend fun snapshot(
        expectedProjectId: String,
        sources: List<HttpMessageSource>,
    ): HttpMetadataIndexSnapshot {
        val coroutineContext = currentCoroutineContext()
        return lock.withLock {
            check(!closed) { "HTTP metadata index is closed" }
            val currentProjectId = api.project().id()
            observeProjectLocked(currentProjectId)
            if (currentProjectId != expectedProjectId) {
                throw HttpMetadataProjectMismatchException(currentProjectId)
            }

            val snapshots = ArrayList<HttpMetadataSourceSnapshot>(sources.size)
            for (source in sources) {
                coroutineContext.ensureActive()
                val view = loadView(source)
                snapshots += refreshSourceLocked(source, view, coroutineContext)
                val projectAfterSource = api.project().id()
                if (projectAfterSource != expectedProjectId) {
                    observeProjectLocked(projectAfterSource)
                    throw HttpMetadataProjectMismatchException(projectAfterSource)
                }
            }
            HttpMetadataIndexSnapshot(expectedProjectId, snapshots)
        }
    }

    suspend fun invalidate() {
        lock.withLock {
            entries.clear()
        }
    }

    override fun close() = runBlocking {
        lock.withLock {
            closed = true
            observedProjectId = null
            entries.clear()
        }
    }

    private fun observeProjectLocked(currentProjectId: String) {
        if (observedProjectId != currentProjectId) {
            entries.clear()
            observedProjectId = currentProjectId
        }
    }

    private fun refreshSourceLocked(
        source: HttpMessageSource,
        view: MetadataSourceView,
        coroutineContext: kotlin.coroutines.CoroutineContext,
    ): HttpMetadataSourceSnapshot {
        val now = nanoTime()
        val existing = entries[source]
        val reusableAge = existing != null && maxReuseNanos > 0 &&
            elapsedNanos(existing.refreshedAtNanos, now) < maxReuseNanos
        val anchorsValid = reusableAge && validateAnchors(view, existing.anchors)

        if (existing != null && reusableAge && anchorsValid && view.size == existing.totalRecords) {
            return existing.toSnapshot(MetadataIndexRefresh.REUSED)
        }

        val refreshed = if (
            existing != null && reusableAge && anchorsValid && view.size > existing.totalRecords
        ) {
            appendToExisting(view, existing, coroutineContext, now)
        } else {
            rebuild(view, coroutineContext, now)
        }
        entries[source] = refreshed
        return refreshed.toSnapshot(
            if (existing != null && reusableAge && anchorsValid && view.size > existing.totalRecords) {
                MetadataIndexRefresh.UPDATED
            } else {
                MetadataIndexRefresh.REBUILT
            }
        )
    }

    private fun appendToExisting(
        view: MetadataSourceView,
        existing: CachedMetadataSource,
        coroutineContext: kotlin.coroutines.CoroutineContext,
        refreshedAtNanos: Long,
    ): CachedMetadataSource {
        val indexedFrom = (view.size - maxRecordsPerSource).coerceAtLeast(0)
        val slots = ArrayList<HttpMetadataRecord?>(view.size - indexedFrom)
        for (index in indexedFrom until view.size) {
            if (index and 63 == 0) coroutineContext.ensureActive()
            val cachedOffset = index - existing.indexedFrom
            val cached = if (index < existing.totalRecords && cachedOffset in existing.slots.indices) {
                existing.slots[cachedOffset]
            } else {
                null
            }
            slots += if (index < existing.totalRecords && cachedOffset in existing.slots.indices) {
                cached
            } else {
                view.metadata(index)
            }
        }
        return CachedMetadataSource(
            source = view.source,
            totalRecords = view.size,
            indexedFrom = indexedFrom,
            slots = slots,
            anchors = createAnchors(view),
            refreshedAtNanos = refreshedAtNanos,
        )
    }

    private fun rebuild(
        view: MetadataSourceView,
        coroutineContext: kotlin.coroutines.CoroutineContext,
        refreshedAtNanos: Long,
    ): CachedMetadataSource {
        val indexedFrom = (view.size - maxRecordsPerSource).coerceAtLeast(0)
        val slots = ArrayList<HttpMetadataRecord?>(view.size - indexedFrom)
        for (index in indexedFrom until view.size) {
            if (index and 63 == 0) coroutineContext.ensureActive()
            slots += view.metadata(index)
        }
        return CachedMetadataSource(
            source = view.source,
            totalRecords = view.size,
            indexedFrom = indexedFrom,
            slots = slots,
            anchors = createAnchors(view),
            refreshedAtNanos = refreshedAtNanos,
        )
    }

    private fun createAnchors(view: MetadataSourceView): List<MetadataAnchor> =
        anchorIndexes(view.size).map { index -> MetadataAnchor(index, view.anchor(index)) }

    private fun validateAnchors(view: MetadataSourceView, anchors: List<MetadataAnchor>): Boolean {
        if (anchors.isEmpty()) return view.size == 0
        if (anchors.any { it.index !in 0 until view.size || it.fingerprint == null }) return false
        return anchors.all { anchor -> view.anchor(anchor.index) == anchor.fingerprint }
    }

    private fun loadView(source: HttpMessageSource): MetadataSourceView = when (source) {
        HttpMessageSource.PROXY -> ProxyMetadataSourceView(api.proxy().history(), fingerprinter)
        HttpMessageSource.SITE_MAP -> SiteMapMetadataSourceView(api.siteMap().requestResponses(), fingerprinter)
        HttpMessageSource.ORGANIZER -> OrganizerMetadataSourceView(api.organizer().items(), fingerprinter)
    }
}

private data class CachedMetadataSource(
    val source: HttpMessageSource,
    val totalRecords: Int,
    val indexedFrom: Int,
    val slots: List<HttpMetadataRecord?>,
    val anchors: List<MetadataAnchor>,
    val refreshedAtNanos: Long,
) {
    fun toSnapshot(refresh: MetadataIndexRefresh) = HttpMetadataSourceSnapshot(
        source = source,
        totalRecords = totalRecords,
        indexedFrom = indexedFrom,
        slots = slots,
        refresh = refresh,
    )
}

private data class MetadataAnchor(val index: Int, val fingerprint: String?)

private interface MetadataSourceView {
    val source: HttpMessageSource
    val size: Int
    fun metadata(index: Int): HttpMetadataRecord?
    fun anchor(index: Int): String? = metadata(index)?.fingerprint
}

private class ProxyMetadataSourceView(
    private val items: List<ProxyHttpRequestResponse>,
    private val fingerprinter: MetadataFingerprinter,
) : MetadataSourceView {
    override val source = HttpMessageSource.PROXY
    override val size: Int get() = items.size

    override fun metadata(index: Int): HttpMetadataRecord? = metadataOrNull {
        val item = items.getOrNull(index) ?: return@metadataOrNull null
        val sourceId = item.id().toString().takeIf { it.length in 1..128 } ?: return@metadataOrNull null
        metadataRecord(
            source = source,
            sourceIndex = index,
            sourceId = sourceId,
            request = item.request() ?: return@metadataOrNull null,
            response = item.response(),
            service = item.httpService(),
            timestampEpochMillis = optionalMetadata { item.time().toInstant().toEpochMilli() },
            fingerprinter = fingerprinter,
        )
    }
}

private class SiteMapMetadataSourceView(
    private val items: List<MontoyaHttpRequestResponse>,
    private val fingerprinter: MetadataFingerprinter,
) : MetadataSourceView {
    override val source = HttpMessageSource.SITE_MAP
    override val size: Int get() = items.size

    override fun metadata(index: Int): HttpMetadataRecord? = metadataOrNull {
        val item = items.getOrNull(index) ?: return@metadataOrNull null
        metadataRecord(
            source = source,
            sourceIndex = index,
            sourceId = null,
            request = item.request() ?: return@metadataOrNull null,
            response = item.response(),
            service = item.httpService(),
            fingerprinter = fingerprinter,
        )
    }
}

private class OrganizerMetadataSourceView(
    private val items: List<OrganizerItem>,
    private val fingerprinter: MetadataFingerprinter,
) : MetadataSourceView {
    override val source = HttpMessageSource.ORGANIZER
    override val size: Int get() = items.size

    override fun metadata(index: Int): HttpMetadataRecord? = metadataOrNull {
        val item = items.getOrNull(index) ?: return@metadataOrNull null
        val sourceId = item.id().toString().takeIf { it.length in 1..128 } ?: return@metadataOrNull null
        metadataRecord(
            source = source,
            sourceIndex = index,
            sourceId = sourceId,
            request = item.request() ?: return@metadataOrNull null,
            response = item.response(),
            service = item.httpService(),
            fingerprinter = fingerprinter,
        )
    }
}

private inline fun metadataOrNull(block: () -> HttpMetadataRecord?): HttpMetadataRecord? = try {
    block()
} catch (e: CancellationException) {
    throw e
} catch (_: Exception) {
    null
}

private inline fun <T> optionalMetadata(block: () -> T): T? = try {
    block()
} catch (e: CancellationException) {
    throw e
} catch (_: Exception) {
    null
}

private fun metadataRecord(
    source: HttpMessageSource,
    sourceIndex: Int,
    sourceId: String?,
    request: HttpRequest,
    response: HttpResponse?,
    service: HttpService,
    timestampEpochMillis: Long? = null,
    fingerprinter: MetadataFingerprinter,
): HttpMetadataRecord? {
    val host = service.host().trim().trimEnd('.').lowercase()
    if (host.isEmpty() || host.length > MAX_HTTP_SEARCH_HOST_CHARS || host.any(Char::isISOControl)) return null
    val port = service.port()
    if (port !in 1..65_535) return null
    val method = request.method().trim().uppercase()
    if (method.isEmpty() || method.length > 32 || method.any(Char::isISOControl)) return null
    val path = normalizeIndexedPath(request.path())
    val statusCode = response?.statusCode()?.toInt()
    val mimeType = response?.mimeType()?.name?.let(NORMALIZED_METADATA_MIME_TYPES::get)
    val scheme = if (service.secure()) "https" else "http"
    val hasResponse = response != null
    val inScope = request.isInScope()
    val fingerprint = fingerprinter.fingerprint(
        source = source,
        sourceIndex = sourceIndex,
        sourceId = sourceId,
        scheme = scheme,
        host = host,
        port = port,
        method = method,
        path = path.first,
        pathTruncated = path.second,
        statusCode = statusCode,
        mimeType = mimeType,
        timestampEpochMillis = timestampEpochMillis,
        hasResponse = hasResponse,
        inScope = inScope,
    )
    return HttpMetadataRecord(
        source = source,
        sourceIndex = sourceIndex,
        sourceId = sourceId,
        fingerprint = fingerprint,
        scheme = scheme,
        host = host,
        port = port,
        method = method,
        path = path.first,
        pathTruncated = path.second,
        statusCode = statusCode,
        mimeType = mimeType,
        timestampEpochMillis = timestampEpochMillis,
        hasResponse = hasResponse,
        inScope = inScope,
    )
}

private fun normalizeIndexedPath(value: String): Pair<String, Boolean> {
    if (
        value.isNotEmpty() && value.startsWith('/') && value.length <= MAX_METADATA_INDEX_PATH_CHARS &&
        '?' !in value && '#' !in value && value.none(Char::isISOControl)
    ) {
        return value to false
    }
    val withoutQuery = value.substringBefore('?').substringBefore('#').ifEmpty { "/" }
    val normalized = buildString(minOf(withoutQuery.length, MAX_METADATA_INDEX_PATH_CHARS)) {
        for (character in withoutQuery) {
            if (length >= MAX_METADATA_INDEX_PATH_CHARS) break
            append(if (character.isISOControl()) '_' else character)
        }
    }.let { if (it.startsWith('/')) it else "/$it" }
    return normalized.take(MAX_METADATA_INDEX_PATH_CHARS) to
        (withoutQuery.length > MAX_METADATA_INDEX_PATH_CHARS || normalized.length > MAX_METADATA_INDEX_PATH_CHARS)
}

private class MetadataFingerprinter {
    private val digest = MessageDigest.getInstance("SHA-256")

    fun fingerprint(
        source: HttpMessageSource,
        sourceIndex: Int,
        sourceId: String?,
        scheme: String,
        host: String,
        port: Int,
        method: String,
        path: String,
        pathTruncated: Boolean,
        statusCode: Int?,
        mimeType: String?,
        timestampEpochMillis: Long?,
        hasResponse: Boolean,
        inScope: Boolean,
    ): String {
        digest.reset()
        digest.update(1.toByte()) // Fingerprint framing version.
        update(source.name)
        update(sourceIndex)
        update(sourceId.orEmpty())
        update(scheme)
        update(host)
        update(port)
        update(method)
        update(path)
        update(pathTruncated)
        updateNullable(statusCode)
        update(mimeType.orEmpty())
        updateNullable(timestampEpochMillis)
        update(hasResponse)
        update(inScope)
        val fingerprintBytes = digest.digest()
        return METADATA_HEX_FORMAT.formatHex(fingerprintBytes, 0, METADATA_FINGERPRINT_HEX_CHARS / 2)
    }

    private fun update(field: String) {
        digest.update(field.toByteArray(Charsets.UTF_8))
        digest.update(0.toByte())
    }

    private fun update(value: Int) {
        for (shift in 24 downTo 0 step 8) digest.update((value ushr shift).toByte())
    }

    private fun update(value: Long) {
        for (shift in 56 downTo 0 step 8) digest.update((value ushr shift).toByte())
    }

    private fun update(value: Boolean) {
        digest.update(if (value) 1.toByte() else 0.toByte())
    }

    private fun updateNullable(value: Int?) {
        update(value != null)
        if (value != null) update(value)
    }

    private fun updateNullable(value: Long?) {
        update(value != null)
        if (value != null) update(value)
    }
}

private fun anchorIndexes(size: Int): List<Int> {
    if (size <= 0) return emptyList()
    if (size <= MAX_METADATA_INDEX_ANCHORS) return (0 until size).toList()
    val last = size - 1
    return (0 until MAX_METADATA_INDEX_ANCHORS)
        .map { slot -> ((slot.toLong() * last) / (MAX_METADATA_INDEX_ANCHORS - 1)).toInt() }
        .distinct()
}

private fun elapsedNanos(start: Long, end: Long): Long = (end - start).coerceAtLeast(0)
