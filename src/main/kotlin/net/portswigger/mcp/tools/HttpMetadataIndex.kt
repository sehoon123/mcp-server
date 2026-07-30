package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse as MontoyaHttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.security.MessageDigest
import java.util.HexFormat
import java.util.concurrent.TimeUnit

internal const val MAX_METADATA_INDEX_RECORDS_PER_SOURCE = 5_000
internal const val MAX_METADATA_INDEX_PATH_CHARS = MAX_INDEXED_HTTP_PATH_CHARS
private const val MAX_METADATA_INDEX_ANCHORS = 16
private const val MAX_METADATA_INDEX_REFRESH_ATTEMPTS = 2
private const val DEFAULT_METADATA_INDEX_REUSE_MILLIS = 30_000L
private const val METADATA_FINGERPRINT_HEX_CHARS = 32
private val METADATA_HEX_FORMAT = HexFormat.of()

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
    val numericSourceId: Int?,
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
    val sourceRevision: Long,
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
    val generation: Long,
    val sources: List<HttpMetadataSourceSnapshot>,
)

internal class HttpMetadataProjectMismatchException(val currentProjectId: String) : Exception()
internal class HttpMetadataIndexChangingException : Exception()

/**
 * Lazily caches bounded metadata for the current project only.
 *
 * Source lists are local to a refresh and are never retained. Refresh builders serialize separately, acquire and process
 * sources outside the state mutex, and publish all candidates only after a project/generation check. Cache reuse validates
 * bounded metadata anchors and is time-limited so same-size edits outside sampled anchors cannot remain indefinitely
 * stale. Project changes discard all records before another result can be returned.
 */
internal class HttpMetadataIndex(
    private val api: MontoyaApi,
    private val maxRecordsPerSource: Int = MAX_METADATA_INDEX_RECORDS_PER_SOURCE,
    reuseMillis: Long = DEFAULT_METADATA_INDEX_REUSE_MILLIS,
    private val nanoTime: () -> Long = System::nanoTime,
    private val performanceDiagnostics: HistoryPerformanceDiagnostics = HistoryPerformanceDiagnostics.NO_OP,
    private val changeSignals: MetadataChangeSignals = MetadataChangeSignals.NO_OP,
) : AutoCloseable {
    private val stateLock = Mutex()
    // Builders and hint validators take their coordination lock before brief stateLock sections. State-only paths never
    // acquire either coordination lock, and close drains them only after releasing stateLock.
    private val refreshLock = Mutex()
    private val searchHintLock = Mutex()
    // Refreshes and search hints may read metadata concurrently. Each serialized path owns its own mutable digest.
    private val refreshFingerprinter = MetadataFingerprinter()
    private val searchHintFingerprinter = MetadataFingerprinter()
    private val entries = mutableMapOf<HttpMessageSource, CachedMetadataSource>()
    private val maxReuseNanos = TimeUnit.MILLISECONDS.toNanos(reuseMillis)
    private var observedProjectId: String? = null
    private var generation = 0L
    private var activeMutations = 0
    private var closed = false

    init {
        require(maxRecordsPerSource > 0) { "maxRecordsPerSource must be positive" }
        require(reuseMillis >= 0) { "reuseMillis must not be negative" }
    }

    suspend fun observeCurrentProject(): String = stateLock.withLock {
        check(!closed) { "HTTP metadata index is closed" }
        ensureNoMutationLocked()
        api.project().id().also(::observeProjectLocked)
    }

    suspend fun snapshot(
        expectedProjectId: String,
        sources: List<HttpMessageSource>,
    ): HttpMetadataIndexSnapshot {
        require(sources.distinct().size == sources.size) { "sources must not contain duplicates" }
        val coroutineContext = currentCoroutineContext()
        return refreshLock.withLock {
            repeat(MAX_METADATA_INDEX_REFRESH_ATTEMPTS) { attempt ->
                try {
                    return@withLock buildSnapshotAttempt(expectedProjectId, sources, coroutineContext)
                } catch (_: MetadataRefreshEpochChangedException) {
                    coroutineContext.ensureActive()
                    if (attempt == MAX_METADATA_INDEX_REFRESH_ATTEMPTS - 1) {
                        throw HttpMetadataIndexChangingException()
                    }
                }
            }
            throw HttpMetadataIndexChangingException()
        }
    }

    private suspend fun buildSnapshotAttempt(
        expectedProjectId: String,
        sources: List<HttpMessageSource>,
        coroutineContext: kotlin.coroutines.CoroutineContext,
    ): HttpMetadataIndexSnapshot {
        val captured = captureRefreshState(expectedProjectId)
        val refreshed = ArrayList<RefreshedMetadataSource>(sources.size)
        for (sourceIndex in sources.indices) {
            val source = sources[sourceIndex]
            coroutineContext.ensureActive()
            val sourceRevision = changeSignals.revision(source.metadataChangeSource())
            val view = loadView(source, refreshFingerprinter)
            refreshed += performanceDiagnostics.measure(source.indexProcessingMetric()) {
                refreshSource(
                    existing = captured.entries[source],
                    sourceRevision = sourceRevision,
                    view = view,
                    coroutineContext = coroutineContext,
                )
            }
            if (sourceIndex < sources.lastIndex) {
                verifyRefreshEpoch(expectedProjectId, captured.generation)
            }
        }
        return publishRefresh(expectedProjectId, captured.generation, refreshed, coroutineContext)
    }

    private suspend fun captureRefreshState(expectedProjectId: String): CapturedMetadataState {
        val coroutineContext = currentCoroutineContext()
        coroutineContext.ensureActive()
        val currentProjectId = api.project().id()
        coroutineContext.ensureActive()
        return stateLock.withLock {
            check(!closed) { "HTTP metadata index is closed" }
            ensureNoMutationLocked()
            observeProjectLocked(currentProjectId)
            if (currentProjectId != expectedProjectId) {
                throw HttpMetadataProjectMismatchException(currentProjectId)
            }
            CapturedMetadataState(generation, entries.toMap())
        }
    }

    private suspend fun verifyRefreshEpoch(expectedProjectId: String, capturedGeneration: Long) {
        val coroutineContext = currentCoroutineContext()
        coroutineContext.ensureActive()
        val currentProjectId = api.project().id()
        coroutineContext.ensureActive()
        stateLock.withLock {
            check(!closed) { "HTTP metadata index is closed" }
            ensureNoMutationLocked()
            observeProjectLocked(currentProjectId)
            if (currentProjectId != expectedProjectId) {
                throw HttpMetadataProjectMismatchException(currentProjectId)
            }
            if (generation != capturedGeneration) throw MetadataRefreshEpochChangedException()
        }
    }

    private suspend fun publishRefresh(
        expectedProjectId: String,
        capturedGeneration: Long,
        refreshed: List<RefreshedMetadataSource>,
        coroutineContext: kotlin.coroutines.CoroutineContext,
    ): HttpMetadataIndexSnapshot {
        coroutineContext.ensureActive()
        val currentProjectId = api.project().id()
        coroutineContext.ensureActive()
        return stateLock.withLock {
            check(!closed) { "HTTP metadata index is closed" }
            ensureNoMutationLocked()
            observeProjectLocked(currentProjectId)
            if (currentProjectId != expectedProjectId) {
                throw HttpMetadataProjectMismatchException(currentProjectId)
            }
            if (generation != capturedGeneration) throw MetadataRefreshEpochChangedException()
            val cacheChanged = refreshed.any { result -> entries[result.cached.source] !== result.cached }
            refreshed.forEach { result -> entries[result.cached.source] = result.cached }
            if (cacheChanged) generation++
            HttpMetadataIndexSnapshot(expectedProjectId, generation, refreshed.map(RefreshedMetadataSource::snapshot))
        }
    }

    /**
     * Returns recent, already-warm metadata strictly as search branch-prediction hints.
     *
     * This path returns only same-size sources that pass the normal bounded anchor and age checks. Every predicted
     * rejection must still be checked against the corresponding field and numeric ID on the current Proxy or Organizer
     * record before it can be skipped; hints must never authorize aggregation, details, or actions. Contention returns no
     * hints immediately, so a selective query never waits for or performs a cold 5,000-record build.
     */
    suspend fun searchHintsSnapshot(
        expectedProjectId: String,
        sources: List<HttpMessageSource>,
        requestScopedRecords: Map<HttpMessageSource, HttpSourceRecords>? = null,
    ): HttpMetadataIndexSnapshot? {
        require(sources.all { it == HttpMessageSource.PROXY || it == HttpMessageSource.ORGANIZER }) {
            "Search hints support only Proxy and Organizer records"
        }
        require(sources.distinct().size == sources.size) { "Search hint sources must not contain duplicates" }
        require(
            requestScopedRecords == null || sources.all { source -> requestScopedRecords[source]?.source == source }
        ) {
            "Request-scoped search records must contain every requested source"
        }
        if (!searchHintLock.tryLock()) return null
        return try {
            val coroutineContext = currentCoroutineContext()
            val captured = captureSearchHintState(expectedProjectId) ?: return null
            val now = nanoTime()
            val validations = ArrayList<MetadataHintValidation>(sources.size)
            for (sourceIndex in sources.indices) {
                val source = sources[sourceIndex]
                coroutineContext.ensureActive()
                val existing = captured.entries[source] ?: continue
                val sourceRevision = changeSignals.revision(source.metadataChangeSource())
                val reusableAge = maxReuseNanos > 0 &&
                    elapsedNanos(existing.rebuiltAtNanos, now) < maxReuseNanos
                if (!reusableAge || existing.sourceRevision != sourceRevision) continue

                val view = requestScopedRecords?.getValue(source)?.toMetadataSourceView(searchHintFingerprinter)
                    ?: loadView(source, searchHintFingerprinter)
                validations += performanceDiagnostics.measure(source.indexProcessingMetric()) {
                    val sameSize = view.size == existing.totalRecords
                    val reusable = sameSize && validateAnchors(view, existing.anchors)
                    MetadataHintValidation(
                        cached = existing,
                        snapshot = if (reusable) existing.toSnapshot(MetadataIndexRefresh.REUSED) else null,
                        invalidatesCachedEntry = sameSize && !reusable,
                    )
                }
                if (
                    sourceIndex < sources.lastIndex &&
                    !isSearchHintEpochCurrent(expectedProjectId, captured.generation, coroutineContext)
                ) {
                    return null
                }
            }
            if (validations.isEmpty()) return null
            publishSearchHints(expectedProjectId, captured.generation, validations, coroutineContext)
        } finally {
            searchHintLock.unlock()
        }
    }

    private suspend fun captureSearchHintState(expectedProjectId: String): CapturedMetadataState? {
        if (!stateLock.tryLock()) return null
        try {
            check(!closed) { "HTTP metadata index is closed" }
            ensureNoMutationLocked()
        } finally {
            stateLock.unlock()
        }

        val coroutineContext = currentCoroutineContext()
        coroutineContext.ensureActive()
        val currentProjectId = api.project().id()
        coroutineContext.ensureActive()
        if (!stateLock.tryLock()) return null
        return try {
            check(!closed) { "HTTP metadata index is closed" }
            ensureNoMutationLocked()
            observeProjectLocked(currentProjectId)
            if (currentProjectId != expectedProjectId) {
                throw HttpMetadataProjectMismatchException(currentProjectId)
            }
            CapturedMetadataState(generation, entries.toMap())
        } finally {
            stateLock.unlock()
        }
    }

    private suspend fun isSearchHintEpochCurrent(
        expectedProjectId: String,
        capturedGeneration: Long,
        coroutineContext: kotlin.coroutines.CoroutineContext,
    ): Boolean {
        coroutineContext.ensureActive()
        val currentProjectId = api.project().id()
        coroutineContext.ensureActive()
        return stateLock.withLock {
            check(!closed) { "HTTP metadata index is closed" }
            ensureNoMutationLocked()
            observeProjectLocked(currentProjectId)
            if (currentProjectId != expectedProjectId) {
                throw HttpMetadataProjectMismatchException(currentProjectId)
            }
            generation == capturedGeneration
        }
    }

    private suspend fun publishSearchHints(
        expectedProjectId: String,
        capturedGeneration: Long,
        validations: List<MetadataHintValidation>,
        coroutineContext: kotlin.coroutines.CoroutineContext,
    ): HttpMetadataIndexSnapshot? {
        coroutineContext.ensureActive()
        val currentProjectId = api.project().id()
        coroutineContext.ensureActive()
        return stateLock.withLock {
            check(!closed) { "HTTP metadata index is closed" }
            ensureNoMutationLocked()
            observeProjectLocked(currentProjectId)
            if (currentProjectId != expectedProjectId) {
                throw HttpMetadataProjectMismatchException(currentProjectId)
            }
            if (generation != capturedGeneration) return@withLock null

            validations.asSequence()
                .filter(MetadataHintValidation::invalidatesCachedEntry)
                .map(MetadataHintValidation::cached)
                .filter { cached -> entries[cached.source] === cached }
                .forEach { cached ->
                    entries.remove(cached.source)
                    generation++
                }
            val snapshots = validations.mapNotNull { validation ->
                validation.snapshot?.takeIf { snapshot ->
                    entries[validation.cached.source] === validation.cached &&
                        changeSignals.revision(snapshot.source.metadataChangeSource()) == snapshot.sourceRevision
                }
            }
            snapshots.takeIf { it.isNotEmpty() }?.let {
                HttpMetadataIndexSnapshot(expectedProjectId, generation, it)
            }
        }
    }

    /** Non-blocking response-point check for advisory search hints; contention forces the existing raw retry. */
    suspend fun areSearchHintsCurrent(snapshot: HttpMetadataIndexSnapshot): Boolean {
        if (!stateLock.tryLock()) return false
        return try {
            check(!closed) { "HTTP metadata index is closed" }
            ensureNoMutationLocked()
            val currentProjectId = api.project().id()
            observeProjectLocked(currentProjectId)
            if (currentProjectId != snapshot.projectId) {
                throw HttpMetadataProjectMismatchException(currentProjectId)
            }
            snapshot.generation == generation && snapshot.hasCurrentSourceRevisions()
        } finally {
            stateLock.unlock()
        }
    }

    /**
     * Rechecks the project and invalidation generation at the response linearization point.
     *
     * A false result means the caller may rebuild once. Project changes and an active project/Scope mutation fail
     * closed with their dedicated exceptions instead of allowing an old snapshot to be returned.
     */
    suspend fun isSnapshotCurrent(snapshot: HttpMetadataIndexSnapshot): Boolean = stateLock.withLock {
        check(!closed) { "HTTP metadata index is closed" }
        ensureNoMutationLocked()
        val currentProjectId = api.project().id()
        observeProjectLocked(currentProjectId)
        if (currentProjectId != snapshot.projectId) {
            throw HttpMetadataProjectMismatchException(currentProjectId)
        }
        snapshot.generation == generation && snapshot.hasCurrentSourceRevisions()
    }

    private fun HttpMetadataIndexSnapshot.hasCurrentSourceRevisions(): Boolean = sources.all { source ->
        changeSignals.revision(source.source.metadataChangeSource()) == source.sourceRevision
    }

    /** Prevents snapshots from being built or returned while an MCP project/Scope mutation is executing. */
    suspend fun <T> withMutation(block: suspend () -> T): T {
        beginMutation()
        return try {
            block()
        } finally {
            withContext(NonCancellable) {
                endMutation()
            }
        }
    }

    suspend fun invalidate() {
        stateLock.withLock {
            if (!closed) invalidateLocked()
        }
    }

    suspend fun resetForProjectBoundary() {
        stateLock.withLock {
            if (!closed) {
                observedProjectId = null
                invalidateLocked()
            }
        }
    }

    override fun close() = runBlocking {
        stateLock.withLock {
            if (!closed) {
                closed = true
                observedProjectId = null
                invalidateLocked()
            }
        }
        // Preserve unload quiescence: no refresh or hint validation may retain Montoya objects after close returns.
        refreshLock.withLock { }
        searchHintLock.withLock { }
    }

    private suspend fun beginMutation() {
        stateLock.withLock {
            check(!closed) { "HTTP metadata index is closed" }
            activeMutations++
            invalidateLocked()
        }
    }

    private suspend fun endMutation() {
        stateLock.withLock {
            check(activeMutations > 0) { "HTTP metadata mutation tracking is unbalanced" }
            activeMutations--
            invalidateLocked()
        }
    }

    private fun ensureNoMutationLocked() {
        if (activeMutations > 0) throw HttpMetadataIndexChangingException()
    }

    private fun observeProjectLocked(currentProjectId: String) {
        if (observedProjectId != currentProjectId) {
            observedProjectId = currentProjectId
            invalidateLocked()
        }
    }

    private fun invalidateLocked() {
        entries.clear()
        generation++
    }

    private fun refreshSource(
        existing: CachedMetadataSource?,
        sourceRevision: Long,
        view: MetadataSourceView,
        coroutineContext: kotlin.coroutines.CoroutineContext,
    ): RefreshedMetadataSource {
        val now = nanoTime()
        val reusableAge = existing != null && maxReuseNanos > 0 &&
            elapsedNanos(existing.rebuiltAtNanos, now) < maxReuseNanos
        val anchorsValid = reusableAge && validateAnchors(view, existing.anchors)

        if (
            existing != null && existing.sourceRevision == sourceRevision && reusableAge && anchorsValid &&
            view.size == existing.totalRecords
        ) {
            return RefreshedMetadataSource(existing, existing.toSnapshot(MetadataIndexRefresh.REUSED))
        }

        val append = existing != null && reusableAge && anchorsValid && view.size > existing.totalRecords
        val refreshed = if (append) {
            appendToExisting(view, requireNotNull(existing), sourceRevision, coroutineContext)
        } else {
            rebuild(view, sourceRevision, coroutineContext, now)
        }
        val refresh = if (append) MetadataIndexRefresh.UPDATED else MetadataIndexRefresh.REBUILT
        return RefreshedMetadataSource(refreshed, refreshed.toSnapshot(refresh))
    }

    private fun appendToExisting(
        view: MetadataSourceView,
        existing: CachedMetadataSource,
        sourceRevision: Long,
        coroutineContext: kotlin.coroutines.CoroutineContext,
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
            sourceRevision = sourceRevision,
            totalRecords = view.size,
            indexedFrom = indexedFrom,
            slots = slots,
            anchors = createAnchors(view),
            rebuiltAtNanos = existing.rebuiltAtNanos,
        )
    }

    private fun rebuild(
        view: MetadataSourceView,
        sourceRevision: Long,
        coroutineContext: kotlin.coroutines.CoroutineContext,
        rebuiltAtNanos: Long,
    ): CachedMetadataSource {
        val indexedFrom = (view.size - maxRecordsPerSource).coerceAtLeast(0)
        val slots = ArrayList<HttpMetadataRecord?>(view.size - indexedFrom)
        for (index in indexedFrom until view.size) {
            if (index and 63 == 0) coroutineContext.ensureActive()
            slots += view.metadata(index)
        }
        return CachedMetadataSource(
            source = view.source,
            sourceRevision = sourceRevision,
            totalRecords = view.size,
            indexedFrom = indexedFrom,
            slots = slots,
            anchors = createAnchors(view),
            rebuiltAtNanos = rebuiltAtNanos,
        )
    }

    private fun createAnchors(view: MetadataSourceView): List<MetadataAnchor> =
        anchorIndexes(view.size).map { index -> MetadataAnchor(index, view.anchor(index)) }

    private fun validateAnchors(view: MetadataSourceView, anchors: List<MetadataAnchor>): Boolean {
        if (anchors.isEmpty()) return view.size == 0
        if (anchors.any { it.index !in 0 until view.size || it.fingerprint == null }) return false
        return anchors.all { anchor -> view.anchor(anchor.index) == anchor.fingerprint }
    }

    private suspend fun loadView(
        source: HttpMessageSource,
        fingerprinter: MetadataFingerprinter,
    ): MetadataSourceView {
        val coroutineContext = currentCoroutineContext()
        coroutineContext.ensureActive()
        val view = when (source) {
            HttpMessageSource.PROXY -> {
                val proxy = api.proxy()
                val records = performanceDiagnostics.measure(source.indexAcquisitionMetric()) {
                    proxy.history()
                }
                ProxyMetadataSourceView(records, fingerprinter)
            }
            HttpMessageSource.SITE_MAP -> {
                val siteMap = api.siteMap()
                val records = performanceDiagnostics.measure(source.indexAcquisitionMetric()) {
                    siteMap.requestResponses()
                }
                SiteMapMetadataSourceView(records, fingerprinter)
            }
            HttpMessageSource.ORGANIZER -> {
                val organizer = api.organizer()
                val records = performanceDiagnostics.measure(source.indexAcquisitionMetric()) {
                    organizer.items()
                }
                OrganizerMetadataSourceView(records, fingerprinter)
            }
        }
        coroutineContext.ensureActive()
        return view
    }
}

private fun HttpMessageSource.indexAcquisitionMetric(): HistoryPerformanceMetric = when (this) {
    HttpMessageSource.PROXY -> HistoryPerformanceMetric.INDEX_PROXY_ACQUISITION
    HttpMessageSource.SITE_MAP -> HistoryPerformanceMetric.INDEX_SITE_MAP_ACQUISITION
    HttpMessageSource.ORGANIZER -> HistoryPerformanceMetric.INDEX_ORGANIZER_ACQUISITION
}

private fun HttpMessageSource.indexProcessingMetric(): HistoryPerformanceMetric = when (this) {
    HttpMessageSource.PROXY -> HistoryPerformanceMetric.INDEX_PROXY_PROCESSING
    HttpMessageSource.SITE_MAP -> HistoryPerformanceMetric.INDEX_SITE_MAP_PROCESSING
    HttpMessageSource.ORGANIZER -> HistoryPerformanceMetric.INDEX_ORGANIZER_PROCESSING
}

private data class CapturedMetadataState(
    val generation: Long,
    val entries: Map<HttpMessageSource, CachedMetadataSource>,
)

private data class RefreshedMetadataSource(
    val cached: CachedMetadataSource,
    val snapshot: HttpMetadataSourceSnapshot,
)

private data class MetadataHintValidation(
    val cached: CachedMetadataSource,
    val snapshot: HttpMetadataSourceSnapshot?,
    val invalidatesCachedEntry: Boolean,
)

private class MetadataRefreshEpochChangedException : Exception()

private data class CachedMetadataSource(
    val source: HttpMessageSource,
    val sourceRevision: Long,
    val totalRecords: Int,
    val indexedFrom: Int,
    val slots: List<HttpMetadataRecord?>,
    val anchors: List<MetadataAnchor>,
    val rebuiltAtNanos: Long,
) {
    fun toSnapshot(refresh: MetadataIndexRefresh) = HttpMetadataSourceSnapshot(
        source = source,
        sourceRevision = sourceRevision,
        totalRecords = totalRecords,
        indexedFrom = indexedFrom,
        slots = slots,
        refresh = refresh,
    )
}

private data class MetadataAnchor(val index: Int, val fingerprint: String?)

private fun HttpSourceRecords.toMetadataSourceView(fingerprinter: MetadataFingerprinter): MetadataSourceView =
    when (this) {
        is HttpSourceRecords.Proxy -> ProxyMetadataSourceView(items, fingerprinter)
        is HttpSourceRecords.SiteMap -> SiteMapMetadataSourceView(items, fingerprinter)
        is HttpSourceRecords.Organizer -> OrganizerMetadataSourceView(items, fingerprinter)
    }

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
        val numericSourceId = item.id()
        val sourceId = numericSourceId.toString().takeIf { it.length in 1..128 } ?: return@metadataOrNull null
        metadataRecord(
            source = source,
            sourceIndex = index,
            sourceId = sourceId,
            numericSourceId = numericSourceId,
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
            numericSourceId = null,
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
        val numericSourceId = item.id()
        val sourceId = numericSourceId.toString().takeIf { it.length in 1..128 } ?: return@metadataOrNull null
        metadataRecord(
            source = source,
            sourceIndex = index,
            sourceId = sourceId,
            numericSourceId = numericSourceId,
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
    numericSourceId: Int?,
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
    val path = normalizeHttpPath(request.path())
    val statusCode = response?.statusCode()?.toInt()
    val mimeType = normalizeHttpMimeType(response?.mimeType())
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
        path = path.value,
        pathTruncated = path.truncated,
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
        numericSourceId = numericSourceId,
        fingerprint = fingerprint,
        scheme = scheme,
        host = host,
        port = port,
        method = method,
        path = path.value,
        pathTruncated = path.truncated,
        statusCode = statusCode,
        mimeType = mimeType,
        timestampEpochMillis = timestampEpochMillis,
        hasResponse = hasResponse,
        inScope = inScope,
    )
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
