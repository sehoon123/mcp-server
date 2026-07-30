package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.organizer.Organizer
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.sitemap.SiteMap
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.ZonedDateTime
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HttpMetadataIndexTest {
    private val api = mockk<MontoyaApi>()
    private val project = mockk<Project>()
    private val proxy = mockk<Proxy>()
    private val history = mutableListOf<ProxyHttpRequestResponse>()
    private var projectId = "project-one"
    private var nowNanos = 1L

    @BeforeEach
    fun setUp() {
        every { api.project() } returns project
        every { project.id() } answers { projectId }
        every { api.proxy() } returns proxy
        every { proxy.history() } answers { history.toList() }
    }

    @Test
    fun `index retains only bounded query-free metadata and never reads bodies headers or notes`() = runBlocking {
        val first = proxyItem(1, "/old?token=old", inScope = true)
        val second = proxyItem(2, "/api/users/123?token=secret", inScope = true)
        val third = proxyItem(3, "/api/users/456#fragment", inScope = false)
        history += listOf(first.item, second.item, third.item)
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })

        val snapshot = index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single()

        assertEquals(3, snapshot.totalRecords)
        assertEquals(1, snapshot.indexedFrom)
        assertEquals(1, snapshot.omittedRecords)
        assertEquals(listOf(1, 2), snapshot.availableRecords.map { it.sourceIndex })
        assertEquals(listOf(2, 3), snapshot.availableRecords.map { it.numericSourceId })
        assertEquals(listOf("/api/users/123", "/api/users/456"), snapshot.availableRecords.map { it.path })
        assertTrue(snapshot.availableRecords.all { '?' !in it.path && '#' !in it.path })
        assertTrue(snapshot.availableRecords.all { it.fingerprint.matches(Regex("[a-f0-9]{32}")) })
        assertTrue(snapshot.availableRecords.all { it.timestampEpochMillis == 1_767_323_045_000L })
        assertFalse(snapshot.availableRecords.first().pathTruncated)
        assertTrue(
            HttpMetadataRecord::class.java.declaredFields.none {
                it.type.name.startsWith("burp.api.montoya") || it.type == ByteArray::class.java
            },
        )
        verify(exactly = 0) { first.request.body() }
        verify(exactly = 0) { second.request.body() }
        verify(exactly = 0) { third.request.body() }
        verify(exactly = 0) { first.request.headers() }
        verify(exactly = 0) { second.request.headers() }
        verify(exactly = 0) { third.request.headers() }
        verify(exactly = 0) { first.item.annotations() }
        verify(exactly = 0) { second.item.annotations() }
        verify(exactly = 0) { third.item.annotations() }
    }

    @Test
    fun `large source indexing touches only the bounded newest range and metadata anchors`() = runBlocking {
        val fixture = proxyItem(1, "/bounded")
        var getCalls = 0
        val syntheticHistory = object : AbstractList<ProxyHttpRequestResponse>() {
            override val size = 100_000

            override fun get(index: Int): ProxyHttpRequestResponse {
                require(index in indices)
                getCalls++
                return fixture.item
            }
        }
        every { proxy.history() } returns syntheticHistory
        val diagnostics = HistoryPerformanceDiagnostics()
        val index = HttpMetadataIndex(
            api,
            nanoTime = { nowNanos },
            performanceDiagnostics = diagnostics,
        )

        val snapshot = index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single()

        assertEquals(MAX_METADATA_INDEX_RECORDS_PER_SOURCE, snapshot.slots.size)
        assertEquals(95_000, snapshot.omittedRecords)
        assertEquals(MAX_METADATA_INDEX_RECORDS_PER_SOURCE, snapshot.availableRecords.size)
        assertTrue(getCalls <= MAX_METADATA_INDEX_RECORDS_PER_SOURCE + 16)
        val metrics = diagnostics.snapshot().metrics.associateBy { it.metric }
        assertEquals(1, metrics.getValue(HistoryPerformanceMetric.INDEX_PROXY_ACQUISITION).attempts)
        assertEquals(1, metrics.getValue(HistoryPerformanceMetric.INDEX_PROXY_PROCESSING).attempts)
        verify(exactly = 0) { fixture.request.body() }
    }

    @Test
    fun `index records source acquisition and processing as separate fixed metrics`() = runBlocking {
        history += proxyItem(1, "/measured").item
        var clock = 0L
        every { api.proxy() } answers {
            clock += 100L
            proxy
        }
        every { proxy.history() } answers {
            clock += 7L
            history.toList()
        }
        val diagnostics = HistoryPerformanceDiagnostics { clock }
        val index = HttpMetadataIndex(
            api,
            maxRecordsPerSource = 2,
            nanoTime = { nowNanos },
            performanceDiagnostics = diagnostics,
        )

        index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        val metrics = diagnostics.snapshot().metrics.associateBy { it.metric }
        assertEquals(1, metrics.getValue(HistoryPerformanceMetric.INDEX_PROXY_ACQUISITION).attempts)
        assertEquals(1, metrics.getValue(HistoryPerformanceMetric.INDEX_PROXY_PROCESSING).attempts)
        assertEquals(0, metrics.getValue(HistoryPerformanceMetric.INDEX_SITE_MAP_ACQUISITION).attempts)
        assertEquals(1, metrics.getValue(HistoryPerformanceMetric.INDEX_PROXY_ACQUISITION).completed)
        assertEquals(7L, metrics.getValue(HistoryPerformanceMetric.INDEX_PROXY_ACQUISITION).maxNanos)
        assertEquals(1, metrics.getValue(HistoryPerformanceMetric.INDEX_PROXY_PROCESSING).completed)
    }

    @Test
    fun `source signals invalidate captured snapshots and drive bounded append refresh`() = runBlocking {
        history += proxyItem(1, "/one").item
        val signals = MetadataChangeSignals()
        val index = HttpMetadataIndex(
            api,
            maxRecordsPerSource = 2,
            nanoTime = { nowNanos },
            changeSignals = signals,
        )
        val first = index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        assertTrue(index.isSnapshotCurrent(first))

        signals.markChanged(MetadataChangeSource.PROXY_HTTP)
        assertFalse(index.isSnapshotCurrent(first))
        history += proxyItem(2, "/two").item
        val refreshed = index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        assertEquals(MetadataIndexRefresh.UPDATED, refreshed.sources.single().refresh)
        assertEquals(1L, refreshed.sources.single().sourceRevision)
        assertEquals(listOf(1, 2), refreshed.sources.single().availableRecords.map { it.numericSourceId })
        assertTrue(index.isSnapshotCurrent(refreshed))
    }

    @Test
    fun `same-size signal forces bounded rebuild while unrelated signals preserve currentness`() = runBlocking {
        history += proxyItem(1, "/one").item
        val signals = MetadataChangeSignals()
        val index = HttpMetadataIndex(
            api,
            maxRecordsPerSource = 2,
            nanoTime = { nowNanos },
            changeSignals = signals,
        )
        val first = index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        signals.markChanged(MetadataChangeSource.ORGANIZER)
        assertTrue(index.isSnapshotCurrent(first))
        signals.markChanged(MetadataChangeSource.PROXY_HTTP)
        val rebuilt = index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        assertEquals(MetadataIndexRefresh.REBUILT, rebuilt.sources.single().refresh)
        assertEquals(1L, rebuilt.sources.single().sourceRevision)
    }

    @Test
    fun `event before list visibility remains advisory and later size change is detected`() = runBlocking {
        history += proxyItem(1, "/old-visible").item
        val signals = MetadataChangeSignals()
        val index = HttpMetadataIndex(
            api,
            maxRecordsPerSource = 2,
            nanoTime = { nowNanos },
            changeSignals = signals,
        )
        index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        signals.markChanged(MetadataChangeSource.PROXY_HTTP)
        val beforeVisibility = index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        assertEquals(MetadataIndexRefresh.REBUILT, beforeVisibility.sources.single().refresh)
        assertEquals(1, beforeVisibility.sources.single().totalRecords)
        history += proxyItem(2, "/later-visible").item

        val hints = index.searchHintsSnapshot("project-one", listOf(HttpMessageSource.PROXY))
        val afterVisibility = index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        assertEquals(null, hints)
        assertEquals(MetadataIndexRefresh.UPDATED, afterVisibility.sources.single().refresh)
        assertEquals(2, afterVisibility.sources.single().totalRecords)
    }

    @Test
    fun `signal racing acquisition prevents publication from becoming current`() = runBlocking {
        history += proxyItem(1, "/raced").item
        val signals = MetadataChangeSignals()
        val acquisitions = AtomicInteger()
        every { proxy.history() } answers {
            if (acquisitions.incrementAndGet() == 1) {
                signals.markChanged(MetadataChangeSource.PROXY_HTTP)
            }
            history.toList()
        }
        val index = HttpMetadataIndex(
            api,
            maxRecordsPerSource = 2,
            nanoTime = { nowNanos },
            changeSignals = signals,
        )

        val raced = index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        val hints = index.searchHintsSnapshot("project-one", listOf(HttpMessageSource.PROXY))
        val refreshed = index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        assertEquals(0L, raced.sources.single().sourceRevision)
        assertFalse(index.isSnapshotCurrent(raced))
        assertEquals(null, hints)
        assertEquals(MetadataIndexRefresh.REBUILT, refreshed.sources.single().refresh)
        assertEquals(1L, refreshed.sources.single().sourceRevision)
        assertTrue(index.isSnapshotCurrent(refreshed))
        assertEquals(2, acquisitions.get())
    }

    @Test
    fun `search hint snapshot never performs a cold source build`() = runBlocking {
        history += proxyItem(1, "/cold").item
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })

        val snapshot = index.searchHintsSnapshot("project-one", listOf(HttpMessageSource.PROXY))

        assertEquals(null, snapshot)
        assertFailsWith<IllegalArgumentException> {
            index.searchHintsSnapshot("project-one", listOf(HttpMessageSource.SITE_MAP))
        }
        verify(exactly = 0) { proxy.history() }
    }

    @Test
    fun `search hint snapshot returns recent same-size anchor-validated metadata`() = runBlocking {
        history += proxyItem(1, "/warm").item
        val diagnostics = HistoryPerformanceDiagnostics()
        val index = HttpMetadataIndex(
            api,
            maxRecordsPerSource = 2,
            nanoTime = { nowNanos },
            performanceDiagnostics = diagnostics,
        )
        index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        val cached = index.searchHintsSnapshot("project-one", listOf(HttpMessageSource.PROXY))

        assertEquals(MetadataIndexRefresh.REUSED, cached?.sources?.single()?.refresh)
        assertEquals(1, cached?.sources?.single()?.availableRecords?.size)
        val metrics = diagnostics.snapshot().metrics.associateBy { it.metric }
        assertEquals(2, metrics.getValue(HistoryPerformanceMetric.INDEX_PROXY_ACQUISITION).attempts)
        assertEquals(2, metrics.getValue(HistoryPerformanceMetric.INDEX_PROXY_PROCESSING).attempts)
        verify(exactly = 2) { proxy.history() }
    }

    @Test
    fun `search hint snapshot reuses request scoped records without a second acquisition`() = runBlocking {
        history += proxyItem(1, "/warm").item
        val diagnostics = HistoryPerformanceDiagnostics()
        val index = HttpMetadataIndex(
            api,
            maxRecordsPerSource = 2,
            nanoTime = { nowNanos },
            performanceDiagnostics = diagnostics,
        )
        index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        val cached = index.searchHintsSnapshot(
            "project-one",
            listOf(HttpMessageSource.PROXY),
            mapOf(HttpMessageSource.PROXY to HttpSourceRecords.Proxy(history.toList())),
        )

        assertEquals(MetadataIndexRefresh.REUSED, cached?.sources?.single()?.refresh)
        val metrics = diagnostics.snapshot().metrics.associateBy { it.metric }
        assertEquals(1, metrics.getValue(HistoryPerformanceMetric.INDEX_PROXY_ACQUISITION).attempts)
        assertEquals(2, metrics.getValue(HistoryPerformanceMetric.INDEX_PROXY_PROCESSING).attempts)
        verify(exactly = 1) { proxy.history() }
    }

    @Test
    fun `dirty search hints omit the source without acquisition or cold work`() = runBlocking {
        history += proxyItem(1, "/dirty").item
        val signals = MetadataChangeSignals()
        val index = HttpMetadataIndex(
            api,
            maxRecordsPerSource = 2,
            nanoTime = { nowNanos },
            changeSignals = signals,
        )
        index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        signals.markChanged(MetadataChangeSource.PROXY_HTTP)

        val hints = index.searchHintsSnapshot("project-one", listOf(HttpMessageSource.PROXY))

        assertEquals(null, hints)
        verify(exactly = 1) { proxy.history() }
    }

    @Test
    fun `search hints never wait for a contended index build`() = runBlocking {
        val fixture = proxyItem(1, "/contended")
        val enteredRequest = CountDownLatch(1)
        val releaseRequest = CountDownLatch(1)
        every { fixture.item.request() } answers {
            enteredRequest.countDown()
            check(releaseRequest.await(5, TimeUnit.SECONDS)) { "timed out waiting to release index build" }
            fixture.request
        }
        history += fixture.item
        val diagnostics = HistoryPerformanceDiagnostics()
        val signals = MetadataChangeSignals()
        val index = HttpMetadataIndex(
            api,
            maxRecordsPerSource = 2,
            nanoTime = { nowNanos },
            performanceDiagnostics = diagnostics,
            changeSignals = signals,
        )
        val build = async(Dispatchers.Default) {
            index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        }
        assertTrue(enteredRequest.await(5, TimeUnit.SECONDS))
        repeat(100_000) { signals.markChanged(MetadataChangeSource.WEBSOCKET) }
        assertEquals(100_000L, signals.revision(MetadataChangeSource.WEBSOCKET))

        try {
            assertEquals(
                null,
                withTimeout(250) { index.searchHintsSnapshot("project-one", listOf(HttpMessageSource.PROXY)) },
            )
        } finally {
            releaseRequest.countDown()
        }
        assertEquals("project-one", build.await().projectId)
        assertEquals(
            1,
            diagnostics.snapshot().metrics.single {
                it.metric == HistoryPerformanceMetric.INDEX_PROXY_ACQUISITION
            }.attempts,
        )
    }

    @Test
    fun `blocked acquisition releases invalidation reset and completed mutation operations`() = runBlocking {
        val before = proxyItem(1, "/before")
        val after = proxyItem(2, "/after")
        history += before.item
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val acquisitions = AtomicInteger()
        every { proxy.history() } answers {
            val captured = history.toList()
            if (acquisitions.incrementAndGet() == 1) {
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS)) { "timed out waiting to release acquisition" }
            }
            captured
        }
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        val build = async(Dispatchers.Default) {
            index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        }
        assertTrue(entered.await(5, TimeUnit.SECONDS))

        try {
            assertEquals("project-one", withTimeout(1_000) { index.observeCurrentProject() })
            withTimeout(1_000) { index.invalidate() }
            withTimeout(1_000) { index.resetForProjectBoundary() }
            withTimeout(1_000) {
                index.withMutation { history[0] = after.item }
            }
        } finally {
            release.countDown()
        }

        val snapshot = build.await().sources.single()
        assertEquals(2, acquisitions.get())
        assertEquals(listOf("2"), snapshot.availableRecords.map { it.sourceId })
        assertEquals(listOf("/after"), snapshot.availableRecords.map { it.path })
    }

    @Test
    fun `refresh lock serializes builders and a cancelled waiter never acquires a source`() = runBlocking {
        history += proxyItem(1, "/serialized").item
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val acquisitions = AtomicInteger()
        every { proxy.history() } answers {
            val attempt = acquisitions.incrementAndGet()
            val captured = history.toList()
            if (attempt == 1) {
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS)) { "timed out waiting to release first builder" }
            }
            captured
        }
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        val first = async(Dispatchers.Default) {
            index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        val cancelled = async(start = CoroutineStart.UNDISPATCHED) {
            index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        }
        assertEquals(1, acquisitions.get())
        cancelled.cancel(CancellationException("cancelled refresh waiter"))
        assertFailsWith<CancellationException> { cancelled.await() }
        val queued = async(start = CoroutineStart.UNDISPATCHED) {
            index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        }
        assertEquals(1, acquisitions.get())

        try {
            release.countDown()
            first.await()
            queued.await()
        } finally {
            release.countDown()
        }

        assertEquals(2, acquisitions.get())
    }

    @Test
    fun `active mutation rejects a candidate built outside the state lock`() = runBlocking {
        history += proxyItem(1, "/mutation-race").item
        val acquisitionEntered = CountDownLatch(1)
        val acquisitionRelease = CountDownLatch(1)
        every { proxy.history() } answers {
            val captured = history.toList()
            acquisitionEntered.countDown()
            check(acquisitionRelease.await(5, TimeUnit.SECONDS)) { "timed out waiting to release acquisition" }
            captured
        }
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        val build = async(Dispatchers.Default) {
            runCatching { index.snapshot("project-one", listOf(HttpMessageSource.PROXY)) }
        }
        assertTrue(acquisitionEntered.await(5, TimeUnit.SECONDS))
        val mutationEntered = kotlinx.coroutines.CompletableDeferred<Unit>()
        val mutationRelease = kotlinx.coroutines.CompletableDeferred<Unit>()
        val mutation = async {
            index.withMutation {
                mutationEntered.complete(Unit)
                mutationRelease.await()
            }
        }
        withTimeout(1_000) { mutationEntered.await() }

        try {
            acquisitionRelease.countDown()
            val result = withTimeout(5_000) { build.await() }
            assertTrue(result.exceptionOrNull() is HttpMetadataIndexChangingException)
        } finally {
            acquisitionRelease.countDown()
            mutationRelease.complete(Unit)
        }
        mutation.await()

        assertEquals(null, index.searchHintsSnapshot("project-one", listOf(HttpMessageSource.PROXY)))
        verify(exactly = 1) { proxy.history() }
    }

    @Test
    fun `cancellation in a later source publishes no earlier source candidate`() = runBlocking {
        history += proxyItem(1, "/proxy-candidate").item
        val siteMap = mockk<SiteMap>()
        val siteMapEntered = CountDownLatch(1)
        val siteMapRelease = CountDownLatch(1)
        every { api.siteMap() } returns siteMap
        every { siteMap.requestResponses() } answers {
            siteMapEntered.countDown()
            check(siteMapRelease.await(5, TimeUnit.SECONDS)) { "timed out waiting to release Site Map acquisition" }
            emptyList()
        }
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        val build = async(Dispatchers.Default) {
            index.snapshot(
                "project-one",
                listOf(HttpMessageSource.PROXY, HttpMessageSource.SITE_MAP),
            )
        }
        assertTrue(siteMapEntered.await(5, TimeUnit.SECONDS))

        try {
            build.cancel(CancellationException("cancelled second source"))
            siteMapRelease.countDown()
            assertFailsWith<CancellationException> { build.await() }
        } finally {
            siteMapRelease.countDown()
        }

        assertEquals(null, index.searchHintsSnapshot("project-one", listOf(HttpMessageSource.PROXY)))
        verify(exactly = 1) { proxy.history() }
        verify(exactly = 1) { siteMap.requestResponses() }
    }

    @Test
    fun `warm hint invalidation during refresh discards the candidate and retries with current metadata`() = runBlocking {
        history += proxyItem(1, "/old").item
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        val replacement = proxyItem(2, "/replacement")
        val requestCalls = AtomicInteger()
        val refreshEntered = CountDownLatch(1)
        val refreshRelease = CountDownLatch(1)
        every { replacement.item.request() } answers {
            if (requestCalls.incrementAndGet() == 1) {
                refreshEntered.countDown()
                check(refreshRelease.await(5, TimeUnit.SECONDS)) { "timed out waiting to release refresh validation" }
            }
            replacement.request
        }
        history[0] = replacement.item
        val build = async(Dispatchers.Default) {
            index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        }
        assertTrue(refreshEntered.await(5, TimeUnit.SECONDS))

        try {
            val hints = withTimeout(1_000) {
                index.searchHintsSnapshot(
                    "project-one",
                    listOf(HttpMessageSource.PROXY),
                    mapOf(HttpMessageSource.PROXY to HttpSourceRecords.Proxy(history.toList())),
                )
            }
            assertEquals(null, hints)
        } finally {
            refreshRelease.countDown()
        }

        val refreshed = build.await().sources.single()
        assertEquals(MetadataIndexRefresh.REBUILT, refreshed.refresh)
        assertEquals(listOf("2"), refreshed.availableRecords.map { it.sourceId })
        assertEquals(listOf("/replacement"), refreshed.availableRecords.map { it.path })
        verify(exactly = 3) { proxy.history() }
    }

    @Test
    fun `blocked hint validation releases state operations and close drains it`() = runBlocking {
        val fixture = proxyItem(1, "/hint-close")
        history += fixture.item
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        val hintEntered = CountDownLatch(1)
        val hintRelease = CountDownLatch(1)
        every { fixture.item.request() } answers {
            hintEntered.countDown()
            check(hintRelease.await(5, TimeUnit.SECONDS)) { "timed out waiting to release hint validation" }
            fixture.request
        }
        val hint = async(Dispatchers.Default) {
            runCatching {
                index.searchHintsSnapshot(
                    "project-one",
                    listOf(HttpMessageSource.PROXY),
                    mapOf(HttpMessageSource.PROXY to HttpSourceRecords.Proxy(history.toList())),
                )
            }
        }
        assertTrue(hintEntered.await(5, TimeUnit.SECONDS))
        withTimeout(1_000) { index.invalidate() }
        withTimeout(1_000) { index.resetForProjectBoundary() }
        withTimeout(1_000) { index.withMutation { } }
        val closeReturned = CountDownLatch(1)
        val closeError = AtomicReference<Throwable?>()
        val closer = Thread({
            try {
                index.close()
            } catch (error: Throwable) {
                closeError.set(error)
            } finally {
                closeReturned.countDown()
            }
        }, "metadata-hint-close-test").also {
            it.isDaemon = true
            it.start()
        }

        try {
            withTimeout(5_000) {
                while (true) {
                    try {
                        index.observeCurrentProject()
                        yield()
                    } catch (_: IllegalStateException) {
                        break
                    }
                }
            }
            assertFalse(closeReturned.await(100, TimeUnit.MILLISECONDS))
        } finally {
            hintRelease.countDown()
        }

        assertTrue(closeReturned.await(5, TimeUnit.SECONDS))
        closer.join(5_000)
        closeError.get()?.let { throw AssertionError("index close failed", it) }
        assertTrue(hint.await().exceptionOrNull() is IllegalStateException)
    }

    @Test
    fun `two invalidated build attempts fail without a third acquisition or cache publication`() = runBlocking {
        history += proxyItem(1, "/changing").item
        val entered = List(2) { CountDownLatch(1) }
        val release = List(2) { CountDownLatch(1) }
        val acquisitions = AtomicInteger()
        every { proxy.history() } answers {
            val attempt = acquisitions.getAndIncrement()
            check(attempt in entered.indices) { "unexpected third metadata acquisition" }
            val captured = history.toList()
            entered[attempt].countDown()
            check(release[attempt].await(5, TimeUnit.SECONDS)) { "timed out waiting to release attempt $attempt" }
            captured
        }
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        val build = async(Dispatchers.Default) {
            runCatching { index.snapshot("project-one", listOf(HttpMessageSource.PROXY)) }
        }

        try {
            for (attempt in entered.indices) {
                assertTrue(entered[attempt].await(5, TimeUnit.SECONDS))
                withTimeout(1_000) { index.invalidate() }
                release[attempt].countDown()
            }
            assertTrue(build.await().exceptionOrNull() is HttpMetadataIndexChangingException)
        } finally {
            release.forEach(CountDownLatch::countDown)
        }

        assertEquals(2, acquisitions.get())
        assertEquals(null, index.searchHintsSnapshot("project-one", listOf(HttpMessageSource.PROXY)))
        assertEquals(2, acquisitions.get())
    }

    @Test
    fun `multi-source refresh publishes nothing when a later source fails`() = runBlocking {
        history += proxyItem(1, "/proxy-only").item
        val siteMap = mockk<SiteMap>()
        every { api.siteMap() } returns siteMap
        every { siteMap.requestResponses() } throws IllegalStateException("synthetic Site Map failure")
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })

        assertFailsWith<IllegalStateException> {
            index.snapshot(
                "project-one",
                listOf(HttpMessageSource.PROXY, HttpMessageSource.SITE_MAP),
            )
        }

        assertEquals(null, index.searchHintsSnapshot("project-one", listOf(HttpMessageSource.PROXY)))
        verify(exactly = 1) { proxy.history() }
    }

    @Test
    fun `close tombstones state and waits for an active refresh to discard its candidate`() = runBlocking {
        history += proxyItem(1, "/closing").item
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        every { proxy.history() } answers {
            val captured = history.toList()
            entered.countDown()
            check(release.await(5, TimeUnit.SECONDS)) { "timed out waiting to release close fixture" }
            captured
        }
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        val build = async(Dispatchers.Default) {
            runCatching { index.snapshot("project-one", listOf(HttpMessageSource.PROXY)) }
        }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        val closeReturned = CountDownLatch(1)
        val closeError = AtomicReference<Throwable?>()
        val closer = Thread({
            try {
                index.close()
            } catch (error: Throwable) {
                closeError.set(error)
            } finally {
                closeReturned.countDown()
            }
        }, "metadata-index-close-test").also {
            it.isDaemon = true
            it.start()
        }

        try {
            withTimeout(5_000) {
                while (true) {
                    try {
                        index.observeCurrentProject()
                        yield()
                    } catch (_: IllegalStateException) {
                        break
                    }
                }
            }
            assertFalse(closeReturned.await(100, TimeUnit.MILLISECONDS))
        } finally {
            release.countDown()
        }

        assertTrue(closeReturned.await(5, TimeUnit.SECONDS))
        closer.join(5_000)
        closeError.get()?.let { throw AssertionError("index close failed", it) }
        assertTrue(build.await().exceptionOrNull() is IllegalStateException)
        assertFailsWith<IllegalStateException> { index.observeCurrentProject() }
        Unit
    }

    @Test
    fun `snapshot admitted after close performs no Montoya access`() = runBlocking {
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        index.close()

        assertFailsWith<IllegalStateException> {
            index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        }

        verify(exactly = 0) { project.id() }
        verify(exactly = 0) { proxy.history() }
    }

    @Test
    fun `close waits for an active mutation block`() = runBlocking {
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        val mutationEntered = CountDownLatch(1)
        val mutationRelease = CountDownLatch(1)
        val mutation = async(Dispatchers.Default) {
            index.withMutation {
                mutationEntered.countDown()
                check(mutationRelease.await(5, TimeUnit.SECONDS)) { "timed out waiting to release mutation" }
            }
        }
        assertTrue(mutationEntered.await(5, TimeUnit.SECONDS))
        val closeReturned = CountDownLatch(1)
        val closeError = AtomicReference<Throwable?>()
        val closer = Thread({
            try {
                index.close()
            } catch (error: Throwable) {
                closeError.set(error)
            } finally {
                closeReturned.countDown()
            }
        }, "metadata-mutation-close-test").also {
            it.isDaemon = true
            it.start()
        }

        try {
            withTimeout(5_000) {
                while (true) {
                    try {
                        index.observeCurrentProject()
                        yield()
                    } catch (_: HttpMetadataIndexChangingException) {
                        yield()
                    } catch (_: IllegalStateException) {
                        break
                    }
                }
            }
            assertFalse(closeReturned.await(100, TimeUnit.MILLISECONDS))
        } finally {
            mutationRelease.countDown()
        }

        mutation.await()
        assertTrue(closeReturned.await(5, TimeUnit.SECONDS))
        closer.join(5_000)
        closeError.get()?.let { throw AssertionError("index close failed", it) }
        assertFailsWith<IllegalStateException> {
            index.withMutation { error("closed mutation block must not run") }
        }
        Unit
    }

    @Test
    fun `duplicate snapshot sources fail before project or source access`() = runBlocking {
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })

        assertFailsWith<IllegalArgumentException> {
            index.snapshot(
                "project-one",
                listOf(HttpMessageSource.PROXY, HttpMessageSource.PROXY),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            index.searchHintsSnapshot(
                "project-one",
                listOf(HttpMessageSource.PROXY, HttpMessageSource.PROXY),
            )
        }

        verify(exactly = 0) { project.id() }
        verify(exactly = 0) { proxy.history() }
    }

    @Test
    fun `resized warm cache falls back and preserves append state`() = runBlocking {
        history += proxyItem(1, "/first").item
        val index = HttpMetadataIndex(
            api,
            maxRecordsPerSource = 2,
            reuseMillis = 1_000,
            nanoTime = { nowNanos },
        )
        index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        history += proxyItem(2, "/second").item
        assertEquals(null, index.searchHintsSnapshot("project-one", listOf(HttpMessageSource.PROXY)))
        assertEquals(
            MetadataIndexRefresh.UPDATED,
            index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single().refresh,
        )

        nowNanos += 1_000_000_000L
        assertEquals(null, index.searchHintsSnapshot("project-one", listOf(HttpMessageSource.PROXY)))
    }

    @Test
    fun `indexed paths have a fixed character bound`() = runBlocking {
        history += proxyItem(1, "/" + "a".repeat(800) + "?secret=value").item
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })

        val record = index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
            .sources.single().availableRecords.single()

        assertEquals(MAX_METADATA_INDEX_PATH_CHARS, record.path.length)
        assertTrue(record.pathTruncated)
        assertFalse(record.path.contains("secret"))
    }

    @Test
    fun `optional Proxy timestamp failure does not discard otherwise valid metadata`() = runBlocking {
        val fixture = proxyItem(1, "/without-time")
        every { fixture.item.time() } throws IllegalStateException("time unavailable")
        history += fixture.item
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })

        val record = index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
            .sources.single().availableRecords.single()

        assertEquals(null, record.timestampEpochMillis)
        assertEquals("/without-time", record.path)
    }

    @Test
    fun `cache reuses validated snapshot and incrementally follows append while keeping newest bound`() = runBlocking {
        history += proxyItem(1, "/one").item
        history += proxyItem(2, "/two").item
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })

        val first = index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single()
        assertEquals(MetadataIndexRefresh.REBUILT, first.refresh)

        nowNanos++
        val reused = index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single()
        assertEquals(MetadataIndexRefresh.REUSED, reused.refresh)

        history += proxyItem(3, "/three").item
        nowNanos++
        val updated = index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single()
        assertEquals(MetadataIndexRefresh.UPDATED, updated.refresh)
        assertEquals(1, updated.indexedFrom)
        assertEquals(listOf("2", "3"), updated.availableRecords.map { it.sourceId })
    }

    @Test
    fun `same-size replacement rebuild invalidates the earlier snapshot`() = runBlocking {
        history += proxyItem(1, "/before").item
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        val before = index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        history[0] = proxyItem(2, "/after").item
        nowNanos++

        val after = index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        val refreshed = after.sources.single()

        assertEquals(MetadataIndexRefresh.REBUILT, refreshed.refresh)
        assertEquals("/after", refreshed.availableRecords.single().path)
        assertFalse(index.isSnapshotCurrent(before))
        assertTrue(index.isSnapshotCurrent(after))
    }

    @Test
    fun `append does not extend the maximum age since the last rebuild`() = runBlocking {
        history += (1..20).map { id -> proxyItem(id, "/item-$id").item }
        val index = HttpMetadataIndex(
            api,
            maxRecordsPerSource = 21,
            reuseMillis = 30_000,
            nanoTime = { nowNanos },
        )
        index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        history[4] = proxyItem(104, "/mutated-unsampled-slot").item
        nowNanos += TimeUnit.SECONDS.toNanos(29)
        history += proxyItem(21, "/appended").item

        val appended = index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single()
        assertEquals(MetadataIndexRefresh.UPDATED, appended.refresh)
        assertEquals("/item-5", appended.availableRecords[4].path)

        nowNanos += TimeUnit.SECONDS.toNanos(2)
        val rebuilt = index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single()

        assertEquals(MetadataIndexRefresh.REBUILT, rebuilt.refresh)
        assertEquals("/mutated-unsampled-slot", rebuilt.availableRecords[4].path)
    }

    @Test
    fun `explicit invalidation prevents reuse`() = runBlocking {
        history += proxyItem(1, "/one").item
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        index.invalidate()
        nowNanos++

        val refreshed = index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single()

        assertEquals(MetadataIndexRefresh.REBUILT, refreshed.refresh)
    }

    @Test
    fun `project boundary reset discards warm metadata even when the project identifier is unchanged`() = runBlocking {
        history += proxyItem(1, "/one").item
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        index.resetForProjectBoundary()

        assertEquals(null, index.searchHintsSnapshot("project-one", listOf(HttpMessageSource.PROXY)))
        assertEquals(
            MetadataIndexRefresh.REBUILT,
            index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single().refresh,
        )
    }

    @Test
    fun `late callback after project reset cannot revive an old snapshot`() = runBlocking {
        history += proxyItem(1, "/old").item
        val signals = MetadataChangeSignals()
        val index = HttpMetadataIndex(
            api,
            maxRecordsPerSource = 2,
            nanoTime = { nowNanos },
            changeSignals = signals,
        )
        val old = index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        index.resetForProjectBoundary()
        signals.markChanged(MetadataChangeSource.PROXY_HTTP)
        history.clear()
        history += proxyItem(2, "/new").item
        val current = index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        assertFalse(index.isSnapshotCurrent(old))
        assertTrue(index.isSnapshotCurrent(current))
        assertEquals("/new", current.sources.single().availableRecords.single().path)
        assertEquals(1L, current.sources.single().sourceRevision)
    }

    @Test
    fun `snapshot generation detects invalidation before a response is returned`() = runBlocking {
        history += proxyItem(1, "/one").item
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        val snapshot = index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        assertTrue(index.isSnapshotCurrent(snapshot))
        index.invalidate()

        assertFalse(index.isSnapshotCurrent(snapshot))
        assertEquals(
            MetadataIndexRefresh.REBUILT,
            index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single().refresh,
        )
    }

    @Test
    fun `snapshot validation rejects a project switch after aggregation started`() = runBlocking {
        history += proxyItem(1, "/old-project").item
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        val snapshot = index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        projectId = "project-two"
        val mismatch = assertFailsWith<HttpMetadataProjectMismatchException> {
            index.isSnapshotCurrent(snapshot)
        }

        assertEquals("project-two", mismatch.currentProjectId)
    }

    @Test
    fun `mutation barrier blocks snapshots and invalidates on exceptional completion`() = runBlocking {
        history += proxyItem(1, "/before").item
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        assertFailsWith<IllegalStateException> {
            index.withMutation {
                assertFailsWith<HttpMetadataIndexChangingException> { index.observeCurrentProject() }
                assertFailsWith<HttpMetadataIndexChangingException> {
                    index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
                }
                history[0] = proxyItem(2, "/after").item
                throw IllegalStateException("simulated mutation failure")
            }
        }

        val refreshed = index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single()
        assertEquals(MetadataIndexRefresh.REBUILT, refreshed.refresh)
        assertEquals("/after", refreshed.availableRecords.single().path)
    }

    @Test
    fun `cancelled signaled rebuild publishes no partial cache`() = runBlocking {
        history += proxyItem(1, "/before").item
        val signals = MetadataChangeSignals()
        val index = HttpMetadataIndex(
            api,
            maxRecordsPerSource = 2,
            nanoTime = { nowNanos },
            changeSignals = signals,
        )
        index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        val cancelled = proxyItem(2, "/cancelled")
        every { cancelled.item.request() } throws CancellationException("cancelled rebuild")
        history[0] = cancelled.item
        signals.markChanged(MetadataChangeSource.PROXY_HTTP)

        assertFailsWith<CancellationException> {
            index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        }
        assertEquals(null, index.searchHintsSnapshot("project-one", listOf(HttpMessageSource.PROXY)))
        history[0] = proxyItem(3, "/after").item

        val refreshed = index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single()
        assertEquals(MetadataIndexRefresh.REBUILT, refreshed.refresh)
        assertEquals("/after", refreshed.availableRecords.single().path)
    }

    @Test
    fun `mutation barrier cleanup is non-cancellable`() = runBlocking {
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })

        assertFailsWith<CancellationException> {
            index.withMutation {
                throw CancellationException("simulated cancellation")
            }
        }

        assertEquals("project-one", index.observeCurrentProject())
        assertEquals(
            MetadataIndexRefresh.REBUILT,
            index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single().refresh,
        )
    }

    @Test
    fun `project observation discards old cache before a new project snapshot`() = runBlocking {
        history += proxyItem(1, "/old-project").item
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 4, nanoTime = { nowNanos })
        index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        projectId = "project-two"
        history.clear()
        history += proxyItem(9, "/new-project").item
        assertEquals("project-two", index.observeCurrentProject())
        assertFailsWith<HttpMetadataProjectMismatchException> {
            index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        }

        val current = index.snapshot("project-two", listOf(HttpMessageSource.PROXY)).sources.single()
        assertEquals(MetadataIndexRefresh.REBUILT, current.refresh)
        assertEquals(listOf("9"), current.availableRecords.map { it.sourceId })
        assertEquals(listOf("/new-project"), current.availableRecords.map { it.path })
    }

    @Test
    fun `project change after one source discards every multi-source candidate`() = runBlocking {
        history += proxyItem(1, "/old-project").item
        val siteMap = mockk<SiteMap>()
        every { api.siteMap() } returns siteMap
        every { siteMap.requestResponses() } returns emptyList()
        var projectReads = 0
        every { project.id() } answers {
            projectReads++
            if (projectReads == 1) "project-one" else "project-two"
        }
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })

        val mismatch = assertFailsWith<HttpMetadataProjectMismatchException> {
            index.snapshot(
                "project-one",
                listOf(HttpMessageSource.PROXY, HttpMessageSource.SITE_MAP),
            )
        }
        assertEquals("project-two", mismatch.currentProjectId)
        every { project.id() } returns "project-two"
        assertEquals(null, index.searchHintsSnapshot("project-two", listOf(HttpMessageSource.PROXY)))
        verify(exactly = 0) { siteMap.requestResponses() }

        history.clear()
        history += proxyItem(2, "/new-project").item
        val current = index.snapshot("project-two", listOf(HttpMessageSource.PROXY)).sources.single()
        assertEquals(MetadataIndexRefresh.REBUILT, current.refresh)
        assertEquals("/new-project", current.availableRecords.single().path)
    }

    @Test
    fun `empty source snapshots are reusable and keep their source identity`() = runBlocking {
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })

        val first = index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single()
        nowNanos++
        val second = index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single()

        assertEquals(HttpMessageSource.PROXY, first.source)
        assertEquals(0, first.totalRecords)
        assertEquals(MetadataIndexRefresh.REUSED, second.refresh)
    }

    @Test
    fun `Site Map and Organizer sources use the same body-free bounded representation`() = runBlocking {
        val siteMap = mockk<SiteMap>()
        val siteItem = mockk<HttpRequestResponse>()
        val siteParts = metadataParts("/site/resource?key=secret")
        every { api.siteMap() } returns siteMap
        every { siteMap.requestResponses() } returns listOf(siteItem)
        every { siteItem.request() } returns siteParts.request
        every { siteItem.response() } returns siteParts.response
        every { siteItem.httpService() } returns siteParts.service

        val organizer = mockk<Organizer>()
        val organizerItem = mockk<OrganizerItem>()
        val organizerParts = metadataParts("/organizer/resource?key=secret")
        every { api.organizer() } returns organizer
        every { organizer.items() } returns listOf(organizerItem)
        every { organizerItem.id() } returns 77
        every { organizerItem.request() } returns organizerParts.request
        every { organizerItem.response() } returns organizerParts.response
        every { organizerItem.httpService() } returns organizerParts.service

        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        val sources = index.snapshot(
            "project-one",
            listOf(HttpMessageSource.SITE_MAP, HttpMessageSource.ORGANIZER),
        ).sources

        assertEquals(listOf(HttpMessageSource.SITE_MAP, HttpMessageSource.ORGANIZER), sources.map { it.source })
        assertEquals("/site/resource", sources[0].availableRecords.single().path)
        assertEquals(null, sources[0].availableRecords.single().sourceId)
        assertEquals(null, sources[0].availableRecords.single().numericSourceId)
        assertEquals("/organizer/resource", sources[1].availableRecords.single().path)
        assertEquals("77", sources[1].availableRecords.single().sourceId)
        assertEquals(77, sources[1].availableRecords.single().numericSourceId)
        verify(exactly = 0) { siteParts.request.body() }
        verify(exactly = 0) { organizerParts.request.body() }
    }

    @Test
    fun `expired cache rebuilds even when bounded anchors are unchanged`() = runBlocking {
        history += proxyItem(1, "/one").item
        val index = HttpMetadataIndex(
            api,
            maxRecordsPerSource = 2,
            reuseMillis = 1,
            nanoTime = { nowNanos },
        )
        index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        nowNanos += 1_000_001
        val refreshed = index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single()

        assertEquals(MetadataIndexRefresh.REBUILT, refreshed.refresh)
    }

    private fun metadataParts(path: String): MetadataParts {
        val request = mockk<HttpRequest>()
        val response = mockk<HttpResponse>()
        val service = mockk<HttpService>()
        every { request.method() } returns "GET"
        every { request.path() } returns path
        every { request.isInScope() } returns true
        every { response.statusCode() } returns 200.toShort()
        every { response.mimeType() } returns MimeType.JSON
        every { service.host() } returns "example.test"
        every { service.port() } returns 443
        every { service.secure() } returns true
        return MetadataParts(request, response, service)
    }

    private fun proxyItem(
        id: Int,
        path: String,
        inScope: Boolean = true,
    ): ProxyFixture {
        val item = mockk<ProxyHttpRequestResponse>()
        val request = mockk<HttpRequest>()
        val response = mockk<HttpResponse>()
        val service = mockk<HttpService>()
        every { item.id() } returns id
        every { item.request() } returns request
        every { item.response() } returns response
        every { item.httpService() } returns service
        every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z")
        every { request.method() } returns "GET"
        every { request.path() } returns path
        every { request.isInScope() } returns inScope
        every { response.statusCode() } returns 200.toShort()
        every { response.mimeType() } returns MimeType.JSON
        every { service.host() } returns "Example.Test."
        every { service.port() } returns 443
        every { service.secure() } returns true
        return ProxyFixture(item, request)
    }

    private data class ProxyFixture(
        val item: ProxyHttpRequestResponse,
        val request: HttpRequest,
    )

    private data class MetadataParts(
        val request: HttpRequest,
        val response: HttpResponse,
        val service: HttpService,
    )
}
