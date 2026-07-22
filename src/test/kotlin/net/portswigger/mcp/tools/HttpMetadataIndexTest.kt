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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.ZonedDateTime
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
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
        val index = HttpMetadataIndex(api, nanoTime = { nowNanos })

        val snapshot = index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single()

        assertEquals(MAX_METADATA_INDEX_RECORDS_PER_SOURCE, snapshot.slots.size)
        assertEquals(95_000, snapshot.omittedRecords)
        assertEquals(MAX_METADATA_INDEX_RECORDS_PER_SOURCE, snapshot.availableRecords.size)
        assertTrue(getCalls <= MAX_METADATA_INDEX_RECORDS_PER_SOURCE + 16)
        verify(exactly = 0) { fixture.request.body() }
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
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        index.snapshot("project-one", listOf(HttpMessageSource.PROXY))

        val cached = index.searchHintsSnapshot("project-one", listOf(HttpMessageSource.PROXY))

        assertEquals(MetadataIndexRefresh.REUSED, cached?.sources?.single()?.refresh)
        assertEquals(1, cached?.sources?.single()?.availableRecords?.size)
        verify(exactly = 2) { proxy.history() }
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
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        val build = async(Dispatchers.Default) {
            index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        }
        assertTrue(enteredRequest.await(5, TimeUnit.SECONDS))

        try {
            assertEquals(
                null,
                withTimeout(250) { index.searchHintsSnapshot("project-one", listOf(HttpMessageSource.PROXY)) },
            )
        } finally {
            releaseRequest.countDown()
        }
        assertEquals("project-one", build.await().projectId)
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
    fun `same-size replacement at a sampled anchor rebuilds the cache`() = runBlocking {
        history += proxyItem(1, "/before").item
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })
        index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        history[0] = proxyItem(2, "/after").item
        nowNanos++

        val refreshed = index.snapshot("project-one", listOf(HttpMessageSource.PROXY)).sources.single()

        assertEquals(MetadataIndexRefresh.REBUILT, refreshed.refresh)
        assertEquals("/after", refreshed.availableRecords.single().path)
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
    fun `project change during a source refresh discards the just-built entries`() = runBlocking {
        history += proxyItem(1, "/old-project").item
        var projectReads = 0
        every { project.id() } answers {
            projectReads++
            if (projectReads == 1) "project-one" else "project-two"
        }
        val index = HttpMetadataIndex(api, maxRecordsPerSource = 2, nanoTime = { nowNanos })

        val mismatch = assertFailsWith<HttpMetadataProjectMismatchException> {
            index.snapshot("project-one", listOf(HttpMessageSource.PROXY))
        }
        assertEquals("project-two", mismatch.currentProjectId)

        every { project.id() } returns "project-two"
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
