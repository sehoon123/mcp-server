package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.logging.Logging
import burp.api.montoya.organizer.Organizer
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.organizer.OrganizerItemStatus
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.sitemap.SiteMap
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.ZonedDateTime
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class HttpMessageIndexedSearchTest {
    private val api = mockk<MontoyaApi>()
    private val logging = mockk<Logging>(relaxed = true)
    private val project = mockk<Project>()
    private val proxy = mockk<Proxy>()
    private val organizer = mockk<Organizer>()
    private val siteMap = mockk<SiteMap>()
    private val proxyHistory = mutableListOf<ProxyHttpRequestResponse>()
    private val organizerItems = mutableListOf<OrganizerItem>()
    private val siteMapItems = mutableListOf<HttpRequestResponse>()
    private val indexes = mutableListOf<HttpMetadataIndex>()
    private lateinit var config: McpConfig
    private var currentProjectId = "project-123"

    @BeforeEach
    fun setUp() {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns false
        every { storage.getString(any()) } returns ""
        every { api.logging() } returns logging
        every { api.project() } returns project
        every { project.id() } answers { currentProjectId }
        every { api.proxy() } returns proxy
        every { proxy.history() } answers { proxyHistory.toList() }
        every { api.organizer() } returns organizer
        every { organizer.items() } answers { organizerItems.toList() }
        every { api.siteMap() } returns siteMap
        every { siteMap.requestResponses() } answers { siteMapItems.toList() }
        config = McpConfig(storage, logging)
    }

    @AfterEach
    fun tearDown() {
        indexes.forEach(HttpMetadataIndex::close)
    }

    @Test
    fun `indexed metadata predicates are byte-for-byte equivalent to the raw search`() = runBlocking {
        proxyHistory += fixture(1, host = { "first.test" }, method = "GET", path = "/one", status = 200).item
        proxyHistory += fixture(2, host = { "example.test" }, method = "POST", path = "/two", status = 201).item
        proxyHistory += fixture(
            3,
            host = { "example.test" },
            method = "GET",
            path = "/query?token=needle",
            status = 200,
            mimeType = MimeType.HTML,
        ).item
        proxyHistory += fixture(4, host = { "other.test" }, method = "DELETE", path = "/four", status = 404).item
        proxyHistory += fixture(
            5,
            host = { "example.test" },
            method = "PATCH",
            path = "/five",
            status = null,
            inScope = { false },
        ).item
        proxyHistory += fixture(6, host = { "last.test" }, method = "GET", path = "/six", status = 500).item

        val queries = listOf(
            SearchHttpMessages(host = "example.test"),
            SearchHttpMessages(methods = listOf("patch")),
            SearchHttpMessages(statusCodes = listOf(201, 404)),
            SearchHttpMessages(mimeTypes = listOf("html")),
            SearchHttpMessages(inScopeOnly = true),
            SearchHttpMessages(hasResponse = false),
            // The index never retains the query. A cached path miss is verified against the current full path.
            SearchHttpMessages(pathContains = "token=needle"),
            SearchHttpMessages(
                host = "example.test",
                methods = listOf("get", "post"),
                statusCodes = listOf(200, 201),
                hasResponse = true,
            ),
        )

        for (query in queries) {
            val index = newIndex(maxRecords = 3)
            index.snapshot(currentProjectId, listOf(HttpMessageSource.PROXY))
            val indexed = service(index).search(query)
            val raw = rawService().search(query)
            assertEquals(raw, indexed, "indexed result differed for $query")
        }
    }

    @Test
    fun `signed cursor snapshot and append behavior are unchanged by indexed filtering`() = runBlocking {
        repeat(5) { index ->
            proxyHistory += fixture(
                id = index + 1,
                host = { "example.test" },
                method = "GET",
                path = "/item/${index + 1}",
                status = 200,
            ).item
        }
        val index = newIndex(maxRecords = 3)
        index.snapshot(currentProjectId, listOf(HttpMessageSource.PROXY))
        val indexedService = service(index)
        val rawService = rawService()
        val query = SearchHttpMessages(host = "example.test", limit = 2)

        val indexedFirst = indexedService.search(query)
        val rawFirst = rawService.search(query)
        assertEquals(rawFirst, indexedFirst)

        proxyHistory += fixture(6, host = { "example.test" }, method = "GET", path = "/item/6", status = 200).item
        val indexedSecond = indexedService.search(SearchHttpMessages(cursor = indexedFirst.nextCursor))
        val rawSecond = rawService.search(SearchHttpMessages(cursor = rawFirst.nextCursor))

        assertEquals(rawSecond, indexedSecond)
        assertEquals(listOf("3", "2", "1"), indexedSecond.items.map { it.ref.id })
    }

    @Test
    fun `Organizer filtering uses the same current-ID and field verified fast path`() = runBlocking {
        repeat(20) { index ->
            organizerItems += organizerFixture(
                id = index + 1,
                host = if (index == 0) "target.test" else "other.test",
                path = "/organizer/$index",
            )
        }
        val query = SearchHttpMessages(
            sources = listOf(HttpMessageSource.ORGANIZER),
            host = "target.test",
        )
        val index = newIndex(maxRecords = 20)
        index.snapshot(currentProjectId, listOf(HttpMessageSource.ORGANIZER))

        val indexed = service(index).search(query)
        val raw = rawService().search(query)

        assertEquals(raw, indexed)
        assertEquals(HttpMessageSource.ORGANIZER, indexed.items.single().ref.source)
        assertEquals("1", indexed.items.single().ref.id)
    }

    @Test
    fun `Site Map filtering retains the raw path before issuing current opaque IDs`() = runBlocking {
        val requestAccesses = AtomicInteger()
        repeat(20) { index ->
            siteMapItems += siteMapFixture(
                host = if (index == 0) "target.test" else "other.test",
                path = "/site-map/$index",
                requestAccesses = requestAccesses,
            )
        }
        val query = SearchHttpMessages(
            sources = listOf(HttpMessageSource.SITE_MAP),
            host = "target.test",
        )
        val index = newIndex(maxRecords = 20)
        index.snapshot(currentProjectId, listOf(HttpMessageSource.SITE_MAP))
        siteMapItems[18] = siteMapFixture("target.test", "/site-map/replacement", requestAccesses)
        requestAccesses.set(0)

        val indexed = service(index).search(query)
        val indexedRequestAccesses = requestAccesses.get()
        requestAccesses.set(0)
        val raw = rawService().search(query)
        val rawRequestAccesses = requestAccesses.get()

        assertEquals(raw, indexed)
        assertEquals(2, indexed.items.size)
        assertTrue(indexed.items.all { it.ref.source == HttpMessageSource.SITE_MAP })
        assertTrue(indexed.items.first().ref.id.startsWith("sitemap_18_"))
        assertEquals(rawRequestAccesses, indexedRequestAccesses)
        assertTrue(indexedRequestAccesses >= siteMapItems.size)
    }

    @Test
    fun `stale metadata hints always recheck the current raw field`() = runBlocking {
        val mutableHost = arrayOf("old.test")
        val mutableScope = AtomicBoolean(false)
        val transitionedResponse = arrayOfNulls<HttpResponse>(1)
        repeat(100) { index ->
            val fixture = when (index) {
                98 -> fixture(index + 1, host = { mutableHost[0] }, method = "GET", path = "/host", status = 200)
                97 -> fixture(
                    index + 1,
                    host = { "other.test" },
                    method = "GET",
                    path = "/scope",
                    status = 200,
                    inScope = mutableScope::get,
                )
                96 -> fixture(
                    index + 1,
                    host = { "other.test" },
                    method = "GET",
                    path = "/response",
                    response = { transitionedResponse[0] },
                )
                95 -> fixture(index + 1, host = { "other.test" }, method = "GET", path = "/old-path", status = 200)
                94 -> fixture(index + 1, host = { "other.test" }, method = "POST", path = "/method", status = 200)
                93 -> fixture(
                    index + 1,
                    host = { "other.test" },
                    method = "GET",
                    path = "/mime",
                    status = 200,
                    mimeType = MimeType.JSON,
                )
                else -> fixture(
                    index + 1,
                    host = { "other.test" },
                    method = "GET",
                    path = "/item/$index",
                    status = 200,
                    inScope = { false },
                )
            }
            proxyHistory += fixture.item
        }
        val index = newIndex(maxRecords = 100)
        index.snapshot(currentProjectId, listOf(HttpMessageSource.PROXY))

        mutableHost[0] = "target.test"
        mutableScope.set(true)
        transitionedResponse[0] = response(201, MimeType.JSON)
        proxyHistory[95] = fixture(96, host = { "other.test" }, method = "GET", path = "/new/needle", status = 200).item
        proxyHistory[94] = fixture(95, host = { "other.test" }, method = "GET", path = "/method", status = 200).item
        proxyHistory[93] = fixture(
            94,
            host = { "other.test" },
            method = "GET",
            path = "/mime",
            status = 200,
            mimeType = MimeType.HTML,
        ).item

        val queries = listOf(
            SearchHttpMessages(host = "target.test"),
            SearchHttpMessages(inScopeOnly = true),
            SearchHttpMessages(statusCodes = listOf(201)),
            SearchHttpMessages(pathContains = "needle"),
            SearchHttpMessages(methods = listOf("get")),
            SearchHttpMessages(mimeTypes = listOf("html")),
            SearchHttpMessages(pathContains = "/response", hasResponse = true),
        )
        for (query in queries) {
            assertEquals(rawService().search(query), service(index).search(query), "stale hint changed $query")
        }
    }

    @Test
    fun `numeric source ID replacement falls back to the current source record`() = runBlocking {
        repeat(100) { index ->
            proxyHistory += fixture(
                id = index + 1,
                host = { "old.test" },
                method = "GET",
                path = "/item/$index",
                status = 200,
            ).item
        }
        val index = newIndex(maxRecords = 100)
        index.snapshot(currentProjectId, listOf(HttpMessageSource.PROXY))
        val replacement = fixture(999, host = { "target.test" }, method = "GET", path = "/replacement", status = 200)
        proxyHistory[98] = replacement.item

        val query = SearchHttpMessages(host = "target.test")
        val indexed = service(index).search(query)
        val raw = rawService().search(query)

        assertEquals(raw, indexed)
        assertEquals("999", indexed.items.single().ref.id)
        verify(atLeast = 1) { replacement.item.id() }
    }

    @Test
    fun `warm selective host search avoids full request dereference while preserving scan counts`() = runBlocking {
        val requestAccesses = AtomicInteger()
        repeat(100) { index ->
            proxyHistory += fixture(
                id = index + 1,
                host = { if (index == 0) "target.test" else "other.test" },
                method = "GET",
                path = "/item/$index",
                status = 200,
                requestAccesses = requestAccesses,
            ).item
        }
        val index = newIndex(maxRecords = 100)
        index.snapshot(currentProjectId, listOf(HttpMessageSource.PROXY))
        requestAccesses.set(0)

        val indexed = service(index).search(SearchHttpMessages(host = "target.test"))
        val indexedRequestAccesses = requestAccesses.get()
        requestAccesses.set(0)
        val raw = rawService().search(SearchHttpMessages(host = "target.test"))
        val rawRequestAccesses = requestAccesses.get()

        assertEquals(raw, indexed)
        assertEquals(100, indexed.scanned)
        assertEquals(100, rawRequestAccesses)
        assertTrue(
            indexedRequestAccesses <= 17,
            "expected at most 16 bounded anchor reads plus the selected request, got $indexedRequestAccesses",
        )
    }

    @Test
    fun `partially warm multi-source search uses hints only for the available source`() = runBlocking {
        proxyHistory += fixture(1, host = { "target.test" }, method = "GET", path = "/proxy", status = 200).item
        siteMapItems += siteMapFixture("target.test", "/site-map")
        val query = SearchHttpMessages(
            sources = listOf(HttpMessageSource.PROXY, HttpMessageSource.SITE_MAP),
            host = "target.test",
        )
        val index = newIndex(maxRecords = 10)
        index.snapshot(currentProjectId, listOf(HttpMessageSource.PROXY))

        assertEquals(rawService().search(query), service(index).search(query))
    }

    @Test
    fun `active index mutation falls back to the original raw search`() = runBlocking {
        val requestAccesses = AtomicInteger()
        repeat(10) { itemIndex ->
            proxyHistory += fixture(
                id = itemIndex + 1,
                host = { if (itemIndex == 0) "target.test" else "other.test" },
                method = "GET",
                path = "/item/$itemIndex",
                status = 200,
                requestAccesses = requestAccesses,
            ).item
        }
        val index = newIndex(maxRecords = 10)
        index.snapshot(currentProjectId, listOf(HttpMessageSource.PROXY))
        requestAccesses.set(0)

        val result = index.withMutation {
            service(index).search(SearchHttpMessages(host = "target.test"))
        }

        assertEquals(HttpMessageSearchStatus.OK, result.status)
        assertEquals("1", result.items.single().ref.id)
        assertEquals(10, requestAccesses.get())
    }

    @Test
    fun `text and oldest-first searches retain the original raw path and content accounting`() = runBlocking {
        proxyHistory += fixture(
            id = 1,
            host = { "target.test" },
            method = "GET",
            path = "/selected",
            status = 200,
        ).item
        val service = service(newIndex(maxRecords = 10))

        val text = service.search(SearchHttpMessages(text = "needle"))
        val oldest = service.search(SearchHttpMessages(host = "target.test", newestFirst = false))

        assertEquals(1, text.scanned)
        assertTrue(text.scannedContentBytes > 0)
        assertEquals("1", oldest.items.single().ref.id)
        verify(exactly = 2) { proxy.history() }
    }

    @Test
    fun `invalidation after indexed aggregation retries once through the raw path`() = runBlocking {
        val index = newIndex(maxRecords = 10)
        val invalidateOnce = AtomicBoolean(true)
        proxyHistory += fixture(
            id = 1,
            host = { "target.test" },
            method = "GET",
            path = "/selected",
            status = 200,
            notes = {
                if (invalidateOnce.compareAndSet(true, false)) runBlocking { index.invalidate() }
                "selected"
            },
        ).item
        index.snapshot(currentProjectId, listOf(HttpMessageSource.PROXY))

        val result = service(index).search(SearchHttpMessages(host = "target.test"))

        assertEquals(HttpMessageSearchStatus.OK, result.status)
        assertEquals("1", result.items.single().ref.id)
        verify(exactly = 4) { proxy.history() }
    }

    @Test
    fun `final project check discards otherwise complete raw results`() = runBlocking {
        proxyHistory += fixture(
            id = 1,
            host = { "target.test" },
            method = "GET",
            path = "/selected",
            status = 200,
            notes = {
                currentProjectId = "project-456"
                null
            },
        ).item

        val result = rawService().search(SearchHttpMessages())

        assertEquals(HttpMessageSearchStatus.PROJECT_MISMATCH, result.status)
        assertEquals("project-456", result.projectId)
        assertTrue(result.items.isEmpty())
    }

    private fun service(index: HttpMetadataIndex): HttpMessageSearchService = HttpMessageSearchService(
        api = api,
        config = config,
        metadataIndex = index,
        cursorSecret = CURSOR_SECRET,
    )

    private fun rawService(): HttpMessageSearchService = HttpMessageSearchService(
        api = api,
        config = config,
        cursorSecret = CURSOR_SECRET,
    )

    private fun newIndex(maxRecords: Int): HttpMetadataIndex = HttpMetadataIndex(
        api = api,
        maxRecordsPerSource = maxRecords,
        reuseMillis = 60_000,
    ).also(indexes::add)

    private fun fixture(
        id: Int,
        host: () -> String,
        method: String,
        path: String,
        status: Int? = null,
        mimeType: MimeType = MimeType.JSON,
        inScope: () -> Boolean = { true },
        response: (() -> HttpResponse?)? = null,
        requestAccesses: AtomicInteger? = null,
        notes: () -> String? = { null },
    ): ProxyFixture {
        val item = mockk<ProxyHttpRequestResponse>()
        val request = request(method, path, host, inScope)
        val fixedResponse = status?.let { response(it, mimeType) }
        val service = service(host)
        val annotations = mockk<Annotations>()
        every { annotations.notes() } answers { notes() }
        every { item.id() } returns id
        every { item.request() } answers {
            requestAccesses?.incrementAndGet()
            request
        }
        every { item.response() } answers { response?.invoke() ?: fixedResponse }
        every { item.httpService() } returns service
        every { item.host() } answers { host() }
        every { item.annotations() } returns annotations
        every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z").plusSeconds(id.toLong())
        every { item.listenerPort() } returns 8080
        every { item.edited() } returns false
        return ProxyFixture(item)
    }

    private fun siteMapFixture(
        host: String,
        path: String,
        requestAccesses: AtomicInteger? = null,
    ): HttpRequestResponse {
        val item = mockk<HttpRequestResponse>()
        val request = request("GET", path, { host }, { true })
        val response = response(200, MimeType.JSON)
        val service = service { host }
        val annotations = mockk<Annotations>()
        every { annotations.notes() } returns null
        every { item.request() } answers {
            requestAccesses?.incrementAndGet()
            request
        }
        every { item.response() } returns response
        every { item.httpService() } returns service
        every { item.annotations() } returns annotations
        return item
    }

    private fun organizerFixture(id: Int, host: String, path: String): OrganizerItem {
        val item = mockk<OrganizerItem>()
        val request = request("GET", path, { host }, { true })
        val response = response(200, MimeType.JSON)
        val service = service { host }
        val annotations = mockk<Annotations>()
        every { annotations.notes() } returns null
        every { item.id() } returns id
        every { item.request() } returns request
        every { item.response() } returns response
        every { item.httpService() } returns service
        every { item.annotations() } returns annotations
        every { item.status() } returns OrganizerItemStatus.NEW
        return item
    }

    private fun request(
        method: String,
        path: String,
        host: () -> String,
        inScope: () -> Boolean,
    ): HttpRequest {
        val request = mockk<HttpRequest>()
        val body = byteArray(0, "")
        every { request.method() } returns method
        every { request.url() } answers { "https://${host()}$path" }
        every { request.path() } returns path
        every { request.isInScope() } answers { inScope() }
        every { request.body() } returns body
        every { request.bodyOffset() } returns 100
        every { request.headers() } returns emptyList()
        every { request.httpVersion() } returns "HTTP/1.1"
        every { request.contains(any<String>(), any<Boolean>()) } returns false
        every { request.toByteArray() } returns body
        return request
    }

    private fun response(status: Int, mimeType: MimeType): HttpResponse {
        val response = mockk<HttpResponse>()
        val body = byteArray(8, "response")
        every { response.statusCode() } returns status.toShort()
        every { response.mimeType() } returns mimeType
        every { response.body() } returns body
        every { response.bodyOffset() } returns 80
        every { response.headers() } returns emptyList()
        every { response.httpVersion() } returns "HTTP/1.1"
        every { response.contains(any<String>(), any<Boolean>()) } returns false
        every { response.toByteArray() } returns body
        return response
    }

    private fun service(host: () -> String): HttpService = mockk<HttpService>().also {
        every { it.host() } answers { host() }
        every { it.port() } returns 443
        every { it.secure() } returns true
    }

    private fun byteArray(length: Int, text: String): MontoyaByteArray {
        val bytes = mockk<MontoyaByteArray>()
        every { bytes.length() } returns length
        every { bytes.getByte(any()) } answers {
            val raw = text.toByteArray()
            if (raw.isEmpty()) 0 else raw[firstArg<Int>().coerceIn(0, raw.lastIndex)]
        }
        every { bytes.toString() } returns text
        every { bytes.getBytes() } returns text.toByteArray()
        return bytes
    }

    private data class ProxyFixture(val item: ProxyHttpRequestResponse)

    private companion object {
        val CURSOR_SECRET = ByteArray(32) { 17 }
    }
}
