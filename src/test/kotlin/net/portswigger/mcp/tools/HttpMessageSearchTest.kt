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
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class HttpMessageSearchTest {
    private val api = mockk<MontoyaApi>()
    private val logging = mockk<Logging>(relaxed = true)
    private val project = mockk<Project>()
    private val proxy = mockk<Proxy>()
    private val siteMap = mockk<SiteMap>()
    private val proxyHistory = mutableListOf<ProxyHttpRequestResponse>()
    private val siteMapItems = mutableListOf<HttpRequestResponse>()
    private lateinit var config: McpConfig
    private lateinit var service: HttpMessageSearchService

    @BeforeEach
    fun setUp() {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns false
        every { storage.getString(any()) } returns ""
        every { api.logging() } returns logging
        every { api.project() } returns project
        every { project.id() } returns "project-123"
        every { api.proxy() } returns proxy
        every { proxy.history() } answers { proxyHistory.toList() }
        every { api.siteMap() } returns siteMap
        every { siteMap.requestResponses() } answers { siteMapItems.toList() }
        config = McpConfig(storage, logging)
        service = HttpMessageSearchService(
            api,
            config,
            cursorSecret = ByteArray(32) { 7 },
        )
    }

    @Test
    fun `search filters metadata before creating compact summaries`() = runBlocking {
        val skipped = proxyItem(1, "GET", "https://example.test/old", 200)
        val selected = proxyItem(2, "POST", "https://example.test/api/items", 201)
        proxyHistory += skipped.item
        proxyHistory += selected.item

        val result = service.search(
            SearchHttpMessages(
                host = "EXAMPLE.TEST.",
                pathContains = "/api",
                methods = listOf("post"),
                statusCodes = listOf(201),
                newestFirst = true,
            )
        )

        assertEquals(HttpMessageSearchStatus.OK, result.status)
        assertEquals("project-123", result.projectId)
        assertEquals(1, result.returned)
        assertEquals("2", result.items.single().ref.id)
        assertEquals("https://example.test/api/items", result.items.single().url)
        assertFalse(result.items.single().urlTruncated)
        verify(exactly = 0) { skipped.item.annotations() }
        verify(exactly = 1) { selected.item.annotations() }
        verify(exactly = 0) { skipped.request.toByteArray() }
        verify(exactly = 0) { api.siteMap() }
    }

    @Test
    fun `signed cursor keeps an append-only snapshot and can be used without repeating filters`() = runBlocking {
        proxyHistory += proxyItem(1, "GET", "https://example.test/one", 200).item
        proxyHistory += proxyItem(2, "GET", "https://example.test/two", 200).item

        val first = service.search(SearchHttpMessages(limit = 1, newestFirst = false))
        assertEquals("1", first.items.single().ref.id)
        assertTrue(first.hasMore)
        val cursor = assertNotNull(first.nextCursor)

        proxyHistory += proxyItem(3, "GET", "https://example.test/three", 200).item
        val second = service.search(SearchHttpMessages(limit = 1, cursor = cursor))

        assertEquals(HttpMessageSearchStatus.OK, second.status)
        assertEquals("2", second.items.single().ref.id)
        assertFalse(second.hasMore)
        assertEquals(null, second.nextCursor)
    }

    @Test
    fun `cursor rejects changed filters and a cleared snapshot`() = runBlocking {
        proxyHistory += proxyItem(1, "GET", "https://example.test/one", 200).item
        proxyHistory += proxyItem(2, "GET", "https://example.test/two", 200).item
        val first = service.search(SearchHttpMessages(host = "example.test", limit = 1, newestFirst = false))
        val cursor = assertNotNull(first.nextCursor)

        val changedFilter = service.search(SearchHttpMessages(host = "other.test", cursor = cursor))
        assertEquals(HttpMessageSearchStatus.INVALID_CURSOR, changedFilter.status)

        proxyHistory.clear()
        val cleared = service.search(SearchHttpMessages(cursor = cursor))
        assertEquals(HttpMessageSearchStatus.STALE_CURSOR, cleared.status)
    }

    @Test
    fun `cursor tampering is rejected before reading history`() = runBlocking {
        proxyHistory += proxyItem(1, "GET", "https://example.test/one", 200).item
        proxyHistory += proxyItem(2, "GET", "https://example.test/two", 200).item
        val first = service.search(SearchHttpMessages(limit = 1, newestFirst = false))
        val cursor = assertNotNull(first.nextCursor)
        val replacement = if (cursor.first() == 'A') "B" else "A"
        val tampered = replacement + cursor.drop(1)

        val result = service.search(SearchHttpMessages(cursor = tampered))

        assertEquals(HttpMessageSearchStatus.INVALID_CURSOR, result.status)
        assertEquals(0, result.scanned)
        verify(exactly = 1) { proxy.history() }
    }

    @Test
    fun `Site Map search returns a project scoped ID that supports bounded detail reads`() = runBlocking {
        val fixture = siteMapItem(
            method = "POST",
            url = "https://example.test/site-map",
            status = 202,
            responseBody = "abcde",
        )
        siteMapItems += fixture.item

        val search = service.search(
            SearchHttpMessages(
                sources = listOf(HttpMessageSource.SITE_MAP),
                newestFirst = false,
            )
        )
        val found = search.items.single()
        assertEquals(HttpMessageSource.SITE_MAP, found.ref.source)
        assertTrue(found.ref.id.matches(Regex("sitemap_0_[0-9a-f]{32}")))

        val detail = service.readSiteMapMessage(
            GetSitemapMessageById(
                projectId = assertNotNull(search.projectId),
                id = found.ref.id,
                part = "response_body",
                offset = 1,
                limit = 3,
            )
        )

        assertEquals(SiteMapReadStatus.OK, detail.status)
        assertEquals("bcd", detail.content?.data)
        assertEquals(5, detail.content?.totalBytes)
        assertEquals(4, detail.content?.nextOffsetBytes)
        assertEquals(found.ref.id, detail.metadata?.id)

        val invalidOffset = service.readSiteMapMessage(
            GetSitemapMessageById(
                projectId = assertNotNull(search.projectId),
                id = found.ref.id,
                part = "response_body",
                offset = 6,
            )
        )
        assertEquals(SiteMapReadStatus.INVALID_ARGUMENT, invalidOffset.status)
        assertTrue(invalidOffset.error.orEmpty().contains("totalBytes"))
    }

    @Test
    fun `Site Map IDs fail closed after a project or indexed item changes`() = runBlocking {
        val first = siteMapItem("GET", "https://example.test/first", 200)
        siteMapItems += first.item
        val search = service.search(SearchHttpMessages(sources = listOf(HttpMessageSource.SITE_MAP)))
        val id = search.items.single().ref.id

        every { project.id() } returns "other-project"
        val wrongProject = service.readSiteMapMessage(GetSitemapMessageById("project-123", id))
        assertEquals(SiteMapReadStatus.PROJECT_MISMATCH, wrongProject.status)

        every { project.id() } returns "project-123"
        siteMapItems[0] = siteMapItem("GET", "https://example.test/replaced", 200).item
        val stale = service.readSiteMapMessage(GetSitemapMessageById("project-123", id))
        assertEquals(SiteMapReadStatus.NOT_FOUND, stale.status)
    }

    @Test
    fun `metadata scan budget returns a resumable cursor without rescanning earlier items`() = runBlocking {
        proxyHistory += proxyItem(1, "GET", "https://example.test/one", 200).item
        proxyHistory += proxyItem(2, "GET", "https://example.test/two", 200).item
        proxyHistory += proxyItem(3, "GET", "https://example.test/three", 200).item
        val boundedService = HttpMessageSearchService(
            api,
            config,
            cursorSecret = ByteArray(32) { 9 },
            maxScannedItems = 2,
        )

        val first = boundedService.search(
            SearchHttpMessages(pathContains = "/missing", newestFirst = false)
        )
        assertEquals(2, first.scanned)
        assertTrue(first.scanLimitReached)
        assertTrue(first.hasMore)

        val second = boundedService.search(SearchHttpMessages(cursor = assertNotNull(first.nextCursor)))
        assertEquals(1, second.scanned)
        assertFalse(second.hasMore)
    }

    @Test
    fun `oversized content search skips the item without scanning its bytes`() = runBlocking {
        val oversized = proxyItem(
            id = 9,
            method = "POST",
            url = "https://example.test/large",
            status = 200,
            requestBodyBytes = MAX_HTTP_SEARCH_TEXT_BYTES.toInt() + 1,
        )
        proxyHistory += oversized.item

        val result = service.search(SearchHttpMessages(text = "needle", searchIn = HttpSearchLocation.REQUEST))

        assertEquals(HttpMessageSearchStatus.OK, result.status)
        assertEquals(1, result.scanned)
        assertEquals(1, result.oversizedContentSkipped)
        assertEquals(0, result.returned)
        verify(exactly = 0) { oversized.request.contains(any<String>(), any<Boolean>()) }
    }

    private fun proxyItem(
        id: Int,
        method: String,
        url: String,
        status: Int,
        requestBodyBytes: Int = 0,
    ): ProxyFixture {
        val item = mockk<ProxyHttpRequestResponse>()
        val request = request(method, url, requestBodyBytes)
        val response = response(status, "response")
        val service = httpService("example.test", 443, true)
        val annotations = mockk<Annotations>()
        every { annotations.notes() } returns null
        every { item.id() } returns id
        every { item.request() } returns request
        every { item.response() } returns response
        every { item.httpService() } returns service
        every { item.annotations() } returns annotations
        every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z").plusSeconds(id.toLong())
        every { item.listenerPort() } returns 8080
        every { item.edited() } returns false
        return ProxyFixture(item, request)
    }

    private fun siteMapItem(
        method: String,
        url: String,
        status: Int,
        responseBody: String = "response",
    ): SiteMapFixture {
        val item = mockk<HttpRequestResponse>()
        val request = request(method, url, 0)
        val response = response(status, responseBody)
        val service = httpService("example.test", 443, true)
        val annotations = mockk<Annotations>()
        every { annotations.notes() } returns null
        every { item.request() } returns request
        every { item.response() } returns response
        every { item.httpService() } returns service
        every { item.annotations() } returns annotations
        return SiteMapFixture(item)
    }

    private fun request(method: String, url: String, bodyLength: Int): HttpRequest {
        val request = mockk<HttpRequest>()
        val body = byteArray(bodyLength, "")
        every { request.method() } returns method
        every { request.url() } returns url
        every { request.path() } returns java.net.URI(url).rawPath
        every { request.isInScope() } returns true
        every { request.body() } returns body
        every { request.bodyOffset() } returns 100
        every { request.headers() } returns emptyList()
        every { request.httpVersion() } returns "HTTP/1.1"
        every { request.contains(any<String>(), any<Boolean>()) } returns false
        every { request.toByteArray() } returns body
        return request
    }

    private fun response(status: Int, bodyText: String): HttpResponse {
        val response = mockk<HttpResponse>()
        val body = byteArray(bodyText.toByteArray().size, bodyText)
        every { response.statusCode() } returns status.toShort()
        every { response.mimeType() } returns MimeType.JSON
        every { response.body() } returns body
        every { response.bodyOffset() } returns 80
        every { response.headers() } returns emptyList()
        every { response.httpVersion() } returns "HTTP/1.1"
        every { response.contains(any<String>(), any<Boolean>()) } returns false
        every { response.toByteArray() } returns body
        return response
    }

    private fun byteArray(length: Int, text: String): MontoyaByteArray {
        val bytes = mockk<MontoyaByteArray>()
        every { bytes.length() } returns length
        every { bytes.getByte(any()) } answers {
            val raw = text.toByteArray()
            if (raw.isEmpty()) 0 else raw[firstArg<Int>().coerceIn(0, raw.lastIndex)]
        }
        every { bytes.subArray(any(), any()) } answers {
            val start = firstArg<Int>()
            val end = secondArg<Int>()
            val selected = mockk<MontoyaByteArray>()
            val raw = text.toByteArray().copyOfRange(start.coerceAtMost(text.length), end.coerceAtMost(text.length))
            every { selected.length() } returns raw.size
            every { selected.toString() } returns raw.toString(Charsets.UTF_8)
            every { selected.getBytes() } returns raw
            selected
        }
        every { bytes.toString() } returns text
        every { bytes.getBytes() } returns text.toByteArray()
        return bytes
    }

    private fun httpService(host: String, port: Int, secure: Boolean): HttpService = mockk<HttpService>().also {
        every { it.host() } returns host
        every { it.port() } returns port
        every { it.secure() } returns secure
    }

    private data class ProxyFixture(
        val item: ProxyHttpRequestResponse,
        val request: HttpRequest,
    )

    private data class SiteMapFixture(val item: HttpRequestResponse)
}
