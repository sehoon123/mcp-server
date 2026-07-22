package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HttpAttackSurfaceTest {
    private val api = mockk<MontoyaApi>()
    private val logging = mockk<Logging>(relaxed = true)
    private val project = mockk<Project>()
    private val proxy = mockk<Proxy>()
    private val history = mutableListOf<ProxyHttpRequestResponse>()
    private lateinit var config: McpConfig
    private lateinit var index: HttpMetadataIndex
    private lateinit var service: HttpAttackSurfaceService
    private var projectId = "project-attack"
    private var nowNanos = 1L

    @BeforeEach
    fun setUp() {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns false
        every { storage.getString(any()) } returns ""
        every { api.logging() } returns logging
        every { api.project() } returns project
        every { project.id() } answers { projectId }
        every { api.proxy() } returns proxy
        every { proxy.history() } answers { history.toList() }
        config = McpConfig(storage, logging)
        index = HttpMetadataIndex(api, maxRecordsPerSource = 20, nanoTime = { nowNanos })
        service = HttpAttackSurfaceService(api, config, index)
    }

    @Test
    fun `summary aggregates scoped body-free metadata and removes query values`() = runBlocking {
        val first = proxyItem(1, "GET", "/api/users/123?token=secret-value", 200, MimeType.JSON, true)
        val second = proxyItem(2, "POST", "/api/users/456?session=another-secret", 404, MimeType.JSON, true)
        val excluded = proxyItem(3, "DELETE", "/admin/private?credential=hidden", 500, MimeType.HTML, false)
        history += listOf(first.item, second.item, excluded.item)

        val result = service.summarize(
            SummarizeHttpAttackSurface(
                projectId = projectId,
                pathDepth = 3,
            )
        )

        assertEquals(HttpAttackSurfaceStatus.OK, result.status)
        assertEquals(3, result.availableRecords)
        assertEquals(2, result.availableInScopeRecords)
        assertEquals(1, result.availableOutOfScopeRecords)
        assertEquals(2, result.matchedRecords)
        assertEquals(2, result.responseRecords)
        assertEquals(0, result.requestOnlyRecords)
        assertEquals(1, result.serviceCount)
        assertEquals(2, result.services.single().messageCount)
        assertEquals(2, result.services.single().responseCount)
        assertEquals(2, result.services.single().inScopeCount)
        assertEquals(0, result.services.single().outOfScopeCount)
        assertEquals(
            listOf(AttackSurfaceCount("GET", 1), AttackSurfaceCount("POST", 1)),
            result.methods,
        )
        assertEquals(listOf(AttackSurfaceCount("2xx", 1), AttackSurfaceCount("4xx", 1)), result.statusClasses)
        assertEquals(listOf(AttackSurfaceCount("json", 2)), result.mimeTypes)
        assertEquals(1, result.pathPrefixCount)
        assertEquals("/api/users/{number}", result.pathPrefixes.single().pathPrefix)
        assertEquals(2, result.pathPrefixes.single().messageCount)
        assertEquals(MetadataIndexRefresh.REBUILT, result.sources.single().refresh)

        val serialized = Json.encodeToString(result)
        assertFalse(serialized.contains("secret-value"))
        assertFalse(serialized.contains("another-secret"))
        assertFalse(serialized.contains("credential"))
        assertFalse(serialized.contains("/admin/private"))
        verify(exactly = 0) { first.request.body() }
        verify(exactly = 0) { second.request.body() }
        verify(exactly = 0) { excluded.request.body() }
        verify(exactly = 0) { first.request.headers() }
        verify(exactly = 0) { second.request.headers() }
        verify(exactly = 0) { excluded.request.headers() }
    }

    @Test
    fun `identifier-like path segments are normalized and output limits are explicit`() = runBlocking {
        history += proxyItem(
            1,
            "GET",
            "/users/550e8400-e29b-41d4-a716-446655440000/details.js",
            200,
            MimeType.JSON,
            true,
        ).item
        history += proxyItem(2, "GET", "/objects/0123456789abcdef01234567/raw.json", 200, MimeType.PLAIN_TEXT, true).item
        history += proxyItem(3, "GET", "/health/live", 204, MimeType.NONE, true, host = "status.test").item

        val result = service.summarize(
            SummarizeHttpAttackSurface(
                projectId = projectId,
                pathDepth = 2,
                serviceLimit = 1,
                pathLimit = 1,
            )
        )

        assertEquals(HttpAttackSurfaceStatus.OK, result.status)
        assertEquals(2, result.serviceCount)
        assertTrue(result.servicesTruncated)
        assertEquals(3, result.pathPrefixCount)
        assertTrue(result.pathPrefixesTruncated)
        assertEquals(listOf(AttackSurfaceCount("js", 1), AttackSurfaceCount("json", 1)), result.extensions)
        assertEquals(result.extensions, result.services.single().extensions)
        assertTrue(
            result.pathPrefixes.single().pathPrefix in setOf("/objects/{id}", "/users/{uuid}"),
            result.pathPrefixes.single().pathPrefix,
        )
    }

    @Test
    fun `path identifiers use conservative ASCII classification`() = runBlocking {
        val invalidUuid = "550e8400-e29b-61d4.a716-446655440000"
        val nonAsciiToken = "é".repeat(24)
        history += proxyItem(1, "GET", "/number/123456", 200, MimeType.JSON, true).item
        history += proxyItem(2, "GET", "/uuid/550E8400-E29B-41D4-A716-446655440000", 200, MimeType.JSON, true).item
        history += proxyItem(3, "GET", "/hex/ABCDEF0123456789ABCDEF", 200, MimeType.JSON, true).item
        history += proxyItem(4, "GET", "/token/token_value-ABCDEFGHIJKLMNOPQRSTUVWXYZ", 200, MimeType.JSON, true).item
        history += proxyItem(5, "GET", "/near/$invalidUuid", 200, MimeType.JSON, true).item
        history += proxyItem(6, "GET", "/unicode/$nonAsciiToken", 200, MimeType.JSON, true).item

        val prefixes = service.summarize(
            SummarizeHttpAttackSurface(projectId = projectId, pathDepth = 2, pathLimit = 20)
        ).pathPrefixes.map { it.pathPrefix }.toSet()

        assertTrue("/number/{number}" in prefixes)
        assertTrue("/uuid/{uuid}" in prefixes)
        assertTrue("/hex/{id}" in prefixes)
        assertTrue("/token/{id}" in prefixes)
        assertTrue("/near/$invalidUuid" in prefixes)
        assertTrue("/unicode/$nonAsciiToken" in prefixes)
    }

    @Test
    fun `response presence and scope counts remain explicit when out-of-scope records are included`() = runBlocking {
        history += proxyItem(
            1,
            "GET",
            "/queued/request",
            0,
            MimeType.NONE,
            false,
            hasResponse = false,
        ).item

        val result = service.summarize(
            SummarizeHttpAttackSurface(projectId = projectId, inScopeOnly = false)
        )

        assertEquals(HttpAttackSurfaceStatus.OK, result.status)
        assertEquals(1, result.availableOutOfScopeRecords)
        assertEquals(1, result.matchedRecords)
        assertEquals(0, result.responseRecords)
        assertEquals(1, result.requestOnlyRecords)
        assertEquals(0, result.services.single().responseCount)
        assertEquals(0, result.services.single().inScopeCount)
        assertEquals(1, result.services.single().outOfScopeCount)
        assertTrue(result.statusClasses.isEmpty())
        assertTrue(result.mimeTypes.isEmpty())
    }

    @Test
    fun `project mismatch is rejected before any source is read`() = runBlocking {
        projectId = "other-project"

        val result = service.summarize(SummarizeHttpAttackSurface(projectId = "project-attack"))

        assertEquals(HttpAttackSurfaceStatus.PROJECT_MISMATCH, result.status)
        assertEquals("other-project", result.projectId)
        verify(exactly = 0) { api.proxy() }
    }

    @Test
    fun `invalid duplicate sources are rejected before project or history access`() = runBlocking {
        val result = service.summarize(
            SummarizeHttpAttackSurface(
                projectId = projectId,
                sources = listOf(HttpMessageSource.PROXY, HttpMessageSource.PROXY),
            )
        )

        assertEquals(HttpAttackSurfaceStatus.INVALID_ARGUMENT, result.status)
        verify(exactly = 0) { api.project() }
        verify(exactly = 0) { api.proxy() }
    }

    @Test
    fun `second summary reports a validated cache reuse`() = runBlocking {
        history += proxyItem(1, "GET", "/health", 200, MimeType.PLAIN_TEXT, true).item
        service.summarize(SummarizeHttpAttackSurface(projectId = projectId))
        nowNanos++

        val second = service.summarize(SummarizeHttpAttackSurface(projectId = projectId))

        assertEquals(MetadataIndexRefresh.REUSED, second.sources.single().refresh)
    }

    private fun proxyItem(
        id: Int,
        method: String,
        path: String,
        status: Int,
        mimeType: MimeType,
        inScope: Boolean,
        host: String = "api.example.test",
        hasResponse: Boolean = true,
    ): ProxyFixture {
        val item = mockk<ProxyHttpRequestResponse>()
        val request = mockk<HttpRequest>()
        val response = if (hasResponse) mockk<HttpResponse>() else null
        val httpService = mockk<HttpService>()
        every { item.id() } returns id
        every { item.request() } returns request
        every { item.response() } returns response
        every { item.httpService() } returns httpService
        every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z")
        every { request.method() } returns method
        every { request.path() } returns path
        every { request.isInScope() } returns inScope
        if (response != null) {
            every { response.statusCode() } returns status.toShort()
            every { response.mimeType() } returns mimeType
        }
        every { httpService.host() } returns host
        every { httpService.port() } returns 443
        every { httpService.secure() } returns true
        return ProxyFixture(item, request)
    }

    private data class ProxyFixture(
        val item: ProxyHttpRequestResponse,
        val request: HttpRequest,
    )
}
