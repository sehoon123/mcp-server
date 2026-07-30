package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.Test
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HttpMessageReadTest {
    @Test
    fun `project switch after resolution fails closed before returning metadata`() = runBlocking {
        val fixture = fixture(projectIds = listOf("project-a", "project-a", "project-b"))

        val result = fixture.service.read(
            GetHttpMessage(
                projectId = "project-a",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "7"),
            )
        )

        assertEquals(HttpMessageReadStatus.PROJECT_MISMATCH, result.status)
        assertEquals("project-b", result.projectId)
        assertNull(result.metadata)
        assertNull(result.content)
        verify(exactly = 1) { fixture.proxy.history(any()) }
    }

    @Test
    fun `Proxy capture-time selection reads no full source metadata`() = runBlocking {
        val fixture = fixture(projectIds = listOf("project-a", "project-a"))
        val resolution = HttpMessageResolver(fixture.api, fixture.config).resolve(
            projectId = "project-a",
            ref = HttpMessageReference(HttpMessageSource.PROXY, "07"),
            sourceMetadata = HttpSourceMetadataSelection.PROXY_CAPTURE_TIME,
        )

        val found = resolution as HttpMessageBatchResolution.Found
        assertEquals(1_767_323_045_000L, found.messages.single().sourceMetadata?.proxyCaptureTimeEpochMillis)
        verify(exactly = 1) { fixture.item.time() }
        verify(exactly = 0) { fixture.item.annotations() }
        verify(exactly = 0) { fixture.item.listenerPort() }
        verify(exactly = 0) { fixture.item.edited() }
        verify(exactly = 0) { fixture.request.body() }
        verify(exactly = 0) { fixture.request.headers() }
    }

    @Test
    fun `invalid source ID is rejected before source lookup without echoing an unverified project`() = runBlocking {
        val fixture = fixture(projectIds = listOf("project-a"))

        val result = fixture.service.read(
            GetHttpMessage(
                projectId = "caller-forged",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "not-numeric"),
            )
        )

        assertEquals(HttpMessageReadStatus.INVALID_ID, result.status)
        assertNull(result.projectId)
        verify(exactly = 0) { fixture.api.project() }
        verify(exactly = 0) { fixture.proxy.history(any()) }
    }

    @Test
    fun `pre-capture page validation does not echo the caller project`() = runBlocking {
        val fixture = fixture(projectIds = listOf("project-a"))

        val result = fixture.service.read(
            GetHttpMessage(
                projectId = "caller-forged",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "7"),
                limit = 0,
            )
        )

        assertEquals(HttpMessageReadStatus.INVALID_ARGUMENT, result.status)
        assertNull(result.projectId)
        verify(exactly = 0) { fixture.api.project() }
        verify(exactly = 0) { fixture.proxy.history(any()) }
    }

    @Test
    fun `offset at and beyond selected HTTP content preserves page boundary semantics`() = runBlocking {
        val fixture = fixture(projectIds = List(6) { "project-a" })
        val input = GetHttpMessage(
            projectId = "project-a",
            ref = HttpMessageReference(HttpMessageSource.PROXY, "7"),
            part = "request_body",
            offset = 0,
        )

        val terminal = fixture.service.read(input)
        val beyond = fixture.service.read(input.copy(offset = 1))

        assertEquals(HttpMessageReadStatus.OK, terminal.status)
        assertEquals("", terminal.content?.data)
        assertEquals(0, terminal.content?.returnedBytes)
        assertEquals(0, terminal.content?.totalBytes)
        assertEquals(false, terminal.content?.hasMore)
        assertNull(terminal.content?.nextOffsetBytes)
        assertEquals(HttpMessageReadStatus.INVALID_ARGUMENT, beyond.status)
        assertEquals("project-a", beyond.projectId)
        assertTrue(beyond.error.orEmpty().contains("totalBytes (0)"))
        assertNull(beyond.metadata)
        assertNull(beyond.content)
    }

    @Test
    fun `final project check supersedes an out-of-range HTTP correction`() = runBlocking {
        val fixture = fixture(projectIds = listOf("project-a", "project-a", "project-a", "project-b"))

        val result = fixture.service.read(
            GetHttpMessage(
                projectId = "project-a",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "7"),
                part = "request_body",
                offset = 1,
            )
        )

        assertEquals(HttpMessageReadStatus.PROJECT_MISMATCH, result.status)
        assertEquals("project-b", result.projectId)
        assertNull(result.metadata)
        assertNull(result.content)
    }

    @Test
    fun `request accessor IllegalArgumentException is a sanitized Burp error`() = runBlocking {
        val fixture = fixture(projectIds = listOf("project-a", "project-a", "project-a"))
        every { fixture.request.url() } throws IllegalArgumentException("PRIVATE_SENTINEL")

        val result = fixture.service.read(
            GetHttpMessage(
                projectId = "project-a",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "7"),
            )
        )

        assertEquals(HttpMessageReadStatus.BURP_ERROR, result.status)
        assertEquals("project-a", result.projectId)
        assertFalse(result.error.orEmpty().contains("PRIVATE_SENTINEL"))
        assertNull(result.metadata)
        assertNull(result.content)
    }

    private fun fixture(projectIds: List<String>): ReadFixture {
        val api = mockk<MontoyaApi>()
        val project = mockk<Project>()
        val proxy = mockk<Proxy>()
        val item = mockk<ProxyHttpRequestResponse>()
        val request = mockk<HttpRequest>()
        val service = mockk<HttpService>()
        val body = mockk<MontoyaByteArray>()
        val annotations = mockk<Annotations>()
        val logging = mockk<Logging>(relaxed = true)
        val storage = mockk<PersistedObject>(relaxed = true)
        val config = McpConfig(storage, logging)

        every { api.project() } returns project
        every { project.id() } returnsMany projectIds
        every { api.proxy() } returns proxy
        every { api.logging() } returns logging
        every { proxy.history(any()) } answers {
            val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
            listOf(item).filter(filter::matches)
        }
        every { item.id() } returns 7
        every { item.request() } returns request
        every { item.response() } returns null
        every { item.annotations() } returns annotations
        every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z")
        every { item.listenerPort() } returns 8080
        every { item.edited() } returns false
        every { annotations.notes() } returns null
        every { request.method() } returns "GET"
        every { request.url() } returns "https://example.test/path"
        every { request.httpService() } returns service
        every { request.body() } returns body
        every { body.length() } returns 0
        every { service.host() } returns "example.test"
        every { service.port() } returns 443
        every { service.secure() } returns true

        return ReadFixture(
            service = HttpMessageReadService(api, config),
            api = api,
            config = config,
            proxy = proxy,
            item = item,
            request = request,
        )
    }

    private data class ReadFixture(
        val service: HttpMessageReadService,
        val api: MontoyaApi,
        val config: McpConfig,
        val proxy: Proxy,
        val item: ProxyHttpRequestResponse,
        val request: HttpRequest,
    )
}
