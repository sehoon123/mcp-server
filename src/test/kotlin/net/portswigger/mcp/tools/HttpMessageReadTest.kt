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
import kotlin.test.assertNull

class HttpMessageReadTest {
    @Test
    fun `project switch after resolution fails closed before returning metadata`() = runBlocking {
        val fixture = fixture(projectIds = listOf("project-a", "project-b"))

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
    fun `invalid source ID is rejected before source lookup`() = runBlocking {
        val fixture = fixture(projectIds = listOf("project-a"))

        val result = fixture.service.read(
            GetHttpMessage(
                projectId = "project-a",
                ref = HttpMessageReference(HttpMessageSource.PROXY, "not-numeric"),
            )
        )

        assertEquals(HttpMessageReadStatus.INVALID_ID, result.status)
        verify(exactly = 0) { fixture.proxy.history(any()) }
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

        return ReadFixture(HttpMessageReadService(api, config), proxy)
    }

    private data class ReadFixture(
        val service: HttpMessageReadService,
        val proxy: Proxy,
    )
}
