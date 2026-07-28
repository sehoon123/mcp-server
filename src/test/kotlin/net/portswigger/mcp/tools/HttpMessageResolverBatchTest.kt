package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.organizer.Organizer
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.sitemap.SiteMap
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import io.mockk.verifyOrder
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class HttpMessageResolverBatchTest {
    @Test
    fun `32 reverse ordered Proxy references use one bounded filtered lookup`() = runBlocking {
        val items = (1..32).map(::proxyItem)
        val fixture = fixture(proxyItems = items)
        val refs = (32 downTo 1).map { HttpMessageReference(HttpMessageSource.PROXY, it.toString()) }

        val result = fixture.resolver.resolveAll("project-one", refs)

        val found = assertIs<HttpMessageBatchResolution.Found>(result)
        assertEquals((32 downTo 1).map(Int::toString), found.messages.map { it.ref.id })
        verify(exactly = 1) { fixture.proxy.history(any()) }
    }

    @Test
    fun `mixed sources use one filtered lookup each and preserve caller order`() = runBlocking {
        val proxyItems = listOf(proxyItem(1), proxyItem(2))
        val organizerItems = listOf(organizerItem(1), organizerItem(2))
        val fixture = fixture(proxyItems = proxyItems.reversed(), organizerItems = organizerItems.reversed())
        val refs = listOf(
            HttpMessageReference(HttpMessageSource.ORGANIZER, "2"),
            HttpMessageReference(HttpMessageSource.PROXY, "1"),
            HttpMessageReference(HttpMessageSource.ORGANIZER, "1"),
            HttpMessageReference(HttpMessageSource.PROXY, "2"),
        )

        val result = fixture.resolver.resolveAll("project-one", refs)

        val found = assertIs<HttpMessageBatchResolution.Found>(result)
        assertEquals(refs, found.messages.map { it.ref })
        verify(exactly = 1) { fixture.proxy.history(any()) }
        verify(exactly = 1) { fixture.organizer.items(any()) }
        verifyOrder {
            fixture.organizer.items(any())
            fixture.proxy.history(any())
        }
    }

    @Test
    fun `duplicate caller references reuse one record and preserve duplicates`() = runBlocking {
        val item = proxyItem(7)
        val fixture = fixture(proxyItems = listOf(item))
        val ref = HttpMessageReference(HttpMessageSource.PROXY, "7")

        val result = fixture.resolver.resolveAll("project-one", listOf(ref, ref))

        val found = assertIs<HttpMessageBatchResolution.Found>(result)
        assertEquals(listOf(ref, ref), found.messages.map { it.ref })
        verify(exactly = 1) { fixture.proxy.history(any()) }
        verify(exactly = 2) { item.request() }
    }

    @Test
    fun `missing early reference retains its exact failure index`() = runBlocking {
        val fixture = fixture(proxyItems = listOf(proxyItem(1)))
        val missing = HttpMessageReference(HttpMessageSource.PROXY, "99")
        val refs = listOf(missing, HttpMessageReference(HttpMessageSource.PROXY, "1"))

        val result = fixture.resolver.resolveAll("project-one", refs)

        val failed = assertIs<HttpMessageBatchResolution.Failed>(result)
        assertEquals(HttpMessageResolutionStatus.NOT_FOUND, failed.status)
        assertEquals(missing, failed.ref)
        assertEquals(0, failed.refIndex)
        verify(exactly = 1) { fixture.proxy.history(any()) }
    }

    @Test
    fun `unordered filtered results are reconstructed in caller order`() = runBlocking {
        val fixture = fixture(proxyItems = listOf(proxyItem(3), proxyItem(1), proxyItem(2)))
        val refs = listOf(2, 3, 1).map { HttpMessageReference(HttpMessageSource.PROXY, it.toString()) }

        val result = fixture.resolver.resolveAll("project-one", refs)

        val found = assertIs<HttpMessageBatchResolution.Found>(result)
        assertEquals(listOf("2", "3", "1"), found.messages.map { it.ref.id })
        verify(exactly = 1) { fixture.proxy.history(any()) }
    }

    @Test
    fun `unexpected filtered record fails closed`() = runBlocking {
        val fixture = fixture(proxyAnswer = { listOf(proxyItem(2)) })

        val result = fixture.resolver.resolveAll(
            "project-one",
            listOf(HttpMessageReference(HttpMessageSource.PROXY, "1")),
        )

        val failed = assertIs<HttpMessageBatchResolution.Failed>(result)
        assertEquals(HttpMessageResolutionStatus.BURP_ERROR, failed.status)
        assertEquals(0, failed.refIndex)
        verify(exactly = 1) { fixture.proxy.history(any()) }
    }

    @Test
    fun `duplicate filtered records fail closed`() = runBlocking {
        val item = proxyItem(1)
        val fixture = fixture(proxyAnswer = { listOf(item, item) })

        val result = fixture.resolver.resolveAll(
            "project-one",
            listOf(
                HttpMessageReference(HttpMessageSource.PROXY, "1"),
                HttpMessageReference(HttpMessageSource.PROXY, "2"),
            ),
        )

        val failed = assertIs<HttpMessageBatchResolution.Failed>(result)
        assertEquals(HttpMessageResolutionStatus.BURP_ERROR, failed.status)
        assertEquals(0, failed.refIndex)
        verify(exactly = 1) { fixture.proxy.history(any()) }
    }

    @Test
    fun `project transition after grouped resolution discards all messages`() = runBlocking {
        val fixture = fixture(
            proxyItems = listOf(proxyItem(1), proxyItem(2)),
            projectIds = listOf("project-one", "project-one", "project-two"),
        )
        val refs = listOf(1, 2).map { HttpMessageReference(HttpMessageSource.PROXY, it.toString()) }

        val result = fixture.resolver.resolveAll("project-one", refs)

        val failed = assertIs<HttpMessageBatchResolution.Failed>(result)
        assertEquals(HttpMessageResolutionStatus.PROJECT_MISMATCH, failed.status)
        assertEquals("project-two", failed.projectId)
        assertEquals(refs.first(), failed.ref)
        assertEquals(0, failed.refIndex)
        verify(exactly = 1) { fixture.proxy.history(any()) }
    }

    @Test
    fun `cancellation after synchronous filtered lookup propagates before records are used`() = runBlocking {
        lateinit var worker: Deferred<HttpMessageBatchResolution>
        val fixture = fixture(proxyAnswer = {
            worker.cancel()
            listOf(proxyItem(1))
        })
        worker = async {
            fixture.resolver.resolveAll(
                "project-one",
                listOf(HttpMessageReference(HttpMessageSource.PROXY, "1")),
            )
        }

        assertFailsWith<CancellationException> { worker.await() }
        verify(exactly = 1) { fixture.proxy.history(any()) }
    }

    @Test
    fun `cancellation after synchronous Organizer lookup propagates before records are used`() = runBlocking {
        lateinit var worker: Deferred<HttpMessageBatchResolution>
        val fixture = fixture(organizerAnswer = {
            worker.cancel()
            listOf(organizerItem(1))
        })
        worker = async {
            fixture.resolver.resolveAll(
                "project-one",
                listOf(HttpMessageReference(HttpMessageSource.ORGANIZER, "1")),
            )
        }

        assertFailsWith<CancellationException> { worker.await() }
        verify(exactly = 1) { fixture.organizer.items(any()) }
    }

    @Test
    fun `cancellation after synchronous Site Map lookup propagates before records are used`() = runBlocking {
        lateinit var worker: Deferred<HttpMessageBatchResolution>
        val fixture = fixture(siteMapAnswer = {
            worker.cancel()
            emptyList()
        })
        worker = async {
            fixture.resolver.resolveAll(
                "project-one",
                listOf(HttpMessageReference(HttpMessageSource.SITE_MAP, "sitemap_0_${"0".repeat(32)}")),
            )
        }

        assertFailsWith<CancellationException> { worker.await() }
        verify(exactly = 1) { fixture.siteMap.requestResponses() }
    }

    private fun fixture(
        proxyItems: List<ProxyHttpRequestResponse> = emptyList(),
        organizerItems: List<OrganizerItem> = emptyList(),
        projectIds: List<String> = listOf("project-one", "project-one", "project-one", "project-one"),
        proxyAnswer: (() -> List<ProxyHttpRequestResponse>)? = null,
        organizerAnswer: (() -> List<OrganizerItem>)? = null,
        siteMapAnswer: (() -> List<HttpRequestResponse>)? = null,
    ): Fixture {
        val api = mockk<MontoyaApi>()
        val project = mockk<Project>()
        val proxy = mockk<Proxy>()
        val organizer = mockk<Organizer>()
        val siteMap = mockk<SiteMap>()
        val logging = mockk<Logging>(relaxed = true)
        val storage = mockk<PersistedObject>(relaxed = true)
        val config = McpConfig(storage, logging)

        every { api.project() } returns project
        every { project.id() } returnsMany projectIds
        every { api.proxy() } returns proxy
        every { api.organizer() } returns organizer
        every { api.siteMap() } returns siteMap
        every { api.logging() } returns logging
        every { proxy.history(any()) } answers {
            proxyAnswer?.invoke() ?: run {
                val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
                proxyItems.filter(filter::matches)
            }
        }
        every { organizer.items(any()) } answers {
            organizerAnswer?.invoke() ?: run {
                val filter = firstArg<burp.api.montoya.organizer.OrganizerItemFilter>()
                organizerItems.filter(filter::matches)
            }
        }
        every { siteMap.requestResponses() } answers { siteMapAnswer?.invoke() ?: emptyList() }

        return Fixture(HttpMessageResolver(api, config), proxy, organizer, siteMap)
    }

    private fun proxyItem(id: Int): ProxyHttpRequestResponse = mockk<ProxyHttpRequestResponse>().also { item ->
        every { item.id() } returns id
        every { item.request() } returns request("/proxy/$id")
        every { item.response() } returns null
    }

    private fun organizerItem(id: Int): OrganizerItem = mockk<OrganizerItem>().also { item ->
        every { item.id() } returns id
        every { item.request() } returns request("/organizer/$id")
        every { item.response() } returns null
    }

    private fun request(path: String): HttpRequest = mockk<HttpRequest>().also { request ->
        every { request.path() } returns path
    }

    private data class Fixture(
        val resolver: HttpMessageResolver,
        val proxy: Proxy,
        val organizer: Organizer,
        val siteMap: SiteMap,
    )
}
