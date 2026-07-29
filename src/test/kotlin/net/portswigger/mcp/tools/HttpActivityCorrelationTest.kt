package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HttpActivityCorrelationTest {
    private val api = mockk<MontoyaApi>()
    private val project = mockk<Project>()
    private val proxy = mockk<Proxy>()
    private val organizer = mockk<Organizer>()
    private val siteMap = mockk<SiteMap>()
    private val logging = mockk<Logging>(relaxed = true)
    private val proxyItems = mutableListOf<ProxyHttpRequestResponse>()
    private val organizerItems = mutableListOf<OrganizerItem>()
    private val siteMapItems = mutableListOf<HttpRequestResponse>()
    private var currentProjectId = "project-correlation"
    private lateinit var originalApprovalHandler: DataAccessApprovalHandler

    @BeforeEach
    fun setUp() {
        originalApprovalHandler = DataAccessSecurity.approvalHandler
        every { api.project() } returns project
        every { project.id() } answers { currentProjectId }
        every { api.proxy() } returns proxy
        every { api.organizer() } returns organizer
        every { api.siteMap() } returns siteMap
        every { api.logging() } returns logging
        every { proxy.history(any()) } answers {
            val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
            proxyItems.filter(filter::matches)
        }
        every { organizer.items(any()) } answers {
            val filter = firstArg<burp.api.montoya.organizer.OrganizerItemFilter>()
            organizerItems.filter(filter::matches)
        }
        every { siteMap.requestResponses() } answers { siteMapItems.toList() }
    }

    @AfterEach
    fun tearDown() {
        DataAccessSecurity.approvalHandler = originalApprovalHandler
    }

    @Test
    fun `mixed sources preserve caller order expose only Proxy time and group similarity without deduplication`() = runBlocking {
        val proxyItem = proxyItem(1, "GET", "/same?proxy-secret=one", 200, MimeType.JSON)
        val siteMapItem = siteMapItem("GET", "/same?sitemap-secret=two", 200, MimeType.JSON)
        val organizerItem = organizerItem(2, "GET", "/same?organizer-secret=three", 200, MimeType.JSON)
        proxyItems += proxyItem.item
        siteMapItems += siteMapItem.item
        organizerItems += organizerItem.item
        val siteMapId = stableSiteMapId(currentProjectId, 0, siteMapItem.item)
        val approvals = mutableListOf<DataAccessType>()
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                approvals += accessType
                return true
            }
        }
        val events = mutableListOf<Double>()

        val result = service(requireDataApproval = true).correlate(
            CorrelateHttpActivity(
                projectId = currentProjectId,
                baselineRefs = listOf(ref(HttpMessageSource.PROXY, "1")),
                comparisonRefs = listOf(
                    ref(HttpMessageSource.SITE_MAP, siteMapId),
                    ref(HttpMessageSource.ORGANIZER, "2"),
                ),
            )
        ) { progress, total, message ->
            assertEquals(5.0, total)
            assertFalse(message.orEmpty().contains(currentProjectId))
            events += progress
        }

        assertEquals(HttpActivityCorrelationStatus.OK, result.status)
        assertEquals((0..5).map(Int::toDouble), events)
        assertEquals(listOf(DataAccessType.HTTP_HISTORY, DataAccessType.SITE_MAP, DataAccessType.ORGANIZER), approvals)
        assertEquals(
            listOf(HttpActivityCohort.BASELINE, HttpActivityCohort.COMPARISON, HttpActivityCohort.COMPARISON),
            result.timeline.map { it.cohort },
        )
        assertEquals(listOf("1", siteMapId, "2"), result.timeline.map { it.ref.id })
        assertEquals(HttpActivityTimestampKind.PROXY_CAPTURED, result.timeline[0].timestampKind)
        assertEquals(1_767_323_045_001L, result.timeline[0].observedAtEpochMillis)
        assertEquals(HttpActivityTimestampKind.UNAVAILABLE, result.timeline[1].timestampKind)
        assertNull(result.timeline[1].observedAtEpochMillis)
        assertEquals(HttpActivityTimestampKind.UNAVAILABLE, result.timeline[2].timestampKind)
        assertNull(result.timeline[2].observedAtEpochMillis)
        assertTrue(result.timeline.all { it.pathPrefix == "/same" })
        assertEquals(3, result.evidence.selectedReferences)
        assertEquals(1, result.evidence.timestampedEvents)
        assertFalse(result.evidence.chronologyEstablished)
        assertFalse(result.evidence.exactCrossSourceIdentityEstablished)
        assertFalse(result.evidence.probableDuplicatesDeduplicated)
        assertEquals(1, result.similarityGroups.size)
        assertEquals(listOf(0, 1, 2), result.similarityGroups.single().eventIndices)
        assertEquals(
            listOf(HttpMessageSource.PROXY, HttpMessageSource.SITE_MAP, HttpMessageSource.ORGANIZER),
            result.similarityGroups.single().sources,
        )
        assertFalse(result.similarityGroups.single().identityEstablished)
        assertTrue(result.timeline.all { it.similarityGroupId == "similarity-1" })
        assertEquals(0, result.delta?.unchangedServiceKeys)
        assertEquals(0, result.delta?.unchangedPathPrefixKeys)
        assertEquals(listOf(ValueCountDelta("GET", 1, 2, 1)), result.delta?.methods)
        assertFalse(result.toString().contains("proxy-secret"))
        assertFalse(result.toString().contains("sitemap-secret"))
        assertFalse(result.toString().contains("organizer-secret"))
        verify(exactly = 0) { proxyItem.request.body() }
        verify(exactly = 0) { proxyItem.request.headers() }
        verify(exactly = 0) { proxyItem.item.annotations() }
        verify(exactly = 0) { organizerItem.request.body() }
        verify(exactly = 0) { organizerItem.request.headers() }
        verify(exactly = 0) { organizerItem.item.annotations() }
    }

    @Test
    fun `similarity IDs follow first event order and near matches remain ungrouped`() = runBlocking {
        proxyItems += proxyItem(1, "GET", "/first", 200, MimeType.JSON).item
        proxyItems += proxyItem(2, "GET", "/second", 200, MimeType.JSON).item
        organizerItems += organizerItem(3, "GET", "/second", 200, MimeType.JSON).item
        organizerItems += organizerItem(4, "GET", "/first", 200, MimeType.JSON).item
        organizerItems += organizerItem(5, "POST", "/first", 200, MimeType.JSON).item

        val result = service().correlate(
            CorrelateHttpActivity(
                currentProjectId,
                baselineRefs = listOf(ref(HttpMessageSource.PROXY, "1"), ref(HttpMessageSource.PROXY, "2")),
                comparisonRefs = listOf(
                    ref(HttpMessageSource.ORGANIZER, "3"),
                    ref(HttpMessageSource.ORGANIZER, "4"),
                    ref(HttpMessageSource.ORGANIZER, "5"),
                ),
            )
        )

        assertEquals(HttpActivityCorrelationStatus.OK, result.status)
        assertEquals(listOf("similarity-1", "similarity-2"), result.similarityGroups.map { it.id })
        assertEquals(listOf(listOf(0, 3), listOf(1, 2)), result.similarityGroups.map { it.eventIndices })
        assertEquals(
            listOf("similarity-1", "similarity-2", "similarity-2", "similarity-1", null),
            result.timeline.map { it.similarityGroupId },
        )
        assertFalse(result.similarityGroups.any { 4 in it.eventIndices })
    }

    @Test
    fun `delta is complete deterministic and redacts path identifiers`() = runBlocking {
        proxyItems += proxyItem(1, "GET", "/api/users/123/report.JSON?token=old", 200, MimeType.JSON).item
        proxyItems += proxyItem(
            2,
            "POST",
            "/admin/550e8400-e29b-41d4-a716-446655440000/report.txt?token=new",
            404,
            MimeType.HTML,
        ).item

        val result = service().correlate(
            CorrelateHttpActivity(
                currentProjectId,
                baselineRefs = listOf(ref(HttpMessageSource.PROXY, "1")),
                comparisonRefs = listOf(ref(HttpMessageSource.PROXY, "2")),
                pathDepth = 3,
            )
        )

        assertEquals(HttpActivityCorrelationStatus.OK, result.status)
        assertEquals(listOf("/api/users/{number}", "/admin/{uuid}/report.txt"), result.timeline.map { it.pathPrefix })
        assertEquals(listOf("GET", "POST"), result.delta?.methods?.map { it.value })
        assertEquals(listOf(-1, 1), result.delta?.methods?.map { it.delta })
        assertEquals(listOf("2xx", "4xx"), result.delta?.statusClasses?.map { it.value })
        assertEquals(listOf("html", "json"), result.delta?.mimeTypes?.map { it.value })
        assertEquals(listOf("json", "txt"), result.delta?.extensions?.map { it.value })
        assertEquals(2, result.delta?.pathPrefixes?.size)
        assertEquals(0, result.delta?.unchangedPathPrefixKeys)
        assertTrue(result.similarityGroups.isEmpty())
        assertFalse(result.toString().contains("token=old"))
        assertFalse(result.toString().contains("token=new"))
    }

    @Test
    fun `service and path deltas are exact sorted and count unchanged keys`() = runBlocking {
        proxyItems += proxyItem(1, "GET", "/same", 200, MimeType.JSON, host = "z.test").item
        proxyItems += proxyItem(2, "GET", "/unchanged", 200, MimeType.JSON, host = "a.test").item
        proxyItems += proxyItem(3, "GET", "/old", 200, MimeType.JSON, host = "a.test").item
        proxyItems += proxyItem(4, "GET", "/same", 200, MimeType.JSON, host = "z.test").item
        proxyItems += proxyItem(5, "GET", "/unchanged", 200, MimeType.JSON, host = "a.test").item
        proxyItems += proxyItem(6, "GET", "/new", 200, MimeType.JSON, host = "b.test").item

        val result = service().correlate(
            CorrelateHttpActivity(
                currentProjectId,
                baselineRefs = (1..3).map { ref(HttpMessageSource.PROXY, it.toString()) },
                comparisonRefs = (4..6).map { ref(HttpMessageSource.PROXY, it.toString()) },
            )
        )

        assertEquals(HttpActivityCorrelationStatus.OK, result.status)
        assertEquals((1..6).map(Int::toString), result.timeline.map { it.ref.id })
        assertEquals(
            listOf(
                ServiceCountDelta("https", "a.test", 443, 2, 1, -1),
                ServiceCountDelta("https", "b.test", 443, 0, 1, 1),
            ),
            result.delta?.services,
        )
        assertEquals(
            listOf(
                PathCountDelta("https", "a.test", 443, "/old", 1, 0, -1),
                PathCountDelta("https", "b.test", 443, "/new", 0, 1, 1),
            ),
            result.delta?.pathPrefixes,
        )
        assertEquals(1, result.delta?.unchangedServiceKeys)
        assertEquals(2, result.delta?.unchangedPathPrefixKeys)
        assertTrue(result.delta?.methods.orEmpty().isEmpty())
        assertTrue(result.delta?.statusClasses.orEmpty().isEmpty())
        assertTrue(result.delta?.mimeTypes.orEmpty().isEmpty())
        assertTrue(result.delta?.extensions.orEmpty().isEmpty())
    }

    @Test
    fun `maximum 16 plus 16 request remains bounded and caller ordered`() = runBlocking {
        proxyItems += (1..32).map { id -> proxyItem(id, "GET", "/item/$id", 200, MimeType.JSON).item }
        val baseline = (1..16).map { ref(HttpMessageSource.PROXY, it.toString()) }
        val comparison = (17..32).map { ref(HttpMessageSource.PROXY, it.toString()) }

        val result = service().correlate(CorrelateHttpActivity(currentProjectId, baseline, comparison))

        assertEquals(HttpActivityCorrelationStatus.OK, result.status)
        assertEquals(32, result.timeline.size)
        assertEquals((1..32).map(Int::toString), result.timeline.map { it.ref.id })
        assertEquals(16, result.delta?.baselineRecords)
        assertEquals(16, result.delta?.comparisonRecords)
        verify(exactly = 1) { proxy.history(any()) }
    }

    @Test
    fun `invalid bounds IDs and numeric aliases fail before project or source access`() = runBlocking {
        val service = service()
        val empty = service.correlate(CorrelateHttpActivity(currentProjectId, emptyList(), listOf(ref(HttpMessageSource.PROXY, "1"))))
        val invalidProject = service.correlate(
            CorrelateHttpActivity(
                "project\u0000bad",
                listOf(ref(HttpMessageSource.PROXY, "1")),
                listOf(ref(HttpMessageSource.PROXY, "2")),
            )
        )
        val tooMany = service.correlate(
            CorrelateHttpActivity(
                currentProjectId,
                (1..17).map { ref(HttpMessageSource.PROXY, it.toString()) },
                listOf(ref(HttpMessageSource.PROXY, "18")),
            )
        )
        val invalidId = service.correlate(
            CorrelateHttpActivity(currentProjectId, listOf(ref(HttpMessageSource.PROXY, "bad")), listOf(ref(HttpMessageSource.PROXY, "2")))
        )
        val duplicateAlias = service.correlate(
            CorrelateHttpActivity(currentProjectId, listOf(ref(HttpMessageSource.PROXY, "1")), listOf(ref(HttpMessageSource.PROXY, "01")))
        )
        val invalidDepth = service.correlate(
            CorrelateHttpActivity(currentProjectId, listOf(ref(HttpMessageSource.PROXY, "1")), listOf(ref(HttpMessageSource.PROXY, "2")), 5)
        )

        assertEquals(HttpActivityCorrelationStatus.INVALID_ARGUMENT, empty.status)
        assertEquals(HttpActivityCorrelationStatus.INVALID_ARGUMENT, invalidProject.status)
        assertEquals(HttpActivityCorrelationStatus.INVALID_ARGUMENT, tooMany.status)
        assertEquals(HttpActivityCorrelationStatus.INVALID_ID, invalidId.status)
        assertEquals(0, invalidId.errorRefIndex)
        assertEquals(HttpActivityCorrelationStatus.INVALID_ARGUMENT, duplicateAlias.status)
        assertEquals(1, duplicateAlias.errorRefIndex)
        assertEquals(HttpActivityCorrelationStatus.INVALID_ARGUMENT, invalidDepth.status)
        listOf(empty, invalidProject, tooMany, invalidId, duplicateAlias, invalidDepth).forEach {
            assertNull(it.projectId, "pre-capture validation must not echo the caller project")
            assertTrue(it.timeline.isEmpty())
            assertNull(it.delta)
            assertEquals(0, it.evidence.selectedReferences)
        }
        verify(exactly = 0) { api.project() }
        verify(exactly = 0) { proxy.history(any()) }
    }

    @Test
    fun `denial reports flattened index and does not read a later source`() = runBlocking {
        proxyItems += proxyItem(1, "GET", "/one", 200, MimeType.JSON).item
        organizerItems += organizerItem(2, "GET", "/two", 200, MimeType.JSON).item
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean = false
        }

        val result = service(requireDataApproval = true).correlate(
            CorrelateHttpActivity(
                currentProjectId,
                baselineRefs = listOf(ref(HttpMessageSource.PROXY, "1")),
                comparisonRefs = listOf(ref(HttpMessageSource.ORGANIZER, "2")),
            )
        )

        assertEquals(HttpActivityCorrelationStatus.ACCESS_DENIED, result.status)
        assertEquals(0, result.errorRefIndex)
        assertTrue(result.timeline.isEmpty())
        assertNull(result.delta)
        verify(exactly = 0) { proxy.history(any()) }
        verify(exactly = 0) { organizer.items(any()) }
    }

    @Test
    fun `project change or accessor failure discards every prepared event`() = runBlocking {
        val switching = proxyItem(1, "GET", "/switch", 200, MimeType.JSON)
        every { switching.request.path() } answers {
            currentProjectId = "replacement-project"
            "/switch"
        }
        proxyItems += switching.item
        proxyItems += proxyItem(2, "GET", "/stable", 200, MimeType.JSON).item

        val mismatch = service().correlate(
            CorrelateHttpActivity(currentProjectId, listOf(ref(HttpMessageSource.PROXY, "1")), listOf(ref(HttpMessageSource.PROXY, "2")))
        )
        assertEquals(HttpActivityCorrelationStatus.PROJECT_MISMATCH, mismatch.status)
        assertTrue(mismatch.timeline.isEmpty())

        currentProjectId = "project-correlation"
        proxyItems.clear()
        val broken = proxyItem(3, "GET", "/broken", 200, MimeType.JSON)
        every { broken.request.path() } throws IllegalStateException("ACCESSOR_SECRET_SENTINEL")
        proxyItems += broken.item
        proxyItems += proxyItem(4, "GET", "/other", 200, MimeType.JSON).item
        val failed = service().correlate(
            CorrelateHttpActivity(currentProjectId, listOf(ref(HttpMessageSource.PROXY, "3")), listOf(ref(HttpMessageSource.PROXY, "4")))
        )

        assertEquals(HttpActivityCorrelationStatus.BURP_ERROR, failed.status)
        assertTrue(failed.timeline.isEmpty())
        assertNull(failed.delta)
        assertFalse(failed.error.orEmpty().contains("ACCESSOR_SECRET_SENTINEL"))
    }

    @Test
    fun `project change during completion progress discards every result`() = runBlocking {
        proxyItems += proxyItem(1, "GET", "/one", 200, MimeType.JSON).item
        proxyItems += proxyItem(2, "GET", "/two", 200, MimeType.JSON).item

        val result = service().correlate(
            CorrelateHttpActivity(
                currentProjectId,
                listOf(ref(HttpMessageSource.PROXY, "1")),
                listOf(ref(HttpMessageSource.PROXY, "2")),
            )
        ) { progress, _, _ ->
            if (progress == 5.0) currentProjectId = "replacement-project"
        }

        assertEquals(HttpActivityCorrelationStatus.PROJECT_MISMATCH, result.status)
        assertEquals("replacement-project", result.projectId)
        assertTrue(result.timeline.isEmpty())
        assertTrue(result.similarityGroups.isEmpty())
        assertNull(result.delta)
        assertEquals(0, result.evidence.selectedReferences)
    }

    @Test
    fun `source resolution failure returns a fixed value-free error`() = runBlocking {
        every { proxy.history(any()) } throws IllegalStateException("RESOLUTION_SECRET_SENTINEL")

        val result = service().correlate(
            CorrelateHttpActivity(
                currentProjectId,
                listOf(ref(HttpMessageSource.PROXY, "1")),
                listOf(ref(HttpMessageSource.PROXY, "2")),
            )
        )

        assertEquals(HttpActivityCorrelationStatus.BURP_ERROR, result.status)
        assertEquals("Burp could not resolve one or more HTTP references", result.error)
        assertFalse(result.toString().contains("RESOLUTION_SECRET_SENTINEL"))
        assertTrue(result.timeline.isEmpty())
        assertNull(result.delta)
    }

    @Test
    fun `cancellation from bounded materialization propagates`() = runBlocking {
        val cancelled = proxyItem(1, "GET", "/cancel", 200, MimeType.JSON)
        every { cancelled.request.path() } throws CancellationException("client cancelled")
        proxyItems += cancelled.item
        proxyItems += proxyItem(2, "GET", "/other", 200, MimeType.JSON).item

        assertFailsWith<CancellationException> {
            service().correlate(
                CorrelateHttpActivity(currentProjectId, listOf(ref(HttpMessageSource.PROXY, "1")), listOf(ref(HttpMessageSource.PROXY, "2")))
            )
        }
        Unit
    }

    private fun service(requireDataApproval: Boolean = false): HttpActivityCorrelationService =
        HttpActivityCorrelationService(api, config(requireDataApproval))

    private fun config(requireDataApproval: Boolean): McpConfig {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers {
            firstArg<String>() == "requireDataAccessApproval" && requireDataApproval
        }
        every { storage.getString(any()) } returns ""
        return McpConfig(storage, logging)
    }

    private fun proxyItem(
        id: Int,
        method: String,
        path: String,
        status: Int,
        mimeType: MimeType,
        host: String = "example.test",
    ): ProxyFixture {
        val item = mockk<ProxyHttpRequestResponse>()
        val message = message(method, path, status, mimeType, host)
        every { item.id() } returns id
        every { item.request() } returns message.request
        every { item.response() } returns message.response
        every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z").plusNanos(id * 1_000_000L)
        return ProxyFixture(item, message.request)
    }

    private fun siteMapItem(
        method: String,
        path: String,
        status: Int,
        mimeType: MimeType,
    ): SiteMapFixture {
        val item = mockk<HttpRequestResponse>()
        val message = message(method, path, status, mimeType)
        every { item.request() } returns message.request
        every { item.response() } returns message.response
        return SiteMapFixture(item, message.request)
    }

    private fun organizerItem(
        id: Int,
        method: String,
        path: String,
        status: Int,
        mimeType: MimeType,
    ): OrganizerFixture {
        val item = mockk<OrganizerItem>()
        val message = message(method, path, status, mimeType)
        every { item.id() } returns id
        every { item.request() } returns message.request
        every { item.response() } returns message.response
        return OrganizerFixture(item, message.request)
    }

    private fun message(
        method: String,
        path: String,
        status: Int,
        mimeType: MimeType,
        host: String = "example.test",
    ): MessageFixture {
        val request = mockk<HttpRequest>()
        val response = mockk<HttpResponse>()
        val service = mockk<HttpService>()
        val emptyBytes = mockk<MontoyaByteArray>()
        every { emptyBytes.length() } returns 0
        every { request.httpService() } returns service
        every { request.method() } returns method
        every { request.path() } returns path
        every { request.url() } returns "https://$host$path"
        every { request.httpVersion() } returns "HTTP/1.1"
        every { request.headers() } returns emptyList()
        every { request.body() } returns emptyBytes
        every { request.isInScope() } returns true
        every { service.host() } returns host
        every { service.port() } returns 443
        every { service.secure() } returns true
        every { response.statusCode() } returns status.toShort()
        every { response.mimeType() } returns mimeType
        every { response.httpVersion() } returns "HTTP/1.1"
        every { response.headers() } returns emptyList()
        every { response.body() } returns emptyBytes
        return MessageFixture(request, response)
    }

    private fun ref(source: HttpMessageSource, id: String) = HttpMessageReference(source, id)

    private data class MessageFixture(val request: HttpRequest, val response: HttpResponse)
    private data class ProxyFixture(val item: ProxyHttpRequestResponse, val request: HttpRequest)
    private data class SiteMapFixture(val item: HttpRequestResponse, val request: HttpRequest)
    private data class OrganizerFixture(val item: OrganizerItem, val request: HttpRequest)
}
