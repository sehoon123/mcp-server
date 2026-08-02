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
        every { proxy.history() } answers { proxyItems.toList() }
        every { proxy.history(any()) } answers {
            val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
            proxyItems.filter(filter::matches)
        }
        every { organizer.items() } answers { organizerItems.toList() }
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
    fun `related discovery appends one ranked metadata match without changing the explicit delta`() = runBlocking {
        val seed = proxyItem(1, "GET", "/api/users/123?seed-token=alpha", 200, MimeType.JSON)
        val comparison = proxyItem(2, "POST", "/admin/9?comparison-secret=bravo", 404, MimeType.HTML)
        val best = proxyItem(3, "GET", "/api/users/456?candidate-secret=charlie", 201, MimeType.JSON)
        val secondary = proxyItem(4, "GET", "/api/orders/1?candidate-secret=delta", 202, MimeType.JSON)
        val pathOnly = proxyItem(5, "DELETE", "/api/users/777?candidate-secret=echo", 500, MimeType.XML)
        proxyItems += listOf(seed.item, comparison.item, best.item, secondary.item, pathOnly.item)
        val approvals = mutableListOf<DataAccessType>()
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                approvals += accessType
                return true
            }
        }
        var metricTick = 0L
        val diagnostics = HistoryPerformanceDiagnostics { metricTick++ }

        val result = service(requireDataApproval = true, performanceDiagnostics = diagnostics).correlate(
            CorrelateHttpActivity(
                projectId = currentProjectId,
                baselineRefs = listOf(ref(HttpMessageSource.PROXY, "1")),
                comparisonRefs = listOf(ref(HttpMessageSource.PROXY, "2")),
                pathDepth = 3,
                relatedTraffic = RelatedHttpTrafficDiscovery(
                    seedEventIndices = listOf(0),
                    limit = 1,
                ),
            ),
        )

        assertEquals(HttpActivityCorrelationStatus.OK, result.status, result.error)
        assertEquals(listOf("1", "2", "3"), result.timeline.map { it.ref.id })
        assertEquals(
            listOf(HttpActivityCohort.BASELINE, HttpActivityCohort.COMPARISON, HttpActivityCohort.RELATED),
            result.timeline.map { it.cohort },
        )
        assertEquals(0, result.timeline.last().cohortIndex)
        assertEquals("/api/users/{number}", result.timeline.last().pathPrefix)
        assertEquals(1_767_323_045_003L, result.timeline.last().observedAtEpochMillis)
        assertEquals(HttpActivityTimestampKind.PROXY_CAPTURED, result.timeline.last().timestampKind)
        assertEquals(1, result.delta?.baselineRecords)
        assertEquals(1, result.delta?.comparisonRecords)
        assertEquals(listOf("GET", "POST"), result.delta?.methods?.map(ValueCountDelta::value))
        assertEquals(listOf(-1, 1), result.delta?.methods?.map(ValueCountDelta::delta))
        val related = requireNotNull(result.relatedTraffic)
        assertEquals(listOf(0), related.seedEventIndices)
        assertEquals(listOf(HttpMessageSource.PROXY), related.sources)
        assertEquals(1, related.queryCount)
        assertEquals(3, related.qualifiedCandidates)
        assertEquals(1, related.returned)
        assertTrue(related.truncated)
        assertFalse(related.identityEstablished)
        assertEquals(2, related.matches.single().eventIndex)
        assertEquals(12, related.matches.single().score)
        assertEquals(
            RelatedHttpTrafficSignal.entries,
            related.matches.single().seedMatches.single().signals,
        )
        assertEquals("caller_supplied_then_related_score", result.evidence.ordering)
        assertEquals(2, result.evidence.selectedReferences)
        assertEquals(1, result.evidence.relatedReferences)
        assertEquals(3, result.evidence.timelineEvents)
        assertEquals(32, result.evidence.maxReferences)
        assertEquals(16, result.evidence.maxRelatedReferences)
        assertEquals(48, result.evidence.maxTimelineEvents)
        assertEquals(listOf(DataAccessType.HTTP_HISTORY), approvals)
        assertFalse(result.toString().contains("seed-token"))
        assertFalse(result.toString().contains("comparison-secret"))
        assertFalse(result.toString().contains("candidate-secret"))
        listOf(seed, comparison, best, secondary, pathOnly).forEach { fixture ->
            verify(exactly = 0) { fixture.request.body() }
            verify(exactly = 0) { fixture.request.headers() }
            verify(exactly = 0) { fixture.item.annotations() }
        }
        verify(exactly = 1) { proxy.history() }
        verify(exactly = 2) { proxy.history(any()) }
        val acquisition = diagnostics.snapshot().metrics.single {
            it.metric == HistoryPerformanceMetric.RELATED_CORRELATION_MONTOYA_ACQUISITION
        }
        val processing = diagnostics.snapshot().metrics.single {
            it.metric == HistoryPerformanceMetric.RELATED_CORRELATION_EXTENSION_PROCESSING
        }
        assertEquals(3, acquisition.attempts)
        assertEquals(3, acquisition.completed)
        assertEquals(3, acquisition.totalNanos)
        assertEquals(16, processing.attempts)
        assertEquals(16, processing.completed)
        assertEquals(16, processing.totalNanos)
        assertEquals(0, diagnostics.snapshot().metrics.single {
            it.metric == HistoryPerformanceMetric.HTTP_SEARCH_PROCESSING
        }.attempts)
    }

    @Test
    fun `distinct related queries share one source snapshot without changing per-query accounting`() = runBlocking {
        val seeds = listOf(
            proxyItem(1, "GET", "/alpha/1", 200, MimeType.JSON, host = "alpha.test"),
            proxyItem(2, "GET", "/bravo/1", 200, MimeType.JSON, host = "bravo.test"),
            proxyItem(3, "GET", "/charlie/1", 200, MimeType.JSON, host = "charlie.test"),
            proxyItem(4, "GET", "/delta/1", 200, MimeType.JSON, host = "delta.test"),
        )
        val candidates = listOf(
            proxyItem(6, "GET", "/alpha/2", 200, MimeType.JSON, host = "alpha.test"),
            proxyItem(7, "GET", "/bravo/2", 200, MimeType.JSON, host = "bravo.test"),
            proxyItem(8, "GET", "/charlie/2", 200, MimeType.JSON, host = "charlie.test"),
            proxyItem(9, "GET", "/delta/2", 200, MimeType.JSON, host = "delta.test"),
        )
        proxyItems += seeds.map { it.item }
        proxyItems += proxyItem(5, "POST", "/comparison", 204, MimeType.HTML, host = "comparison.test").item
        proxyItems += candidates.map { it.item }
        val diagnostics = HistoryPerformanceDiagnostics()

        val result = service(performanceDiagnostics = diagnostics).correlate(
            CorrelateHttpActivity(
                projectId = currentProjectId,
                baselineRefs = (1..4).map { ref(HttpMessageSource.PROXY, it.toString()) },
                comparisonRefs = listOf(ref(HttpMessageSource.PROXY, "5")),
                relatedTraffic = RelatedHttpTrafficDiscovery(
                    seedEventIndices = listOf(0, 1, 2, 3),
                    sources = listOf(
                        HttpMessageSource.PROXY,
                        HttpMessageSource.SITE_MAP,
                        HttpMessageSource.ORGANIZER,
                    ),
                ),
            ),
        )

        assertEquals(HttpActivityCorrelationStatus.OK, result.status, result.error)
        assertEquals(
            listOf("1", "2", "3", "4", "5", "6", "7", "8", "9"),
            result.timeline.map { it.ref.id },
        )
        val related = requireNotNull(result.relatedTraffic)
        assertEquals(4, related.queryCount)
        assertEquals(8, related.candidateSummariesExamined)
        assertEquals(4, related.qualifiedCandidates)
        assertEquals(4, related.returned)
        assertEquals(listOf(5, 6, 7, 8), related.matches.map { it.eventIndex })
        assertFalse(related.truncated)
        verify(exactly = 1) { proxy.history() }
        verify(exactly = 1) { siteMap.requestResponses() }
        verify(exactly = 1) { organizer.items() }
        verify(exactly = 2) { proxy.history(any()) }
        verify(exactly = 0) { organizer.items(any()) }
        val acquisition = diagnostics.snapshot().metrics.single {
            it.metric == HistoryPerformanceMetric.RELATED_CORRELATION_MONTOYA_ACQUISITION
        }
        // Explicit and selected Proxy resolution plus one shared acquisition for each requested discovery source.
        assertEquals(5, acquisition.attempts)
    }

    @Test
    fun `mixed Proxy and Site Map related attribution matches resolver and search phase boundaries`() = runBlocking {
        val seed = proxyItem(1, "GET", "/api/items/1", 200, MimeType.JSON)
        val comparison = siteMapItem("POST", "/other", 404, MimeType.HTML)
        val candidate = siteMapItem("GET", "/api/items/2?site-map-private=value", 201, MimeType.JSON)
        proxyItems += seed.item
        siteMapItems += listOf(comparison.item, candidate.item)
        val comparisonId = stableSiteMapId(currentProjectId, 0, comparison.item)
        val candidateId = stableSiteMapId(currentProjectId, 1, candidate.item)
        var metricTick = 0L
        val diagnostics = HistoryPerformanceDiagnostics { metricTick++ }

        val result = service(performanceDiagnostics = diagnostics).correlate(
            CorrelateHttpActivity(
                projectId = currentProjectId,
                baselineRefs = listOf(ref(HttpMessageSource.PROXY, "1")),
                comparisonRefs = listOf(ref(HttpMessageSource.SITE_MAP, comparisonId)),
                pathDepth = 3,
                relatedTraffic = RelatedHttpTrafficDiscovery(
                    seedEventIndices = listOf(0),
                    sources = listOf(HttpMessageSource.PROXY, HttpMessageSource.SITE_MAP),
                    limit = 1,
                ),
            ),
        )

        assertEquals(HttpActivityCorrelationStatus.OK, result.status, result.error)
        assertEquals(
            listOf(HttpMessageSource.PROXY, HttpMessageSource.SITE_MAP, HttpMessageSource.SITE_MAP),
            result.timeline.map { it.ref.source },
        )
        assertEquals(candidateId, result.timeline.last().ref.id)
        assertEquals(1, result.relatedTraffic?.queryCount)
        assertEquals(1, result.relatedTraffic?.returned)
        assertFalse(result.toString().contains("site-map-private"))
        val snapshots = diagnostics.snapshot().metrics.associateBy { it.metric }
        // Acquisition: two explicit sources + two searched sources + one selected Site Map reacquisition.
        // Processing: 3 explicit resolver + 8 correlation/search/assembly + 4 selected Site Map segments. A Proxy
        // selection would add its resolver index segment and produce 16, so 15 pins the source-specific boundary.
        assertEquals(5, snapshots.getValue(HistoryPerformanceMetric.RELATED_CORRELATION_MONTOYA_ACQUISITION).attempts)
        assertEquals(15, snapshots.getValue(HistoryPerformanceMetric.RELATED_CORRELATION_EXTENSION_PROCESSING).attempts)
        assertEquals(0, snapshots.getValue(HistoryPerformanceMetric.HTTP_SEARCH_PROXY_ACQUISITION).attempts)
        assertEquals(0, snapshots.getValue(HistoryPerformanceMetric.HTTP_SEARCH_SITE_MAP_ACQUISITION).attempts)
        assertEquals(0, snapshots.getValue(HistoryPerformanceMetric.HTTP_SEARCH_PROCESSING).attempts)
    }

    @Test
    fun `explicit-only correlation does not record related phase metrics`() = runBlocking {
        proxyItems += proxyItem(1, "GET", "/one", 200, MimeType.JSON).item
        proxyItems += proxyItem(2, "GET", "/two", 200, MimeType.JSON).item
        var metricTick = 0L
        val diagnostics = HistoryPerformanceDiagnostics { metricTick++ }

        val result = service(performanceDiagnostics = diagnostics).correlate(
            CorrelateHttpActivity(
                projectId = currentProjectId,
                baselineRefs = listOf(ref(HttpMessageSource.PROXY, "1")),
                comparisonRefs = listOf(ref(HttpMessageSource.PROXY, "2")),
            ),
        )

        assertEquals(HttpActivityCorrelationStatus.OK, result.status)
        HistoryPerformanceMetric.entries.filter { it.name.startsWith("RELATED_CORRELATION_") }.forEach { metric ->
            assertEquals(0, diagnostics.snapshot().metrics.single { it.metric == metric }.attempts)
        }
    }

    @Test
    fun `related discovery can search an additionally authorized source without reapproving it`() = runBlocking {
        proxyItems += proxyItem(1, "GET", "/api/items/1", 200, MimeType.JSON).item
        proxyItems += proxyItem(2, "POST", "/other", 404, MimeType.HTML).item
        val candidate = organizerItem(7, "GET", "/api/items/2?private=value", 204, MimeType.JSON)
        organizerItems += candidate.item
        val approvals = mutableListOf<DataAccessType>()
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                approvals += accessType
                return true
            }
        }

        val result = service(requireDataApproval = true).correlate(
            CorrelateHttpActivity(
                projectId = currentProjectId,
                baselineRefs = listOf(ref(HttpMessageSource.PROXY, "1")),
                comparisonRefs = listOf(ref(HttpMessageSource.PROXY, "2")),
                relatedTraffic = RelatedHttpTrafficDiscovery(
                    seedEventIndices = listOf(0),
                    sources = listOf(HttpMessageSource.ORGANIZER),
                ),
            ),
        )

        assertEquals(HttpActivityCorrelationStatus.OK, result.status, result.error)
        assertEquals(listOf("1", "2", "7"), result.timeline.map { it.ref.id })
        assertEquals(HttpMessageSource.ORGANIZER, result.timeline.last().ref.source)
        assertEquals(HttpActivityTimestampKind.UNAVAILABLE, result.timeline.last().timestampKind)
        assertEquals(
            listOf(DataAccessType.HTTP_HISTORY, DataAccessType.ORGANIZER),
            approvals,
        )
        assertFalse(result.toString().contains("private=value"))
        verify(exactly = 0) { candidate.request.body() }
        verify(exactly = 0) { candidate.request.headers() }
        verify(exactly = 0) { candidate.item.annotations() }
        verify(exactly = 1) { organizer.items() }
        verify(exactly = 1) { organizer.items(any()) }
    }

    @Test
    fun `related discovery leaves explicit similarity groups unchanged`() = runBlocking {
        proxyItems += proxyItem(1, "GET", "/same", 200, MimeType.JSON).item
        organizerItems += organizerItem(2, "GET", "/same", 200, MimeType.JSON).item
        val candidate = siteMapItem("GET", "/same", 200, MimeType.JSON)
        siteMapItems += candidate.item
        val explicitInput = CorrelateHttpActivity(
            projectId = currentProjectId,
            baselineRefs = listOf(ref(HttpMessageSource.PROXY, "1")),
            comparisonRefs = listOf(ref(HttpMessageSource.ORGANIZER, "2")),
        )
        val explicit = service().correlate(explicitInput)

        val withRelated = service().correlate(
            explicitInput.copy(
                relatedTraffic = RelatedHttpTrafficDiscovery(
                    seedEventIndices = listOf(0),
                    sources = listOf(HttpMessageSource.SITE_MAP),
                ),
            ),
        )

        assertEquals(HttpActivityCorrelationStatus.OK, explicit.status, explicit.error)
        assertEquals(HttpActivityCorrelationStatus.OK, withRelated.status, withRelated.error)
        assertEquals(explicit.timeline, withRelated.timeline.take(2))
        assertEquals(explicit.similarityGroups, withRelated.similarityGroups)
        assertEquals(explicit.evidence.similarityGroupCount, withRelated.evidence.similarityGroupCount)
        assertEquals(1, withRelated.relatedTraffic?.returned)
        assertNull(withRelated.timeline.last().similarityGroupId)
    }

    @Test
    fun `related discovery fails closed when a selected stable reference disappears`() = runBlocking {
        proxyItems += proxyItem(1, "GET", "/api/items/1", 200, MimeType.JSON).item
        proxyItems += proxyItem(2, "POST", "/other", 404, MimeType.HTML).item
        proxyItems += proxyItem(3, "GET", "/api/items/2", 200, MimeType.JSON).item
        var filteredReads = 0
        every { proxy.history(any()) } answers {
            filteredReads++
            val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
            if (filteredReads == 1) proxyItems.filter(filter::matches) else emptyList()
        }

        val result = service().correlate(
            CorrelateHttpActivity(
                projectId = currentProjectId,
                baselineRefs = listOf(ref(HttpMessageSource.PROXY, "1")),
                comparisonRefs = listOf(ref(HttpMessageSource.PROXY, "2")),
                relatedTraffic = RelatedHttpTrafficDiscovery(seedEventIndices = listOf(0)),
            ),
        )

        assertEquals(HttpActivityCorrelationStatus.NOT_FOUND, result.status)
        assertEquals("A related HTTP candidate was no longer available", result.error)
        assertTrue(result.timeline.isEmpty())
        assertNull(result.relatedTraffic)
    }

    @Test
    fun `related discovery drops a selected candidate that fails materialized metadata revalidation`() = runBlocking {
        proxyItems += proxyItem(1, "GET", "/api/items/1", 200, MimeType.JSON).item
        proxyItems += proxyItem(2, "POST", "/other", 404, MimeType.HTML).item
        val candidate = proxyItem(3, "GET", "/api/items/2?private=value", 200, MimeType.JSON)
        var pathReads = 0
        every { candidate.request.path() } answers {
            pathReads++
            if (pathReads <= 2) "/api/items/2?private=value" else "/unrelated"
        }
        var methodReads = 0
        every { candidate.request.method() } answers {
            methodReads++
            if (methodReads == 1) "GET" else "DELETE"
        }
        val response = requireNotNull(candidate.item.response())
        var statusReads = 0
        every { response.statusCode() } answers {
            statusReads++
            if (statusReads == 1) 200.toShort() else 500.toShort()
        }
        var mimeReads = 0
        every { response.mimeType() } answers {
            mimeReads++
            if (mimeReads == 1) MimeType.JSON else MimeType.XML
        }
        proxyItems += candidate.item

        val result = service().correlate(
            CorrelateHttpActivity(
                projectId = currentProjectId,
                baselineRefs = listOf(ref(HttpMessageSource.PROXY, "1")),
                comparisonRefs = listOf(ref(HttpMessageSource.PROXY, "2")),
                relatedTraffic = RelatedHttpTrafficDiscovery(seedEventIndices = listOf(0)),
            ),
        )

        assertEquals(HttpActivityCorrelationStatus.OK, result.status, result.error)
        assertEquals(listOf("1", "2"), result.timeline.map { it.ref.id })
        val related = requireNotNull(result.relatedTraffic)
        assertEquals(1, related.qualifiedCandidates)
        assertEquals(0, related.returned)
        assertTrue(related.matches.isEmpty())
        assertFalse(result.toString().contains("private=value"))
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
        val invalidRelatedSeed = service.correlate(
            CorrelateHttpActivity(
                currentProjectId,
                listOf(ref(HttpMessageSource.PROXY, "1")),
                listOf(ref(HttpMessageSource.PROXY, "2")),
                relatedTraffic = RelatedHttpTrafficDiscovery(seedEventIndices = listOf(2)),
            ),
        )
        val duplicateRelatedSources = service.correlate(
            CorrelateHttpActivity(
                currentProjectId,
                listOf(ref(HttpMessageSource.PROXY, "1")),
                listOf(ref(HttpMessageSource.PROXY, "2")),
                relatedTraffic = RelatedHttpTrafficDiscovery(
                    seedEventIndices = listOf(0),
                    sources = listOf(HttpMessageSource.PROXY, HttpMessageSource.PROXY),
                ),
            ),
        )

        assertEquals(HttpActivityCorrelationStatus.INVALID_ARGUMENT, empty.status)
        assertEquals(HttpActivityCorrelationStatus.INVALID_ARGUMENT, invalidProject.status)
        assertEquals(HttpActivityCorrelationStatus.INVALID_ARGUMENT, tooMany.status)
        assertEquals(HttpActivityCorrelationStatus.INVALID_ID, invalidId.status)
        assertEquals(0, invalidId.errorRefIndex)
        assertEquals(HttpActivityCorrelationStatus.INVALID_ARGUMENT, duplicateAlias.status)
        assertEquals(1, duplicateAlias.errorRefIndex)
        assertEquals(HttpActivityCorrelationStatus.INVALID_ARGUMENT, invalidDepth.status)
        assertEquals(HttpActivityCorrelationStatus.INVALID_ARGUMENT, invalidRelatedSeed.status)
        assertEquals(HttpActivityCorrelationStatus.INVALID_ARGUMENT, duplicateRelatedSources.status)
        listOf(
            empty,
            invalidProject,
            tooMany,
            invalidId,
            duplicateAlias,
            invalidDepth,
            invalidRelatedSeed,
            duplicateRelatedSources,
        ).forEach {
            assertNull(it.projectId, "pre-capture validation must not echo the caller project")
            assertTrue(it.timeline.isEmpty())
            assertNull(it.delta)
            assertEquals(0, it.evidence.selectedReferences)
        }
        verify(exactly = 0) { api.project() }
        verify(exactly = 0) { proxy.history(any()) }
    }

    @Test
    fun `unavailable related search fails before project or source access`() = runBlocking {
        val result = HttpActivityCorrelationService(api, config(false)).correlate(
            CorrelateHttpActivity(
                currentProjectId,
                baselineRefs = listOf(ref(HttpMessageSource.PROXY, "1")),
                comparisonRefs = listOf(ref(HttpMessageSource.PROXY, "2")),
                relatedTraffic = RelatedHttpTrafficDiscovery(seedEventIndices = listOf(0)),
            ),
        )

        assertEquals(HttpActivityCorrelationStatus.BURP_ERROR, result.status)
        assertNull(result.projectId)
        assertTrue(result.timeline.isEmpty())
        verify(exactly = 0) { api.project() }
        verify(exactly = 0) { proxy.history() }
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
    fun `denied additional discovery source fails before any explicit or discovery source acquisition`() = runBlocking {
        proxyItems += proxyItem(1, "GET", "/api", 200, MimeType.JSON).item
        proxyItems += proxyItem(2, "POST", "/other", 404, MimeType.HTML).item
        organizerItems += organizerItem(3, "GET", "/api", 200, MimeType.JSON).item
        val approvals = mutableListOf<DataAccessType>()
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                approvals += accessType
                return accessType != DataAccessType.ORGANIZER
            }
        }

        val result = service(requireDataApproval = true).correlate(
            CorrelateHttpActivity(
                currentProjectId,
                baselineRefs = listOf(ref(HttpMessageSource.PROXY, "1")),
                comparisonRefs = listOf(ref(HttpMessageSource.PROXY, "2")),
                relatedTraffic = RelatedHttpTrafficDiscovery(
                    seedEventIndices = listOf(0),
                    sources = listOf(HttpMessageSource.ORGANIZER),
                ),
            ),
        )

        assertEquals(HttpActivityCorrelationStatus.ACCESS_DENIED, result.status)
        assertNull(result.errorRefIndex)
        assertTrue(result.timeline.isEmpty())
        assertNull(result.relatedTraffic)
        assertEquals(listOf(DataAccessType.HTTP_HISTORY, DataAccessType.ORGANIZER), approvals)
        verify(exactly = 0) { proxy.history() }
        verify(exactly = 0) { proxy.history(any()) }
        verify(exactly = 0) { organizer.items() }
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

    private fun service(
        requireDataApproval: Boolean = false,
        performanceDiagnostics: HistoryPerformanceDiagnostics = HistoryPerformanceDiagnostics.NO_OP,
    ): HttpActivityCorrelationService {
        val config = config(requireDataApproval)
        return HttpActivityCorrelationService(
            api,
            config,
            HttpMessageSearchService(
                api,
                config,
                cursorSecret = ByteArray(32) { 7 },
                performanceDiagnostics = performanceDiagnostics,
            ),
            performanceDiagnostics,
        )
    }

    private fun config(requireDataApproval: Boolean): McpConfig {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers {
            firstArg<String>() == "requireDataAccessApproval" && requireDataApproval
        }
        every { storage.getString(any()) } returns ""
        return McpConfig(storage, logging, net.portswigger.mcp.testPreferences())
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
        every { item.httpService() } returns message.service
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
        every { item.httpService() } returns message.service
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
        every { item.httpService() } returns message.service
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
        return MessageFixture(request, response, service)
    }

    private fun ref(source: HttpMessageSource, id: String) = HttpMessageReference(source, id)

    private data class MessageFixture(
        val request: HttpRequest,
        val response: HttpResponse,
        val service: HttpService,
    )
    private data class ProxyFixture(val item: ProxyHttpRequestResponse, val request: HttpRequest)
    private data class SiteMapFixture(val item: HttpRequestResponse, val request: HttpRequest)
    private data class OrganizerFixture(val item: OrganizerItem, val request: HttpRequest)
}
