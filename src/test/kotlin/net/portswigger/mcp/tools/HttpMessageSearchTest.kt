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
import io.mockk.verifyOrder
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.ZonedDateTime
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.assertIs

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
    private lateinit var resolver: HttpMessageResolver
    private lateinit var originalDataAccessHandler: DataAccessApprovalHandler

    @BeforeEach
    fun setUp() {
        originalDataAccessHandler = DataAccessSecurity.approvalHandler
        val storedBooleans = mutableMapOf<String, Boolean>()
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers { storedBooleans[firstArg()] ?: false }
        every { storage.setBoolean(any(), any()) } answers {
            storedBooleans[firstArg()] = secondArg()
        }
        every { storage.getString(any()) } returns ""
        every { api.logging() } returns logging
        every { api.project() } returns project
        every { project.id() } returns "project-123"
        every { api.proxy() } returns proxy
        every { proxy.history() } answers { proxyHistory.toList() }
        every { proxy.history(any()) } answers {
            val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
            proxyHistory.filter(filter::matches)
        }
        every { api.siteMap() } returns siteMap
        every { siteMap.requestResponses() } answers { siteMapItems.toList() }
        config = McpConfig(storage, logging, net.portswigger.mcp.testPreferences())
        service = HttpMessageSearchService(
            api,
            config,
            cursorSecret = ByteArray(32) { 7 },
        )
        resolver = HttpMessageResolver(api, config)
    }

    @AfterEach
    fun tearDown() {
        DataAccessSecurity.approvalHandler = originalDataAccessHandler
    }

    @Test
    fun `project transition during HTTP data approval prevents history access`() = runBlocking {
        config.requireDataAccessApproval = true
        var currentProjectId = "project-123"
        every { project.id() } answers { currentProjectId }
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                currentProjectId = "other-project"
                return true
            }
        }

        val result = service.search(SearchHttpMessages())

        assertEquals(HttpMessageSearchStatus.PROJECT_MISMATCH, result.status)
        assertEquals("other-project", result.projectId)
        assertTrue(result.items.isEmpty())
        verify(exactly = 0) { proxy.history() }
    }

    @Test
    fun `HTTP denial after a project transition returns mismatch without history access`() = runBlocking {
        config.requireDataAccessApproval = true
        var currentProjectId = "project-123"
        every { project.id() } answers { currentProjectId }
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                currentProjectId = "project-after-denial"
                return false
            }
        }

        val result = service.search(SearchHttpMessages())

        assertEquals(HttpMessageSearchStatus.PROJECT_MISMATCH, result.status)
        assertEquals("project-after-denial", result.projectId)
        assertTrue(result.items.isEmpty())
        verify(exactly = 0) { proxy.history() }
    }

    @Test
    fun `reference metadata projection reuses exact preauthorization without materializing private summary fields`() = runBlocking {
        val fixture = proxyItem(9, "GET", "https://example.test/api/items/1?private=query", 200, 512)
        proxyHistory += fixture.item
        val authorization = proxyAuthorization("9")
        config.requireDataAccessApproval = true
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                error("reference metadata search must reuse prior authorization")
            }
        }

        val result = service.searchReferenceMetadata(
            input = SearchHttpMessages(host = "example.test", pathContains = "/api"),
            authorization = authorization,
            authorizationVerifier = resolver,
        )

        assertEquals(HttpMessageSearchStatus.OK, result.status)
        assertEquals(1, result.returned)
        val item = result.items.single()
        assertEquals("/api/items/1", item.url)
        assertFalse(item.urlTruncated)
        assertEquals(0, item.requestBodyBytes)
        assertEquals(null, item.responseBodyBytes)
        assertEquals(null, item.notes)
        assertFalse(item.notesTruncated)
        assertEquals(null, item.time)
        assertFalse(result.toString().contains("private=query"))
        verify(exactly = 0) { fixture.item.annotations() }
        verify(exactly = 0) { fixture.item.time() }
        verify(exactly = 0) { fixture.request.body() }
        verify(exactly = 0) { fixture.request.url() }
    }

    @Test
    fun `reference metadata projection rejects a handle from another resolver before source access`() = runBlocking {
        proxyHistory += proxyItem(9, "GET", "https://example.test/api", 200).item
        val authorization = proxyAuthorization("9")
        val foreignResolver = HttpMessageResolver(api, config)

        val result = service.searchReferenceMetadata(
            input = SearchHttpMessages(sources = listOf(HttpMessageSource.PROXY)),
            authorization = authorization,
            authorizationVerifier = foreignResolver,
        )

        assertEquals(HttpMessageSearchStatus.BURP_ERROR, result.status)
        assertTrue(result.items.isEmpty())
        verify(exactly = 1) { proxy.history(any()) }
        verify(exactly = 0) { proxy.history() }
    }

    @Test
    fun `reference metadata batch rejects defensive argument failures before source access`() = runBlocking {
        val authorization = HttpMessageResolutionAuthorization(
            projectId = "project-123",
            sources = setOf(HttpMessageSource.PROXY),
            issuer = resolver,
        )

        val oversized = service.searchReferenceMetadataBatch(
            inputs = List(MAX_RELATED_TRAFFIC_SEEDS + 1) { SearchHttpMessages() },
            authorization = authorization,
            authorizationVerifier = resolver,
        )
        val cursor = service.searchReferenceMetadataBatch(
            inputs = listOf(SearchHttpMessages(cursor = "not-a-batch-cursor")),
            authorization = authorization,
            authorizationVerifier = resolver,
        )
        val invalidLimit = service.searchReferenceMetadataBatch(
            inputs = listOf(SearchHttpMessages(limit = 0)),
            authorization = authorization,
            authorizationVerifier = resolver,
        )

        assertEquals(MAX_RELATED_TRAFFIC_SEEDS + 1, oversized.size)
        assertTrue(oversized.all { it.status == HttpMessageSearchStatus.INVALID_ARGUMENT })
        assertEquals(HttpMessageSearchStatus.INVALID_CURSOR, cursor.single().status)
        assertEquals(HttpMessageSearchStatus.INVALID_ARGUMENT, invalidLimit.single().status)
        verify(exactly = 0) { proxy.history() }
        verify(exactly = 0) { proxy.history(any()) }
    }

    @Test
    fun `search reports only fixed monotonic stages without project or filter values`() = runBlocking {
        val events = mutableListOf<Triple<Double, Double?, String?>>()

        val result = service.search(
            SearchHttpMessages(host = "sensitive.example"),
        ) { progress, total, message -> events += Triple(progress, total, message) }

        assertEquals(HttpMessageSearchStatus.OK, result.status)
        assertEquals((0..5).map(Int::toDouble), events.map { it.first })
        assertTrue(events.all { it.second == 5.0 })
        assertEquals("Validating HTTP search", events.first().third)
        assertEquals("HTTP search completed", events.last().third)
        assertTrue(events.none { it.third.orEmpty().contains("sensitive.example") })
        assertTrue(events.none { it.third.orEmpty().contains("project-123") })
    }

    @Test
    fun `search progress cancellation stops before history acquisition`() = runBlocking {
        val diagnostics = HistoryPerformanceDiagnostics()
        val measuredService = HttpMessageSearchService(
            api,
            config,
            cursorSecret = ByteArray(32) { 8 },
            performanceDiagnostics = diagnostics,
        )

        assertFailsWith<CancellationException> {
            measuredService.search(SearchHttpMessages()) { progress, _, _ ->
                if (progress == 3.0) throw CancellationException("client cancelled")
            }
        }

        verify(exactly = 0) { proxy.history() }
        assertEquals(0, diagnostics.snapshot().metrics.sumOf { it.attempts })
    }

    @Test
    fun `HTTP search records ordered source acquisition separately from processing`() = runBlocking {
        var clock = 0L
        every { api.proxy() } answers {
            clock += 100L
            proxy
        }
        every { proxy.history() } answers {
            clock += 7L
            proxyHistory.toList()
        }
        every { api.siteMap() } answers {
            clock += 200L
            siteMap
        }
        every { siteMap.requestResponses() } answers {
            clock += 11L
            siteMapItems.toList()
        }
        val diagnostics = HistoryPerformanceDiagnostics { clock }
        val measuredService = HttpMessageSearchService(
            api,
            config,
            cursorSecret = ByteArray(32) { 8 },
            performanceDiagnostics = diagnostics,
        )

        val result = measuredService.search(
            SearchHttpMessages(sources = listOf(HttpMessageSource.PROXY, HttpMessageSource.SITE_MAP)),
        )

        assertEquals(HttpMessageSearchStatus.OK, result.status)
        val metrics = diagnostics.snapshot().metrics.associateBy { it.metric }
        assertEquals(1, metrics.getValue(HistoryPerformanceMetric.HTTP_SEARCH_PROXY_ACQUISITION).attempts)
        assertEquals(7L, metrics.getValue(HistoryPerformanceMetric.HTTP_SEARCH_PROXY_ACQUISITION).maxNanos)
        assertEquals(1, metrics.getValue(HistoryPerformanceMetric.HTTP_SEARCH_SITE_MAP_ACQUISITION).attempts)
        assertEquals(11L, metrics.getValue(HistoryPerformanceMetric.HTTP_SEARCH_SITE_MAP_ACQUISITION).maxNanos)
        assertEquals(0, metrics.getValue(HistoryPerformanceMetric.HTTP_SEARCH_ORGANIZER_ACQUISITION).attempts)
        assertEquals(1, metrics.getValue(HistoryPerformanceMetric.HTTP_SEARCH_PROCESSING).attempts)
        verifyOrder {
            proxy.history()
            siteMap.requestResponses()
        }
    }

    @Test
    fun `HTTP source cancellation is recorded once and propagated`() = runBlocking {
        val diagnostics = HistoryPerformanceDiagnostics()
        val cancellation = CancellationException("source cancelled")
        every { proxy.history() } throws cancellation
        val measuredService = HttpMessageSearchService(
            api,
            config,
            cursorSecret = ByteArray(32) { 9 },
            performanceDiagnostics = diagnostics,
        )

        val observed = assertFailsWith<CancellationException> {
            measuredService.search(SearchHttpMessages())
        }

        assertEquals(cancellation, observed)
        val acquisition = diagnostics.snapshot().metrics.single {
            it.metric == HistoryPerformanceMetric.HTTP_SEARCH_PROXY_ACQUISITION
        }
        assertEquals(1, acquisition.attempts)
        assertEquals(1, acquisition.cancelled)
        assertEquals(0, diagnostics.snapshot().metrics.single {
            it.metric == HistoryPerformanceMetric.HTTP_SEARCH_PROCESSING
        }.attempts)
    }

    @Test
    fun `Burp source failure returns a complete structured read error`() = runBlocking {
        every { proxy.history() } throws IllegalStateException("PRIVATE_SENTINEL")

        val result = service.search(SearchHttpMessages())

        assertEquals(HttpMessageSearchStatus.BURP_ERROR, result.status)
        assertEquals("project-123", result.projectId)
        assertTrue(result.items.isEmpty())
        assertEquals(0, result.returned)
        assertEquals(0, result.scanned)
        assertEquals(false, result.hasMore)
        assertEquals(null, result.nextCursor)
        assertTrue(result.error.orEmpty().contains("Burp could not read HTTP history"))
        assertFalse(result.error.orEmpty().contains("PRIVATE_SENTINEL"))
    }

    @Test
    fun `project capture failure returns bounded burp_error without accessing history`() = runBlocking {
        every { project.id() } throws IllegalStateException("synthetic project failure")

        val result = service.search(SearchHttpMessages())

        assertEquals(HttpMessageSearchStatus.BURP_ERROR, result.status)
        assertEquals(null, result.projectId)
        assertTrue(result.items.isEmpty())
        assertTrue(result.error.orEmpty().contains("capture the current project"))
        verify(exactly = 0) { proxy.history() }
    }

    @Test
    fun `cancellation during synchronous acquisition records the returned call before propagation`() = runBlocking {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        every { proxy.history() } answers {
            entered.countDown()
            check(release.await(5, TimeUnit.SECONDS)) { "timed out waiting to release history" }
            proxyHistory.toList()
        }
        val diagnostics = HistoryPerformanceDiagnostics()
        val measuredService = HttpMessageSearchService(
            api,
            config,
            cursorSecret = ByteArray(32) { 10 },
            performanceDiagnostics = diagnostics,
        )

        val search = async(Dispatchers.Default) {
            measuredService.search(SearchHttpMessages())
        }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        search.cancel(CancellationException("client cancelled while Montoya was blocked"))
        release.countDown()

        assertFailsWith<CancellationException> { search.await() }
        val metrics = diagnostics.snapshot().metrics.associateBy { it.metric }
        val acquisition = metrics.getValue(HistoryPerformanceMetric.HTTP_SEARCH_PROXY_ACQUISITION)
        assertEquals(1, acquisition.attempts)
        assertEquals(1, acquisition.completed)
        assertEquals(0, acquisition.cancelled)
        assertEquals(0, metrics.getValue(HistoryPerformanceMetric.HTTP_SEARCH_PROCESSING).attempts)
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
    fun `Site Map search returns a project scoped ID that supports bounded canonical reads`() = runBlocking {
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
        val projectId = assertNotNull(search.projectId)
        val reader = HttpMessageReadService(api, config)
        assertEquals(HttpMessageSource.SITE_MAP, found.ref.source)
        assertTrue(found.ref.id.matches(Regex("sitemap_0_[0-9a-f]{32}")))

        val detail = reader.read(
            GetHttpMessage(
                projectId = projectId,
                ref = found.ref,
                part = "response_body",
                offset = 1,
                limit = 3,
            )
        )
        assertEquals(HttpMessageReadStatus.OK, detail.status)
        assertEquals("bcd", detail.content?.data)
        assertEquals(5, detail.content?.totalBytes)
        assertEquals(4, detail.content?.nextOffsetBytes)
        assertEquals(true, detail.metadata?.inScope)
        assertEquals(found.ref, detail.metadata?.ref)

        val invalidOffset = reader.read(
            GetHttpMessage(
                projectId = projectId,
                ref = found.ref,
                part = "response_body",
                offset = 6,
            )
        )
        assertEquals(HttpMessageReadStatus.INVALID_ARGUMENT, invalidOffset.status)
        assertTrue(invalidOffset.error.orEmpty().contains("totalBytes"))
    }

    @Test
    fun `Site Map references fail closed after a project or indexed item changes`() = runBlocking {
        val first = siteMapItem("GET", "https://example.test/first", 200)
        siteMapItems += first.item
        val search = service.search(SearchHttpMessages(sources = listOf(HttpMessageSource.SITE_MAP)))
        val ref = search.items.single().ref
        val reader = HttpMessageReadService(api, config)

        every { project.id() } returns "other-project"
        val wrongProject = reader.read(GetHttpMessage("project-123", ref))
        assertEquals(HttpMessageReadStatus.PROJECT_MISMATCH, wrongProject.status)

        every { project.id() } returns "project-123"
        siteMapItems[0] = siteMapItem("GET", "https://example.test/replaced", 200).item
        val stale = reader.read(GetHttpMessage("project-123", ref))
        assertEquals(HttpMessageReadStatus.NOT_FOUND, stale.status)
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
        assertTrue(first.items.isEmpty())
        assertTrue(first.scanLimitReached)
        assertTrue(first.hasMore)

        val second = boundedService.search(SearchHttpMessages(cursor = assertNotNull(first.nextCursor)))
        assertEquals(1, second.scanned)
        assertFalse(second.hasMore)
    }

    @Test
    fun `content budget is spent only after metadata filters match`() = runBlocking {
        val metadataMismatch = proxyItem(
            id = 8,
            method = "GET",
            url = "https://example.test/large",
            status = 200,
            requestBodyBytes = MAX_HTTP_SEARCH_TEXT_BYTES.toInt() + 1,
        )
        val selected = proxyItem(
            id = 9,
            method = "POST",
            url = "https://example.test/selected",
            status = 201,
        )
        val selectedResponse = requireNotNull(selected.item.response())
        every { selected.request.contains("needle", false) } returns true
        proxyHistory += metadataMismatch.item
        proxyHistory += selected.item

        val result = service.search(
            SearchHttpMessages(
                methods = listOf("POST"),
                statusCodes = listOf(201),
                text = "needle",
                searchIn = HttpSearchLocation.REQUEST,
                newestFirst = false,
            )
        )

        assertEquals(HttpMessageSearchStatus.OK, result.status)
        assertEquals(2, result.scanned)
        assertEquals(0, result.oversizedContentSkipped)
        assertEquals(1, result.returned)
        assertEquals("9", result.items.single().ref.id)
        verify(exactly = 0) { metadataMismatch.request.bodyOffset() }
        verify(exactly = 0) { metadataMismatch.request.contains(any<String>(), any<Boolean>()) }
        verify(exactly = 1) { selected.request.body() }
        verify(exactly = 1) { selectedResponse.body() }
        verify(exactly = 1) { selected.request.contains("needle", false) }
    }

    @Test
    fun `safe regex search is budgeted cursor-bound and defaults to case sensitive`() = runBlocking {
        val skipped = proxyItem(10, "GET", "https://example.test/skipped", 200)
        val selected = proxyItem(11, "GET", "https://example.test/selected", 200)
        every { skipped.request.contains(any<Pattern>()) } answers {
            firstArg<Pattern>().matcher("TOKEN-123").find()
        }
        every { selected.request.contains(any<Pattern>()) } answers {
            firstArg<Pattern>().matcher("token-456").find()
        }
        proxyHistory += skipped.item
        proxyHistory += selected.item

        val caseSensitive = service.search(
            SearchHttpMessages(
                regex = "token-[0-9]+",
                searchIn = HttpSearchLocation.REQUEST,
                newestFirst = false,
                limit = 1,
            )
        )
        assertEquals(listOf("11"), caseSensitive.items.map { it.ref.id })
        assertEquals(2, caseSensitive.scanned)
        assertTrue(caseSensitive.scannedContentBytes > 0)

        val insensitive = service.search(
            SearchHttpMessages(
                regex = "token-[0-9]+",
                searchIn = HttpSearchLocation.REQUEST,
                caseSensitive = false,
                newestFirst = false,
                limit = 1,
            )
        )
        assertEquals(listOf("10"), insensitive.items.map { it.ref.id })
        assertNotNull(insensitive.nextCursor)

        val changed = service.search(
            SearchHttpMessages(regex = "other", cursor = insensitive.nextCursor)
        )
        assertEquals(HttpMessageSearchStatus.INVALID_CURSOR, changed.status)
    }

    @Test
    fun `regex rejects unsafe or conflicting predicates before history access`() = runBlocking {
        val conflictingProgress = mutableListOf<Double>()
        val conflicting = service.search(SearchHttpMessages(text = "literal", regex = "safe")) { progress, _, _ ->
            conflictingProgress += progress
        }
        val unsafeProgress = mutableListOf<Double>()
        val unsafe = service.search(SearchHttpMessages(regex = "(a+)+")) { progress, _, _ ->
            unsafeProgress += progress
        }

        assertEquals(HttpMessageSearchStatus.INVALID_ARGUMENT, conflicting.status)
        assertEquals(HttpMessageSearchStatus.INVALID_ARGUMENT, unsafe.status)
        assertEquals(listOf(0.0), conflictingProgress)
        assertEquals(listOf(0.0), unsafeProgress)
        verify(exactly = 0) { proxy.history() }
    }

    @Test
    fun `reference metadata projection skips a method that cannot be materialized within its bound`() = runBlocking {
        proxyHistory += proxyItem(
            id = 9,
            method = "X".repeat(33),
            url = "https://example.test/api/items/1",
            status = 200,
        ).item

        val result = service.searchReferenceMetadata(
            input = SearchHttpMessages(host = "example.test"),
            authorization = proxyAuthorization("9"),
            authorizationVerifier = resolver,
        )

        assertEquals(HttpMessageSearchStatus.OK, result.status)
        assertEquals(1, result.scanned)
        assertEquals(0, result.returned)
        assertTrue(result.items.isEmpty())
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
        val uri = java.net.URI(url)
        val service = httpService(uri.host, if (uri.port > 0) uri.port else 443, uri.scheme == "https")
        every { request.method() } returns method
        every { request.url() } returns url
        every { request.path() } returns uri.rawPath
        every { request.httpService() } returns service
        every { request.isInScope() } returns true
        every { request.body() } returns body
        every { request.bodyOffset() } returns 100
        every { request.headers() } returns emptyList()
        every { request.httpVersion() } returns "HTTP/1.1"
        every { request.contains(any<String>(), any<Boolean>()) } returns false
        every { request.contains(any<Pattern>()) } returns false
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
        every { response.contains(any<Pattern>()) } returns false
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

    private suspend fun proxyAuthorization(id: String): HttpMessageResolutionAuthorization {
        val result = resolver.resolveAll(
            projectId = "project-123",
            refs = listOf(HttpMessageReference(HttpMessageSource.PROXY, id)),
        )
        return assertIs<HttpMessageBatchResolution.Found>(result).authorization
    }

    private data class ProxyFixture(
        val item: ProxyHttpRequestResponse,
        val request: HttpRequest,
    )

    private data class SiteMapFixture(val item: HttpRequestResponse)
}
