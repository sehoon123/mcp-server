package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.utilities.Utilities
import burp.api.montoya.utilities.rank.RankedHttpRequestResponse
import burp.api.montoya.utilities.rank.RankingAlgorithm
import burp.api.montoya.utilities.rank.RankingUtils
import io.mockk.*
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.SensitiveActionApprovalHandler
import net.portswigger.mcp.security.SensitiveActionSecurity
import net.portswigger.mcp.testPreferences
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class NativeHttpUtilitiesTest {
    private val api = mockk<MontoyaApi>()
    private val project = mockk<Project>()
    private val proxy = mockk<Proxy>()
    private val utilities = mockk<Utilities>()
    private val rankingUtils = mockk<RankingUtils>()
    private val logging = mockk<Logging>(relaxed = true)
    private lateinit var originalSensitiveHandler: SensitiveActionApprovalHandler

    @BeforeEach
    fun setUp() {
        originalSensitiveHandler = SensitiveActionSecurity.approvalHandler
        every { api.project() } returns project
        every { project.id() } returns "project-1"
        every { api.proxy() } returns proxy
        every { api.utilities() } returns utilities
        every { utilities.rankingUtils() } returns rankingUtils
        every { api.logging() } returns logging
        mockkStatic(HttpRequestResponse::class)
    }

    @AfterEach
    fun tearDown() {
        SensitiveActionSecurity.approvalHandler = originalSensitiveHandler
        unmockkStatic(HttpRequestResponse::class)
    }

    @Test
    fun `native ranking uses the exact bounded set and sorts Burp ordinals`() = runBlocking {
        val first = proxyItem(1, 100, 200)
        val second = proxyItem(2, 110, 210)
        stubHistory(first.item, second.item)
        every { HttpRequestResponse.httpRequestResponse(first.request, first.response) } returns first.envelope
        every { HttpRequestResponse.httpRequestResponse(second.request, second.response) } returns second.envelope
        val firstRank = rank(first.envelope, 2)
        val secondRank = rank(second.envelope, 1)
        every { rankingUtils.rank(listOf(first.envelope, second.envelope), RankingAlgorithm.ANOMALY) } returns
            listOf(firstRank, secondRank)

        val result = NativeHttpRankingService(api, config()).rank(
            RankHttpMessages(
                "project-1",
                listOf(ref(1), ref(2)),
            )
        )

        assertEquals(NativeToolStatus.OK, result.status)
        assertEquals(listOf(ref(2), ref(1)), result.ranked.map { it.ref })
        assertEquals(listOf(1, 2), result.ranked.map { it.rank })
        assertEquals(620, result.totalBytes)
        verify(exactly = 1) { rankingUtils.rank(listOf(first.envelope, second.envelope), RankingAlgorithm.ANOMALY) }
        verify(exactly = 0) { first.request.toString() }
        verify(exactly = 0) { first.response.toString() }
    }

    @Test
    fun `canonical duplicate references are rejected before Burp access`() = runBlocking {
        val aliases = listOf(
            HttpMessageReference(HttpMessageSource.PROXY, "1"),
            HttpMessageReference(HttpMessageSource.PROXY, "01"),
        )

        val ranked = NativeHttpRankingService(api, config()).rank(RankHttpMessages("project-1", aliases))
        val annotated = HttpAnnotationService(api, config(), withMutation = { _, block -> block() }).annotate(
            AnnotateHttpMessages("project-1", aliases, notes = "x")
        )

        assertEquals(NativeToolStatus.INVALID_ARGUMENT, ranked.status)
        assertEquals(NativeToolStatus.INVALID_ARGUMENT, annotated.status)
        verify(exactly = 0) { api.project() }
    }

    @Test
    fun `ranking fails closed when Burp returns an entry outside the requested set`() = runBlocking {
        val first = proxyItem(1, 100, 200)
        stubHistory(first.item)
        every { HttpRequestResponse.httpRequestResponse(first.request, first.response) } returns first.envelope
        every { rankingUtils.rank(any(), RankingAlgorithm.ANOMALY) } returns listOf(rank(mockk(), 1))

        val result = NativeHttpRankingService(api, config()).rank(
            RankHttpMessages("project-1", listOf(ref(1)))
        )

        assertEquals(NativeToolStatus.BURP_ERROR, result.status)
        assertTrue(result.ranked.isEmpty())
    }

    @Test
    fun `annotation updates live Proxy annotations only after approval and verifies the result`() = runBlocking {
        val annotations = mockk<Annotations>()
        var notes = "before"
        var color = HighlightColor.NONE
        every { annotations.notes() } answers { notes }
        every { annotations.hasHighlightColor() } answers { color != HighlightColor.NONE }
        every { annotations.highlightColor() } answers { color }
        every { annotations.setNotes(any()) } answers { notes = firstArg() }
        every { annotations.setHighlightColor(any()) } answers { color = firstArg() }
        val item = proxyItem(1, 100, null, annotations)
        stubHistory(item.item)
        SensitiveActionSecurity.approvalHandler = allowSensitive()
        val service = HttpAnnotationService(api, config(), withMutation = { _, block -> block() })

        val result = service.annotate(
            AnnotateHttpMessages(
                projectId = "project-1",
                refs = listOf(ref(1)),
                notes = "after",
                highlight = HttpAnnotationHighlight.RED,
            )
        )

        assertEquals(NativeToolStatus.OK, result.status)
        assertEquals(StandardExecutionState.COMPLETED, result.executionState)
        assertEquals(1, result.updated)
        assertEquals("after", notes)
        assertEquals(HighlightColor.RED, color)
        verify(exactly = 1) { annotations.setNotes("after") }
        verify(exactly = 1) { annotations.setHighlightColor(HighlightColor.RED) }
        verify(exactly = 2) { proxy.history(any()) }
    }

    @Test
    fun `annotation field failure preserves partial change and returns uncertain`() = runBlocking {
        val annotations = mockk<Annotations>()
        var notes = "before"
        every { annotations.notes() } answers { notes }
        every { annotations.hasHighlightColor() } returns false
        every { annotations.setNotes("after") } answers { notes = "after" }
        every { annotations.setHighlightColor(HighlightColor.RED) } throws IllegalStateException("private")
        stubHistory(proxyItem(1, 100, null, annotations).item)
        SensitiveActionSecurity.approvalHandler = allowSensitive()

        val result = HttpAnnotationService(api, config(), withMutation = { _, block -> block() }).annotate(
            AnnotateHttpMessages(
                "project-1",
                listOf(ref(1)),
                notes = "after",
                highlight = HttpAnnotationHighlight.RED,
            )
        )

        assertEquals(NativeToolStatus.EXECUTION_UNCERTAIN, result.status)
        assertEquals(ToolRetryGuidance.DO_NOT_RETRY, result.retry)
        assertEquals("after", notes)
        assertTrue(!result.error.orEmpty().contains("private"))
    }

    @Test
    fun `annotation denial and stale approval perform no mutation`() = runBlocking {
        val annotations = mockk<Annotations>()
        var notes = "before"
        every { annotations.notes() } answers { notes }
        every { annotations.hasHighlightColor() } returns false
        val item = proxyItem(1, 100, null, annotations)
        stubHistory(item.item)
        val service = HttpAnnotationService(api, config(), withMutation = { _, block -> block() })

        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean = false
        }
        val denied = service.annotate(AnnotateHttpMessages("project-1", listOf(ref(1)), notes = "after"))
        assertEquals(NativeToolStatus.ACCESS_DENIED, denied.status)

        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean {
                notes = "local edit"
                return true
            }
        }
        val stale = service.annotate(AnnotateHttpMessages("project-1", listOf(ref(1)), notes = "after"))
        assertEquals(NativeToolStatus.STALE_STATE, stale.status)
        verify(exactly = 0) { annotations.setNotes(any()) }
    }

    private fun config(): McpConfig {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers {
            when (firstArg<String>()) {
                "requireDataAccessApproval" -> false
                "approvalYoloMode" -> false
                else -> false
            }
        }
        return McpConfig(storage, logging, testPreferences())
    }

    private fun allowSensitive() = object : SensitiveActionApprovalHandler {
        override suspend fun requestApproval(
            action: String,
            summary: String,
            reviewContent: String?,
            renderContentAsHttp: Boolean,
            api: MontoyaApi,
        ): Boolean = true
    }

    private fun ref(id: Int) = HttpMessageReference(HttpMessageSource.PROXY, id.toString())

    private fun stubHistory(vararg items: ProxyHttpRequestResponse) {
        every { proxy.history(any()) } answers {
            val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
            items.filter(filter::matches)
        }
    }

    private data class ProxyFixture(
        val item: ProxyHttpRequestResponse,
        val request: HttpRequest,
        val response: HttpResponse?,
        val envelope: HttpRequestResponse,
    )

    private fun proxyItem(
        id: Int,
        requestBytes: Int,
        responseBytes: Int?,
        annotations: Annotations = mockk(relaxed = true),
    ): ProxyFixture {
        val item = mockk<ProxyHttpRequestResponse>()
        val request = mockk<HttpRequest>()
        val requestBody = bytes(requestBytes / 2)
        every { request.bodyOffset() } returns requestBytes - requestBody.length()
        every { request.body() } returns requestBody
        every { item.id() } returns id
        every { item.request() } returns request
        every { item.response() } returns responseBytes?.let { size ->
            mockk<HttpResponse>().also { response ->
                val body = bytes(size / 2)
                every { response.bodyOffset() } returns size - body.length()
                every { response.body() } returns body
            }
        }
        every { item.annotations() } returns annotations
        return ProxyFixture(item, request, item.response(), mockk())
    }

    private fun rank(envelope: HttpRequestResponse, ordinal: Int) = mockk<RankedHttpRequestResponse>().also {
        every { it.requestResponse() } returns envelope
        every { it.rank() } returns ordinal
    }

    private fun bytes(length: Int) = mockk<MontoyaByteArray>().also {
        every { it.length() } returns length
    }
}
