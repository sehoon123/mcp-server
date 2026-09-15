package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.message.responses.analysis.AttributeType
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import io.mockk.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HttpMessageComparisonTest {
    private val api = mockk<MontoyaApi>()
    private val project = mockk<Project>()
    private val proxy = mockk<Proxy>()
    private val http = mockk<Http>()
    private val logging = mockk<Logging>(relaxed = true)
    private lateinit var service: HttpMessageComparisonService
    private lateinit var originalDataHandler: DataAccessApprovalHandler

    @BeforeEach
    fun setUp() {
        originalDataHandler = DataAccessSecurity.approvalHandler
        every { api.project() } returns project
        every { project.id() } returns "project-123"
        every { api.proxy() } returns proxy
        every { api.http() } returns http
        every { api.logging() } returns logging
        service = HttpMessageComparisonService(api, config(requireDataApproval = false))
    }

    @AfterEach
    fun tearDown() {
        DataAccessSecurity.approvalHandler = originalDataHandler
    }

    @Test
    fun `pre-capture comparison validation does not echo the caller project`() = runBlocking {
        val result = service.compare(
            CompareHttpMessages(
                projectId = "caller-forged",
                refs = emptyList(),
            )
        )

        assertEquals(HttpComparisonStatus.INVALID_ARGUMENT, result.status)
        assertNull(result.projectId)
        verify(exactly = 0) { api.project() }
        verify(exactly = 0) { proxy.history(any()) }
    }

    @Test
    fun `two response bodies return a bounded first difference`() = runBlocking {
        val first = proxyItem(1, "alpha-one")
        val second = proxyItem(2, "alpha-two")
        stubProxyHistory(first, second)

        val result = service.compare(
            CompareHttpMessages(
                projectId = "project-123",
                refs = refs(1, 2),
                part = HttpComparisonPart.RESPONSE_BODY,
                includeResponseVariations = false,
            )
        )

        assertEquals(HttpComparisonStatus.OK, result.status)
        assertEquals(false, result.allEqual)
        assertEquals(6, result.contentDifference?.firstDifferenceOffsetBytes)
        assertTrue(result.contentDifference?.left?.data.orEmpty().contains("alpha-one"))
        assertTrue(result.contentDifference?.right?.data.orEmpty().contains("alpha-two"))
        assertEquals(18, result.inspectedBytes)
    }

    @Test
    fun `project transition during comparison materialization discards results`() = runBlocking {
        val first = proxyItem(1, "alpha-one")
        val second = proxyItem(2, "alpha-two")
        stubProxyHistory(first, second)
        val response = requireNotNull(first.response())
        val body = response.body()
        var currentProjectId = "project-123"
        every { project.id() } answers { currentProjectId }
        every { response.body() } answers {
            currentProjectId = "other-project"
            body
        }

        val result = service.compare(
            CompareHttpMessages(
                projectId = "project-123",
                refs = refs(1, 2),
                part = HttpComparisonPart.RESPONSE_BODY,
                includeResponseVariations = false,
            )
        )

        assertEquals(HttpComparisonStatus.PROJECT_MISMATCH, result.status)
        assertEquals("other-project", result.projectId)
        assertTrue(result.items.isEmpty())
    }

    @Test
    fun `matching inspected prefixes report unknown equality when truncated`() = runBlocking {
        val first = proxyItem(1, "abcdef")
        val second = proxyItem(2, "abcdZZ")
        stubProxyHistory(first, second)

        val result = service.compare(
            CompareHttpMessages(
                "project-123",
                refs(1, 2),
                HttpComparisonPart.RESPONSE_BODY,
                limitBytesPerMessage = 4,
                includeResponseVariations = false,
            )
        )

        assertEquals(HttpComparisonStatus.OK, result.status)
        assertNull(result.allEqual)
        assertNull(result.contentDifference?.equal)
        assertTrue(result.items.all { it.truncated && it.inspectedBytes == 4 })
    }

    @Test
    fun `length mismatch does not invent a first difference beyond a truncated prefix`() = runBlocking {
        val first = proxyItem(1, "abcdef")
        val second = proxyItem(2, "abcdefg")
        stubProxyHistory(first, second)

        val result = service.compare(
            CompareHttpMessages(
                "project-123",
                refs(1, 2),
                HttpComparisonPart.RESPONSE_BODY,
                limitBytesPerMessage = 4,
                includeResponseVariations = false,
            )
        )

        assertEquals(false, result.allEqual)
        assertEquals(false, result.contentDifference?.equal)
        assertNull(result.contentDifference?.firstDifferenceOffsetBytes)
    }

    @Test
    fun `header comparison ignores selected dynamic headers and preserves duplicate values`() = runBlocking {
        val firstHeaders = listOf(
            header("Content-Type", "text/plain"),
            header("X-Role", "user"),
            header("Date", "one"),
        )
        val secondHeaders = listOf(
            header("content-type", "text/plain"),
            header("X-Role", "admin"),
            header("Date", "two"),
        )
        val first = proxyItem(1, "body", firstHeaders)
        val second = proxyItem(2, "body", secondHeaders)
        stubProxyHistory(first, second)

        val result = service.compare(
            CompareHttpMessages(
                "project-123",
                refs(1, 2),
                HttpComparisonPart.RESPONSE_HEADERS,
                ignoreHeaders = listOf("Date"),
                includeResponseVariations = false,
            )
        )

        val headers = result.headerComparison!!
        assertEquals(false, headers.equal)
        assertEquals(listOf("x-role"), headers.variantNames)
        assertEquals(listOf("user"), headers.differences.single().leftValues)
        assertEquals(listOf("admin"), headers.differences.single().rightValues)
        assertTrue("content-type" in headers.invariantNames)
        assertFalse("date" in headers.variantNames)
    }

    @Test
    fun `header equality is unknown when Burp supplies more headers than the structured bound`() = runBlocking {
        val common = (0 until 128).map { header("X-$it", "same") }
        val first = proxyItem(1, "body", common + header("X-Tail", "one"))
        val second = proxyItem(2, "body", common + header("X-Tail", "two"))
        stubProxyHistory(first, second)

        val result = service.compare(
            CompareHttpMessages(
                "project-123",
                refs(1, 2),
                HttpComparisonPart.RESPONSE_HEADERS,
                includeResponseVariations = false,
            )
        )

        assertNull(result.headerComparison?.equal)
        assertTrue(result.headerComparison!!.differencesTruncated)
        assertEquals(false, result.allEqual)
    }

    @Test
    fun `Burp native response variations are bounded and returned structurally`() = runBlocking {
        val first = proxyItem(1, "one")
        val second = proxyItem(2, "two")
        stubProxyHistory(first, second)
        val analyzer = mockk<ResponseVariationsAnalyzer>(relaxed = true)
        every { http.createResponseVariationsAnalyzer() } returns analyzer
        every { analyzer.variantAttributes() } returns setOf(AttributeType.STATUS_CODE, AttributeType.BODY_CONTENT)
        every { analyzer.invariantAttributes() } returns setOf(AttributeType.CONTENT_TYPE)

        val result = service.compare(
            CompareHttpMessages("project-123", refs(1, 2), HttpComparisonPart.RESPONSE)
        )

        assertEquals(listOf("body_content", "status_code"), result.responseVariations?.variantAttributes)
        assertEquals(listOf("content_type"), result.responseVariations?.invariantAttributes)
        assertFalse(result.responseVariations!!.skipped)
        verify(exactly = 2) { analyzer.updateWith(any()) }
    }

    @Test
    fun `optional native response keywords use complete responses and return a bounded partition`() = runBlocking {
        val first = proxyItem(1, "one alpha")
        val second = proxyItem(2, "two beta")
        stubProxyHistory(first, second)
        val analyzer = mockk<ResponseKeywordsAnalyzer>(relaxed = true)
        every { http.createResponseKeywordsAnalyzer(listOf("alpha", "beta", "common")) } returns analyzer
        every { analyzer.variantKeywords() } returns setOf("alpha", "beta")
        every { analyzer.invariantKeywords() } returns setOf("common")

        val result = service.compare(
            CompareHttpMessages(
                "project-123",
                refs(1, 2),
                HttpComparisonPart.RESPONSE_BODY,
                limitBytesPerMessage = 1,
                includeResponseVariations = false,
                responseKeywords = listOf("alpha", "beta", "common"),
            )
        )

        assertEquals(listOf("alpha", "beta"), result.keywordAnalysis?.variantKeywords)
        assertEquals(listOf("common"), result.keywordAnalysis?.invariantKeywords)
        assertFalse(result.keywordAnalysis!!.skipped)
        verify(exactly = 2) { analyzer.updateWith(any()) }
    }

    @Test
    fun `omitted or invalid response keywords never invoke the native analyzer or source`() = runBlocking {
        val first = proxyItem(1, "one")
        val second = proxyItem(2, "two")
        stubProxyHistory(first, second)
        val omitted = service.compare(
            CompareHttpMessages(
                "project-123",
                refs(1, 2),
                HttpComparisonPart.RESPONSE_BODY,
                includeResponseVariations = false,
            )
        )
        assertNull(omitted.keywordAnalysis)
        verify(exactly = 0) { http.createResponseKeywordsAnalyzer(any()) }

        clearMocks(proxy, answers = false, recordedCalls = true)
        val base = CompareHttpMessages(
            "caller-forged",
            refs(1, 2),
            HttpComparisonPart.RESPONSE_BODY,
            includeResponseVariations = false,
        )
        listOf(
            base.copy(part = HttpComparisonPart.REQUEST_BODY, responseKeywords = listOf("alpha")),
            base.copy(responseKeywords = emptyList()),
            base.copy(responseKeywords = listOf("alpha", "alpha")),
            base.copy(responseKeywords = listOf("bad\nvalue")),
            base.copy(responseKeywords = List(33) { "keyword-$it" }),
            base.copy(responseKeywords = listOf("x".repeat(257))),
            base.copy(responseKeywords = List(32) { "${"x".repeat(128)}-$it" }),
        ).forEach { input ->
            val invalid = service.compare(input)
            assertEquals(HttpComparisonStatus.INVALID_ARGUMENT, invalid.status)
            assertNull(invalid.projectId)
        }
        verify(exactly = 0) { proxy.history(any()) }
    }

    @Test
    fun `unexpected native keyword output is skipped without escaping values`() = runBlocking {
        stubProxyHistory(proxyItem(1, "one"), proxyItem(2, "two"))
        val analyzer = mockk<ResponseKeywordsAnalyzer>(relaxed = true)
        every { http.createResponseKeywordsAnalyzer(listOf("expected")) } returns analyzer
        every { analyzer.variantKeywords() } returns setOf("PRIVATE_UNEXPECTED")
        every { analyzer.invariantKeywords() } returns emptySet()

        val result = service.compare(
            CompareHttpMessages(
                "project-123",
                refs(1, 2),
                HttpComparisonPart.RESPONSE,
                includeResponseVariations = false,
                responseKeywords = listOf("expected"),
            )
        )

        assertTrue(result.keywordAnalysis!!.skipped)
        assertTrue(result.keywordAnalysis!!.variantKeywords.isEmpty())
        assertFalse(result.toString().contains("PRIVATE_UNEXPECTED"))

        val oversized = mockk<Set<String>>()
        every { oversized.size } returns 33
        every { analyzer.variantKeywords() } returns oversized
        val bounded = service.compare(
            CompareHttpMessages(
                "project-123", refs(1, 2), HttpComparisonPart.RESPONSE_BODY,
                includeResponseVariations = false, responseKeywords = listOf("expected"),
            )
        )
        assertTrue(bounded.keywordAnalysis!!.skipped)
        verify(exactly = 0) { oversized.iterator() }
    }

    @Test
    fun `keyword native failures and full-response limits return fixed skipped summaries`() = runBlocking {
        stubProxyHistory(proxyItem(1, "one"), proxyItem(2, "two"))
        every { http.createResponseKeywordsAnalyzer(listOf("expected")) } throws
            IllegalStateException("PRIVATE_NATIVE_FAILURE")
        val failed = service.compare(
            CompareHttpMessages(
                "project-123",
                refs(1, 2),
                HttpComparisonPart.RESPONSE_BODY,
                includeResponseVariations = false,
                responseKeywords = listOf("expected"),
            )
        )
        assertTrue(failed.keywordAnalysis!!.skipped)
        assertEquals("Burp response keyword analysis was unavailable", failed.keywordAnalysis!!.reason)
        assertFalse(failed.toString().contains("PRIVATE_NATIVE_FAILURE"))

        val oversized = "x".repeat(1024 * 1024)
        stubProxyHistory(proxyItem(1, oversized), proxyItem(2, "two"))
        val bounded = service.compare(
            CompareHttpMessages(
                "project-123",
                refs(1, 2),
                HttpComparisonPart.RESPONSE_BODY,
                limitBytesPerMessage = 1,
                includeResponseVariations = false,
                responseKeywords = listOf("expected"),
            )
        )
        assertTrue(bounded.keywordAnalysis!!.skipped)
        assertTrue(bounded.keywordAnalysis!!.reason.orEmpty().contains("1048576-byte keyword-analysis limit"))

        val messages = (1..6).map { proxyItem(it, "x".repeat(800_000)) }
        stubProxyHistory(*messages.toTypedArray())
        val input = CompareHttpMessages(
            "project-123", refs(1, 2, 3, 4, 5, 6), HttpComparisonPart.RESPONSE_BODY,
            limitBytesPerMessage = 1, includeResponseVariations = false, responseKeywords = listOf("expected"),
        )
        val aggregate = service.compare(input)
        assertTrue(aggregate.keywordAnalysis!!.skipped)
        assertTrue(aggregate.keywordAnalysis!!.reason.orEmpty().contains("4194304-byte total"))

        val firstResponse = messages.first().response()!!
        every { firstResponse.bodyOffset() } returns -1
        val invalidLength = service.compare(input)
        assertTrue(invalidLength.keywordAnalysis!!.skipped)
        assertEquals("a response reported an invalid byte length", invalidLength.keywordAnalysis!!.reason)
    }

    @Test
    fun `project transition during keyword analysis discards native results`() = runBlocking {
        stubProxyHistory(proxyItem(1, "one"), proxyItem(2, "two"))
        var currentProject = "project-123"
        every { project.id() } answers { currentProject }
        val analyzer = mockk<ResponseKeywordsAnalyzer>(relaxed = true)
        every { http.createResponseKeywordsAnalyzer(listOf("expected")) } returns analyzer
        every { analyzer.updateWith(any()) } answers { currentProject = "other-project" }
        every { analyzer.variantKeywords() } returns emptySet()
        every { analyzer.invariantKeywords() } returns setOf("expected")

        val result = service.compare(
            CompareHttpMessages(
                "project-123",
                refs(1, 2),
                HttpComparisonPart.RESPONSE,
                includeResponseVariations = false,
                responseKeywords = listOf("expected"),
            )
        )

        assertEquals(HttpComparisonStatus.PROJECT_MISMATCH, result.status)
        assertEquals("other-project", result.projectId)
        assertNull(result.keywordAnalysis)
        assertTrue(result.items.isEmpty())
    }

    @Test
    fun `keyword analyzer cancellation propagates`() {
        stubProxyHistory(proxyItem(1, "one"), proxyItem(2, "two"))
        val analyzer = mockk<ResponseKeywordsAnalyzer>(relaxed = true)
        every { http.createResponseKeywordsAnalyzer(listOf("expected")) } returns analyzer
        every { analyzer.updateWith(any()) } throws CancellationException("cancelled")

        assertFailsWith<CancellationException> {
            runBlocking {
                service.compare(
                    CompareHttpMessages(
                        "project-123",
                        refs(1, 2),
                        HttpComparisonPart.RESPONSE,
                        includeResponseVariations = false,
                        responseKeywords = listOf("expected"),
                    )
                )
            }
        }
    }

    @Test
    fun `missing response fails before attempting native variation analysis`() = runBlocking {
        val first = proxyItem(1, "one")
        val second = proxyItem(2, null)
        stubProxyHistory(first, second)

        val result = service.compare(
            CompareHttpMessages("project-123", refs(1, 2), HttpComparisonPart.RESPONSE_BODY)
        )

        assertEquals(HttpComparisonStatus.PART_UNAVAILABLE, result.status)
        assertEquals(1, result.errorRefIndex)
        verify(exactly = 0) { http.createResponseVariationsAnalyzer() }
    }

    @Test
    fun `project transition during batch data approval prevents message resolution`() = runBlocking {
        service = HttpMessageComparisonService(api, config(requireDataApproval = true))
        var currentProjectId = "project-123"
        every { project.id() } answers { currentProjectId }
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                currentProjectId = "other-project"
                return true
            }
        }

        val result = service.compare(
            CompareHttpMessages(
                "project-123",
                refs(1, 2),
                HttpComparisonPart.RESPONSE_BODY,
                includeResponseVariations = false,
            )
        )

        assertEquals(HttpComparisonStatus.PROJECT_MISMATCH, result.status)
        assertEquals("other-project", result.projectId)
        assertTrue(result.items.isEmpty())
        verify(exactly = 0) { proxy.history(any()) }
    }

    @Test
    fun `batch resolver asks for one data approval for repeated source`() = runBlocking {
        service = HttpMessageComparisonService(api, config(requireDataApproval = true))
        var approvals = 0
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                approvals++
                return true
            }
        }
        val first = proxyItem(1, "one")
        val second = proxyItem(2, "two")
        stubProxyHistory(first, second)

        val result = service.compare(
            CompareHttpMessages(
                "project-123",
                refs(1, 2),
                HttpComparisonPart.RESPONSE_BODY,
                includeResponseVariations = false,
            )
        )

        assertEquals(HttpComparisonStatus.OK, result.status)
        assertEquals(1, approvals)
    }

    @Test
    fun `JSON body modes return structural equality without raw excerpts headers or native analysis`() = runBlocking {
        val first = proxyItem(1, """{"a":1,"b":"PRIVATE_VALUE"}""")
        val second = proxyItem(2, """{ "b": "PRIVATE_VALUE", "a": 1 }""")
        stubProxyHistory(first, second)
        val result = service.compare(CompareHttpMessages("project-123", refs(1, 2), HttpComparisonPart.RESPONSE_JSON))
        assertEquals(HttpComparisonStatus.OK, result.status)
        assertEquals(true, result.allEqual)
        assertEquals(HttpJsonComparisonStatus.OK, result.jsonComparison?.status)
        assertNull(result.contentDifference)
        assertNull(result.headerComparison)
        assertNull(result.responseVariations)
        assertTrue(result.items.map { it.inspectedSha256 }.distinct().size == 2)
        assertFalse(result.toString().contains("PRIVATE_VALUE"))
        verify(exactly = 0) { http.createResponseVariationsAnalyzer() }
        val firstResponse = first.response()!!
        verify(exactly = 0) { firstResponse.toByteArray() }

        val requestOnly = proxyItem(3, null)
        val requestOther = proxyItem(4, null)
        every { requestOnly.request().body() } returns montoyaBytes("{\"x\":1}".toByteArray())
        every { requestOther.request().body() } returns montoyaBytes("{\"x\":2}".toByteArray())
        stubProxyHistory(requestOnly, requestOther)
        val requests = service.compare(CompareHttpMessages("project-123", refs(3, 4), HttpComparisonPart.REQUEST_JSON))
        assertEquals(false, requests.allEqual)
        assertEquals("/x", requests.jsonComparison?.differences?.single()?.path)
        assertNull(requests.contentDifference)
    }

    @Test
    fun `JSON byte cap and malformed complete input are explicitly unknown`() = runBlocking {
        val oversized = "{}" + " ".repeat(MAX_JSON_COMPARISON_BYTES)
        val first = proxyItem(1, oversized)
        val second = proxyItem(2, oversized)
        stubProxyHistory(first, second)
        val body = first.response()!!.body()
        val result = service.compare(CompareHttpMessages("project-123", refs(1, 2), HttpComparisonPart.RESPONSE_JSON))
        assertEquals(HttpJsonComparisonStatus.INPUT_TRUNCATED, result.jsonComparison?.status)
        assertNull(result.allEqual)
        assertTrue(result.items.all { it.truncated && it.inspectedBytes == MAX_JSON_COMPARISON_BYTES })
        verify(exactly = 0) { body.getBytes() }
        verify(exactly = 1) { body.subArray(0, MAX_JSON_COMPARISON_BYTES) }
        stubProxyHistory(proxyItem(1, "not JSON"), proxyItem(2, "not JSON"))
        val invalid = service.compare(CompareHttpMessages("project-123", refs(1, 2), HttpComparisonPart.RESPONSE_JSON))
        assertEquals(HttpComparisonStatus.OK, invalid.status)
        assertEquals(HttpJsonComparisonStatus.INVALID_JSON, invalid.jsonComparison?.status)
        assertNull(invalid.allEqual)
        assertNull(invalid.contentDifference)
    }

    @Test
    fun `JSON results retain data approval and are discarded after a project transition`() = runBlocking {
        service = HttpMessageComparisonService(api, config(requireDataApproval = true))
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig) = false
        }
        val input = CompareHttpMessages("project-123", refs(1, 2), HttpComparisonPart.RESPONSE_JSON)
        assertEquals(HttpComparisonStatus.ACCESS_DENIED, service.compare(input).status)
        verify(exactly = 0) { proxy.history(any()) }

        service = HttpMessageComparisonService(api, config(requireDataApproval = false))
        val first = proxyItem(1, "{\"x\":1}")
        stubProxyHistory(first, proxyItem(2, "{\"x\":2}"))
        val response = first.response()!!
        val body = response.body()
        var currentProject = "project-123"
        every { project.id() } answers { currentProject }
        every { response.body() } answers { currentProject = "other-project"; body }
        val moved = service.compare(input)
        assertEquals(HttpComparisonStatus.PROJECT_MISMATCH, moved.status)
        assertNull(moved.jsonComparison)
        assertTrue(moved.items.isEmpty())
    }

    private fun config(requireDataApproval: Boolean): McpConfig {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers {
            when (firstArg<String>()) {
                "requireDataAccessApproval" -> requireDataApproval
                else -> false
            }
        }
        every { storage.getString(any()) } returns ""
        return McpConfig(storage, logging, net.portswigger.mcp.testPreferences())
    }

    private fun refs(vararg ids: Int) = ids.map {
        HttpMessageReference(HttpMessageSource.PROXY, it.toString())
    }

    private fun stubProxyHistory(vararg items: ProxyHttpRequestResponse) {
        every { proxy.history(any()) } answers {
            val filter = firstArg<burp.api.montoya.proxy.ProxyHistoryFilter>()
            items.filter(filter::matches)
        }
    }

    private fun proxyItem(
        id: Int,
        responseBody: String?,
        responseHeaders: List<HttpHeader> = emptyList(),
    ): ProxyHttpRequestResponse {
        val item = mockk<ProxyHttpRequestResponse>()
        val request = mockk<HttpRequest>()
        every { item.id() } returns id
        every { item.request() } returns request
        every { request.url() } returns "https://example.test/$id"
        val response = responseBody?.let { response(it, responseHeaders) }
        every { item.response() } returns response
        return item
    }

    private fun response(bodyText: String, headers: List<HttpHeader>): HttpResponse {
        val response = mockk<HttpResponse>()
        val body = montoyaBytes(bodyText.toByteArray())
        val preludeText = buildString {
            append("HTTP/1.1 200 OK\r\n")
            headers.forEach { append("${it.name()}: ${it.value()}\r\n") }
            append("\r\n")
        }
        val raw = montoyaBytes(preludeText.toByteArray() + bodyText.toByteArray())
        every { response.body() } returns body
        every { response.bodyOffset() } returns preludeText.toByteArray().size
        every { response.toByteArray() } returns raw
        every { response.headers() } returns headers
        every { response.statusCode() } returns 200
        every { response.httpVersion() } returns "HTTP/1.1"
        return response
    }

    private fun header(name: String, value: String): HttpHeader = mockk<HttpHeader>().also {
        every { it.name() } returns name
        every { it.value() } returns value
    }

    private fun montoyaBytes(raw: ByteArray): MontoyaByteArray {
        val bytes = mockk<MontoyaByteArray>()
        every { bytes.length() } returns raw.size
        every { bytes.getBytes() } returns raw
        every { bytes.subArray(any(), any()) } answers {
            val start = firstArg<Int>()
            val end = secondArg<Int>()
            montoyaBytes(raw.copyOfRange(start, end))
        }
        return bytes
    }
}
