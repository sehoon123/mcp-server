package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.message.responses.analysis.AttributeType
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import io.mockk.*
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
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
    fun `two response bodies return a bounded first difference`() = runBlocking {
        val first = proxyItem(1, "alpha-one")
        val second = proxyItem(2, "alpha-two")
        every { proxy.history(any()) } returnsMany listOf(listOf(first), listOf(second))

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
    fun `matching inspected prefixes report unknown equality when truncated`() = runBlocking {
        val first = proxyItem(1, "abcdef")
        val second = proxyItem(2, "abcdZZ")
        every { proxy.history(any()) } returnsMany listOf(listOf(first), listOf(second))

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
        every { proxy.history(any()) } returnsMany listOf(listOf(first), listOf(second))

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
        every { proxy.history(any()) } returnsMany listOf(listOf(first), listOf(second))

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
        every { proxy.history(any()) } returnsMany listOf(listOf(first), listOf(second))

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
        every { proxy.history(any()) } returnsMany listOf(listOf(first), listOf(second))
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
    fun `missing response fails before attempting native variation analysis`() = runBlocking {
        val first = proxyItem(1, "one")
        val second = proxyItem(2, null)
        every { proxy.history(any()) } returnsMany listOf(listOf(first), listOf(second))

        val result = service.compare(
            CompareHttpMessages("project-123", refs(1, 2), HttpComparisonPart.RESPONSE_BODY)
        )

        assertEquals(HttpComparisonStatus.PART_UNAVAILABLE, result.status)
        assertEquals(1, result.errorRefIndex)
        verify(exactly = 0) { http.createResponseVariationsAnalyzer() }
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
        every { proxy.history(any()) } returnsMany listOf(listOf(first), listOf(second))

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

    private fun config(requireDataApproval: Boolean): McpConfig {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers {
            when (firstArg<String>()) {
                "requireDataAccessApproval" -> requireDataApproval
                else -> false
            }
        }
        every { storage.getString(any()) } returns ""
        return McpConfig(storage, logging)
    }

    private fun refs(vararg ids: Int) = ids.map {
        HttpMessageReference(HttpMessageSource.PROXY, it.toString())
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
