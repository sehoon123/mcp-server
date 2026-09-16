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
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
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
        verify(exactly = 2) { fixture.request.body() }
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
    fun `JSON pointer selects complete escaped object array and null values`() = runBlocking {
        val fixture = fixture(
            projectIds = List(15) { "project-a" },
            bodyText = """{"a/b":{"~key":[null,{"value":"ok"}]}}""",
        )
        val base = GetHttpMessage(
            projectId = "project-a",
            ref = HttpMessageReference(HttpMessageSource.PROXY, "7"),
            part = "request_body",
            jsonPointer = "/a~1b/~0key/1/value",
        )

        val nested = fixture.service.read(base)
        val nullValue = fixture.service.read(base.copy(jsonPointer = "/a~1b/~0key/0"))
        val missing = fixture.service.read(base.copy(jsonPointer = "/a~1b/~0key/01"))
        val root = fixture.service.read(base.copy(jsonPointer = ""))
        for (index in listOf("١", "+1", "-")) {
            val invalidIndex = fixture.service.read(base.copy(jsonPointer = "/a~1b/~0key/$index"))
            assertEquals(HttpJsonSelectionStatus.MISSING, invalidIndex.jsonSelection?.status)
        }

        assertEquals(HttpJsonSelectionStatus.FOUND, nested.jsonSelection?.status)
        assertEquals("\"ok\"", nested.jsonSelection?.valueJson)
        assertNull(nested.content)
        assertNull(nested.metadata)
        verify(exactly = 0) { fixture.request.url() }
        verify(exactly = 0) { fixture.request.httpService() }
        verify(exactly = 0) { fixture.item.annotations() }
        assertEquals(HttpJsonSelectionStatus.FOUND, nullValue.jsonSelection?.status)
        assertEquals("null", nullValue.jsonSelection?.valueJson)
        assertEquals(HttpJsonSelectionStatus.MISSING, missing.jsonSelection?.status)
        assertNull(missing.jsonSelection?.valueJson)
        assertEquals(HttpJsonSelectionStatus.FOUND, root.jsonSelection?.status)
        assertTrue(root.jsonSelection?.valueJson.orEmpty().startsWith("{"))
    }

    @Test
    fun `default preview and explicit larger reads preserve complete pagination`() = runBlocking {
        val body = "x".repeat(40 * 1024)
        val fixture = fixture(List(50) { "project-a" }, body)
        val input = GetHttpMessage("project-a", HttpMessageReference(HttpMessageSource.PROXY, "7"), part = "request_body")
        val first = fixture.service.read(input)
        val oldSize = fixture.service.read(input.copy(limit = 32 * 1024))
        val whole = fixture.service.read(input.copy(limit = MAX_HISTORY_SLICE_BYTES))
        fun wireBytes(value: GetHttpMessageResult): Int {
            val structured = Json.encodeToJsonElement(GetHttpMessageResult.serializer(), value).jsonObject
            return Json.encodeToString(CallToolResult(
                content = listOf(TextContent(structured.toString())), structuredContent = structured,
            )).toByteArray().size
        }
        println("HTTP_READ_BYTES default=${wireBytes(first)} explicit32KiB=${wireBytes(oldSize)} payload=${first.content!!.returnedBytes}")
        assertEquals(8192, first.content!!.returnedBytes)
        assertTrue(wireBytes(first) * 10 < wireBytes(oldSize) * 3, "Default mirrored preview should be at least 70% smaller")
        assertEquals(DEFAULT_HISTORY_SLICE_BYTES, first.content!!.nextOffsetBytes)
        assertEquals(body.length, first.content!!.totalBytes)
        assertEquals(body, whole.content!!.data)
        val reconstructed = StringBuilder(first.content!!.data)
        var next = first.content!!.nextOffsetBytes
        while (next != null) {
            val page = fixture.service.read(input.copy(offset = next)).content!!
            reconstructed.append(page.data)
            next = page.nextOffsetBytes
        }
        assertEquals(body, reconstructed.toString())
    }

    @Test
    fun `JSON selection above the preview default requires explicit larger limit`() = runBlocking {
        val value = "x".repeat(8192)
        val fixture = fixture(List(8) { "project-a" }, """{"value":"$value"}""")
        val input = GetHttpMessage(
            "project-a", HttpMessageReference(HttpMessageSource.PROXY, "7"), part = "request_body", jsonPointer = "/value",
        )
        val preview = fixture.service.read(input)
        assertEquals(HttpJsonSelectionStatus.LIMIT_EXCEEDED, preview.jsonSelection?.status)
        assertNull(preview.jsonSelection?.valueJson)
        assertNull(preview.content)
        val complete = fixture.service.read(input.copy(limit = 32768))
        assertEquals(HttpJsonSelectionStatus.FOUND, complete.jsonSelection?.status)
        assertEquals("\"$value\"", complete.jsonSelection?.valueJson)
    }

    @Test
    fun `invalid JSON pointer options fail before source access`() = runBlocking {
        val fixture = fixture(projectIds = listOf("project-a"), bodyText = "{}")
        val base = GetHttpMessage(
            projectId = "caller-forged",
            ref = HttpMessageReference(HttpMessageSource.PROXY, "7"),
            part = "request_body",
            jsonPointer = "/x",
        )

        listOf(
            base.copy(part = null),
            base.copy(offset = 1),
            base.copy(encoding = "base64"),
            base.copy(jsonPointer = "x"),
            base.copy(jsonPointer = "/bad~2escape"),
            base.copy(jsonPointer = "x".repeat(513)),
        ).forEach { input ->
            val result = fixture.service.read(input)
            assertEquals(HttpMessageReadStatus.INVALID_ARGUMENT, result.status)
            assertNull(result.projectId)
        }
        verify(exactly = 0) { fixture.api.project() }
        verify(exactly = 0) { fixture.proxy.history(any()) }
    }

    @Test
    fun `JSON selection reports parse and output limits without partial content`() = runBlocking {
        val invalid = fixture(List(3) { "project-a" }, """{"x":1,"x":2}""").service.read(
            GetHttpMessage(
                "project-a",
                HttpMessageReference(HttpMessageSource.PROXY, "7"),
                part = "request_body",
                jsonPointer = "/x",
            )
        )
        assertEquals(HttpJsonSelectionStatus.DUPLICATE_KEY, invalid.jsonSelection?.status)
        assertNull(invalid.jsonSelection?.valueJson)
        assertNull(invalid.content)

        val malformed = fixture(List(3) { "project-a" }, "{not-json").service.read(
            GetHttpMessage(
                "project-a",
                HttpMessageReference(HttpMessageSource.PROXY, "7"),
                part = "request_body",
                jsonPointer = "",
            )
        )
        assertEquals(HttpJsonSelectionStatus.INVALID_JSON, malformed.jsonSelection?.status)
        assertNull(malformed.jsonSelection?.valueJson)

        val oversizedFixture = fixture(List(3) { "project-a" }, "{}" + " ".repeat(MAX_JSON_COMPARISON_BYTES))
        val oversized = oversizedFixture.service.read(
            GetHttpMessage(
                "project-a",
                HttpMessageReference(HttpMessageSource.PROXY, "7"),
                part = "request_body",
                jsonPointer = "",
            )
        )
        assertEquals(HttpJsonSelectionStatus.INPUT_TRUNCATED, oversized.jsonSelection?.status)
        assertNull(oversized.jsonSelection?.valueJson)
        verify(exactly = 0) { oversizedFixture.body.getBytes() }

        val limited = fixture(List(3) { "project-a" }, """{"x":"abcd"}""").service.read(
            GetHttpMessage(
                "project-a",
                HttpMessageReference(HttpMessageSource.PROXY, "7"),
                part = "request_body",
                limit = 3,
                jsonPointer = "/x",
            )
        )
        assertEquals(HttpJsonSelectionStatus.LIMIT_EXCEEDED, limited.jsonSelection?.status)
        assertNull(limited.jsonSelection?.valueJson)
    }

    @Test
    fun `final project fence discards a prepared JSON selection`() = runBlocking {
        val fixture = fixture(listOf("project-a", "project-a", "project-b"), """{"x":"private"}""")

        val result = fixture.service.read(
            GetHttpMessage(
                "project-a",
                HttpMessageReference(HttpMessageSource.PROXY, "7"),
                part = "request_body",
                jsonPointer = "/x",
            )
        )

        assertEquals(HttpMessageReadStatus.PROJECT_MISMATCH, result.status)
        assertNull(result.jsonSelection)
        assertNull(result.content)
        assertFalse(result.toString().contains("private"))
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

    private fun fixture(projectIds: List<String>, bodyText: String = ""): ReadFixture {
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
        val config = McpConfig(storage, logging, net.portswigger.mcp.testPreferences())

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
        val bodyBytes = bodyText.toByteArray()
        every { request.body() } returns body
        every { body.length() } returns bodyBytes.size
        every { body.getBytes() } returns bodyBytes
        every { body.subArray(any(), any()) } answers {
            val start = firstArg<Int>()
            val end = secondArg<Int>()
            val slice = bodyBytes.copyOfRange(start, end)
            mockk<MontoyaByteArray>().also { selected ->
                every { selected.length() } returns slice.size
                every { selected.getBytes() } returns slice
                every { selected.toString() } returns slice.toString(Charsets.UTF_8)
            }
        }
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
            body = body,
        )
    }

    private data class ReadFixture(
        val service: HttpMessageReadService,
        val api: MontoyaApi,
        val config: McpConfig,
        val proxy: Proxy,
        val item: ProxyHttpRequestResponse,
        val request: HttpRequest,
        val body: MontoyaByteArray,
    )
}
