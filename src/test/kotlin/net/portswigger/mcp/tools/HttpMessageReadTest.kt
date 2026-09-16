package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.http.message.responses.HttpResponse
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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.Job
import kotlinx.coroutines.CancellationException
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.Test
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
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

    @Test
    fun `selected headers preserve duplicate empty values without unrelated content`() = runBlocking {
        val f = fixture(List(20) { "project-a" }, "BODY_PRIVATE")
        val other = mockk<HttpHeader>()
        every { other.name() } returns "Authorization"
        every { f.request.bodyOffset() } returns 128
        every { f.request.headers() } returns listOf(header("X-Value", "first"), other, header("x-value", ""))
        val input = GetHttpMessage("project-a", HttpMessageReference(HttpMessageSource.PROXY, "7"), part = "request_headers", headerName = "X-VALUE")
        val result = f.service.read(input)
        assertEquals(HttpHeaderSelection(HttpHeaderSelectionStatus.FOUND, listOf("first", "")), result.headerSelection)
        assertNull(result.metadata)
        assertNull(result.content)
        assertEquals(HttpHeaderSelectionStatus.MISSING, f.service.read(input.copy(headerName = "Absent", limit = 2)).headerSelection?.status)
        assertEquals(HttpHeaderSelection(HttpHeaderSelectionStatus.LIMIT_EXCEEDED), f.service.read(input.copy(headerName = "Absent", limit = 1)).headerSelection)
        every { f.request.headers() } returns listOf(header("X-Value", ""))
        assertEquals(listOf(""), f.service.read(input).headerSelection?.values)
        every { f.request.headers() } returns listOf(header("K", "not-an-ascii-name"))
        assertEquals(HttpHeaderSelectionStatus.MISSING, f.service.read(input.copy(headerName = "K")).headerSelection?.status)
        every { f.request.headers() } returns listOf(header("a".repeat(256), "boundary"))
        assertEquals(listOf("boundary"), f.service.read(input.copy(headerName = "a".repeat(256))).headerSelection?.values)
        verify(exactly = 0) { other.value() }
        verify(exactly = 0) { f.request.toByteArray() }
        verify(exactly = 0) { f.request.body() }
        verify(exactly = 0) { f.request.url() }
        verify(exactly = 0) { f.request.httpService() }
        verify(exactly = 0) { f.item.annotations() }
    }

    @Test
    fun `selected headers enforce complete input count and escaped UTF8 output budgets`() = runBlocking {
        val f = fixture(List(40) { "project-a" })
        val input = GetHttpMessage("project-a", HttpMessageReference(HttpMessageSource.PROXY, "7"), part = "request_headers", headerName = "X")
        every { f.request.bodyOffset() } returns 65537
        assertEquals(HttpHeaderSelectionStatus.INPUT_TRUNCATED, f.service.read(input).headerSelection?.status)
        verify(exactly = 0) { f.request.headers() }
        every { f.request.bodyOffset() } returns 65536
        every { f.request.headers() } returns object : AbstractList<HttpHeader>() {
            override val size = 129
            override fun get(index: Int): HttpHeader = error("must not inspect oversized header lists")
        }
        assertEquals(HttpHeaderSelectionStatus.INPUT_TRUNCATED, f.service.read(input).headerSelection?.status)
        val ignored = mockk<HttpHeader>()
        every { ignored.name() } returns "Other"
        every { f.request.headers() } returns List(127) { ignored } + header("X", "yes")
        assertEquals(listOf("yes"), f.service.read(input).headerSelection?.values)
        verify(exactly = 0) { ignored.value() }
        every { f.request.headers() } returns List(32) { header("X", "") }
        assertEquals(32, f.service.read(input).headerSelection?.values?.size)
        every { f.request.headers() } returns List(33) { header("X", "") }
        assertEquals(HttpHeaderSelection(HttpHeaderSelectionStatus.LIMIT_EXCEEDED), f.service.read(input).headerSelection)
        every { f.request.headers() } returns listOf(header("X", "x".repeat(65537)))
        assertEquals(HttpHeaderSelection(HttpHeaderSelectionStatus.INPUT_TRUNCATED), f.service.read(input).headerSelection)
        every { f.request.headers() } returns listOf(header("a".repeat(257), ""))
        assertEquals(HttpHeaderSelectionStatus.INPUT_TRUNCATED, f.service.read(input).headerSelection?.status)
        val values = listOf("가\"\\\n", "")
        val exactBytes = JsonArray(values.map(::JsonPrimitive)).toString().toByteArray(Charsets.UTF_8).size
        every { f.request.headers() } returns values.map { header("X", it) }
        assertEquals(values, f.service.read(input.copy(limit = exactBytes)).headerSelection?.values)
        val tooSmall = f.service.read(input.copy(limit = exactBytes - 1))
        assertEquals(HttpHeaderSelection(HttpHeaderSelectionStatus.LIMIT_EXCEEDED), tooSmall.headerSelection)
        assertNull(tooSmall.content)
        every { f.request.bodyOffset() } returns -1
        assertEquals(HttpMessageReadStatus.BURP_ERROR, f.service.read(input).status)
    }

    @Test
    fun `inspection arguments fail before project source or approvals`() = runBlocking {
        val f = fixture(listOf("project-a"))
        val input = GetHttpMessage("project-a", HttpMessageReference(HttpMessageSource.PROXY, "7"), part = "request_headers", headerName = "X")
        val invalid = listOf("", "a".repeat(257), "X Y", "X:Y", "X\nY", "K").map { input.copy(headerName = it) } + listOf(
            input.copy(part = null), input.copy(part = "request_body"), input.copy(jsonPointer = "/x"),
            input.copy(offset = 1), input.copy(encoding = "base64"), input.copy(limit = 0), input.copy(limit = 262145),
            input.copy(part = "response_mime"), input.copy(part = "response_mime", headerName = null, offset = 1),
            input.copy(part = "response_mime", headerName = null, encoding = "base64"),
        )
        invalid.forEach { assertEquals(HttpMessageReadStatus.INVALID_ARGUMENT, f.service.read(it).status) }
        verify(exactly = 0) { f.api.project() }
        verify(exactly = 0) { f.proxy.history(any()) }
    }

    @Test
    fun `response MIME is an opt-in observation with indeterminate labels`() = runBlocking {
        val pairs = listOf<Triple<MimeType?, MimeType?, Boolean?>>(
            Triple(MimeType.JSON, MimeType.JSON, false), Triple(MimeType.PLAIN_TEXT, MimeType.HTML, true),
            Triple(null, MimeType.JSON, null), Triple(MimeType.JSON, null, null), Triple(null, null, null),
        ) + listOf(MimeType.NONE, MimeType.UNRECOGNIZED, MimeType.AMBIGUOUS, MimeType.IMAGE_UNKNOWN, MimeType.APPLICATION_UNKNOWN)
            .flatMap { listOf(Triple(it, MimeType.JSON, null), Triple(MimeType.JSON, it, null), Triple(it, it, null)) }
        for ((stated, inferred, disagreement) in pairs) {
            val f = fixture(List(3) { "project-a" })
            val response = response(f, 128)
            every { response.statedMimeType() } returns stated
            every { response.inferredMimeType() } returns inferred
            val result = f.service.read(GetHttpMessage("project-a", HttpMessageReference(HttpMessageSource.PROXY, "7"), part = "response_mime"))
            assertEquals(HttpMimeAnalysis(stated?.name, inferred?.name, disagreement, false), result.mimeAnalysis)
            assertNull(result.metadata)
            assertNull(result.content)
            verify(exactly = 0) { response.toByteArray() }
            verify(exactly = 0) { response.headers() }
            verify(exactly = 0) { f.request.url() }
            verify(exactly = 0) { f.request.body() }
            verify(exactly = 0) { f.item.annotations() }
        }
    }

    @Test
    fun `response inspection distinguishes missing size caps and invalid native lengths`() = runBlocking {
        val f = fixture(List(30) { "project-a" })
        val input = GetHttpMessage("project-a", HttpMessageReference(HttpMessageSource.PROXY, "7"), part = "response_mime")
        assertEquals(HttpMessageReadStatus.PART_UNAVAILABLE, f.service.read(input).status)
        assertEquals(HttpMessageReadStatus.PART_UNAVAILABLE, f.service.read(input.copy(part = "response_headers", headerName = "X")).status)
        val response = response(f, 1048576 - 32)
        every { response.statedMimeType() } returns MimeType.JSON
        every { response.inferredMimeType() } returns MimeType.JSON
        assertEquals(false, f.service.read(input).mimeAnalysis?.skipped)
        every { response.body().length() } returns 1048576 - 31
        assertEquals(HttpMimeAnalysis(null, null, null, true), f.service.read(input).mimeAnalysis)
        every { response.bodyOffset() } returns Int.MAX_VALUE
        every { response.body().length() } returns Int.MAX_VALUE
        assertEquals(true, f.service.read(input).mimeAnalysis?.skipped)
        verify(exactly = 1) { response.statedMimeType() }
        verify(exactly = 1) { response.inferredMimeType() }
        every { response.bodyOffset() } returns -1
        assertEquals(HttpMessageReadStatus.BURP_ERROR, f.service.read(input).status)
        every { response.bodyOffset() } returns 32
        every { response.body().length() } returns -1
        assertEquals(HttpMessageReadStatus.BURP_ERROR, f.service.read(input).status)
        every { response.body().length() } returns 0
        every { response.headers() } returns listOf(header("X", "response-only"))
        assertEquals(listOf("response-only"), f.service.read(input.copy(part = "response_headers", headerName = "x")).headerSelection?.values)
    }

    @Test
    fun `inspection errors cancellation and final project changes never leak selected data`() = runBlocking {
        for (part in listOf("request_headers", "response_mime")) {
            val f = fixture(List(4) { "project-a" })
            val input = GetHttpMessage("project-a", HttpMessageReference(HttpMessageSource.PROXY, "7"), part = part, headerName = if (part == "request_headers") "X" else null)
            val mimeResponse = if (part == "response_mime") response(f, 0) else null
            if (part == "request_headers") {
                every { f.request.bodyOffset() } returns 32
                every { f.request.headers() } throws IllegalStateException("PRIVATE_SENTINEL")
            } else {
                every { mimeResponse!!.statedMimeType() } throws IllegalStateException("PRIVATE_SENTINEL")
            }
            val result = f.service.read(input)
            assertEquals(HttpMessageReadStatus.BURP_ERROR, result.status)
            assertNull(result.headerSelection)
            assertNull(result.mimeAnalysis)
            assertFalse(result.toString().contains("PRIVATE_SENTINEL"))
            if (part == "request_headers") {
                every { f.request.headers() } throws CancellationException("cancel")
            } else {
                every { mimeResponse!!.statedMimeType() } throws CancellationException("cancel")
            }
            assertFailsWith<CancellationException> { f.service.read(input) }

            val moved = fixture(listOf("project-a", "project-a", "project-b"))
            if (part == "request_headers") {
                every { moved.request.bodyOffset() } returns 32
                every { moved.request.headers() } returns listOf(header("X", "PRIVATE_SENTINEL"))
            } else {
                val response = response(moved, 0)
                every { response.statedMimeType() } returns MimeType.JSON
                every { response.inferredMimeType() } returns MimeType.HTML
            }
            val discarded = moved.service.read(input)
            assertEquals(HttpMessageReadStatus.PROJECT_MISMATCH, discarded.status)
            assertNull(discarded.headerSelection)
            assertNull(discarded.mimeAnalysis)
            assertFalse(discarded.toString().contains("PRIVATE_SENTINEL"))
        }
    }

    @Test
    fun `inspection source denial never reads either native selector`() = runBlocking {
        val previous = DataAccessSecurity.approvalHandler
        try {
            DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
                override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig) = false
            }
            for (part in listOf("request_headers", "response_mime")) {
                val f = fixture(List(3) { "project-a" }, requireApproval = true)
                val result = f.service.read(GetHttpMessage("project-a", HttpMessageReference(HttpMessageSource.PROXY, "7"), part = part, headerName = if (part == "request_headers") "X" else null))
                assertEquals(HttpMessageReadStatus.ACCESS_DENIED, result.status)
                verify(exactly = 0) { f.proxy.history(any()) }
            }
        } finally {
            DataAccessSecurity.approvalHandler = previous
        }
    }

    @Test
    fun `HTTP approval Job cancellation avoids subsequent logging project and history access`() = runBlocking {
        val previous = DataAccessSecurity.approvalHandler
        try {
            DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
                override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                    currentCoroutineContext().cancel()
                    return true
                }
            }
            val f = fixture(List(4) { "project-a" }, requireApproval = true)
            var returned: GetHttpMessageResult? = null
            val operation = async {
                returned = f.service.read(GetHttpMessage("project-a", HttpMessageReference(HttpMessageSource.PROXY, "7")))
            }
            assertFailsWith<CancellationException> { operation.await() }
            assertNull(returned)
            verify(exactly = 1) { f.api.project() }
            verify(exactly = 0) { f.api.logging() }
            verify(exactly = 0) { f.proxy.history(any()) }
        } finally {
            DataAccessSecurity.approvalHandler = previous
        }
    }

    @Test
    fun `HTTP resolver does not swallow native logging cancellation`() = runBlocking {
        val f = fixture(List(4) { "project-a" })
        every { f.api.logging() } throws CancellationException("native logging cancelled")
        assertFailsWith<CancellationException> {
            f.service.read(GetHttpMessage("project-a", HttpMessageReference(HttpMessageSource.PROXY, "7")))
        }
        verify(exactly = 1) { f.api.project() }
        verify(exactly = 0) { f.proxy.history(any()) }
    }

    @Test
    fun `already cancelled HTTP reads avoid native project and source access`() = runBlocking {
        val f = fixture(List(4) { "project-a" })
        var returned: GetHttpMessageResult? = null
        val operation = async {
            currentCoroutineContext().cancel()
            returned = f.service.read(GetHttpMessage("project-a", HttpMessageReference(HttpMessageSource.PROXY, "7")))
        }
        assertFailsWith<CancellationException> { operation.await() }
        assertNull(returned)
        verify(exactly = 0) { f.api.project() }
        verify(exactly = 0) { f.proxy.history(any()) }
    }

    @Test
    fun `HTTP Job cancellation after materialization or final project read never returns a result`() = runBlocking {
        for (phase in listOf("lookup_return", "lookup_throw", "body_return", "body_throw", "project_return", "project_throw")) {
            val f = fixture(List(8) { "project-a" }, "PRIVATE_SENTINEL")
            var operationJob: Job? = null
            var bodyRead = false
            var projectsAfterBody = 0
            var returned: GetHttpMessageResult? = null
            every { f.proxy.history(any()) } answers {
                if (phase.startsWith("lookup")) {
                    operationJob!!.cancel()
                    if (phase.endsWith("throw")) throw IllegalStateException("PRIVATE_SENTINEL")
                }
                listOf(f.item)
            }
            every { f.request.body() } answers {
                bodyRead = true
                if (phase.startsWith("body")) {
                    operationJob!!.cancel()
                    if (phase.endsWith("throw")) throw IllegalStateException("PRIVATE_SENTINEL")
                }
                f.body
            }
            every { f.project.id() } answers {
                if (bodyRead) {
                    projectsAfterBody++
                    if (phase.startsWith("project")) {
                        operationJob!!.cancel()
                        if (phase.endsWith("throw")) throw IllegalStateException("PRIVATE_SENTINEL")
                    }
                }
                "project-a"
            }
            val operation = async {
                operationJob = currentCoroutineContext()[Job]
                returned = f.service.read(GetHttpMessage("project-a", HttpMessageReference(HttpMessageSource.PROXY, "7"), part = "request_body"))
            }
            assertFailsWith<CancellationException>(phase) { operation.await() }
            assertNull(returned, phase)
            assertEquals(if (phase.startsWith("project")) 1 else 0, projectsAfterBody, phase)
        }
    }

    private fun header(name: String, value: String): HttpHeader = mockk<HttpHeader>().also {
        every { it.name() } returns name
        every { it.value() } returns value
    }

    private fun response(f: ReadFixture, bodyBytes: Int): HttpResponse = mockk<HttpResponse>().also { response ->
        val body = mockk<MontoyaByteArray>()
        every { body.length() } returns bodyBytes
        every { response.body() } returns body
        every { response.bodyOffset() } returns 32
        every { f.item.response() } returns response
    }

    private fun fixture(projectIds: List<String>, bodyText: String = "", requireApproval: Boolean = false): ReadFixture {
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
        if (requireApproval) every { storage.getBoolean("requireDataAccessApproval") } returns true
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
            project = project,
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
        val project: Project,
        val config: McpConfig,
        val proxy: Proxy,
        val item: ProxyHttpRequestResponse,
        val request: HttpRequest,
        val body: MontoyaByteArray,
    )
}
