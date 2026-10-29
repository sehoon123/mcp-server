package net.portswigger.mcp.tools

import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.core.Range
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Test
import kotlin.test.*

class HttpReflectionsTest {
    private val selector = HttpInsertionPointSelector(HttpInsertionPointKind.PARAMETER, "id", HttpActionParameterType.URL)
    private val json = Json { encodeDefaults = true }

    @Test
    fun `selects exact type name and occurrence and counts overlapping section-relative raw bytes`() = runBlocking {
        val parameters = listOf(parameter("id", 0, 1), parameter("id", 0, 1, HttpParameterType.JSON), parameter("ID", 0, 1), parameter("id", 1, 4))
        val request = request("xaaax", parameters)
        val result = inspectParameterReflection(request, response("aaaa", "aaaaa"), selector.copy(occurrence = 1), 8192)
        assertEquals(HttpReflectionStatus.OK, result.status)
        assertEquals(2, result.headerCount)
        assertEquals(3, result.bodyCount)
        assertEquals(listOf(0, 1), result.headerOffsets)
        assertEquals(listOf(0, 1, 2), result.bodyOffsets)
        parameters.forEach { verify(exactly = 0) { it.value() } }
        assertFalse(json.encodeToString(result).contains("aaa"))
        val encoded = inspectParameterReflection(request("a%20b"), response("", "a b a%20b"), selector, 8192)
        assertEquals(listOf(4), encoded.bodyOffsets)
        assertEquals(1, encoded.bodyCount)
        val split = inspectParameterReflection(request("abc"), response("ab", "c"), selector, 8192)
        assertEquals(0, split.headerCount)
        assertEquals(0, split.bodyCount)
    }

    @Test
    fun `counts all hits but bounds positions and complete JSON without returning partial findings`() = runBlocking {
        val request = request("x")
        val response = response("", "x".repeat(100))
        val complete = inspectParameterReflection(request, response, selector, 8192)
        assertEquals(100, complete.bodyCount)
        assertEquals((0 until 16).toList(), complete.bodyOffsets)
        val bytes = json.encodeToString(complete).toByteArray().size
        assertEquals(complete, inspectParameterReflection(request, response, selector, bytes))
        val failure = inspectParameterReflection(request, response, selector, bytes - 1)
        assertFailure(HttpReflectionStatus.OUTPUT_LIMIT_EXCEEDED, failure)
    }

    @Test
    fun `unavailable selection is distinct from a complete zero-hit observation`() = runBlocking {
        for (parameters in listOf(emptyList(), listOf(parameter("id", 0, 0)), listOf(parameter("id", -1, 1)),
            listOf(parameter("id", 2, 1)), listOf(parameter("id", 0, 10)))) {
            assertFailure(HttpReflectionStatus.PARAMETER_UNAVAILABLE,
                inspectParameterReflection(request("abc", parameters), response("", "abc"), selector, 8192))
        }
        val zero = inspectParameterReflection(request("abc"), response("", "xyz"), selector, 8192)
        assertEquals(HttpReflectionStatus.OK, zero.status)
        assertEquals(0, zero.bodyCount)
    }

    @Test
    fun `input bounds precede native parsing copying and list iteration`() = runBlocking {
        val request = request("abc")
        every { request.body().length() } returns MAX_ACTION_REQUEST_BYTES + 1
        assertFailure(HttpReflectionStatus.INPUT_LIMIT_EXCEEDED,
            inspectParameterReflection(request, response("", "abc"), selector, 8192))
        verify(exactly = 0) { request.parameters(); request.toByteArray() }
        val largeResponse = response("", "")
        every { largeResponse.body().length() } returns MAX_REFLECTION_RESPONSE_BYTES + 1
        val small = request("abc")
        assertFailure(HttpReflectionStatus.INPUT_LIMIT_EXCEEDED, inspectParameterReflection(small, largeResponse, selector, 8192))
        verify(exactly = 0) { small.parameters(); largeResponse.toByteArray() }
        val many = mockk<List<ParsedHttpParameter>>()
        every { many.size } returns 129
        assertFailure(HttpReflectionStatus.INPUT_LIMIT_EXCEEDED,
            inspectParameterReflection(request("abc", many), response("", ""), selector, 8192))
        verify(exactly = 0) { many[any()] }
        assertFailure(HttpReflectionStatus.INPUT_LIMIT_EXCEEDED,
            inspectParameterReflection(request("abc", listOf(parameter("n".repeat(65537), 0, 1))), response("", ""), selector, 8192))
        assertFailure(HttpReflectionStatus.INPUT_LIMIT_EXCEEDED,
            inspectParameterReflection(request("x".repeat(1025)), response("", ""), selector, 8192))
        val inconsistent = request("abc")
        val inconsistentBytes = inconsistent.toByteArray()
        every { inconsistentBytes.length() } returns MAX_ACTION_REQUEST_BYTES + 1
        assertFailsWith<IllegalArgumentException> { inspectParameterReflection(inconsistent, response("", "abc"), selector, 8192) }
        verify(exactly = 0) { inconsistentBytes.getBytes() }
    }

    @Test
    fun `work cap discards prior header matches and cancelled inspections do not return results`() = runBlocking<Unit> {
        val needle = "a".repeat(1023) + "b"
        assertFailure(HttpReflectionStatus.WORK_LIMIT_EXCEEDED,
            inspectParameterReflection(request(needle), response(needle, "a".repeat(20000)), selector, 8192))
        val request = request("abc")
        val requestBytes = request.toByteArray()
        val job = async {
            val context = currentCoroutineContext()
            every { requestBytes.getBytes() } answers { context.cancel(); "abc".toByteArray() }
            inspectParameterReflection(request, response("", "abc"), selector, 8192)
        }
        assertFailsWith<CancellationException> { job.await() }
    }

    @Test
    fun `selectors reject other kinds missing fields invalid names and occurrences`() {
        for (input in listOf(selector.copy(kind = HttpInsertionPointKind.HEADER), selector.copy(name = null),
            selector.copy(name = ""), selector.copy(name = "x\n"), selector.copy(name = "x".repeat(513)),
            selector.copy(parameterType = null), selector.copy(occurrence = -1), selector.copy(occurrence = 32))) {
            assertFailsWith<IllegalArgumentException> { validateReflectionParameter(input) }
        }
    }

    private fun assertFailure(status: HttpReflectionStatus, result: HttpParameterReflection) {
        assertEquals(status, result.status)
        assertNull(result.headerCount)
        assertNull(result.bodyCount)
        assertTrue(result.headerOffsets.isEmpty())
        assertTrue(result.bodyOffsets.isEmpty())
    }

    private fun bytes(raw: ByteArray): MontoyaByteArray = mockk<MontoyaByteArray>().also {
        every { it.length() } returns raw.size
        every { it.getBytes() } returns raw
    }

    private fun request(raw: String, parameters: List<ParsedHttpParameter> = listOf(parameter("id", 0, raw.length))): HttpRequest = mockk<HttpRequest>().also {
        every { it.bodyOffset() } returns 0
        every { it.body() } returns bytes(raw.toByteArray())
        every { it.toByteArray() } returns bytes(raw.toByteArray())
        every { it.parameters() } returns parameters
    }

    private fun response(headers: String, body: String): HttpResponse = mockk<HttpResponse>().also {
        every { it.bodyOffset() } returns headers.length
        every { it.body() } returns bytes(body.toByteArray())
        every { it.toByteArray() } returns bytes((headers + body).toByteArray())
    }

    private fun parameter(name: String, start: Int, end: Int, type: HttpParameterType = HttpParameterType.URL): ParsedHttpParameter = mockk<ParsedHttpParameter>().also {
        val range = mockk<Range>()
        every { range.startIndexInclusive() } returns start
        every { range.endIndexExclusive() } returns end
        every { it.name() } returns name
        every { it.type() } returns type
        every { it.valueOffsets() } returns range
    }
}
