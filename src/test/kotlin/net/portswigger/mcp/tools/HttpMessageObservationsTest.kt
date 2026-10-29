package net.portswigger.mcp.tools

import burp.api.montoya.core.Range
import burp.api.montoya.http.handler.TimingData
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
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
import java.time.Duration
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HttpMessageObservationsTest {
    private val json = Json { encodeDefaults = true }

    @Test
    fun `inventory preserves exact type and name occurrences without values or offsets`() = runBlocking {
        val parameters = listOf(parameter("id"), parameter("id", HttpParameterType.JSON), parameter("id"))
        val request = request(parameters)
        val result = inspectHttpParameters(request, 8192)
        assertEquals(HttpParameterInventoryStatus.OK, result.status)
        assertEquals(listOf(0, 0, 1), result.parameters.map { it.occurrence })
        assertEquals(listOf(HttpActionParameterType.URL, HttpActionParameterType.JSON, HttpActionParameterType.URL),
            result.parameters.map { it.parameterType })
        assertTrue(result.parameters.all { it.unavailableReason == null })
        val serialized = json.encodeToString(result)
        assertFalse(serialized.contains("offset", ignoreCase = true))
        assertFalse(serialized.contains("PRIVATE_VALUE"))
        parameters.forEach { verify(exactly = 0) { it.value(); it.nameOffsets() } }
        verify(exactly = 0) { request.url(); request.headers(); request.toByteArray(); request.httpService() }
    }

    @Test
    fun `inventory distinguishes invalid names occurrences and empty or invalid ranges`() = runBlocking {
        val parameters = listOf(parameter(""), parameter("bad\nname"), parameter("x".repeat(513)),
            parameter("empty", start = 20, end = 20), parameter("bad", start = -1),
            parameter("backward", start = 25, end = 24), parameter("large", end = 1001)) +
            List(33) { parameter("duplicate") }
        val result = inspectHttpParameters(request(parameters), 65536)
        assertEquals(HttpParameterInventoryStatus.OK, result.status)
        assertEquals(List(3) { null }, result.parameters.take(3).map { it.name })
        assertEquals(List(3) { HttpParameterUnavailableReason.INVALID_NAME }, result.parameters.take(3).map { it.unavailableReason })
        assertEquals(HttpParameterUnavailableReason.EMPTY_VALUE, result.parameters[3].unavailableReason)
        assertTrue(result.parameters.subList(4, 7).all { it.unavailableReason == HttpParameterUnavailableReason.INVALID_RANGE })
        assertEquals(32, result.parameters.last().occurrence)
        assertEquals(HttpParameterUnavailableReason.OCCURRENCE_LIMIT, result.parameters.last().unavailableReason)
        val invalidDuplicates = inspectHttpParameters(request(listOf(parameter("\n"), parameter("\t"), parameter("\n"))), 8192)
        assertEquals(listOf(0, 0, 1), invalidDuplicates.parameters.map { it.occurrence })
    }

    @Test
    fun `inventory bounds complete input before parser and list visits`() = runBlocking {
        val empty = request(emptyList(), MAX_ACTION_REQUEST_BYTES)
        assertEquals(HttpParameterInventoryStatus.OK, inspectHttpParameters(empty, 8192).status)
        val tooLarge = request(emptyList(), MAX_ACTION_REQUEST_BYTES + 1)
        assertEquals(HttpParameterInventoryStatus.INPUT_LIMIT_EXCEEDED, inspectHttpParameters(tooLarge, 8192).status)
        verify(exactly = 0) { tooLarge.parameters() }
        val tooMany = mockk<List<ParsedHttpParameter>>()
        every { tooMany.size } returns 129
        val result = inspectHttpParameters(request(tooMany), 8192)
        assertEquals(HttpParameterInventoryStatus.INPUT_LIMIT_EXCEEDED, result.status)
        assertTrue(result.parameters.isEmpty())
        verify(exactly = 0) { tooMany[any()] }
        assertEquals(128, inspectHttpParameters(request(List(128) { parameter("p$it") }), 65536).parameters.size)
        assertEquals(HttpParameterInventoryStatus.INPUT_LIMIT_EXCEEDED,
            inspectHttpParameters(request(listOf(parameter("x".repeat(65537)))), 65536).status)
    }

    @Test
    fun `inventory budgets complete escaped UTF8 JSON including empty lists and never returns a prefix`() = runBlocking {
        for (parameters in listOf(emptyList(), listOf(parameter("한\"\\"), parameter("other")))) {
            val request = request(parameters)
            val complete = inspectHttpParameters(request, 65536)
            val bytes = json.encodeToString(complete).toByteArray(Charsets.UTF_8).size
            assertEquals(complete, inspectHttpParameters(request, bytes))
            val failure = inspectHttpParameters(request, bytes - 1)
            assertEquals(HttpParameterInventoryStatus.OUTPUT_LIMIT_EXCEEDED, failure.status)
            assertTrue(failure.parameters.isEmpty())
        }
    }

    @Test
    fun `native timing is UTC milliseconds with nullable absent invalid overflow or inconsistent durations`() = runBlocking {
        val timing = timing()
        assertEquals(HttpTimingSummary("2026-01-01T00:00:00Z", 12, 34), readHttpTiming { timing })
        every { timing.timeBetweenRequestSentAndStartOfResponse() } returns Duration.ofNanos(999999)
        every { timing.timeBetweenRequestSentAndEndOfResponse() } returns null
        assertEquals(0L, readHttpTiming { timing }?.responseStartMillis)
        assertNull(readHttpTiming { timing }?.responseEndMillis)
        every { timing.timeBetweenRequestSentAndStartOfResponse() } returns Duration.ofMillis(-1)
        every { timing.timeBetweenRequestSentAndEndOfResponse() } returns Duration.ofSeconds(Long.MAX_VALUE)
        assertNull(readHttpTiming { timing }?.responseStartMillis)
        assertNull(readHttpTiming { timing }?.responseEndMillis)
        every { timing.timeBetweenRequestSentAndStartOfResponse() } returns Duration.ofMillis(100)
        every { timing.timeBetweenRequestSentAndEndOfResponse() } returns Duration.ofMillis(99)
        assertNull(readHttpTiming { timing }?.responseEndMillis)
        assertNull(readHttpTiming { null })
        assertNull(readHttpTiming { throw IllegalStateException("PRIVATE_VALUE") })
    }

    @Test
    fun `native timing and inventory preserve cancellation`() = runBlocking {
        assertFailsWith<CancellationException> { readHttpTiming { throw CancellationException("cancel") } }
        val request = request(listOf(parameter("id")))
        val operation = async {
            currentCoroutineContext().cancel()
            inspectHttpParameters(request, 8192)
        }
        assertFailsWith<CancellationException> { operation.await() }
        verify(exactly = 0) { request.parameters() }
        val timing = timing()
        val cancelledTiming = async {
            currentCoroutineContext().cancel()
            readHttpTiming { timing }
        }
        assertFailsWith<CancellationException> { cancelledTiming.await() }
        verify(exactly = 0) { timing.timeRequestSent() }
    }

    private fun parameter(name: String, type: HttpParameterType = HttpParameterType.URL, start: Int = 20, end: Int = 23): ParsedHttpParameter {
        val range = mockk<Range>()
        every { range.startIndexInclusive() } returns start
        every { range.endIndexExclusive() } returns end
        return mockk<ParsedHttpParameter>().also {
            every { it.name() } returns name
            every { it.type() } returns type
            every { it.valueOffsets() } returns range
            every { it.value() } returns "PRIVATE_VALUE"
        }
    }

    private fun request(parameters: List<ParsedHttpParameter>, bytes: Int = 1000): HttpRequest = mockk<HttpRequest>().also {
        every { it.bodyOffset() } returns 100
        every { it.body().length() } returns bytes - 100
        every { it.parameters() } returns parameters
    }

    private fun timing(): TimingData = mockk<TimingData>().also {
        every { it.timeRequestSent() } returns ZonedDateTime.parse("2026-01-01T09:00:00+09:00")
        every { it.timeBetweenRequestSentAndStartOfResponse() } returns Duration.ofMillis(12)
        every { it.timeBetweenRequestSentAndEndOfResponse() } returns Duration.ofMillis(34)
    }
}
