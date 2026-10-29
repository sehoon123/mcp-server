package net.portswigger.mcp.tools

import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.responses.HttpResponse
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.Random
import java.util.zip.CRC32
import java.util.zip.GZIPOutputStream
import kotlin.test.*

class HttpBodyDecodingTest {
    @Test
    fun `single-member JDK gzip including optional headers and empty streams round trips exactly`() = runBlocking {
        val random = Random(1234)
        for (size in listOf(0, 1, 2, 255, 8192, 65536)) {
            val raw = ByteArray(size).also(random::nextBytes)
            val compressed = gzip(raw)
            for (input in listOf(compressed, optionalHeaders(compressed))) {
                val result = decodeSingleGzip(input)
                assertEquals(HttpBodyDecodingStatus.OK, result.status)
                assertContentEquals(raw, result.bytes)
            }
        }
    }

    @Test
    fun `rejects every truncation corrupt headers checksums trailers multiple members and trailing bytes`() = runBlocking {
        val original = gzip("private payload".toByteArray())
        for (size in 0 until original.size) assertInvalid(original.copyOf(size))
        for (position in listOf(0, 1, 2, original.size - 8, original.size - 4)) {
            assertInvalid(original.copyOf().also { it[position] = (it[position].toInt() xor 1).toByte() })
        }
        assertInvalid(original.copyOf().also { it[3] = 0x20 })
        assertInvalid(original + original)
        assertInvalid(original + byteArrayOf(0))
        val optional = optionalHeaders(original)
        val headerCrcIndex = optional.size - (original.size - 10) - 2
        assertInvalid(optional.copyOf().also { it[headerCrcIndex] = (it[headerCrcIndex].toInt() xor 1).toByte() })
        assertInvalid(optional.copyOf().also { it[10] = 0xff.toByte(); it[11] = 0xff.toByte() })
        val unterminated = original.copyOfRange(0, 10).also { it[3] = 8 } + ByteArray(100) { 1 }
        assertInvalid(unterminated)
        assertInvalid("already decoded".toByteArray())
    }

    @Test
    fun `caps compressed input and inflation before returning any partial body`() = runBlocking {
        assertEquals(HttpBodyDecodingStatus.INPUT_LIMIT_EXCEEDED, decodeSingleGzip(ByteArray(MAX_GZIP_INPUT_BYTES + 1)).status)
        val exact = decodeSingleGzip(gzip(ByteArray(MAX_GZIP_OUTPUT_BYTES)))
        assertEquals(HttpBodyDecodingStatus.OK, exact.status)
        assertEquals(MAX_GZIP_OUTPUT_BYTES, exact.bytes?.size)
        val excessive = decodeSingleGzip(gzip(ByteArray(MAX_GZIP_OUTPUT_BYTES + 1)))
        assertEquals(HttpBodyDecodingStatus.OUTPUT_LIMIT_EXCEEDED, excessive.status)
        assertNull(excessive.bytes)
    }

    @Test
    fun `requires one unambiguous gzip header and never sniffs or falls back to raw`() = runBlocking {
        val compressed = gzip("abc".toByteArray())
        for (values in listOf(emptyList(), listOf("identity"), listOf("br"), listOf("gzip, gzip"),
            listOf("gzip", "gzip"), listOf("gzip", "identity"), listOf("gzip\r\n"),
            listOf("gz\u0131p"), listOf("gz\u0130p"))) {
            val response = response(compressed, values)
            val result = decodeStoredResponseBody(response)
            assertEquals(HttpBodyDecodingStatus.UNSUPPORTED_ENCODING, result.status)
            assertNull(result.bytes)
            verify(exactly = 0) { response.body() }
        }
        assertContentEquals("abc".toByteArray(), decodeStoredResponseBody(response(compressed, listOf(" \tGZip\t "))).bytes)
        val mismatch = decodeStoredResponseBody(response("abc".toByteArray()))
        assertEquals(HttpBodyDecodingStatus.INVALID_DATA, mismatch.status)
        assertNull(mismatch.bytes)
    }

    @Test
    fun `stored input bounds precede copying and inconsistent native lengths are rejected`() = runBlocking<Unit> {
        val response = response(gzip(byteArrayOf(1)))
        every { response.bodyOffset() } returns 65537
        assertEquals(HttpBodyDecodingStatus.INPUT_LIMIT_EXCEEDED, decodeStoredResponseBody(response).status)
        verify(exactly = 0) { response.headers(); response.body() }
        val many = response(byteArrayOf(), List(129) { "gzip" })
        assertEquals(HttpBodyDecodingStatus.INPUT_LIMIT_EXCEEDED, decodeStoredResponseBody(many).status)
        val hugeHeader = response(byteArrayOf(), listOf("x".repeat(65536)))
        assertEquals(HttpBodyDecodingStatus.INPUT_LIMIT_EXCEEDED, decodeStoredResponseBody(hugeHeader).status)
        val large = response(byteArrayOf())
        val body = large.body()
        every { body.length() } returns MAX_GZIP_INPUT_BYTES + 1
        assertEquals(HttpBodyDecodingStatus.INPUT_LIMIT_EXCEEDED, decodeStoredResponseBody(large).status)
        verify(exactly = 0) { body.getBytes() }
        every { body.length() } returns 1
        assertFailsWith<IllegalArgumentException> { decodeStoredResponseBody(large) }
    }

    @Test
    fun `decoded slices use decoded offsets UTF8 replacement and byte-exact base64`() {
        val bytes = "한글abc".toByteArray()
        val first = bytes.toDecodedHistorySlice(0, 3, "text")
        assertEquals("한", first.data)
        assertEquals(3, first.nextOffsetBytes)
        assertEquals(bytes.size, first.totalBytes)
        assertEquals("�", bytes.toDecodedHistorySlice(0, 1, "text").data)
        assertContentEquals(bytes.copyOfRange(1, 5), Base64.getDecoder().decode(bytes.toDecodedHistorySlice(1, 4, "base64").data))
        assertFalse(bytes.toDecodedHistorySlice(bytes.size, 1, "text").hasMore)
        assertFailsWith<HistoryOffsetOutOfRangeException> { bytes.toDecodedHistorySlice(bytes.size + 1, 1, "text") }
    }

    @Test
    fun `native-copy cancellation and pre-cancelled inflation propagate`() = runBlocking<Unit> {
        val response = response(gzip("hello".toByteArray()))
        val body = response.body()
        val operation = async {
            val context = currentCoroutineContext()
            every { body.getBytes() } answers { context.cancel(); gzip("hello".toByteArray()) }
            decodeStoredResponseBody(response)
        }
        assertFailsWith<CancellationException> { operation.await() }
        val cancelled = async {
            currentCoroutineContext().cancel()
            decodeSingleGzip(gzip(byteArrayOf(1)))
        }
        assertFailsWith<CancellationException> { cancelled.await() }
    }

    private suspend fun assertInvalid(bytes: ByteArray) {
        val result = decodeSingleGzip(bytes)
        assertEquals(HttpBodyDecodingStatus.INVALID_DATA, result.status)
        assertNull(result.bytes)
    }

    private fun gzip(bytes: ByteArray): ByteArray = ByteArrayOutputStream().also { out ->
        GZIPOutputStream(out).use { it.write(bytes) }
    }.toByteArray()

    private fun optionalHeaders(gzip: ByteArray): ByteArray {
        val header = ByteArrayOutputStream()
        header.write(gzip.copyOfRange(0, 10).also { it[3] = 31 })
        header.write(byteArrayOf(3, 0, 1, 2, 3))
        header.write("file\u0000comment\u0000".toByteArray())
        val crc = CRC32().apply { update(header.toByteArray()) }.value.toInt()
        header.write(crc and 255)
        header.write((crc ushr 8) and 255)
        return header.toByteArray() + gzip.copyOfRange(10, gzip.size)
    }

    private fun response(raw: ByteArray, encodings: List<String> = listOf("gzip")): HttpResponse = mockk<HttpResponse>().also {
        val bytes = mockk<MontoyaByteArray>()
        every { bytes.length() } returns raw.size
        every { bytes.getBytes() } returns raw
        every { it.bodyOffset() } returns 100
        every { it.body() } returns bytes
        every { it.headers() } returns encodings.map { value -> mockk<HttpHeader>().also { header ->
            every { header.name() } returns "content-encoding"
            every { header.value() } returns value
        } }
    }
}
