package net.portswigger.mcp.tools

import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.util.HexFormat
import kotlin.math.min
import kotlin.test.assertEquals

/**
 * Frozen compatibility vectors for project-scoped Site Map IDs and cursor boundary anchors.
 *
 * The literal hashes were generated before this test with an independent Python implementation. The local preimage
 * writer documents and cross-checks the framing without calling production helpers. An intentional framing change must
 * introduce a new public ID prefix rather than silently updating these literals.
 */
class SiteMapIdentityGoldenVectorTest {
    @Test
    fun `request-only non-ASCII identity matches the golden vectors`() {
        val vector = SiteMapVector(
            projectId = "project-π",
            index = 0,
            request = RequestVector(
                method = "GET",
                url = "https://例.test/경로",
                httpVersion = "HTTP/1.1",
                headers = emptyList(),
                body = byteArrayOf(),
            ),
            response = null,
        )
        val item = vector.toMontoyaItem()

        assertEquals("585f84f57e6837a65575ce6b180e967e", independentBoundaryAnchor(vector))
        assertEquals("sitemap_0_a217e3cef290e0ecf90465456e5b4b96", independentStableId(vector))
        assertEquals("585f84f57e6837a65575ce6b180e967e", siteMapBoundaryAnchor(item))
        val stableId = stableSiteMapId(vector.projectId, vector.index, item)
        assertEquals("sitemap_0_a217e3cef290e0ecf90465456e5b4b96", stableId)
        assertEquals(vector.index, parseSiteMapId(stableId)?.index)
    }

    @Test
    fun `response headers and bounded body samples match the golden vectors`() {
        val vector = SiteMapVector(
            projectId = "project-vector",
            index = 35,
            request = RequestVector(
                method = "POST",
                url = "https://example.test/upload",
                httpVersion = "HTTP/2",
                headers = List(130) { index ->
                    val suffix = index.toString().padStart(3, '0')
                    HeaderVector("X-Test-$suffix", "value-$suffix")
                },
                body = ByteArray(300) { index -> (index * 37 + 11).toByte() },
            ),
            response = ResponseVector(
                statusCode = 207,
                httpVersion = "HTTP/1.1",
                headers = listOf(
                    HeaderVector("Content-Type", "application/json"),
                    HeaderVector("X-Trace", "trace-vector"),
                ),
                body = ByteArray(129) { index -> (index * 19 + 3).toByte() },
            ),
        )
        val item = vector.toMontoyaItem()

        assertEquals("755dccf395aece96ffb26a80692c3d52", independentBoundaryAnchor(vector))
        assertEquals("sitemap_35_6b49386939041b4da8cf757a0d9be546", independentStableId(vector))
        assertEquals("755dccf395aece96ffb26a80692c3d52", siteMapBoundaryAnchor(item))
        val stableId = stableSiteMapId(vector.projectId, vector.index, item)
        assertEquals("sitemap_35_6b49386939041b4da8cf757a0d9be546", stableId)
        assertEquals(vector.index, parseSiteMapId(stableId)?.index)
    }

    @Test
    fun `long URL bounding matches the golden vectors`() {
        val vector = SiteMapVector(
            projectId = "project-long",
            index = 36,
            request = RequestVector(
                method = "GET",
                url = "https://example.test/" + "a".repeat(2_500) + "/tail",
                httpVersion = "HTTP/1.1",
                headers = emptyList(),
                body = byteArrayOf(),
            ),
            response = null,
        )
        val item = vector.toMontoyaItem()

        assertEquals("8b02031257b5ff4e27cf840b8ecfdf70", independentBoundaryAnchor(vector))
        assertEquals("sitemap_36_04a7c8ebe9108bb35ce9724d7cba9d84", independentStableId(vector))
        assertEquals("8b02031257b5ff4e27cf840b8ecfdf70", siteMapBoundaryAnchor(item))
        val stableId = stableSiteMapId(vector.projectId, vector.index, item)
        assertEquals("sitemap_36_04a7c8ebe9108bb35ce9724d7cba9d84", stableId)
        assertEquals(vector.index, parseSiteMapId(stableId)?.index)
    }

    private fun independentStableId(vector: SiteMapVector): String {
        val digest = independentDigest {
            writeBounded(vector.projectId)
            writeInt(vector.index)
            writeIdentity(vector)
        }
        return "sitemap_${vector.index}_$digest"
    }

    private fun independentBoundaryAnchor(vector: SiteMapVector): String = independentDigest {
        writeIdentity(vector)
    }

    private fun independentDigest(writePreimage: DataOutputStream.() -> Unit): String {
        val preimage = ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output -> output.writePreimage() }
            bytes.toByteArray()
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(preimage)
        return HexFormat.of().formatHex(digest, 0, 16)
    }

    private fun DataOutputStream.writeIdentity(vector: SiteMapVector) {
        writeBounded(vector.request.method)
        writeBounded(vector.request.url)
        writeBounded(vector.request.httpVersion)
        writeHeaders(vector.request.headers)
        writeSample(vector.request.body)
        val response = vector.response
        if (response == null) {
            writeByte(0)
        } else {
            writeByte(1)
            writeInt(response.statusCode)
            writeBounded(response.httpVersion)
            writeHeaders(response.headers)
            writeSample(response.body)
        }
    }

    private fun DataOutputStream.writeBounded(value: String) {
        writeInt(value.length)
        if (value.length <= 2_048) {
            write(value.toByteArray(Charsets.UTF_8))
        } else {
            // Production encodes these slices separately, which matters if a cut splits a surrogate pair.
            write(value.take(1_024).toByteArray(Charsets.UTF_8))
            write(value.takeLast(1_024).toByteArray(Charsets.UTF_8))
        }
    }

    private fun DataOutputStream.writeHeaders(headers: List<HeaderVector>) {
        writeInt(headers.size)
        headers.take(128).forEach { header ->
            writeBounded(header.name)
            writeBounded(header.value)
        }
    }

    private fun DataOutputStream.writeSample(body: ByteArray) {
        writeInt(body.size)
        if (body.isEmpty()) return
        val ranges = buildList {
            add(0 until min(body.size, 128))
            if (body.size > 256) {
                val middleStart = (body.size / 2 - 64).coerceAtLeast(0)
                add(middleStart until min(body.size, middleStart + 128))
            }
            if (body.size > 128) add((body.size - 128).coerceAtLeast(0) until body.size)
        }
        ranges.distinct().forEach { range ->
            range.forEach { index -> writeByte(body[index].toInt()) }
        }
    }

    private fun SiteMapVector.toMontoyaItem(): HttpRequestResponse {
        val requestMock = mockk<HttpRequest>()
        every { requestMock.method() } returns request.method
        every { requestMock.url() } returns request.url
        every { requestMock.httpVersion() } returns request.httpVersion
        every { requestMock.headers() } returns request.headers.map { it.toMontoyaHeader() }
        every { requestMock.body() } returns request.body.toMontoyaByteArray()
        val responseMock = response?.let { response ->
            mockk<HttpResponse>().also { mock ->
                every { mock.statusCode() } returns response.statusCode.toShort()
                every { mock.httpVersion() } returns response.httpVersion
                every { mock.headers() } returns response.headers.map { it.toMontoyaHeader() }
                every { mock.body() } returns response.body.toMontoyaByteArray()
            }
        }
        return mockk<HttpRequestResponse>().also { item ->
            every { item.request() } returns requestMock
            every { item.response() } returns responseMock
        }
    }

    private fun HeaderVector.toMontoyaHeader(): HttpHeader = mockk<HttpHeader>().also { header ->
        every { header.name() } returns name
        every { header.value() } returns value
    }

    private fun ByteArray.toMontoyaByteArray(): MontoyaByteArray = mockk<MontoyaByteArray>().also { bytes ->
        every { bytes.length() } returns size
        every { bytes.getByte(any()) } answers { this@toMontoyaByteArray[firstArg()] }
    }

    private data class SiteMapVector(
        val projectId: String,
        val index: Int,
        val request: RequestVector,
        val response: ResponseVector?,
    )

    private data class RequestVector(
        val method: String,
        val url: String,
        val httpVersion: String,
        val headers: List<HeaderVector>,
        val body: ByteArray,
    )

    private data class ResponseVector(
        val statusCode: Int,
        val httpVersion: String,
        val headers: List<HeaderVector>,
        val body: ByteArray,
    )

    private data class HeaderVector(val name: String, val value: String)
}
