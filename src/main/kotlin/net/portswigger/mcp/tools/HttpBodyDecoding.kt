package net.portswigger.mcp.tools

import burp.api.montoya.http.message.responses.HttpResponse
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.io.ByteArrayOutputStream
import java.util.zip.CRC32
import java.util.zip.DataFormatException
import java.util.zip.Inflater

internal const val MAX_GZIP_INPUT_BYTES = 1024 * 1024
internal const val MAX_GZIP_OUTPUT_BYTES = 1024 * 1024
private const val MAX_GZIP_HEADER_CHARS = 64 * 1024

@Serializable
enum class HttpBodyDecodingStatus {
    @SerialName("ok") OK,
    @SerialName("unsupported_encoding") UNSUPPORTED_ENCODING,
    @SerialName("invalid_data") INVALID_DATA,
    @SerialName("input_limit_exceeded") INPUT_LIMIT_EXCEEDED,
    @SerialName("output_limit_exceeded") OUTPUT_LIMIT_EXCEEDED,
}

internal data class DecodedHttpBody(val status: HttpBodyDecodingStatus, val bytes: ByteArray? = null)

internal suspend fun decodeStoredResponseBody(response: HttpResponse): DecodedHttpBody {
    currentCoroutineContext().ensureActive()
    val headerBytes = response.bodyOffset()
    require(headerBytes >= 0)
    if (headerBytes > MAX_GZIP_HEADER_CHARS) return DecodedHttpBody(HttpBodyDecodingStatus.INPUT_LIMIT_EXCEEDED)
    val headers = response.headers()
    val count = headers.size
    require(count >= 0)
    if (count > 128) return DecodedHttpBody(HttpBodyDecodingStatus.INPUT_LIMIT_EXCEEDED)
    var characters = 0
    var encodings = 0
    var gzip = false
    for (index in 0 until count) {
        currentCoroutineContext().ensureActive()
        val header = headers[index]
        val name = header.name()
        if (name.length > MAX_GZIP_HEADER_CHARS - characters) return DecodedHttpBody(HttpBodyDecodingStatus.INPUT_LIMIT_EXCEEDED)
        characters += name.length
        val value = header.value()
        if (value.length > MAX_GZIP_HEADER_CHARS - characters) return DecodedHttpBody(HttpBodyDecodingStatus.INPUT_LIMIT_EXCEEDED)
        characters += value.length
        if (name.all { it.code < 128 } && name.equals("Content-Encoding", ignoreCase = true)) {
            encodings++
            val token = value.trim(' ', '\t')
            gzip = token.all { it.code < 128 } && token.equals("gzip", ignoreCase = true)
        }
    }
    check(headers.size == count) { "Burp response headers changed during inspection" }
    if (encodings != 1 || !gzip) return DecodedHttpBody(HttpBodyDecodingStatus.UNSUPPORTED_ENCODING)
    currentCoroutineContext().ensureActive()
    val body = response.body()
    val length = body.length()
    require(length >= 0)
    if (length > MAX_GZIP_INPUT_BYTES) return DecodedHttpBody(HttpBodyDecodingStatus.INPUT_LIMIT_EXCEEDED)
    val bytes = body.getBytes()
    require(bytes.size == length) { "Inconsistent stored body length" }
    return decodeSingleGzip(bytes)
}

/** JDK inflation with strict framing: GZIPInputStream otherwise accepts concatenation and ignores trailing junk. */
internal suspend fun decodeSingleGzip(raw: ByteArray): DecodedHttpBody {
    currentCoroutineContext().ensureActive()
    if (raw.size > MAX_GZIP_INPUT_BYTES) return DecodedHttpBody(HttpBodyDecodingStatus.INPUT_LIMIT_EXCEEDED)
    try {
        fun valid(condition: Boolean) { if (!condition) throw InvalidGzip() }
        fun unsigned(index: Int) = raw[index].toInt() and 255
        fun uint32(index: Int): Long = (0..3).fold(0L) { value, n -> value or ((raw[index + n].toLong() and 255) shl (8 * n)) }
        valid(raw.size >= 18)
        valid(unsigned(0) == 0x1f && unsigned(1) == 0x8b && unsigned(2) == 8)
        val flags = unsigned(3)
        valid(flags and 0xe0 == 0)
        var position = 10
        suspend fun next(): Int {
            if (position and 4095 == 0) currentCoroutineContext().ensureActive()
            valid(position < raw.size - 8)
            return unsigned(position++)
        }
        if (flags and 4 != 0) {
            val extra = next() or (next() shl 8)
            valid(extra <= raw.size - 8 - position)
            position += extra
        }
        if (flags and 8 != 0) while (next() != 0) { /* bounded zero-terminated file name */ }
        if (flags and 16 != 0) while (next() != 0) { /* bounded zero-terminated comment */ }
        if (flags and 2 != 0) {
            val headerCrc = CRC32().apply { update(raw, 0, position) }.value and 65535
            val storedCrc = next() or (next() shl 8)
            valid(headerCrc == storedCrc.toLong())
        }
        currentCoroutineContext().ensureActive()
        val inflater = Inflater(true)
        try {
            inflater.setInput(raw, position, raw.size - position)
            val output = ByteArrayOutputStream()
            val crc = CRC32()
            val chunk = ByteArray(8192)
            while (!inflater.finished()) {
                currentCoroutineContext().ensureActive()
                val size = inflater.inflate(chunk, 0, minOf(chunk.size, MAX_GZIP_OUTPUT_BYTES - output.size() + 1))
                if (size > MAX_GZIP_OUTPUT_BYTES - output.size()) {
                    return DecodedHttpBody(HttpBodyDecodingStatus.OUTPUT_LIMIT_EXCEEDED)
                }
                valid(size > 0 || inflater.finished())
                output.write(chunk, 0, size)
                crc.update(chunk, 0, size)
            }
            currentCoroutineContext().ensureActive()
            val trailer = raw.size - inflater.remaining
            valid(raw.size - trailer == 8)
            valid(uint32(trailer) == crc.value && uint32(trailer + 4) == output.size().toLong())
            return DecodedHttpBody(HttpBodyDecodingStatus.OK, output.toByteArray())
        } finally {
            inflater.end()
        }
    } catch (_: InvalidGzip) {
        return DecodedHttpBody(HttpBodyDecodingStatus.INVALID_DATA)
    } catch (_: DataFormatException) {
        return DecodedHttpBody(HttpBodyDecodingStatus.INVALID_DATA)
    }
}

private class InvalidGzip : RuntimeException()
