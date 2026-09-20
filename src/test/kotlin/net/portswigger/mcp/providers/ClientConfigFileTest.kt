package net.portswigger.mcp.providers

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.io.TempDir
import java.io.InputStream
import java.nio.charset.CharacterCodingException
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.readBytes
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ClientConfigFileTest {
    @Test
    fun `bounded encoding preserves existing pretty JSON and UTF-8 round trips`() {
        val document = buildJsonObject {
            put("mcpServers", buildJsonObject {})
            put("unrelated", "한글 🚀\n\"value\"\\path")
        }
        val previousFormat = Json { prettyPrint = true; encodeDefaults = true }
            .encodeToString(JsonObject.serializer(), document).toByteArray(Charsets.UTF_8)
        val encoded = encodeBoundedClientConfig(document)

        assertContentEquals(previousFormat, encoded)
        assertEquals(document, Json.parseToJsonElement(readBoundedClientConfig(encoded.inputStream())))
    }

    @Test
    fun `output accepts the exact byte budget and rejects an extra byte`() {
        val overhead = encodeBoundedClientConfig(buildJsonObject { put("padding", "") }).size
        val document = buildJsonObject { put("padding", "a".repeat(MAX_PROVIDER_CONFIG_BYTES - overhead)) }
        val encoded = encodeBoundedClientConfig(document)
        assertEquals(MAX_PROVIDER_CONFIG_BYTES, encoded.size)
        assertEquals(document, Json.parseToJsonElement(readBoundedClientConfig(encoded.inputStream())))

        val oversized = buildJsonObject { put("padding", "a".repeat(MAX_PROVIDER_CONFIG_BYTES - overhead + 1)) }
        assertThrows<IllegalArgumentException> { encodeBoundedClientConfig(oversized) }
    }

    @Test
    fun `output bound counts UTF-8 bytes and JSON escaping rather than source characters`() {
        listOf("é".repeat(MAX_PROVIDER_CONFIG_BYTES / 2), "\u0000".repeat(MAX_PROVIDER_CONFIG_BYTES / 4))
            .forEach { value ->
                val error = assertThrows<IllegalArgumentException> {
                    encodeBoundedClientConfig(buildJsonObject { put("padding", value) })
                }
                assertEquals(
                    "Updated client configuration exceeds the $MAX_PROVIDER_CONFIG_BYTES-byte safety limit",
                    error.message,
                )
            }
    }

    @Test
    fun `pretty print growth cannot produce a file beyond the next read budget`() {
        val zero = JsonPrimitive(0)
        val document = buildJsonObject {
            put("values", JsonArray(List(MAX_PROVIDER_CONFIG_BYTES / 10 + 1) { zero }))
        }
        val compact = Json.encodeToString(JsonObject.serializer(), document)
        assertTrue(compact.toByteArray(Charsets.UTF_8).size < MAX_PROVIDER_CONFIG_BYTES)
        assertThrows<IllegalArgumentException> { encodeBoundedClientConfig(document) }
    }

    @Test
    fun `regular client config is read without modifying it`(@TempDir directory: Path) {
        val path = directory.resolve("client.json")
        val content = """{"mcpServers":{},"label":"한글 🚀"}"""
        path.writeText(content)

        assertEquals(content, readBoundedClientConfig(path))
        assertContentEquals(content.toByteArray(Charsets.UTF_8), path.readBytes())
    }

    @Test
    fun `read accepts empty and exactly bounded UTF-8 files`(@TempDir directory: Path) {
        val path = directory.resolve("client.json")
        path.writeText("")
        assertEquals("", readBoundedClientConfig(path))

        val content = "é".repeat(MAX_PROVIDER_CONFIG_BYTES / 2)
        path.writeText(content)
        assertEquals(MAX_PROVIDER_CONFIG_BYTES.toLong(), Files.size(path))
        assertEquals(content, readBoundedClientConfig(path))
    }

    @Test
    fun `oversized config is rejected and preserved`(@TempDir directory: Path) {
        val path = directory.resolve("client.json")
        val bytes = ByteArray(MAX_PROVIDER_CONFIG_BYTES + 1) { 'a'.code.toByte() }
        path.writeBytes(bytes)

        assertThrows<IllegalArgumentException> { readBoundedClientConfig(path) }
        assertContentEquals(bytes, path.readBytes())
        Files.list(directory).use { assertEquals(1L, it.count()) }
    }

    @Test
    fun `growing content consumes no more than the budget and one sentinel byte`() {
        // A size observation cannot constrain a later read. This never-ending source models growth after the check.
        var consumed = 0
        val input = object : InputStream() {
            override fun read(): Int {
                consumed++
                return 'a'.code
            }

            override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                bytes.fill('a'.code.toByte(), offset, offset + length)
                consumed += length
                return length
            }
        }

        val error = assertThrows<IllegalArgumentException> { readBoundedClientConfig(input) }
        assertEquals(MAX_PROVIDER_CONFIG_BYTES + 1, consumed)
        assertEquals("Client configuration exceeds the $MAX_PROVIDER_CONFIG_BYTES-byte safety limit", error.message)
    }

    @Test
    fun `malformed UTF-8 is not silently repaired`(@TempDir directory: Path) {
        val path = directory.resolve("client.json")
        val bytes = byteArrayOf('{'.code.toByte(), 0xc3.toByte(), '}'.code.toByte())
        path.writeBytes(bytes)

        assertThrows<CharacterCodingException> { readBoundedClientConfig(path) }
        assertContentEquals(bytes, path.readBytes())
    }

    @Test
    fun `nonregular client config is rejected`(@TempDir directory: Path) {
        val error = assertThrows<IllegalArgumentException> { readBoundedClientConfig(directory) }
        assertEquals("Client configuration must be a regular file", error.message)
    }

    @Test
    fun `symlinked config and parent are rejected`(@TempDir directory: Path) {
        val real = Files.createDirectory(directory.resolve("real"))
        val path = real.resolve("client.json").also { it.writeText("{}") }
        val link = directory.resolve("client.json")
        val linkedParent = directory.resolve("linked")
        assumeTrue(runCatching {
            Files.createSymbolicLink(link, path)
            Files.createSymbolicLink(linkedParent, real)
        }.isSuccess, "Symbolic links are unavailable on this filesystem")

        listOf(link, linkedParent.resolve("client.json")).forEach { candidate ->
            val error = assertThrows<IllegalArgumentException> { readBoundedClientConfig(candidate) }
            assertTrue(error.message.orEmpty().contains("symbolic link"))
        }
        assertEquals("{}", readBoundedClientConfig(path))
    }
}
