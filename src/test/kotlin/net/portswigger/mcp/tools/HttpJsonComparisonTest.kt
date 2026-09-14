package net.portswigger.mcp.tools

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Test
import kotlin.test.*

class HttpJsonComparisonTest {
    @Test
    fun `object order whitespace and escaped strings do not change JSON equality`() = runBlocking {
        val result = compare("""{"a":1,"b":[true,null,"\u0061"]}""", """{ "b": [true, null, "a"], "a": 1 }""")
        assertEquals(HttpJsonComparisonStatus.OK, result.status)
        assertEquals(true, result.equal)
        assertTrue(result.differences.isEmpty())
        assertFalse(result.differencesTruncated)
        assertEquals(true, compare("""{"\uD83D\uDE00":"\uD83D\uDE00"}""", """{"😀":"😀"}""").equal)
    }

    @Test
    fun `differences identify ordered array positions added removed and changed keys without scalar values`() = runBlocking {
        val result = compare(
            """{"a/b~c":"PRIVATE_LEFT","array":[1,2],"removed":true}""",
            """{"a/b~c":"PRIVATE_RIGHT","array":[2,1],"added":null}""",
            """{"a/b~c":"PRIVATE_LEFT","array":[1,2],"removed":false}""",
        )
        assertEquals(false, result.equal)
        assertEquals(
            listOf(
                HttpJsonDifference(1, "/a~1b~0c", HttpJsonDifferenceKind.CHANGED),
                HttpJsonDifference(1, "/added", HttpJsonDifferenceKind.ADDED),
                HttpJsonDifference(1, "/array/0", HttpJsonDifferenceKind.CHANGED),
                HttpJsonDifference(1, "/array/1", HttpJsonDifferenceKind.CHANGED),
                HttpJsonDifference(1, "/removed", HttpJsonDifferenceKind.REMOVED),
                HttpJsonDifference(2, "/removed", HttpJsonDifferenceKind.CHANGED),
            ),
            result.differences,
        )
        assertFalse(Json.encodeToString(result).contains("PRIVATE_"))
        assertEquals("", compare("null", "0").differences.single().path)
        assertEquals(false, compare("1", "1.0").equal)
        assertEquals(false, compare("-0", "0").equal)
        assertEquals(false, compare("1", "\"1\"").equal)
    }

    @Test
    fun `duplicate escaped object keys fail closed but repeated keys in distinct objects are valid`() = runBlocking {
        val result = compare("{}", """{"a":1,"\u0061":2}""")
        assertEquals(HttpJsonComparisonStatus.DUPLICATE_KEY, result.status)
        assertNull(result.equal)
        assertEquals(1, result.errorRefIndex)
        assertTrue(result.differences.isEmpty())
        val valid = """{"a":{"x":1},"b":{"x":2},"text":"[{}[]\""}"""
        assertEquals(true, compare(valid, valid).equal)
    }

    @Test
    fun `malformed JSON and UTF8 never produce equality or source-bearing parse errors`() = runBlocking {
        listOf(
            "NaN", "Infinity", "01", "+1", "TRUE", "[1,]", """{"a":1,}""",
            """{"a": unquoted}""", "{} trailing", "[truefalse]", "\"bare\nnewline\"",
            """{"a":"bad\q"}""", """{"PRIVATE_PARSE_VALUE":"unterminated}""",
            """{"\ud800":1}""", """{"x":"\udfff"}""", "\"\\ud800\"",
        ).forEach { invalid ->
            val result = compare(invalid, invalid)
            assertEquals(HttpJsonComparisonStatus.INVALID_JSON, result.status, invalid)
            assertNull(result.equal)
            assertTrue(result.differences.isEmpty())
            assertFalse(Json.encodeToString(result).contains("PRIVATE_PARSE_VALUE"))
        }
        val result = compareJsonBodies(listOf(byteArrayOf(0xc3.toByte(), 0x28), "{}".toByteArray()), listOf(false, false))
        assertEquals(HttpJsonComparisonStatus.INVALID_JSON, result.status)
        assertNull(result.equal)
    }

    @Test
    fun `byte depth node and output caps never turn partial comparison into equal`() = runBlocking {
        val fullAtLimit = "{}" + " ".repeat(MAX_JSON_COMPARISON_BYTES - 2)
        assertEquals(true, compare(fullAtLimit, fullAtLimit).equal)
        assertEquals(HttpJsonComparisonStatus.INPUT_TRUNCATED, compare(fullAtLimit + " ", "{}").status)
        val truncated = compareJsonBodies(listOf("{}".toByteArray(), "{}".toByteArray()), listOf(false, true))
        assertNull(truncated.equal)
        assertEquals(1, truncated.errorRefIndex)
        val depth32 = "[".repeat(32) + "0" + "]".repeat(32)
        assertEquals(true, compare(depth32, depth32).equal)
        assertEquals(HttpJsonComparisonStatus.LIMIT_EXCEEDED, compare("[$depth32]", "[]").status)
        val many = List(3_500) { "0" }.joinToString(",", "[", "]")
        assertEquals(HttpJsonComparisonStatus.LIMIT_EXCEEDED, compare(many, many).status)
        val changed = (0 until 40).joinToString(",", "{", "}") { "\"field_$it\":true" }
        val bounded = compare("{}", changed)
        assertEquals(false, bounded.equal)
        assertEquals(32, bounded.differences.size)
        assertTrue(bounded.differencesTruncated)
        val longPath = compare("""{"${"x".repeat(513)}":1}""", """{"${"x".repeat(513)}":2}""")
        assertEquals(false, longPath.equal)
        assertTrue(longPath.differences.isEmpty())
        assertTrue(longPath.differencesTruncated)
    }

    @Test
    fun `cancellation propagates even for an incomplete input`() = runBlocking {
        var propagated = false
        val child = launch {
            cancel()
            try {
                compareJsonBodies(listOf(byteArrayOf(), byteArrayOf()), listOf(true, true))
            } catch (error: CancellationException) {
                propagated = true
                throw error
            }
        }
        child.join()
        assertTrue(propagated)
    }

    private suspend fun compare(vararg bodies: String): HttpJsonComparison =
        compareJsonBodies(bodies.map { it.toByteArray() }, List(bodies.size) { false })
}
