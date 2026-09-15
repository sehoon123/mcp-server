package net.portswigger.mcp.tools

import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*
import net.portswigger.mcp.schema.JsonSchemaMetadata
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

internal const val MAX_JSON_COMPARISON_BYTES = 65_536
private const val MAX_JSON_DEPTH = 32
private const val MAX_JSON_NODE_VISITS = 10_000
private const val MAX_JSON_DIFFERENCES = 32
private const val MAX_JSON_POINTER_CHARS = 512
private val JSON_NUMBER = Regex("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")

@Serializable
enum class HttpJsonComparisonStatus {
    @SerialName("ok") OK,
    @SerialName("input_truncated") INPUT_TRUNCATED,
    @SerialName("invalid_json") INVALID_JSON,
    @SerialName("duplicate_key") DUPLICATE_KEY,
    @SerialName("limit_exceeded") LIMIT_EXCEEDED,
}

@Serializable
enum class HttpJsonDifferenceKind {
    @SerialName("added") ADDED,
    @SerialName("removed") REMOVED,
    @SerialName("changed") CHANGED,
}

@Serializable
data class HttpJsonDifference(
    @JsonSchemaMetadata(description = "Zero-based comparison reference index; baseline is always refs[0].", minimum = 1, maximum = 7)
    val refIndex: Int,
    @JsonSchemaMetadata(description = "RFC 6901 pointer; empty string means root. Contains member names, never scalar values.", maxLength = MAX_JSON_POINTER_CHARS)
    val path: String,
    val kind: HttpJsonDifferenceKind,
)

@Serializable
data class HttpJsonComparison(
    val status: HttpJsonComparisonStatus,
    @JsonSchemaMetadata(description = "JSON structural equality, or null when input cannot be fully compared. Numeric literals compare lexically; arrays remain ordered.")
    val equal: Boolean?,
    @JsonSchemaMetadata(maxItems = MAX_JSON_DIFFERENCES)
    val differences: List<HttpJsonDifference>,
    @JsonSchemaMetadata(description = "Some differences were omitted by the 32-entry or 512-character pointer cap; equality remains authoritative when status is ok.")
    val differencesTruncated: Boolean,
    @JsonSchemaMetadata(description = "Input reference that could not be parsed or fully inspected, when known.", minimum = 0, maximum = 7)
    val errorRefIndex: Int? = null,
)

private class JsonComparisonFailure(val status: HttpJsonComparisonStatus) : RuntimeException()

internal sealed interface StrictJsonParseResult {
    data class Parsed(val root: JsonElement) : StrictJsonParseResult
    data class Failed(val status: HttpJsonComparisonStatus) : StrictJsonParseResult
}

/** Strictly parses one complete bounded UTF-8 JSON document without exposing parser exception details. */
internal suspend fun parseStrictJsonBody(
    bytes: ByteArray,
    visit: suspend () -> Unit,
): StrictJsonParseResult {
    currentCoroutineContext().ensureActive()
    if (bytes.size > MAX_JSON_COMPARISON_BYTES) {
        return StrictJsonParseResult.Failed(HttpJsonComparisonStatus.INPUT_TRUNCATED)
    }
    return try {
        val text = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString()
        guardJsonStructure(text)
        val root = Json.parseToJsonElement(text)
        val unicodeEncoder = Charsets.UTF_8.newEncoder()
        val pending = ArrayDeque<JsonElement>().apply { add(root) }
        while (pending.isNotEmpty()) {
            visit()
            when (val node = pending.removeLast()) {
                is JsonObject -> pending.addAll(node.values)
                is JsonArray -> pending.addAll(node)
                is JsonPrimitive -> {
                    val valid = if (node.isString) unicodeEncoder.canEncode(node.content) else
                        node is JsonNull || node.content in listOf("true", "false") || JSON_NUMBER.matches(node.content)
                    if (!valid) throw JsonComparisonFailure(HttpJsonComparisonStatus.INVALID_JSON)
                }
            }
        }
        StrictJsonParseResult.Parsed(root)
    } catch (error: JsonComparisonFailure) {
        StrictJsonParseResult.Failed(error.status)
    } catch (_: CharacterCodingException) {
        StrictJsonParseResult.Failed(HttpJsonComparisonStatus.INVALID_JSON)
    } catch (_: SerializationException) {
        StrictJsonParseResult.Failed(HttpJsonComparisonStatus.INVALID_JSON)
    }
}

/** Input is a bounded, already-approved body snapshot. No Montoya objects or raw values escape this comparison. */
internal suspend fun compareJsonBodies(bodies: List<ByteArray>, truncated: List<Boolean>): HttpJsonComparison {
    val context = currentCoroutineContext()
    context.ensureActive()
    require(bodies.size in 2..8 && truncated.size == bodies.size)
    val incomplete = bodies.indices.firstOrNull { truncated[it] || bodies[it].size > MAX_JSON_COMPARISON_BYTES }
    if (incomplete != null) {
        return HttpJsonComparison(HttpJsonComparisonStatus.INPUT_TRUNCATED, null, emptyList(), false, incomplete)
    }
    var visits = 0
    suspend fun visit() {
        context.ensureActive()
        if (++visits > MAX_JSON_NODE_VISITS) throw JsonComparisonFailure(HttpJsonComparisonStatus.LIMIT_EXCEEDED)
    }
    val documents = ArrayList<JsonElement>(bodies.size)
    for ((index, bytes) in bodies.withIndex()) {
        when (val parsed = parseStrictJsonBody(bytes, ::visit)) {
            is StrictJsonParseResult.Parsed -> documents += parsed.root
            is StrictJsonParseResult.Failed -> return HttpJsonComparison(
                parsed.status,
                null,
                emptyList(),
                false,
                index,
            )
        }
    }
    val differences = ArrayList<HttpJsonDifference>()
    var equal = true
    var omitted = false
    suspend fun compare(left: JsonElement?, right: JsonElement?, path: String?, refIndex: Int) {
        visit()
        when {
            left is JsonObject && right is JsonObject -> (left.keys + right.keys).toSortedSet().forEach { key ->
                compare(left[key], right[key], childPointer(path, key), refIndex)
            }
            left is JsonArray && right is JsonArray -> for (index in 0 until maxOf(left.size, right.size)) {
                compare(left.getOrNull(index), right.getOrNull(index), childPointer(path, index.toString()), refIndex)
            }
            left != right -> {
                equal = false
                if (path == null || differences.size == MAX_JSON_DIFFERENCES) {
                    omitted = true
                } else {
                    val kind = when {
                        left == null -> HttpJsonDifferenceKind.ADDED
                        right == null -> HttpJsonDifferenceKind.REMOVED
                        else -> HttpJsonDifferenceKind.CHANGED
                    }
                    differences += HttpJsonDifference(refIndex, path, kind)
                }
            }
        }
    }
    return try {
        for (index in 1 until documents.size) compare(documents[0], documents[index], "", index)
        context.ensureActive()
        HttpJsonComparison(HttpJsonComparisonStatus.OK, equal, differences, omitted)
    } catch (error: JsonComparisonFailure) {
        HttpJsonComparison(error.status, null, emptyList(), false)
    }
}

/** Only resource limits and duplicate keys are handled here; the installed JSON parser owns JSON grammar. */
private suspend fun guardJsonStructure(text: String) {
    val context = currentCoroutineContext()
    val containers = ArrayList<MutableSet<String>?>()
    val unicodeEncoder = Charsets.UTF_8.newEncoder()
    var structuralTokens = 1 // Conservative node-allocation bound before constructing the parsed tree.
    var index = 0
    while (index < text.length) {
        context.ensureActive()
        when (text[index]) {
            '{', '[' -> {
                if (containers.size == MAX_JSON_DEPTH) throw JsonComparisonFailure(HttpJsonComparisonStatus.LIMIT_EXCEEDED)
                containers += if (text[index] == '{') HashSet<String>() else null
                structuralTokens++
            }
            '}', ']' -> if (containers.isNotEmpty()) containers.removeAt(containers.lastIndex)
            ':', ',' -> structuralTokens++
            '"' -> {
                val start = index++
                while (index < text.length && text[index] != '"') {
                    if (text[index] < ' ') throw JsonComparisonFailure(HttpJsonComparisonStatus.INVALID_JSON)
                    if (text[index] == '\\') index++
                    index++
                }
                if (index >= text.length) throw JsonComparisonFailure(HttpJsonComparisonStatus.INVALID_JSON)
                var following = index + 1
                while (following < text.length && text[following] in " \t\r\n") following++
                if (following < text.length && text[following] == ':') {
                    val keys = containers.lastOrNull()
                    val key = Json.decodeFromString<String>(text.substring(start, index + 1))
                    // Unpaired surrogate escapes cannot round-trip as UTF-8 JSON pointers.
                    if (!unicodeEncoder.canEncode(key)) throw JsonComparisonFailure(HttpJsonComparisonStatus.INVALID_JSON)
                    if (keys != null && !keys.add(key)) throw JsonComparisonFailure(HttpJsonComparisonStatus.DUPLICATE_KEY)
                }
            }
        }
        if (structuralTokens > MAX_JSON_NODE_VISITS) throw JsonComparisonFailure(HttpJsonComparisonStatus.LIMIT_EXCEEDED)
        index++
    }
}

private fun childPointer(parent: String?, token: String): String? {
    if (parent == null || token.length > MAX_JSON_POINTER_CHARS) return null
    val escaped = token.replace("~", "~0").replace("/", "~1")
    return if (parent.length + escaped.length + 1 <= MAX_JSON_POINTER_CHARS) "$parent/$escaped" else null
}
