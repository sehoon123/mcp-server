package net.portswigger.mcp.schema

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.serializer
import net.portswigger.mcp.tools.CheckScope
import net.portswigger.mcp.tools.UpdateScope
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Verifies that [JsonSchemaExactlyOneOf] produces a real, enforceable `oneOf` constraint for
 * nested object schemas, and that the tools which rely on it (`check_scope`/`update_scope`
 * targets) actually emit it. This exists so that "exactly one of A or B" is caught by schema
 * validation on the client/server transport, not only by the tool's own runtime `require()`.
 */
@OptIn(ExperimentalSerializationApi::class)
class JsonSchemaTest {

    @JsonSchemaExactlyOneOf("a", "b")
    @Serializable
    private data class ExactlyOnePair(val a: String? = null, val b: String? = null)

    @Serializable
    private data class NoAnnotationPair(val a: String? = null, val b: String? = null)

    @Serializable
    private data class ListContainer(val items: List<ExactlyOnePair>)

    @Serializable
    private data class ObjectContainer(val target: ExactlyOnePair)

    @Serializable
    private data class NullableObjectContainer(val target: ExactlyOnePair? = null)

    @Serializable
    private data class NoAnnotationListContainer(val items: List<NoAnnotationPair>)

    @Serializable
    private enum class OptionalMode { ONE, TWO }

    @Serializable
    private data class NullableEnumContainer(val mode: OptionalMode? = null)

    @Serializable
    private data class MetadataEnumContainer(
        @JsonSchemaMetadata(enumValues = ["one", "two"])
        val mode: String? = null,
    )

    @Test
    fun `oneOf is emitted for a list item type carrying the annotation`() {
        val schema = serializer<ListContainer>().descriptor.asInputSchema()
        val itemSchema = schema.properties!!["items"]!!.jsonObject["items"]!!.jsonObject
        val oneOf = itemSchema["oneOf"]!!.jsonArray

        assertEquals(2, oneOf.size)
        assertEquals(listOf("a"), oneOf[0].jsonObject["required"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals(listOf("b"), oneOf[1].jsonObject["required"]!!.jsonArray.map { it.jsonPrimitive.content })
        oneOf.forEach { alternative ->
            val selected = alternative.jsonObject["required"]!!.jsonArray.single().jsonPrimitive.content
            assertEquals(
                "null",
                alternative.jsonObject["properties"]!!.jsonObject[selected]!!.jsonObject["not"]!!
                    .jsonObject["type"]!!.jsonPrimitive.content,
            )
        }
    }

    @Test
    fun `oneOf selection counts non-null values like Kotlin runtime validation`() {
        val schema = serializer<ObjectContainer>().descriptor.asInputSchema()
            .properties!!["target"]!!.jsonObject
        val cases = mapOf(
            "{}" to false,
            "{\"a\":\"value\"}" to true,
            "{\"b\":\"value\"}" to true,
            "{\"a\":null}" to false,
            "{\"b\":null}" to false,
            "{\"a\":null,\"b\":\"value\"}" to true,
            "{\"a\":\"value\",\"b\":null}" to true,
            "{\"a\":\"value\",\"b\":\"value\"}" to false,
            "{\"a\":null,\"b\":null}" to false,
        )

        cases.forEach { (payload, expected) ->
            val value = Json.parseToJsonElement(payload).jsonObject
            assertEquals(expected, schema.matchesGeneratedOneOf(value), payload)
            val decoded = Json.decodeFromString<ExactlyOnePair>(payload)
            assertEquals(expected, (decoded.a == null) != (decoded.b == null), payload)
        }
    }

    @Test
    fun `nullable exactly-one object wraps the constrained object and null as alternatives`() {
        val schema = serializer<NullableObjectContainer>().descriptor.asInputSchema()
            .properties!!["target"]!!.jsonObject
        val alternatives = schema["anyOf"]!!.jsonArray

        assertEquals(2, alternatives.size)
        assertTrue(alternatives[0].jsonObject.containsKey("oneOf"))
        assertEquals("object", alternatives[0].jsonObject["type"]!!.jsonPrimitive.content)
        assertEquals("null", alternatives[1].jsonObject["type"]!!.jsonPrimitive.content)
        assertEquals(null, Json.decodeFromString<NullableObjectContainer>("{\"target\":null}").target)
    }

    @Test
    fun `nullable enum schemas include null in type and enum constraints`() {
        val enumSchema = serializer<NullableEnumContainer>().descriptor.asInputSchema()
            .properties!!["mode"]!!.jsonObject
        val metadataSchema = serializer<MetadataEnumContainer>().descriptor.asInputSchema()
            .properties!!["mode"]!!.jsonObject

        assertTrue(JsonNull in enumSchema["enum"]!!.jsonArray)
        assertTrue(JsonNull in metadataSchema["enum"]!!.jsonArray)
        assertTrue(enumSchema["type"]!!.jsonArray.any { it.jsonPrimitive.content == "null" })
        assertTrue(metadataSchema["type"]!!.jsonArray.any { it.jsonPrimitive.content == "null" })
        assertEquals(null, Json.decodeFromString<NullableEnumContainer>("{\"mode\":null}").mode)
        assertEquals(null, Json.decodeFromString<MetadataEnumContainer>("{\"mode\":null}").mode)
    }

    @Test
    fun `oneOf is emitted for a nested object property type carrying the annotation`() {
        val schema = serializer<ObjectContainer>().descriptor.asInputSchema()
        val targetSchema = schema.properties!!["target"]!!.jsonObject

        assertTrue(targetSchema.containsKey("oneOf"), "expected a oneOf constraint on the nested target schema")
    }

    @Test
    fun `oneOf is absent without the annotation`() {
        val schema = serializer<NoAnnotationListContainer>().descriptor.asInputSchema()
        val itemSchema = schema.properties!!["items"]!!.jsonObject["items"]!!.jsonObject

        assertFalse(itemSchema.containsKey("oneOf"))
    }

    @Test
    fun `check_scope and update_scope targets enforce exactly one of url or ref in schema`() {
        val checkScopeItemSchema = serializer<CheckScope>().descriptor.asInputSchema()
            .properties!!["targets"]!!.jsonObject["items"]!!.jsonObject
        val checkScopeOneOf = checkScopeItemSchema["oneOf"]!!.jsonArray
        val checkScopeRequiredNames = checkScopeOneOf.map { alt ->
            alt.jsonObject["required"]!!.jsonArray.single().jsonPrimitive.content
        }
        assertEquals(listOf("url", "ref"), checkScopeRequiredNames)

        val updateScopeItemSchema = serializer<UpdateScope>().descriptor.asInputSchema()
            .properties!!["targets"]!!.jsonObject["items"]!!.jsonObject
        assertTrue(updateScopeItemSchema.containsKey("oneOf"))
    }

    private fun JsonObject.matchesGeneratedOneOf(value: JsonObject): Boolean {
        val alternatives = this["oneOf"] as JsonArray
        return alternatives.count { candidate ->
            val schema = candidate.jsonObject
            val required = schema["required"]!!.jsonArray.single().jsonPrimitive.content
            value.containsKey(required) && value[required] != JsonNull
        } == 1
    }
}
