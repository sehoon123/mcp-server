package net.portswigger.mcp.schema

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
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
    private data class NoAnnotationListContainer(val items: List<NoAnnotationPair>)

    @Test
    fun `oneOf is emitted for a list item type carrying the annotation`() {
        val schema = serializer<ListContainer>().descriptor.asInputSchema()
        val itemSchema = schema.properties!!["items"]!!.jsonObject["items"]!!.jsonObject
        val oneOf = itemSchema["oneOf"]!!.jsonArray

        assertEquals(2, oneOf.size)
        assertEquals(listOf("a"), oneOf[0].jsonObject["required"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals(listOf("b"), oneOf[1].jsonObject["required"]!!.jsonArray.map { it.jsonPrimitive.content })
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
}
