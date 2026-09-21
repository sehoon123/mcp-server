package net.portswigger.mcp.schema

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.serializer
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

@OptIn(ExperimentalSerializationApi::class)
class JsonSchemaMetadataTest {
    private fun propertySchema(
        metadata: JsonSchemaMetadata,
        descriptor: SerialDescriptor = serializer<String>().descriptor,
        output: Boolean = false,
    ): JsonObject {
        val root = buildClassSerialDescriptor("MetadataProbe") {
            element("value", descriptor, annotations = listOf(metadata))
        }
        return (if (output) root.asOutputSchema() else root.asInputSchema()).properties!!.getValue("value").jsonObject
    }

    @Test
    fun `size bounds reject negative values other than the unset sentinel`() {
        val cases = listOf(
            JsonSchemaMetadata(minLength = -2) to serializer<String>().descriptor,
            JsonSchemaMetadata(maxLength = -2) to serializer<String>().descriptor,
            JsonSchemaMetadata(minItems = -2) to serializer<List<String>>().descriptor,
            JsonSchemaMetadata(maxItems = -2) to serializer<List<String>>().descriptor,
            JsonSchemaMetadata(minProperties = -2) to serializer<Map<String, String>>().descriptor,
            JsonSchemaMetadata(maxProperties = -2) to serializer<Map<String, String>>().descriptor,
        )
        for ((metadata, descriptor) in cases) {
            for (output in listOf(false, true)) {
                val error = assertFailsWith<IllegalArgumentException> { propertySchema(metadata, descriptor, output) }
                assertTrue(error.message.orEmpty().contains("non-negative or unset"))
            }
        }
    }

    @Test
    fun `contradictory bounds fail before a schema is advertised`() {
        val cases = listOf(
            JsonSchemaMetadata(minLength = 2, maxLength = 1) to serializer<String>().descriptor,
            JsonSchemaMetadata(minItems = 2, maxItems = 1) to serializer<List<String>>().descriptor,
            JsonSchemaMetadata(minProperties = 2, maxProperties = 1) to serializer<Map<String, String>>().descriptor,
            JsonSchemaMetadata(minimum = 2, maximum = 1) to serializer<Long>().descriptor,
            JsonSchemaMetadata(minimum = -1, maximum = -2) to serializer<Long>().descriptor,
        )
        for ((metadata, descriptor) in cases) {
            for (output in listOf(false, true)) {
                val error = assertFailsWith<IllegalArgumentException> { propertySchema(metadata, descriptor, output) }
                assertTrue(error.message.orEmpty().contains("must not exceed"))
            }
        }
    }

    @Test
    fun `unset one-sided and equal size bounds keep their wire meaning`() {
        assertEquals(setOf("type"), propertySchema(JsonSchemaMetadata()).keys)
        assertEquals("0", propertySchema(JsonSchemaMetadata(minLength = 0)).getValue("minLength").toString())
        assertEquals("0", propertySchema(JsonSchemaMetadata(maxLength = 0)).getValue("maxLength").toString())
        val equalLength = propertySchema(JsonSchemaMetadata(minLength = 0, maxLength = 0))
        assertEquals("0", equalLength.getValue("minLength").toString())
        assertEquals("0", equalLength.getValue("maxLength").toString())
        val equalItems = propertySchema(
            JsonSchemaMetadata(minItems = 0, maxItems = 0), serializer<List<String>>().descriptor,
        )
        assertEquals("0", equalItems.getValue("minItems").toString())
        assertEquals("0", equalItems.getValue("maxItems").toString())
        val equalProperties = propertySchema(
            JsonSchemaMetadata(minProperties = 0, maxProperties = 0), serializer<Map<String, String>>().descriptor,
        )
        assertEquals("0", equalProperties.getValue("minProperties").toString())
        assertEquals("0", equalProperties.getValue("maxProperties").toString())
    }

    @Test
    fun `negative one-sided and equal numeric bounds are not mistaken for size limits`() {
        val descriptor = serializer<Long>().descriptor
        val lower = propertySchema(JsonSchemaMetadata(minimum = Long.MIN_VALUE + 1), descriptor)
        assertEquals((Long.MIN_VALUE + 1).toString(), lower.getValue("minimum").toString())
        assertTrue("maximum" !in lower)
        val upper = propertySchema(JsonSchemaMetadata(maximum = -1), descriptor)
        assertEquals("-1", upper.getValue("maximum").toString())
        assertTrue("minimum" !in upper)
        val equal = propertySchema(JsonSchemaMetadata(minimum = -1, maximum = -1), descriptor)
        assertEquals("-1", equal.getValue("minimum").toString())
        assertEquals("-1", equal.getValue("maximum").toString())
    }

    @Test
    fun `pattern at the catalog limit is preserved verbatim`() {
        val pattern = "^" + "a".repeat(510) + "$"
        assertEquals(512, pattern.length)
        for (output in listOf(false, true)) {
            assertEquals(pattern, propertySchema(JsonSchemaMetadata(pattern = pattern), output = output)
                .getValue("pattern").jsonPrimitive.content)
        }
    }

    @Test
    fun `oversized patterns are rejected rather than silently changing their meaning`() {
        val pattern = "^" + "a".repeat(511) + "$"
        for (output in listOf(false, true)) {
            val error = assertFailsWith<IllegalArgumentException> {
                propertySchema(JsonSchemaMetadata(pattern = pattern), output = output)
            }
            assertTrue(error.message.orEmpty().contains("pattern"))
            assertTrue(error.message.orEmpty().contains("512"))
        }
    }

    @Test
    fun `description prose remains bounded without affecting constraints`() {
        val schema = propertySchema(JsonSchemaMetadata(description = "d".repeat(513), minLength = 1, maxLength = 8))
        assertEquals("d".repeat(512), schema.getValue("description").jsonPrimitive.content)
        assertEquals("1", schema.getValue("minLength").toString())
        assertEquals("8", schema.getValue("maxLength").toString())
    }
}
