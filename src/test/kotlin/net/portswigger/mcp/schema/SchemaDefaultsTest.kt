package net.portswigger.mcp.schema

import com.networknt.schema.InputFormat
import com.networknt.schema.SchemaRegistry
import com.networknt.schema.dialect.Dialects
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The generator emits inline schemas. Validate defaults as examples, without inserting them into requests. */
internal fun assertSchemaDefaultsValid(schema: JsonElement, location: String = "root"): Int {
    val registry = SchemaRegistry.withDialect(Dialects.getDraft202012())
    val literalKeywords = setOf("default", "enum", "const", "examples")
    val schemaMaps = setOf("properties", "\$defs", "definitions", "patternProperties", "dependentSchemas")

    fun visit(element: JsonElement, path: String, propertyMap: Boolean = false): Int = when (element) {
        is JsonObject -> {
            var checked = 0
            if (!propertyMap && "default" in element) {
                val errors = registry.getSchema(element.toString(), InputFormat.JSON)
                    .validate(element.getValue("default").toString(), InputFormat.JSON)
                assertTrue(errors.isEmpty(), "$path has a default outside its declared schema: $errors")
                checked++
            }
            for ((key, value) in element) {
                if (propertyMap || key !in literalKeywords) {
                    checked += visit(value, "$path/$key", !propertyMap && key in schemaMaps)
                }
            }
            checked
        }
        is JsonArray -> element.withIndex().sumOf { (index, value) -> visit(value, "$path/$index") }
        else -> 0
    }

    return visit(schema, location)
}

class SchemaDefaultsTest {
    @Test
    fun `invalid defaults fail the contract test rather than becoming suggested arguments`() {
        for (schema in listOf(
            """{"type":"integer","default":"25"}""",
            """{"type":"integer","minimum":1,"default":0}""",
            """{"type":"string","enum":["text","base64"],"default":"unknown"}""",
            """{"type":"string","minLength":1,"default":""}""",
            """{"type":"string","pattern":"^[a-z]+$","default":"123"}""",
            """{"type":"array","maxItems":1,"default":[1,2]}""",
            """{"type":"string","default":null}""",
        )) {
            assertFailsWith<AssertionError>(schema) {
                assertSchemaDefaultsValid(Json.parseToJsonElement(schema))
            }
        }
    }

    @Test
    fun `nullable defaults and nested array item defaults are checked`() {
        val schema = Json.parseToJsonElement("""{
            "type":"object",
            "properties":{
                "mode":{"type":["string","null"],"enum":["text",null],"default":null},
                "limits":{"type":"array","items":{"type":"integer","minimum":1,"default":25}}
            }
        }""")
        assertEquals(2, assertSchemaDefaultsValid(schema))
    }

    @Test
    fun `literal objects are data while a property named default is still a schema`() {
        val schema = Json.parseToJsonElement("""{
            "type":"object",
            "properties":{
                "type":{"type":"string"},
                "default":{"type":"boolean","default":true}
            },
            "default":{"type":"string","default":false},
            "enum":[{"type":"string","default":false}],
            "const":{"type":"string","default":false},
            "examples":[{"type":"string","default":false}]
        }""")
        assertEquals(2, assertSchemaDefaultsValid(schema))
        assertFailsWith<AssertionError> {
            assertSchemaDefaultsValid(Json.parseToJsonElement(
                """{"type":"object","properties":{"default":{"type":"string","default":false}}}""",
            ))
        }
    }
}
