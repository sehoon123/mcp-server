package net.portswigger.mcp.schema

import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialInfo
import kotlinx.serialization.descriptors.PolymorphicKind
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.SerialKind
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

private const val MAX_SCHEMA_ANNOTATION_CHARS = 512

@OptIn(ExperimentalSerializationApi::class)
@SerialInfo
@Target(AnnotationTarget.PROPERTY)
annotation class JsonSchemaMetadata(
    val description: String = "",
    val minLength: Int = -1,
    val maxLength: Int = -1,
    val pattern: String = "",
    val enumValues: Array<String> = [],
    val minimum: Long = Long.MIN_VALUE,
    val maximum: Long = Long.MIN_VALUE,
    val minItems: Int = -1,
    val maxItems: Int = -1,
    val minProperties: Int = -1,
    val maxProperties: Int = -1,
    /** A JSON literal, for example `20`, `false`, or `\"utf8\"`. */
    val defaultJson: String = "",
)

/**
 * Marks a serializable class whose generated JSON Schema must require exactly one of the
 * named sibling properties to contain a non-null value. This is emitted as a standard `oneOf`
 * constraint over per-property required/non-null alternatives. A sibling explicitly set to
 * null therefore does not count as selected, matching nullable Kotlin decoding and runtime
 * validation.
 *
 * This only takes effect where the annotated class is used as a *nested* schema, for example
 * as a `List<T>` item type or a nested object property. The MCP Kotlin SDK's `ToolSchema` has
 * a fixed shape (`type`/`properties`/`required`/`defs`) with no slot for root-level schema
 * combinators. Applying this annotation to a tool's own top-level input or output class is
 * rejected rather than silently dropping the constraint. Use a nested object and retain
 * runtime validation; field descriptions alone are not an enforceable schema constraint.
 */
@OptIn(ExperimentalSerializationApi::class)
@SerialInfo
@Target(AnnotationTarget.CLASS)
annotation class JsonSchemaExactlyOneOf(vararg val properties: String)

@OptIn(ExperimentalSerializationApi::class)
fun SerialDescriptor.asInputSchema(): ToolSchema = asToolSchema("input")

@OptIn(ExperimentalSerializationApi::class)
fun SerialDescriptor.asOutputSchema(): ToolSchema = asToolSchema("output")

@OptIn(ExperimentalSerializationApi::class)
private fun SerialDescriptor.asToolSchema(schemaRole: String): ToolSchema {
    require(kind == StructureKind.CLASS || kind == StructureKind.OBJECT) {
        "Tool $schemaRole must serialize as an object, but $serialName uses $kind"
    }
    require(annotations.none { it is JsonSchemaExactlyOneOf }) {
        "JsonSchemaExactlyOneOf on $serialName requires a nested schema; root ToolSchema cannot represent it"
    }
    val properties = buildMap {
        for (index in 0 until elementsCount) {
            put(getElementName(index), elementSchema(index))
        }
    }
    val required = buildList {
        for (index in 0 until elementsCount) {
            if (!isElementOptional(index)) add(getElementName(index))
        }
    }
    return ToolSchema(properties = JsonObject(properties), required = required)
}

@OptIn(ExperimentalSerializationApi::class)
private fun SerialDescriptor.asJsonSchema(): JsonElement {
    val schema = when (val descriptorKind = kind) {
        PrimitiveKind.STRING, PrimitiveKind.CHAR -> typedSchema("string")
        PrimitiveKind.BOOLEAN -> typedSchema("boolean")
        PrimitiveKind.BYTE, PrimitiveKind.SHORT, PrimitiveKind.INT, PrimitiveKind.LONG -> typedSchema("integer")
        PrimitiveKind.FLOAT, PrimitiveKind.DOUBLE -> typedSchema("number")
        SerialKind.ENUM -> JsonObject(
            mapOf(
                "type" to JsonPrimitive("string"),
                "enum" to JsonArray((0 until elementsCount).map { JsonPrimitive(getElementName(it)) }),
            )
        )
        StructureKind.LIST -> JsonObject(
            mapOf(
                "type" to JsonPrimitive("array"),
                "items" to getElementDescriptor(0).asJsonSchema(),
            )
        )
        StructureKind.MAP -> JsonObject(
            mapOf(
                "type" to JsonPrimitive("object"),
                "additionalProperties" to getElementDescriptor(1).asJsonSchema(),
            )
        )
        StructureKind.CLASS, StructureKind.OBJECT -> {
            val properties = buildMap {
                for (index in 0 until elementsCount) {
                    put(getElementName(index), elementSchema(index))
                }
            }
            val required = buildList {
                for (index in 0 until elementsCount) {
                    if (!isElementOptional(index)) add(getElementName(index))
                }
            }
            val exactlyOneOf = annotations.filterIsInstance<JsonSchemaExactlyOneOf>().singleOrNull()
            JsonObject(
                buildMap {
                    put("type", JsonPrimitive("object"))
                    put("properties", JsonObject(properties))
                    if (required.isNotEmpty()) {
                        put("required", JsonArray(required.map(::JsonPrimitive)))
                    }
                    put("additionalProperties", JsonPrimitive(false))
                    if (exactlyOneOf != null) {
                        require(exactlyOneOf.properties.size >= 2) {
                            "JsonSchemaExactlyOneOf on $serialName must name at least two properties"
                        }
                        require(exactlyOneOf.properties.all(properties::containsKey)) {
                            "JsonSchemaExactlyOneOf on $serialName names a property that is not declared on the class"
                        }
                        require(exactlyOneOf.properties.distinct().size == exactlyOneOf.properties.size) {
                            "JsonSchemaExactlyOneOf on $serialName must name distinct properties"
                        }
                        put(
                            "oneOf",
                            JsonArray(
                                exactlyOneOf.properties.map { name ->
                                    JsonObject(
                                        mapOf(
                                            "required" to JsonArray(listOf(JsonPrimitive(name))),
                                            "properties" to JsonObject(
                                                mapOf(
                                                    name to JsonObject(
                                                        mapOf("not" to typedSchema("null"))
                                                    )
                                                )
                                            ),
                                        )
                                    )
                                }
                            ),
                        )
                    }
                }
            )
        }
        is PolymorphicKind -> JsonObject(emptyMap())
        else -> error("Unsupported serialization kind $descriptorKind for $serialName")
    }
    return if (isNullable) schema.withNullType() else schema
}

@OptIn(ExperimentalSerializationApi::class)
private fun SerialDescriptor.elementSchema(index: Int): JsonElement =
    getElementDescriptor(index).asJsonSchema().withMetadata(
        getElementAnnotations(index).filterIsInstance<JsonSchemaMetadata>().singleOrNull()
    )

private fun JsonElement.withMetadata(metadata: JsonSchemaMetadata?): JsonElement {
    if (metadata == null) return this
    val schema = this as? JsonObject ?: return this
    metadata.validateBounds()
    return JsonObject(buildMap {
        putAll(schema)
        if (metadata.description.isNotBlank()) put("description", JsonPrimitive(metadata.description.take(MAX_SCHEMA_ANNOTATION_CHARS)))
        if (metadata.minLength >= 0) put("minLength", JsonPrimitive(metadata.minLength))
        if (metadata.maxLength >= 0) put("maxLength", JsonPrimitive(metadata.maxLength))
        if (metadata.pattern.isNotEmpty()) put("pattern", JsonPrimitive(metadata.pattern))
        if (metadata.enumValues.isNotEmpty()) {
            val values = metadata.enumValues.distinct().map { value ->
                JsonPrimitive(value) as JsonElement
            }.toMutableList()
            if (schema.acceptsNull()) values += JsonNull
            put("enum", JsonArray(values))
        }
        if (metadata.minimum != Long.MIN_VALUE) put("minimum", JsonPrimitive(metadata.minimum))
        if (metadata.maximum != Long.MIN_VALUE) put("maximum", JsonPrimitive(metadata.maximum))
        if (metadata.minItems >= 0) put("minItems", JsonPrimitive(metadata.minItems))
        if (metadata.maxItems >= 0) put("maxItems", JsonPrimitive(metadata.maxItems))
        if (metadata.minProperties >= 0) put("minProperties", JsonPrimitive(metadata.minProperties))
        if (metadata.maxProperties >= 0) put("maxProperties", JsonPrimitive(metadata.maxProperties))
        if (metadata.defaultJson.isNotEmpty()) put("default", Json.parseToJsonElement(metadata.defaultJson))
    })
}

/** Checks trusted declaration mistakes, not request data or the full JSON Schema vocabulary. */
private fun JsonSchemaMetadata.validateBounds() {
    for ((name, lower, upper) in listOf(
        Triple("length", minLength, maxLength),
        Triple("items", minItems, maxItems),
        Triple("properties", minProperties, maxProperties),
    )) {
        require(lower >= -1 && upper >= -1) { "Schema $name bounds must be non-negative or unset (-1)" }
        require(lower == -1 || upper == -1 || lower <= upper) {
            "Schema $name minimum must not exceed maximum"
        }
    }
    require(minimum == Long.MIN_VALUE || maximum == Long.MIN_VALUE || minimum <= maximum) {
        "Schema numeric minimum must not exceed maximum"
    }
    // Unlike prose, truncating a pattern changes its constraint (or makes it invalid).
    require(pattern.length <= MAX_SCHEMA_ANNOTATION_CHARS) {
        "Schema pattern must not exceed $MAX_SCHEMA_ANNOTATION_CHARS characters"
    }
}

private fun typedSchema(type: String) = JsonObject(mapOf("type" to JsonPrimitive(type)))

private fun JsonElement.withNullType(): JsonElement {
    val objectSchema = this as? JsonObject ?: return this
    if (objectSchema.containsKey("oneOf") || objectSchema.containsKey("allOf")) {
        return JsonObject(mapOf("anyOf" to JsonArray(listOf(this, typedSchema("null")))))
    }
    val type = objectSchema["type"] as? JsonPrimitive ?: return JsonObject(
        mapOf("anyOf" to JsonArray(listOf(this, typedSchema("null"))))
    )
    return JsonObject(buildMap {
        putAll(objectSchema)
        put("type", JsonArray(listOf(type, JsonPrimitive("null"))))
        val enumValues = objectSchema["enum"] as? JsonArray
        if (enumValues != null && JsonNull !in enumValues) {
            put("enum", JsonArray(enumValues + JsonNull))
        }
    })
}

private fun JsonObject.acceptsNull(): Boolean {
    val type = this["type"]
    return type == JsonPrimitive("null") || (type is JsonArray && JsonPrimitive("null") in type) ||
        ((this["anyOf"] as? JsonArray)?.any { candidate ->
            (candidate as? JsonObject)?.get("type") == JsonPrimitive("null")
        } == true)
}
