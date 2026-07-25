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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.reflect.KClass
import kotlin.reflect.full.memberProperties

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
 * named sibling properties to be present. This is emitted as a standard `oneOf` constraint
 * over per-property `required` alternatives (`oneOf: [{required: [a]}, {required: [b]}]`),
 * which JSON Schema satisfies only when exactly one alternative matches - i.e. exactly one
 * of the named properties is present.
 *
 * This only takes effect where the annotated class is used as a *nested* schema, for example
 * as a `List<T>` item type or a nested object property. The MCP Kotlin SDK's `ToolSchema` has
 * a fixed shape (`type`/`properties`/`required`/`defs`) with no slot for root-level schema
 * combinators, so applying this annotation to a tool's own top-level input class has no
 * effect; such constraints must remain documented in field descriptions instead.
 */
@OptIn(ExperimentalSerializationApi::class)
@SerialInfo
@Target(AnnotationTarget.CLASS)
annotation class JsonSchemaExactlyOneOf(vararg val properties: String)

fun getJsonSchemaForProperty(kType: kotlin.reflect.KType): JsonElement {
    return when (kType.classifier) {
        String::class ->
            JsonObject(mapOf("type" to JsonPrimitive("string")))

        Int::class, Long::class ->
            JsonObject(mapOf("type" to JsonPrimitive("integer")))

        Float::class, Double::class ->
            JsonObject(mapOf("type" to JsonPrimitive("number")))

        Boolean::class ->
            JsonObject(mapOf("type" to JsonPrimitive("boolean")))

        List::class, Array::class -> {
            val argType = kType.arguments.firstOrNull()?.type
            val itemsSchema = when {
                argType != null -> getJsonSchemaForProperty(argType)
                else -> JsonObject(mapOf("type" to JsonPrimitive("object")))
            }
            JsonObject(mapOf("type" to JsonPrimitive("array"), "items" to itemsSchema))
        }

        Map::class -> {
            val valueType = kType.arguments.getOrNull(1)?.type
            val valueSchema = when {
                valueType != null -> getJsonSchemaForProperty(valueType)
                else -> JsonObject(mapOf("type" to JsonPrimitive("object")))
            }
            JsonObject(mapOf("type" to JsonPrimitive("object"), "additionalProperties" to valueSchema))
        }

        else ->
            JsonObject(mapOf("type" to JsonPrimitive("object")))
    }
}

@OptIn(ExperimentalSerializationApi::class)
fun SerialDescriptor.asInputSchema(): ToolSchema = asToolSchema("input")

@OptIn(ExperimentalSerializationApi::class)
fun SerialDescriptor.asOutputSchema(): ToolSchema = asToolSchema("output")

@OptIn(ExperimentalSerializationApi::class)
private fun SerialDescriptor.asToolSchema(schemaRole: String): ToolSchema {
    require(kind == StructureKind.CLASS || kind == StructureKind.OBJECT) {
        "Tool $schemaRole must serialize as an object, but $serialName uses $kind"
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
                        put(
                            "oneOf",
                            JsonArray(
                                exactlyOneOf.properties.map { name ->
                                    JsonObject(mapOf("required" to JsonArray(listOf(JsonPrimitive(name)))))
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
    return JsonObject(buildMap {
        putAll(schema)
        if (metadata.description.isNotBlank()) put("description", JsonPrimitive(metadata.description.take(512)))
        if (metadata.minLength >= 0) put("minLength", JsonPrimitive(metadata.minLength))
        if (metadata.maxLength >= 0) put("maxLength", JsonPrimitive(metadata.maxLength))
        if (metadata.pattern.isNotEmpty()) put("pattern", JsonPrimitive(metadata.pattern.take(512)))
        if (metadata.enumValues.isNotEmpty()) {
            put("enum", JsonArray(metadata.enumValues.distinct().map(::JsonPrimitive)))
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

private fun typedSchema(type: String) = JsonObject(mapOf("type" to JsonPrimitive(type)))

private fun JsonElement.withNullType(): JsonElement {
    val objectSchema = this as? JsonObject ?: return this
    val type = objectSchema["type"] as? JsonPrimitive ?: return JsonObject(
        mapOf("anyOf" to JsonArray(listOf(this, typedSchema("null"))))
    )
    return JsonObject(objectSchema + ("type" to JsonArray(listOf(type, JsonPrimitive("null")))))
}

fun KClass<*>.asInputSchema(): ToolSchema {
    val properties = mutableMapOf<String, JsonElement>()
    val required = mutableListOf<String>()

    for (prop in memberProperties) {
        properties[prop.name] = getJsonSchemaForProperty(prop.returnType)

        if (!prop.returnType.isMarkedNullable) {
            required.add(prop.name)
        }
    }

    return ToolSchema(
        properties = JsonObject(properties),
        required = required
    )
}