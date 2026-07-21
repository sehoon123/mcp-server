package net.portswigger.mcp.schema

import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.descriptors.PolymorphicKind
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.SerialKind
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.reflect.KClass
import kotlin.reflect.full.memberProperties

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
            put(getElementName(index), getElementDescriptor(index).asJsonSchema())
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
                    put(getElementName(index), getElementDescriptor(index).asJsonSchema())
                }
            }
            val required = buildList {
                for (index in 0 until elementsCount) {
                    if (!isElementOptional(index)) add(getElementName(index))
                }
            }
            JsonObject(
                buildMap {
                    put("type", JsonPrimitive("object"))
                    put("properties", JsonObject(properties))
                    if (required.isNotEmpty()) {
                        put("required", JsonArray(required.map(::JsonPrimitive)))
                    }
                }
            )
        }
        is PolymorphicKind -> JsonObject(emptyMap())
        else -> error("Unsupported serialization kind $descriptorKind for $serialName")
    }
    return if (isNullable) schema.withNullType() else schema
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