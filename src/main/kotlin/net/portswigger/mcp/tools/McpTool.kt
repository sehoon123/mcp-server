package net.portswigger.mcp.tools

import io.modelcontextprotocol.kotlin.sdk.server.ClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ContentBlock
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.serializer
import net.portswigger.mcp.schema.asInputSchema
import kotlin.experimental.ExperimentalTypeInference

private const val MAX_CONCURRENT_TOOL_EXECUTIONS = 16

@PublishedApi
internal val toolExecutionDispatcher = Dispatchers.IO.limitedParallelism(MAX_CONCURRENT_TOOL_EXECUTIONS)
private val lowerToUpperBoundary = Regex("([a-z0-9])([A-Z])")
private val acronymBoundary = Regex("([A-Z])([A-Z][a-z])")
private val wordSeparator = Regex("[\\s-]+")

@OptIn(InternalSerializationApi::class)
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: suspend I.() -> List<ContentBlock>
) {
    val toolName = I::class.simpleName?.toLowerSnakeCase() ?: error("Couldn't find name for ${I::class}")
    val serializer = I::class.serializer()
    val inputSchema = I::class.asInputSchema()

    val handler: suspend (ClientConnection, CallToolRequest) -> CallToolResult = { _, request ->
        try {
            val input = Json.decodeFromJsonElement(
                serializer,
                request.params.arguments ?: JsonObject(emptyMap())
            )
            CallToolResult(
                content = withContext(toolExecutionDispatcher) { execute(input) },
                isError = false
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            CallToolResult(
                content = listOf(TextContent("Error: ${e.message}")),
                isError = true
            )
        }
    }

    addTool(name = toolName, description = description, inputSchema = inputSchema, handler = handler)
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolString")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: suspend I.() -> String
) {
    mcpTool<I>(description, execute = {
        listOf(TextContent(execute(this)))
    })
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolUnit")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: suspend I.() -> Unit
) {
    mcpTool<I>(description, execute = {
        execute(this)

        listOf(TextContent("Executed tool"))
    })
}

inline fun <reified I : Paginated, J : Any> Server.mcpPaginatedTool(
    description: String,
    noinline mapper: (J) -> CharSequence = { it.toString() },
    crossinline execute: suspend I.() -> List<J>
) {
    mcpTool<I>(description, execute = {

        val items = execute(this)

        when {
            offset >= items.size -> {
                "Reached end of items"
            }

            else -> {
                val upperLimit = (offset + count).coerceAtMost(items.size)

                items.subList(offset, upperLimit)
                    .joinToString(separator = "\n\n", transform = mapper)
            }
        }
    })
}

internal sealed interface PaginatedSource<out J> {
    data class Items<J>(val sequence: Sequence<J>) : PaginatedSource<J>
    data class Message(val text: String) : PaginatedSource<Nothing>
}

/** Applies offset/count before mapping so skipped records are never serialized. */
internal inline fun <reified I : Paginated, J : Any> Server.mcpPaginatedSequenceTool(
    description: String,
    noinline mapper: (J) -> CharSequence = { it.toString() },
    crossinline execute: suspend I.() -> PaginatedSource<J>
) {
    mcpTool<I>(description, execute = {
        when (val source = execute(this)) {
            is PaginatedSource.Message -> {
                val message = sequenceOf(source.text).drop(offset).take(count).firstOrNull()
                listOf(TextContent(message ?: "Reached end of items"))
            }

            is PaginatedSource.Items -> {
                val iterator = source.sequence.drop(offset).take(count).iterator()
                if (!iterator.hasNext()) {
                    listOf(TextContent("Reached end of items"))
                } else {
                    val output = buildString {
                        append(mapper(iterator.next()))
                        while (iterator.hasNext()) {
                            append("\n\n")
                            append(mapper(iterator.next()))
                        }
                    }
                    listOf(TextContent(output))
                }
            }
        }
    })
}

inline fun <reified I : Paginated> Server.mcpPaginatedTool(
    description: String,
    crossinline execute: suspend I.() -> Sequence<String>
) {
    mcpTool<I>(description, execute = {
        val iterator = execute(this).drop(offset).take(count).iterator()
        if (!iterator.hasNext()) {
            listOf(TextContent("Reached end of items"))
        } else {
            val output = buildString {
                append(iterator.next())
                while (iterator.hasNext()) {
                    append("\n\n")
                    append(iterator.next())
                }
            }
            listOf(TextContent(output))
        }
    })
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpNamedToolString")
inline fun Server.mcpTool(
    name: String,
    description: String,
    crossinline execute: suspend () -> List<ContentBlock>
) {
    val handler: suspend (ClientConnection, CallToolRequest) -> CallToolResult = { _, _ ->
        CallToolResult(
            content = withContext(toolExecutionDispatcher) { execute() },
            isError = false
        )
    }
    addTool(name = name, description = description, inputSchema = ToolSchema(), handler = handler)
}

inline fun Server.mcpTool(
    name: String,
    description: String,
    crossinline execute: suspend () -> String
) {
    val handler: suspend (ClientConnection, CallToolRequest) -> CallToolResult = { _, _ ->
        CallToolResult(
            content = listOf(TextContent(withContext(toolExecutionDispatcher) { execute() })),
            isError = false
        )
    }
    addTool(name = name, description = description, inputSchema = ToolSchema(), handler = handler)
}

fun String.toLowerSnakeCase(): String {
    return this
        .replace(lowerToUpperBoundary, "$1_$2")
        .replace(acronymBoundary, "$1_$2")
        .replace(wordSeparator, "_")
        .lowercase()
}

interface Paginated {
    val count: Int
    val offset: Int
}
