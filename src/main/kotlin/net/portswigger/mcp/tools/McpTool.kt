package net.portswigger.mcp.tools

import io.modelcontextprotocol.kotlin.sdk.server.ClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ContentBlock
import io.modelcontextprotocol.kotlin.sdk.types.ProgressNotification
import io.modelcontextprotocol.kotlin.sdk.types.ProgressNotificationParams
import io.modelcontextprotocol.kotlin.sdk.types.ProgressToken
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolAnnotations
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.serializer
import net.portswigger.mcp.schema.asInputSchema
import net.portswigger.mcp.schema.asOutputSchema
import net.portswigger.mcp.security.safeExceptionSummary
import kotlin.experimental.ExperimentalTypeInference

private const val MAX_CONCURRENT_TOOL_EXECUTIONS = 16
private const val MAX_PROGRESS_MESSAGE_CHARS = 256

@PublishedApi
internal val READ_ONLY_TOOL_ANNOTATIONS = ToolAnnotations(
    readOnlyHint = true,
    destructiveHint = false,
    idempotentHint = true,
    openWorldHint = false,
)

internal val REQUEST_ROUTING_TOOL_ANNOTATIONS = ToolAnnotations(
    readOnlyHint = false,
    destructiveHint = false,
    idempotentHint = false,
    openWorldHint = false,
)

internal val HTTP_REQUEST_ACTION_ANNOTATIONS = ToolAnnotations(
    readOnlyHint = false,
    destructiveHint = true,
    idempotentHint = false,
    openWorldHint = true,
)

internal val SCOPE_MUTATION_TOOL_ANNOTATIONS = ToolAnnotations(
    readOnlyHint = false,
    destructiveHint = true,
    idempotentHint = true,
    openWorldHint = false,
)

internal val SCANNER_START_TOOL_ANNOTATIONS = ToolAnnotations(
    readOnlyHint = false,
    destructiveHint = true,
    idempotentHint = false,
    openWorldHint = true,
)

internal val SCANNER_CANCEL_TOOL_ANNOTATIONS = ToolAnnotations(
    readOnlyHint = false,
    destructiveHint = true,
    idempotentHint = true,
    openWorldHint = false,
)

internal val COLLABORATOR_READ_TOOL_ANNOTATIONS = ToolAnnotations(
    readOnlyHint = true,
    destructiveHint = false,
    idempotentHint = false,
    openWorldHint = true,
)

internal val COLLABORATOR_GENERATE_TOOL_ANNOTATIONS = ToolAnnotations(
    readOnlyHint = false,
    destructiveHint = false,
    idempotentHint = false,
    openWorldHint = true,
)

internal val PROJECT_MUTATION_TOOL_ANNOTATIONS = ToolAnnotations(
    readOnlyHint = false,
    destructiveHint = true,
    idempotentHint = true,
    openWorldHint = false,
)

internal val LOCAL_TRANSFORM_TOOL_ANNOTATIONS = ToolAnnotations(
    readOnlyHint = true,
    destructiveHint = false,
    idempotentHint = true,
    openWorldHint = false,
)

@PublishedApi
internal val toolExecutionDispatcher = Dispatchers.IO.limitedParallelism(MAX_CONCURRENT_TOOL_EXECUTIONS)
private val lowerToUpperBoundary = Regex("([a-z0-9])([A-Z])")
private val acronymBoundary = Regex("([A-Z])([A-Z][a-z])")
private val wordSeparator = Regex("[\\s-]+")

@OptIn(InternalSerializationApi::class)
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    annotations: ToolAnnotations? = null,
    crossinline execute: suspend I.() -> List<ContentBlock>
) {
    val toolName = I::class.simpleName?.toLowerSnakeCase() ?: error("Couldn't find name for ${I::class}")
    val serializer = I::class.serializer()
    val inputSchema = serializer.descriptor.asInputSchema()

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
                content = listOf(TextContent("Error: ${safeExceptionSummary(e)}")),
                isError = true
            )
        }
    }

    addTool(
        name = toolName,
        description = description,
        inputSchema = inputSchema,
        toolAnnotations = annotations,
        handler = handler,
    )
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolString")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    annotations: ToolAnnotations? = null,
    crossinline execute: suspend I.() -> String
) {
    mcpTool<I>(description, annotations, execute = {
        listOf(TextContent(execute(this)))
    })
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolUnit")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    annotations: ToolAnnotations? = null,
    crossinline execute: suspend I.() -> Unit
) {
    mcpTool<I>(description, annotations, execute = {
        execute(this)

        listOf(TextContent("Executed tool"))
    })
}

inline fun <reified I : Paginated, J : Any> Server.mcpPaginatedTool(
    description: String,
    noinline mapper: (J) -> CharSequence = { it.toString() },
    crossinline execute: suspend I.() -> List<J>
) {
    mcpTool<I>(description, READ_ONLY_TOOL_ANNOTATIONS, execute = {
        requireBoundedPage()
        val items = execute(this)

        when {
            offset >= items.size -> {
                "Reached end of items"
            }

            else -> {
                val upperLimit = (offset + count).coerceAtMost(items.size)

                boundedLegacyPage(
                    items.subList(offset, upperLimit).asSequence().map { mapper(it) }.iterator()
                )
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
    noinline mapper: I.(J) -> CharSequence = { it.toString() },
    crossinline execute: suspend I.() -> PaginatedSource<J>
) {
    mcpTool<I>(description, READ_ONLY_TOOL_ANNOTATIONS, execute = {
        requireBoundedPage()
        val input = this
        when (val source = execute(input)) {
            is PaginatedSource.Message -> {
                val message = sequenceOf(source.text).drop(offset).take(count).firstOrNull()
                listOf(TextContent(message ?: "Reached end of items"))
            }

            is PaginatedSource.Items -> {
                val iterator = source.sequence.drop(offset).take(count).iterator()
                if (!iterator.hasNext()) {
                    listOf(TextContent("Reached end of items"))
                } else {
                    val mapped = iterator.asSequence().map { mapper(input, it) }.iterator()
                    listOf(TextContent(boundedLegacyPage(mapped)))
                }
            }
        }
    })
}

inline fun <reified I : Paginated> Server.mcpPaginatedTool(
    description: String,
    crossinline execute: suspend I.() -> Sequence<String>
) {
    mcpTool<I>(description, READ_ONLY_TOOL_ANNOTATIONS, execute = {
        requireBoundedPage()
        val iterator = execute(this).drop(offset).take(count).iterator()
        if (!iterator.hasNext()) {
            listOf(TextContent("Reached end of items"))
        } else {
            listOf(TextContent(boundedLegacyPage(iterator)))
        }
    })
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpNamedToolString")
inline fun Server.mcpTool(
    name: String,
    description: String,
    annotations: ToolAnnotations? = null,
    crossinline execute: suspend () -> List<ContentBlock>
) {
    val handler: suspend (ClientConnection, CallToolRequest) -> CallToolResult = { _, _ ->
        CallToolResult(
            content = withContext(toolExecutionDispatcher) { execute() },
            isError = false
        )
    }
    addTool(
        name = name,
        description = description,
        inputSchema = ToolSchema(),
        toolAnnotations = annotations,
        handler = handler,
    )
}

inline fun Server.mcpTool(
    name: String,
    description: String,
    annotations: ToolAnnotations? = null,
    crossinline execute: suspend () -> String
) {
    val handler: suspend (ClientConnection, CallToolRequest) -> CallToolResult = { _, _ ->
        CallToolResult(
            content = listOf(TextContent(withContext(toolExecutionDispatcher) { execute() })),
            isError = false
        )
    }
    addTool(
        name = name,
        description = description,
        inputSchema = ToolSchema(),
        toolAnnotations = annotations,
        handler = handler,
    )
}

data class StructuredToolResponse<O : Any>(
    val output: O,
    val text: String? = null,
)

class ToolCallContext @PublishedApi internal constructor(
    private val connection: ClientConnection,
    private val progressToken: ProgressToken?,
) {
    suspend fun reportProgress(progress: Double, total: Double? = null, message: String? = null) {
        if (progressToken == null) return
        require(progress.isFinite() && progress >= 0.0) { "progress must be a finite non-negative number" }
        require(total == null || (total.isFinite() && total >= 0.0)) {
            "progress total must be a finite non-negative number"
        }
        try {
            connection.notification(
                ProgressNotification(
                    ProgressNotificationParams(
                        progressToken = progressToken,
                        progress = progress,
                        total = total,
                        message = message?.take(MAX_PROGRESS_MESSAGE_CHARS),
                    )
                )
            )
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            // Progress is optional. A client that cannot receive it must not turn a completed Burp action into failure.
        }
    }
}

@OptIn(InternalSerializationApi::class)
inline fun <reified I : Any, reified O : Any> Server.mcpStructuredToolWithContext(
    description: String,
    annotations: ToolAnnotations? = null,
    crossinline execute: suspend ToolCallContext.(I) -> StructuredToolResponse<O>,
) {
    val toolName = I::class.simpleName?.toLowerSnakeCase() ?: error("Couldn't find name for ${I::class}")
    val inputSerializer = I::class.serializer()
    val outputSerializer = O::class.serializer()
    val inputSchema = inputSerializer.descriptor.asInputSchema()
    val outputSchema = outputSerializer.descriptor.asOutputSchema()

    val handler: suspend (ClientConnection, CallToolRequest) -> CallToolResult = { connection, request ->
        try {
            val input = Json.decodeFromJsonElement(
                inputSerializer,
                request.params.arguments ?: JsonObject(emptyMap()),
            )
            val context = ToolCallContext(connection, request.params.meta?.progressToken)
            val response = withContext(toolExecutionDispatcher) { context.execute(input) }
            val structuredContent = Json.encodeToJsonElement(outputSerializer, response.output).jsonObject
            CallToolResult(
                content = listOf(TextContent(response.text ?: structuredContent.toString())),
                isError = false,
                structuredContent = structuredContent,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            CallToolResult(
                content = listOf(TextContent("Error: ${safeExceptionSummary(e)}")),
                isError = true,
            )
        }
    }

    addTool(
        name = toolName,
        description = description,
        inputSchema = inputSchema,
        outputSchema = outputSchema,
        toolAnnotations = annotations,
        handler = handler,
    )
}

@OptIn(InternalSerializationApi::class)
inline fun <reified I : Any, reified O : Any> Server.mcpStructuredTool(
    description: String,
    annotations: ToolAnnotations? = null,
    crossinline execute: suspend I.() -> O,
) {
    val toolName = I::class.simpleName?.toLowerSnakeCase() ?: error("Couldn't find name for ${I::class}")
    val inputSerializer = I::class.serializer()
    val outputSerializer = O::class.serializer()
    val inputSchema = inputSerializer.descriptor.asInputSchema()
    val outputSchema = outputSerializer.descriptor.asOutputSchema()

    val handler: suspend (ClientConnection, CallToolRequest) -> CallToolResult = { _, request ->
        try {
            val input = Json.decodeFromJsonElement(
                inputSerializer,
                request.params.arguments ?: JsonObject(emptyMap()),
            )
            val output = withContext(toolExecutionDispatcher) { execute(input) }
            val structuredContent = Json.encodeToJsonElement(outputSerializer, output).jsonObject
            CallToolResult(
                content = listOf(TextContent(structuredContent.toString())),
                isError = false,
                structuredContent = structuredContent,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            CallToolResult(
                content = listOf(TextContent("Error: ${safeExceptionSummary(e)}")),
                isError = true,
            )
        }
    }

    addTool(
        name = toolName,
        description = description,
        inputSchema = inputSchema,
        outputSchema = outputSchema,
        toolAnnotations = annotations,
        handler = handler,
    )
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

@PublishedApi
internal const val MAX_LEGACY_PAGE_COUNT = 50

@PublishedApi
internal const val MAX_LEGACY_PAGE_CHARS = 128 * 1024

@PublishedApi
internal fun Paginated.requireBoundedPage() {
    require(count in 1..MAX_LEGACY_PAGE_COUNT) { "count must be between 1 and $MAX_LEGACY_PAGE_COUNT" }
    require(offset in 0..1_000_000) { "offset must be between 0 and 1000000" }
}

@PublishedApi
internal fun boundedLegacyPage(iterator: Iterator<CharSequence>): String = buildString {
    var omitted = 0
    while (iterator.hasNext()) {
        val item = iterator.next().toString()
        val separatorChars = if (isEmpty()) 0 else 2
        if (length + separatorChars + item.length > MAX_LEGACY_PAGE_CHARS) {
            omitted++
            while (iterator.hasNext()) {
                iterator.next()
                omitted++
            }
            if (isNotEmpty()) append("\n\n")
            append("{\"pageTruncated\":true,\"omittedItems\":$omitted,")
            append("\"hint\":\"use a stable-ID read tool with byte pagination\"}")
            break
        }
        if (isNotEmpty()) append("\n\n")
        append(item)
    }
}
