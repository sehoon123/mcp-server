package net.portswigger.mcp.presets

import net.portswigger.mcp.tools.CompareHttpMessages
import net.portswigger.mcp.tools.HttpMessageReference
import net.portswigger.mcp.tools.SearchHttpMessages
import net.portswigger.mcp.tools.SearchWebsocketMessages

/**
 * Pure mappings from persisted safe fields and per-invocation values to the authoritative runtime inputs.
 * Save-time validation and execution must use these same mappings so their admitted fields cannot drift apart.
 */
internal fun SavedHttpSearch.toHttpSearchInput(
    limit: Int?,
    cursor: String?,
): SearchHttpMessages = SearchHttpMessages(
    sources = sources,
    host = host,
    pathContains = pathContains,
    methods = methods,
    statusCodes = statusCodes,
    mimeTypes = mimeTypes,
    inScopeOnly = inScopeOnly,
    hasResponse = hasResponse,
    text = null,
    regex = null,
    searchIn = null,
    caseSensitive = null,
    newestFirst = newestFirst,
    limit = limit ?: defaultLimit,
    cursor = cursor,
)

internal fun SavedWebSocketSearch.toWebSocketSearchInput(
    projectId: String,
    limit: Int?,
    cursor: String?,
): SearchWebsocketMessages = SearchWebsocketMessages(
    projectId = projectId,
    cursor = cursor,
    limit = limit ?: defaultLimit,
    webSocketId = null,
    direction = direction,
    listenerPort = listenerPort,
    regex = null,
    caseSensitive = null,
    newestFirst = newestFirst,
)

internal fun SavedHttpComparison.toHttpComparisonInput(
    projectId: String,
    refs: List<HttpMessageReference>,
): CompareHttpMessages = CompareHttpMessages(
    projectId = projectId,
    refs = refs,
    part = part,
    limitBytesPerMessage = limitBytesPerMessage,
    excerptEncoding = excerptEncoding,
    ignoreHeaders = ignoreHeaders,
    includeResponseVariations = includeResponseVariations,
)
