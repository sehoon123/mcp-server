package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.websocket.Direction
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.safeExceptionSummary
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.HexFormat
import java.util.RandomAccess
import java.util.regex.Pattern
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private const val WEBSOCKET_CURSOR_VERSION = 1
private const val DEFAULT_WEBSOCKET_SEARCH_LIMIT = 25
private const val MAX_WEBSOCKET_SEARCH_LIMIT = 50
private const val DEFAULT_WEBSOCKET_SCAN_LIMIT = 10_000
private const val DEFAULT_WEBSOCKET_CONTENT_LIMIT = 32L * 1024 * 1024
private const val MAX_WEBSOCKET_CURSOR_CHARS = 4_096
private const val MAX_WEBSOCKET_REGEX_CHARS = 512
private const val WEBSOCKET_CURSOR_HMAC = "HmacSHA256"

@Serializable
enum class WebSocketSearchDirection {
    @SerialName("client_to_server")
    CLIENT_TO_SERVER,

    @SerialName("server_to_client")
    SERVER_TO_CLIENT,
}

@Serializable
data class SearchWebsocketMessages(
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Returned nextCursor from the previous page. When set, supply only projectId, cursor, and optional limit.", maxLength = 4096)
    val cursor: String? = null,
    @JsonSchemaMetadata(description = "Maximum summaries returned.", minimum = 1, maximum = 50, defaultJson = "25")
    val limit: Int? = null,
    @JsonSchemaMetadata(description = "Filter by Burp WebSocket connection ID.", minimum = 0)
    val webSocketId: Int? = null,
    @JsonSchemaMetadata(description = "Filter by message direction.")
    val direction: WebSocketSearchDirection? = null,
    @JsonSchemaMetadata(description = "Filter by Proxy listener port.", minimum = 1, maximum = 65535)
    val listenerPort: Int? = null,
    @JsonSchemaMetadata(description = "Conservatively safe payload regex.", minLength = 1, maxLength = 512)
    val regex: String? = null,
    @JsonSchemaMetadata(description = "Use case-sensitive regex matching.", defaultJson = "true")
    val caseSensitive: Boolean? = null,
    @JsonSchemaMetadata(description = "Return newest matches first.", defaultJson = "true")
    val newestFirst: Boolean? = null,
)

@Serializable
enum class WebSocketSearchStatus {
    @SerialName("ok")
    OK,

    @SerialName("access_denied")
    ACCESS_DENIED,

    @SerialName("invalid_argument")
    INVALID_ARGUMENT,

    @SerialName("invalid_cursor")
    INVALID_CURSOR,

    @SerialName("stale_cursor")
    STALE_CURSOR,

    @SerialName("project_mismatch")
    PROJECT_MISMATCH,

    @SerialName("burp_error")
    BURP_ERROR,
}

@Serializable
data class SearchWebsocketMessagesResult(
    val status: WebSocketSearchStatus,
    val projectId: String,
    val items: List<WebSocketHistorySummary> = emptyList(),
    val returned: Int = 0,
    val scanned: Int = 0,
    val scannedContentBytes: Long = 0,
    val oversizedContentSkipped: Int = 0,
    val scanLimitReached: Boolean = false,
    val contentLimitReached: Boolean = false,
    val hasMore: Boolean = false,
    val nextCursor: String? = null,
    val error: String? = null,
)

@Serializable
private data class NormalizedWebSocketQuery(
    val webSocketId: Int?,
    val direction: WebSocketSearchDirection?,
    val listenerPort: Int?,
    val regex: String?,
    val caseSensitive: Boolean,
    val newestFirst: Boolean,
)

@Serializable
private data class WebSocketSearchCursor(
    val version: Int,
    val projectId: String,
    val query: NormalizedWebSocketQuery,
    val snapshotSize: Int,
    val itemIndex: Int,
    val firstAnchor: String?,
    val lastAnchor: String?,
)

private data class WebSocketHistorySource(
    val records: List<ProxyWebSocketMessage>,
    val revalidateScanWindow: Boolean,
)

private data class ObservedWebSocketRecord(
    val sourceIndex: Int,
    val message: ProxyWebSocketMessage,
)

private enum class WebSocketSearchProgressStage(val message: String) {
    VALIDATING("Validating WebSocket search"),
    AUTHORIZING("Authorizing WebSocket history"),
    LOADING("Loading WebSocket history snapshot"),
    SCANNING("Scanning bounded WebSocket history"),
    FINALIZING("Finalizing WebSocket search"),
    COMPLETED("WebSocket search completed"),
}

private val WEBSOCKET_SEARCH_PROGRESS_MESSAGES =
    WebSocketSearchProgressStage.entries.map(WebSocketSearchProgressStage::message)

internal class WebSocketMessageSearchService(
    private val api: MontoyaApi,
    private val config: McpConfig,
    cursorSecret: ByteArray = ByteArray(32).also(SecureRandom()::nextBytes),
    private val maxScannedItems: Int = DEFAULT_WEBSOCKET_SCAN_LIMIT,
    private val maxContentBytes: Long = DEFAULT_WEBSOCKET_CONTENT_LIMIT,
    private val performanceDiagnostics: HistoryPerformanceDiagnostics = HistoryPerformanceDiagnostics.NO_OP,
) {
    private val secret = cursorSecret.copyOf().also {
        require(it.size >= 32) { "cursorSecret must contain at least 32 bytes" }
    }
    private val cursorJson = Json {
        encodeDefaults = true
        explicitNulls = false
    }

    init {
        require(maxScannedItems in 1..DEFAULT_WEBSOCKET_SCAN_LIMIT) {
            "maxScannedItems must be between 1 and $DEFAULT_WEBSOCKET_SCAN_LIMIT"
        }
        require(maxContentBytes in 1..DEFAULT_WEBSOCKET_CONTENT_LIMIT) {
            "maxContentBytes must be between 1 and $DEFAULT_WEBSOCKET_CONTENT_LIMIT"
        }
    }

    suspend fun search(
        input: SearchWebsocketMessages,
        reportProgress: ToolProgressReporter = NO_TOOL_PROGRESS_REPORTER,
    ): SearchWebsocketMessagesResult {
        val progress = FixedStageProgress(WEBSOCKET_SEARCH_PROGRESS_MESSAGES, reportProgress)
        progress.report(WebSocketSearchProgressStage.VALIDATING.ordinal)
        val boundedInputProject = input.projectId.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS)
        val limit = input.limit ?: DEFAULT_WEBSOCKET_SEARCH_LIMIT
        if (!validProjectId(input.projectId) || limit !in 1..MAX_WEBSOCKET_SEARCH_LIMIT) {
            return invalidArgument(boundedInputProject, "projectId or limit is invalid")
        }

        val decodedCursor = if (input.cursor == null) {
            null
        } else {
            try {
                decodeCursor(input.cursor)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return invalidCursor(boundedInputProject, e)
            }
        }
        if (decodedCursor != null &&
            (decodedCursor.version != WEBSOCKET_CURSOR_VERSION || decodedCursor.projectId != input.projectId)
        ) {
            return invalidCursor(boundedInputProject, "cursor version or project does not match")
        }

        val query = try {
            when {
                decodedCursor == null -> normalizeQuery(input)
                input.hasExplicitQuery() -> normalizeQuery(input).also {
                    require(it == decodedCursor.query) { "cursor query does not match supplied filters" }
                }
                else -> decodedCursor.query
            }
        } catch (e: IllegalArgumentException) {
            return if (decodedCursor == null) invalidArgument(boundedInputProject, e)
            else invalidCursor(boundedInputProject, e)
        }
        val regex = try {
            query.regex?.let { validateSafeRegex(it, query.caseSensitive) }
        } catch (e: IllegalArgumentException) {
            return invalidArgument(boundedInputProject, e)
        }

        progress.report(WebSocketSearchProgressStage.AUTHORIZING.ordinal)
        val expectedProjectId = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return burpError(boundedInputProject, e)
        }
        if (expectedProjectId != input.projectId) {
            return projectMismatch(expectedProjectId, "WebSocket cursor or projectId belongs to a different Burp project")
        }

        val allowed = try {
            DataAccessSecurity.checkDataAccessPermission(DataAccessType.WEBSOCKET_HISTORY, config)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return burpError(expectedProjectId, e)
        }
        val projectAfterApproval = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return burpError(expectedProjectId, e)
        }
        if (projectAfterApproval != expectedProjectId) {
            return projectMismatch(projectAfterApproval, "Burp project changed during WebSocket history approval")
        }
        if (!allowed) {
            return SearchWebsocketMessagesResult(
                status = WebSocketSearchStatus.ACCESS_DENIED,
                projectId = expectedProjectId.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
                error = "WebSocket history access denied by Burp Suite",
            )
        }

        progress.report(WebSocketSearchProgressStage.LOADING.ordinal)
        val history = try {
            val coroutineContext = currentCoroutineContext()
            coroutineContext.ensureActive()
            val proxy = api.proxy()
            val acquired = performanceDiagnostics.measure(HistoryPerformanceMetric.WEBSOCKET_SEARCH_ACQUISITION) {
                proxy.webSocketHistory()
            }
            coroutineContext.ensureActive()
            acquired
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return burpError(expectedProjectId, e)
        }
        return performanceDiagnostics.measure(
            metric = HistoryPerformanceMetric.WEBSOCKET_SEARCH_PROCESSING,
            outcomeForResult = { result ->
                if (result.status == WebSocketSearchStatus.OK) HistoryPerformanceOutcome.COMPLETED
                else HistoryPerformanceOutcome.FAILED
            },
        ) {
            processLoadedHistory(history, expectedProjectId, query, regex, decodedCursor, limit, progress)
        }
    }

    private suspend fun processLoadedHistory(
        history: List<ProxyWebSocketMessage>,
        expectedProjectId: String,
        query: NormalizedWebSocketQuery,
        regex: Pattern?,
        decodedCursor: WebSocketSearchCursor?,
        limit: Int,
        progress: FixedStageProgress,
    ): SearchWebsocketMessagesResult {
        val source = try {
            if (history is RandomAccess) {
                WebSocketHistorySource(history, revalidateScanWindow = true)
            } else {
                WebSocketHistorySource(history.toList(), revalidateScanWindow = false)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return burpError(expectedProjectId, e)
        }
        val records = source.records
        val projectAfterAccess = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return burpError(expectedProjectId, e)
        }
        if (projectAfterAccess != expectedProjectId) {
            return projectMismatch(projectAfterAccess, "Burp project changed while WebSocket history was opened")
        }

        val snapshot = try {
            decodedCursor?.also { validateSnapshot(it, records) } ?: newCursorSnapshot(expectedProjectId, query, records)
        } catch (e: StaleWebSocketCursorException) {
            return if (decodedCursor == null) burpError(expectedProjectId, e) else staleCursor(expectedProjectId, e)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return burpError(expectedProjectId, e)
        }

        progress.report(WebSocketSearchProgressStage.SCANNING.ordinal)
        val scanWindow = try {
            captureScanWindow(snapshot, records, query, limit)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return burpError(expectedProjectId, e)
        }
        var itemIndex = snapshot.itemIndex
        val items = ArrayList<WebSocketHistorySummary>(limit)
        var scanned = 0
        var scannedContentBytes = 0L
        var oversizedContentSkipped = 0
        var scanLimitReached = false
        var contentLimitReached = false
        try {
            for (observed in scanWindow) {
                if (items.size >= limit) break
                if (scanned and 63 == 0) currentCoroutineContext().ensureActive()
                check(observed.sourceIndex == itemIndex) { "WebSocket scan window is inconsistent" }
                val item = observed.message
                scanned++
                if (!item.matchesMetadata(query)) {
                    itemIndex = advance(itemIndex, query.newestFirst)
                    continue
                }
                if (regex != null) {
                    val payloadBytes = item.searchablePayloadByteLength()
                    if (payloadBytes > maxContentBytes) {
                        oversizedContentSkipped++
                        itemIndex = advance(itemIndex, query.newestFirst)
                        continue
                    }
                    if (scannedContentBytes + payloadBytes > maxContentBytes) {
                        contentLimitReached = true
                        break
                    }
                    scannedContentBytes += payloadBytes
                    if (!item.contains(regex)) {
                        itemIndex = advance(itemIndex, query.newestFirst)
                        continue
                    }
                }
                items += item.toHistorySummary()
                itemIndex = advance(itemIndex, query.newestFirst)
            }
            scanLimitReached = items.size < limit && inSnapshot(itemIndex, snapshot.snapshotSize) &&
                scanned >= maxScannedItems
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return burpError(expectedProjectId, e)
        }

        progress.report(WebSocketSearchProgressStage.FINALIZING.ordinal)
        try {
            if (source.revalidateScanWindow) validateScanWindow(scanWindow, scanned, records)
            validateSnapshot(snapshot.copy(itemIndex = itemIndex), records)
        } catch (e: StaleWebSocketCursorException) {
            return if (decodedCursor == null) burpError(expectedProjectId, e) else staleCursor(expectedProjectId, e)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return burpError(expectedProjectId, e)
        }
        val finalProjectId = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return burpError(expectedProjectId, e)
        }
        if (finalProjectId != expectedProjectId) {
            return projectMismatch(finalProjectId, "Burp project changed while WebSocket results were prepared")
        }

        val hasMore = inSnapshot(itemIndex, snapshot.snapshotSize)
        val nextCursor = if (hasMore) {
            try {
                encodeCursor(snapshot.copy(itemIndex = itemIndex))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return burpError(expectedProjectId, e)
            }
        } else null
        progress.report(WebSocketSearchProgressStage.COMPLETED.ordinal)
        return SearchWebsocketMessagesResult(
            status = WebSocketSearchStatus.OK,
            projectId = expectedProjectId.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
            items = items,
            returned = items.size,
            scanned = scanned,
            scannedContentBytes = scannedContentBytes,
            oversizedContentSkipped = oversizedContentSkipped,
            scanLimitReached = scanLimitReached,
            contentLimitReached = contentLimitReached,
            hasMore = hasMore,
            nextCursor = nextCursor,
        )
    }

    private suspend fun captureScanWindow(
        snapshot: WebSocketSearchCursor,
        records: List<ProxyWebSocketMessage>,
        query: NormalizedWebSocketQuery,
        limit: Int,
    ): List<ObservedWebSocketRecord> {
        val maximumWindowSize = if (query.hasSearchPredicate()) maxScannedItems else minOf(limit, maxScannedItems)
        val window = ArrayList<ObservedWebSocketRecord>(
            minOf(maximumWindowSize, snapshot.snapshotSize.coerceAtLeast(0)),
        )
        var sourceIndex = snapshot.itemIndex
        while (window.size < maximumWindowSize && inSnapshot(sourceIndex, snapshot.snapshotSize)) {
            if (window.size and 63 == 0) currentCoroutineContext().ensureActive()
            window += ObservedWebSocketRecord(sourceIndex, records[sourceIndex])
            sourceIndex = advance(sourceIndex, query.newestFirst)
        }
        return window
    }

    private fun validateScanWindow(
        window: List<ObservedWebSocketRecord>,
        inspected: Int,
        records: List<ProxyWebSocketMessage>,
    ) {
        for (index in 0 until inspected) {
            val observed = window[index]
            if (records[observed.sourceIndex] !== observed.message) {
                throw StaleWebSocketCursorException(
                    "WebSocket history was cleared, reordered, or replaced while the page was prepared",
                )
            }
        }
    }

    private fun newCursorSnapshot(
        projectId: String,
        query: NormalizedWebSocketQuery,
        records: List<ProxyWebSocketMessage>,
    ): WebSocketSearchCursor {
        val snapshotSize = records.size
        val firstAnchor = if (snapshotSize == 0) null else records[0].cursorAnchor()
        val lastAnchor = if (snapshotSize == 0) null else records[snapshotSize - 1].cursorAnchor()
        if (records.size < snapshotSize) {
            throw StaleWebSocketCursorException("WebSocket history shrank while the snapshot was opened")
        }
        return WebSocketSearchCursor(
            version = WEBSOCKET_CURSOR_VERSION,
            projectId = projectId,
            query = query,
            snapshotSize = snapshotSize,
            itemIndex = if (query.newestFirst) snapshotSize - 1 else 0,
            firstAnchor = firstAnchor,
            lastAnchor = lastAnchor,
        )
    }

    private fun validateSnapshot(cursor: WebSocketSearchCursor, records: List<ProxyWebSocketMessage>) {
        if (cursor.snapshotSize < 0 || records.size < cursor.snapshotSize) {
            throw StaleWebSocketCursorException("WebSocket history shrank after the cursor snapshot")
        }
        if (cursor.snapshotSize == 0) {
            if (cursor.firstAnchor != null || cursor.lastAnchor != null) {
                throw StaleWebSocketCursorException("WebSocket cursor has invalid empty-source anchors")
            }
            return
        }
        val first = records[0].cursorAnchor()
        val last = records[cursor.snapshotSize - 1].cursorAnchor()
        if (first != cursor.firstAnchor || last != cursor.lastAnchor) {
            throw StaleWebSocketCursorException("WebSocket history was cleared, reordered, or replaced")
        }
        val validIndex = if (cursor.query.newestFirst) {
            cursor.itemIndex in -1 until cursor.snapshotSize
        } else {
            cursor.itemIndex in 0..cursor.snapshotSize
        }
        if (!validIndex) throw IllegalArgumentException("cursor position is invalid")
    }

    private fun encodeCursor(cursor: WebSocketSearchCursor): String {
        val payload = cursorJson.encodeToString(cursor).toByteArray(StandardCharsets.UTF_8)
        val signature = hmac(payload)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(payload) + "." +
            Base64.getUrlEncoder().withoutPadding().encodeToString(signature)
    }

    private fun decodeCursor(value: String): WebSocketSearchCursor {
        require(value.length in 3..MAX_WEBSOCKET_CURSOR_CHARS) { "cursor is too long" }
        val parts = value.split('.')
        require(parts.size == 2 && parts.all(String::isNotEmpty)) { "cursor format is invalid" }
        val payload = Base64.getUrlDecoder().decode(parts[0])
        val signature = Base64.getUrlDecoder().decode(parts[1])
        require(payload.size <= MAX_WEBSOCKET_CURSOR_CHARS) { "cursor payload is too large" }
        require(MessageDigest.isEqual(signature, hmac(payload))) { "cursor signature is invalid" }
        return cursorJson.decodeFromString(WebSocketSearchCursor.serializer(), payload.toString(StandardCharsets.UTF_8))
    }

    private fun hmac(payload: ByteArray): ByteArray = Mac.getInstance(WEBSOCKET_CURSOR_HMAC).run {
        init(SecretKeySpec(secret, WEBSOCKET_CURSOR_HMAC))
        doFinal(payload)
    }
}

private class StaleWebSocketCursorException(message: String) : IllegalArgumentException(message)

internal fun validateWebSocketMetadataSearchSettings(input: SearchWebsocketMessages) {
    require(input.cursor == null && input.webSocketId == null && input.regex == null && input.caseSensitive == null) {
        "content, cursor, and connection fields are not valid saved WebSocket metadata settings"
    }
    require((input.limit ?: DEFAULT_WEBSOCKET_SEARCH_LIMIT) in 1..MAX_WEBSOCKET_SEARCH_LIMIT) {
        "limit is out of range"
    }
    normalizeQuery(input)
}

private fun normalizeQuery(input: SearchWebsocketMessages): NormalizedWebSocketQuery {
    input.webSocketId?.let { require(it >= 0) { "webSocketId must be non-negative" } }
    input.listenerPort?.let { require(it in 1..65_535) { "listenerPort is out of range" } }
    val regex = input.regex?.also {
        require(it.length <= MAX_WEBSOCKET_REGEX_CHARS) { "regex is too long" }
        validateSafeRegex(it, input.caseSensitive ?: true)
    }
    return NormalizedWebSocketQuery(
        webSocketId = input.webSocketId,
        direction = input.direction,
        listenerPort = input.listenerPort,
        regex = regex,
        caseSensitive = input.caseSensitive ?: true,
        newestFirst = input.newestFirst ?: true,
    )
}

private fun SearchWebsocketMessages.hasExplicitQuery(): Boolean =
    webSocketId != null || direction != null || listenerPort != null || regex != null ||
        caseSensitive != null || newestFirst != null

private fun NormalizedWebSocketQuery.hasSearchPredicate(): Boolean =
    webSocketId != null || direction != null || listenerPort != null || regex != null

private fun ProxyWebSocketMessage.matchesMetadata(query: NormalizedWebSocketQuery): Boolean {
    if (query.webSocketId != null && webSocketId() != query.webSocketId) return false
    if (query.listenerPort != null && listenerPort() != query.listenerPort) return false
    if (query.direction != null) {
        val expected = when (query.direction) {
            WebSocketSearchDirection.CLIENT_TO_SERVER -> Direction.CLIENT_TO_SERVER
            WebSocketSearchDirection.SERVER_TO_CLIENT -> Direction.SERVER_TO_CLIENT
        }
        if (direction() != expected) return false
    }
    return true
}

private fun ProxyWebSocketMessage.cursorAnchor(): String {
    val digest = MessageDigest.getInstance("SHA-256")
    sequenceOf(
        id().toString(),
        webSocketId().toString(),
        time().toString(),
        direction().name,
        listenerPort().toString(),
        (payload()?.length() ?: -1).toString(),
        (editedPayload()?.length() ?: -1).toString(),
    ).forEach { value ->
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        digest.update((bytes.size ushr 24).toByte())
        digest.update((bytes.size ushr 16).toByte())
        digest.update((bytes.size ushr 8).toByte())
        digest.update(bytes.size.toByte())
        digest.update(bytes)
    }
    return HexFormat.of().formatHex(digest.digest(), 0, 16)
}

private fun ProxyWebSocketMessage.searchablePayloadByteLength(): Long =
    (payload()?.length() ?: 0).coerceAtLeast(0).toLong() +
        (editedPayload()?.length() ?: 0).coerceAtLeast(0).toLong()

private fun inSnapshot(index: Int, size: Int): Boolean = index in 0 until size
private fun advance(index: Int, newestFirst: Boolean): Int = if (newestFirst) index - 1 else index + 1
private fun validProjectId(value: String): Boolean =
    value.length in 1..MAX_HTTP_REFERENCE_PROJECT_ID_CHARS && value.none(Char::isISOControl)

private fun invalidArgument(projectId: String, error: Exception) =
    invalidArgument(projectId, safeExceptionSummary(error))

private fun invalidArgument(projectId: String, message: String) = SearchWebsocketMessagesResult(
    status = WebSocketSearchStatus.INVALID_ARGUMENT,
    projectId = projectId,
    error = message.take(512),
)

private fun invalidCursor(projectId: String, error: Exception) =
    invalidCursor(projectId, safeExceptionSummary(error))

private fun invalidCursor(projectId: String, message: String) = SearchWebsocketMessagesResult(
    status = WebSocketSearchStatus.INVALID_CURSOR,
    projectId = projectId,
    error = message.take(512),
)

private fun staleCursor(projectId: String, error: StaleWebSocketCursorException) = SearchWebsocketMessagesResult(
    status = WebSocketSearchStatus.STALE_CURSOR,
    projectId = projectId.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
    error = error.message.orEmpty().take(512),
)

private fun projectMismatch(projectId: String, message: String) = SearchWebsocketMessagesResult(
    status = WebSocketSearchStatus.PROJECT_MISMATCH,
    projectId = projectId.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
    error = message.take(512),
)

private fun burpError(projectId: String, error: Exception) = SearchWebsocketMessagesResult(
    status = WebSocketSearchStatus.BURP_ERROR,
    projectId = projectId.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
    error = "Burp could not search WebSocket history: ${safeExceptionSummary(error)}".take(512),
)
