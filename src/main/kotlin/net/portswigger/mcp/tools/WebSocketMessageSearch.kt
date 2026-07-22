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
    @JsonSchemaMetadata(description = "Signed cursor from a previous page; continue with only projectId, cursor, and optional limit.", maxLength = 4096)
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

internal class WebSocketMessageSearchService(
    private val api: MontoyaApi,
    private val config: McpConfig,
    cursorSecret: ByteArray = ByteArray(32).also(SecureRandom()::nextBytes),
    private val maxScannedItems: Int = DEFAULT_WEBSOCKET_SCAN_LIMIT,
    private val maxContentBytes: Long = DEFAULT_WEBSOCKET_CONTENT_LIMIT,
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

    suspend fun search(input: SearchWebsocketMessages): SearchWebsocketMessagesResult {
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

        val expectedProjectId = try {
            api.project().id()
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
        if (!allowed) {
            return SearchWebsocketMessagesResult(
                status = WebSocketSearchStatus.ACCESS_DENIED,
                projectId = expectedProjectId.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
                error = "WebSocket history access denied by Burp Suite",
            )
        }

        val records = try {
            api.proxy().webSocketHistory().toList()
        } catch (e: Exception) {
            return burpError(expectedProjectId, e)
        }
        val projectAfterAccess = try {
            api.project().id()
        } catch (e: Exception) {
            return burpError(expectedProjectId, e)
        }
        if (projectAfterAccess != expectedProjectId) {
            return projectMismatch(projectAfterAccess, "Burp project changed while WebSocket history was opened")
        }

        val snapshot = try {
            decodedCursor?.also { validateSnapshot(it, records) } ?: newCursorSnapshot(expectedProjectId, query, records)
        } catch (e: StaleWebSocketCursorException) {
            return SearchWebsocketMessagesResult(
                status = WebSocketSearchStatus.STALE_CURSOR,
                projectId = expectedProjectId.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
                error = e.message.orEmpty().take(512),
            )
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
            while (inSnapshot(itemIndex, snapshot.snapshotSize) && items.size < limit) {
                if (scanned and 63 == 0) currentCoroutineContext().ensureActive()
                if (scanned >= maxScannedItems) {
                    scanLimitReached = true
                    break
                }
                val item = records[itemIndex]
                scanned++
                if (!item.matchesMetadata(query)) {
                    itemIndex = advance(itemIndex, query.newestFirst)
                    continue
                }
                if (regex != null) {
                    val payloadBytes = item.payload()?.length()?.toLong()?.coerceAtLeast(0) ?: 0L
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
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return burpError(expectedProjectId, e)
        }

        val finalProjectId = try {
            api.project().id()
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
            } catch (e: Exception) {
                return burpError(expectedProjectId, e)
            }
        } else null
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

    private fun newCursorSnapshot(
        projectId: String,
        query: NormalizedWebSocketQuery,
        records: List<ProxyWebSocketMessage>,
    ) = WebSocketSearchCursor(
        version = WEBSOCKET_CURSOR_VERSION,
        projectId = projectId,
        query = query,
        snapshotSize = records.size,
        itemIndex = if (query.newestFirst) records.lastIndex else 0,
        firstAnchor = records.firstOrNull()?.cursorAnchor(),
        lastAnchor = records.lastOrNull()?.cursorAnchor(),
    )

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
