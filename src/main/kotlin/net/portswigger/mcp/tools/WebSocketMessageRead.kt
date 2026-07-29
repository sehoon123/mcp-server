package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import kotlinx.coroutines.CancellationException
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessType

/** Shared implementation for the tool and native resource forms of a project-bound WebSocket read. */
internal class WebSocketMessageReadService(
    private val api: MontoyaApi,
    private val config: McpConfig,
) {
    suspend fun read(input: GetWebsocketMessageById): WebSocketMessageReadResult {
        val normalizedOffset: Int
        val normalizedLimit: Int
        val normalizedEncoding: String
        try {
            require(input.id >= 0) { "id must be non-negative" }
            require(
                input.projectId.length in 1..MAX_HTTP_REFERENCE_PROJECT_ID_CHARS &&
                    input.projectId.none(Char::isISOControl)
            ) {
                "projectId is invalid"
            }
            normalizedOffset = normalizeHistoryOffset(input.offset)
            normalizedLimit = normalizeHistoryLimit(input.limit)
            normalizedEncoding = normalizeHistoryEncoding(input.encoding)
        } catch (e: IllegalArgumentException) {
            return webSocketReadError(input, HistoryReadStatus.INVALID_ARGUMENT, null, e.message.orEmpty())
        }

        val expectedProjectId = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return webSocketReadError(
                input,
                HistoryReadStatus.BURP_ERROR,
                null,
                "Burp could not capture the current project",
            )
        }
        return try {
            readValidated(input, normalizedOffset, normalizedLimit, normalizedEncoding, expectedProjectId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            webSocketReadError(
                input,
                HistoryReadStatus.BURP_ERROR,
                expectedProjectId,
                "Burp could not read the WebSocket message",
            )
        }
    }

    private suspend fun readValidated(
        input: GetWebsocketMessageById,
        offset: Int,
        limit: Int,
        encoding: String,
        expectedProjectId: String,
    ): WebSocketMessageReadResult {
        if (input.projectId != expectedProjectId) {
            return webSocketReadError(
                input,
                HistoryReadStatus.PROJECT_MISMATCH,
                expectedProjectId,
                "WebSocket history ID belongs to a different Burp project",
            )
        }
        val allowed = checkDataAccessOrDeny(
            DataAccessType.WEBSOCKET_HISTORY,
            config,
            api,
            "WebSocket history item ${input.id}",
        )
        val projectAfterApproval = api.project().id()
        if (projectAfterApproval != expectedProjectId) {
            return webSocketReadError(
                input,
                HistoryReadStatus.PROJECT_MISMATCH,
                projectAfterApproval,
                "Burp project changed during WebSocket history approval",
            )
        }
        if (!allowed) {
            return webSocketReadError(
                input,
                HistoryReadStatus.ACCESS_DENIED,
                expectedProjectId,
                "WebSocket history access denied by Burp Suite",
            )
        }

        val item = api.proxy().webSocketHistory { it.id() == input.id }.firstOrNull()
        val currentProjectId = api.project().id()
        if (currentProjectId != expectedProjectId) {
            return webSocketReadError(
                input,
                HistoryReadStatus.PROJECT_MISMATCH,
                currentProjectId,
                "Burp project changed while the WebSocket message was resolved",
            )
        }
        if (item == null) {
            return webSocketReadError(
                input,
                HistoryReadStatus.NOT_FOUND,
                expectedProjectId,
                "Proxy WebSocket history item ${input.id} was not found",
            )
        }
        val result = item.readPayload(input.edited == true, offset, limit, encoding)
        val finalProjectId = api.project().id()
        if (finalProjectId != expectedProjectId) {
            return webSocketReadError(
                input,
                HistoryReadStatus.PROJECT_MISMATCH,
                finalProjectId,
                "Burp project changed while the WebSocket message was read",
            )
        }
        return result.copy(projectId = expectedProjectId)
    }
}

private fun webSocketReadError(
    input: GetWebsocketMessageById,
    status: HistoryReadStatus,
    projectId: String?,
    error: String,
) = WebSocketMessageReadResult(
    status = status,
    id = input.id,
    projectId = projectId?.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
    error = error.take(MAX_STRUCTURED_TOOL_ERROR_CHARS),
)
