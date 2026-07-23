package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessType

/** Shared implementation for the tool and native resource forms of a project-bound WebSocket read. */
internal class WebSocketMessageReadService(
    private val api: MontoyaApi,
    private val config: McpConfig,
) {
    suspend fun read(input: GetWebsocketMessageById): WebSocketMessageReadResult {
        require(input.id >= 0) { "id must be non-negative" }
        require(
            input.projectId.length in 1..MAX_HTTP_REFERENCE_PROJECT_ID_CHARS &&
                input.projectId.none(Char::isISOControl)
        ) {
            "projectId is invalid"
        }
        val normalizedOffset = normalizeHistoryOffset(input.offset)
        val normalizedLimit = normalizeHistoryLimit(input.limit)
        val normalizedEncoding = normalizeHistoryEncoding(input.encoding)
        val expectedProjectId = api.project().id()
        if (input.projectId != expectedProjectId) {
            return WebSocketMessageReadResult(
                status = HistoryReadStatus.PROJECT_MISMATCH,
                id = input.id,
                projectId = expectedProjectId,
                error = "WebSocket history ID belongs to a different Burp project",
            )
        }
        if (!checkDataAccessOrDeny(
                DataAccessType.WEBSOCKET_HISTORY,
                config,
                api,
                "WebSocket history item ${input.id}",
            )
        ) {
            return WebSocketMessageReadResult(
                status = HistoryReadStatus.ACCESS_DENIED,
                id = input.id,
                projectId = expectedProjectId,
                error = "WebSocket history access denied by Burp Suite",
            )
        }

        val item = api.proxy().webSocketHistory { it.id() == input.id }.firstOrNull()
        val currentProjectId = api.project().id()
        if (currentProjectId != expectedProjectId) {
            return WebSocketMessageReadResult(
                status = HistoryReadStatus.PROJECT_MISMATCH,
                id = input.id,
                projectId = currentProjectId,
                error = "Burp project changed while the WebSocket message was resolved",
            )
        }
        if (item == null) {
            return WebSocketMessageReadResult(
                status = HistoryReadStatus.NOT_FOUND,
                id = input.id,
                projectId = expectedProjectId,
                error = "Proxy WebSocket history item ${input.id} was not found",
            )
        }
        val result = item.readPayload(
            input.edited == true,
            normalizedOffset,
            normalizedLimit,
            normalizedEncoding,
        )
        val finalProjectId = api.project().id()
        if (finalProjectId != expectedProjectId) {
            return WebSocketMessageReadResult(
                status = HistoryReadStatus.PROJECT_MISMATCH,
                id = input.id,
                projectId = finalProjectId,
                error = "Burp project changed while the WebSocket message was read",
            )
        }
        return result.copy(projectId = expectedProjectId)
    }
}
