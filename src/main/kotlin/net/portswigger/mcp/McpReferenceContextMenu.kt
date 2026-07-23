package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.InvocationType
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent
import burp.api.montoya.ui.contextmenu.WebSocketMessage as ContextWebSocketMessage
import net.portswigger.mcp.tools.HttpMessageReference
import net.portswigger.mcp.tools.HttpMessageSource
import net.portswigger.mcp.tools.stableHistoryId
import net.portswigger.mcp.tools.stableSiteMapId
import java.awt.Component
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.security.MessageDigest
import java.util.HexFormat
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import javax.swing.JMenuItem

internal const val COPY_MCP_REFERENCE_LABEL = "Copy MCP reference"
private const val COPY_MCP_REFERENCE_DESCRIPTION =
    "Copies a project-scoped reference for use with this Burp MCP server. No raw traffic is copied."
private const val COPY_MCP_REFERENCE_SUCCESS = "MCP reference copied"
private const val COPY_MCP_REFERENCE_FAILURE =
    "MCP reference could not be copied. Run the corresponding MCP search to obtain a current stable reference."
private const val COPY_MCP_REFERENCE_BUSY = "MCP reference copy is busy. Try again after the current copy completes."
private const val MAX_REFERENCE_SOURCE_SCAN = 100_000
private const val REFERENCE_HASH_SAMPLE_BYTES = 32
private const val REFERENCE_HASH_STRING_CHARS = 512
private const val MAX_PENDING_REFERENCE_COPIES = 8

internal fun interface McpReferenceClipboard {
    fun setText(value: String)
}

internal interface McpReferenceTaskExecutor : AutoCloseable {
    fun submit(task: () -> Unit): Boolean
    override fun close()
}

private class BoundedMcpReferenceTaskExecutor : McpReferenceTaskExecutor {
    private val executor = ThreadPoolExecutor(
        1,
        1,
        0L,
        TimeUnit.MILLISECONDS,
        ArrayBlockingQueue(MAX_PENDING_REFERENCE_COPIES),
        { task -> Thread(task, "burp-mcp-reference-copy").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )

    override fun submit(task: () -> Unit): Boolean = try {
        executor.execute(task)
        true
    } catch (_: RejectedExecutionException) {
        false
    }

    override fun close() {
        executor.shutdownNow()
    }
}

private class SystemMcpReferenceClipboard : McpReferenceClipboard {
    override fun setText(value: String) {
        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(value), null)
    }
}

/**
 * Adds a user-initiated, read-only context-menu action for canonical MCP references.
 *
 * Menu construction only inspects selection count/type and directly exposed source IDs. Fallback source matching and
 * Scanner hashing run on a bounded background executor so Burp's event dispatch thread is not blocked by source scans
 * or large issue detail.
 */
internal class McpReferenceContextMenuProvider(
    private val api: MontoyaApi,
    private val professionalEdition: Boolean = runCatching {
        api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL
    }.getOrDefault(false),
    private val taskExecutor: McpReferenceTaskExecutor = BoundedMcpReferenceTaskExecutor(),
    private val clipboard: McpReferenceClipboard = SystemMcpReferenceClipboard(),
) : ContextMenuItemsProvider, AutoCloseable {

    override fun provideMenuItems(event: ContextMenuEvent): List<Component> = menuFor(
        runCatching { selectedHttpReference(event) }.getOrNull(),
    )

    override fun provideMenuItems(event: WebSocketContextMenuEvent): List<Component> = menuFor(
        runCatching {
            val selected = event.selectedWebSocketMessages().singleOrNull() ?: return@runCatching null
            if (selected is ProxyWebSocketMessage && selected.id() >= 0) {
                SelectedMcpReference.WebSocketId(selected.id())
            } else {
                SelectedMcpReference.WebSocketMessage(selected)
            }
        }.getOrNull(),
    )

    override fun provideMenuItems(event: AuditIssueContextMenuEvent): List<Component> {
        if (!professionalEdition) return emptyList()
        return menuFor(
            runCatching { event.selectedIssues().singleOrNull()?.let(SelectedMcpReference::ScannerIssue) }.getOrNull(),
        )
    }

    private fun selectedHttpReference(event: ContextMenuEvent): SelectedMcpReference? {
        val selected = event.selectedRequestResponses().singleOrNull() ?: return null
        return when {
            event.invocationType() == InvocationType.SITE_MAP_TREE ||
                event.invocationType() == InvocationType.SITE_MAP_TABLE ->
                SelectedMcpReference.SiteMap(selected)

            event.invocationType() == InvocationType.PROXY_HISTORY -> {
                val id = (selected as? ProxyHttpRequestResponse)?.id()?.takeIf { it >= 0 }
                if (id != null) {
                    SelectedMcpReference.Http(HttpMessageReference(HttpMessageSource.PROXY, id.toString()))
                } else {
                    SelectedMcpReference.ProxyHistory(selected)
                }
            }

            event.toolType() == ToolType.ORGANIZER -> {
                val id = (selected as? OrganizerItem)?.id()?.takeIf { it >= 0 }
                if (id != null) {
                    SelectedMcpReference.Http(HttpMessageReference(HttpMessageSource.ORGANIZER, id.toString()))
                } else {
                    SelectedMcpReference.Organizer(selected)
                }
            }

            else -> null
        }
    }

    private fun menuFor(selection: SelectedMcpReference?): List<Component> {
        if (selection == null) return emptyList()
        return listOf(
            JMenuItem(COPY_MCP_REFERENCE_LABEL).apply {
                accessibleContext.accessibleDescription = COPY_MCP_REFERENCE_DESCRIPTION
                toolTipText = COPY_MCP_REFERENCE_DESCRIPTION
                addActionListener { enqueueCopy(selection) }
            },
        )
    }

    private fun enqueueCopy(selection: SelectedMcpReference) {
        if (!taskExecutor.submit { copyReference(selection) }) {
            raiseError(COPY_MCP_REFERENCE_BUSY)
        }
    }

    private fun copyReference(selection: SelectedMcpReference) {
        try {
            val projectId = api.project().id()
            check(validMcpProjectId(projectId))
            val reference = when (selection) {
                is SelectedMcpReference.Http -> canonicalHttpMcpReference(projectId, selection.reference)
                is SelectedMcpReference.ProxyHistory -> canonicalHttpMcpReference(
                    projectId,
                    HttpMessageReference(HttpMessageSource.PROXY, findCurrentProxyId(selection.item).toString()),
                )
                is SelectedMcpReference.Organizer -> canonicalHttpMcpReference(
                    projectId,
                    HttpMessageReference(HttpMessageSource.ORGANIZER, findCurrentOrganizerId(selection.item).toString()),
                )
                is SelectedMcpReference.SiteMap -> {
                    val match = findCurrentSiteMapItem(selection.item)
                    val id = stableSiteMapId(projectId, match.index, match.item)
                    canonicalHttpMcpReference(
                        projectId,
                        HttpMessageReference(HttpMessageSource.SITE_MAP, id),
                    )
                }

                is SelectedMcpReference.WebSocketId -> canonicalWebSocketMcpReference(projectId, selection.id)
                is SelectedMcpReference.WebSocketMessage ->
                    canonicalWebSocketMcpReference(projectId, findCurrentWebSocketId(selection.message))
                is SelectedMcpReference.ScannerIssue ->
                    canonicalScannerIssueMcpReference(projectId, selection.issue.stableHistoryId())
            }
            check(api.project().id() == projectId)
            check(!Thread.currentThread().isInterrupted)
            clipboard.setText(reference)
            raiseInfo(COPY_MCP_REFERENCE_SUCCESS)
        } catch (_: Exception) {
            raiseError(COPY_MCP_REFERENCE_FAILURE)
        }
    }

    private fun findCurrentProxyId(selected: HttpRequestResponse): Int {
        val items = api.proxy().history()
        val selectedAnchor = httpReferenceAnchor(selected.request(), selected.response())
        var match: Int? = null
        for (index in 0 until items.size.coerceAtMost(MAX_REFERENCE_SOURCE_SCAN)) {
            val item = items[index]
            if ((item as Any) === selected) return item.id()
            val request = item.request() ?: continue
            if (httpReferenceAnchor(request, item.response()) != selectedAnchor) continue
            check(match == null)
            match = item.id()
        }
        return requireNotNull(match).also { check(it >= 0) }
    }

    private fun findCurrentOrganizerId(selected: HttpRequestResponse): Int {
        val items = api.organizer().items()
        val selectedAnchor = httpReferenceAnchor(selected.request(), selected.response())
        var match: Int? = null
        for (index in 0 until items.size.coerceAtMost(MAX_REFERENCE_SOURCE_SCAN)) {
            val item = items[index]
            if (item === selected) return item.id()
            if (httpReferenceAnchor(item.request(), item.response()) != selectedAnchor) continue
            check(match == null)
            match = item.id()
        }
        return requireNotNull(match).also { check(it >= 0) }
    }

    private fun findCurrentSiteMapItem(selected: HttpRequestResponse): MatchedSiteMapItem {
        val items = api.siteMap().requestResponses()
        val scanSize = items.size.coerceAtMost(MAX_REFERENCE_SOURCE_SCAN)
        for (index in 0 until scanSize) {
            if (items[index] === selected) return MatchedSiteMapItem(index, items[index])
        }

        val selectedAnchor = httpReferenceAnchor(selected.request(), selected.response())
        var match: MatchedSiteMapItem? = null
        for (index in 0 until scanSize) {
            val item = items[index]
            if (httpReferenceAnchor(item.request(), item.response()) != selectedAnchor) continue
            check(match == null)
            match = MatchedSiteMapItem(index, item)
        }
        return requireNotNull(match)
    }

    private fun findCurrentWebSocketId(selected: ContextWebSocketMessage): Int {
        val items = api.proxy().webSocketHistory()
        val selectedAnchor = selected.referenceAnchor()
        var match: Int? = null
        for (index in 0 until items.size.coerceAtMost(MAX_REFERENCE_SOURCE_SCAN)) {
            val item = items[index]
            if (item === selected) return item.id()
            if (item.referenceAnchor() != selectedAnchor) continue
            check(match == null)
            match = item.id()
        }
        return requireNotNull(match).also { check(it >= 0) }
    }

    private fun raiseInfo(message: String) {
        runCatching { api.logging().raiseInfoEvent(message) }
    }

    private fun raiseError(message: String) {
        runCatching { api.logging().raiseErrorEvent(message) }
    }

    override fun close() {
        taskExecutor.close()
    }
}

private data class MatchedSiteMapItem(val index: Int, val item: HttpRequestResponse)

private sealed interface SelectedMcpReference {
    data class Http(val reference: HttpMessageReference) : SelectedMcpReference
    data class ProxyHistory(val item: HttpRequestResponse) : SelectedMcpReference
    data class Organizer(val item: HttpRequestResponse) : SelectedMcpReference
    data class SiteMap(val item: HttpRequestResponse) : SelectedMcpReference
    data class WebSocketId(val id: Int) : SelectedMcpReference
    data class WebSocketMessage(val message: ContextWebSocketMessage) : SelectedMcpReference
    data class ScannerIssue(val issue: AuditIssue) : SelectedMcpReference
}

private fun ContextWebSocketMessage.referenceAnchor(): String {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.updateReferenceString(direction().name)
    digest.updateReferenceString(httpReferenceAnchor(upgradeRequest(), null))
    digest.updateReferenceBytes(payload())
    return HexFormat.of().formatHex(digest.digest(), 0, 16)
}

private fun httpReferenceAnchor(request: HttpRequest, response: HttpResponse?): String {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.updateReferenceString(request.method())
    digest.updateReferenceString(request.url())
    digest.updateReferenceString(request.httpVersion())
    digest.updateReferenceBytes(request.body())
    if (response == null) {
        digest.update(0)
    } else {
        digest.update(1)
        digest.updateReferenceInt(response.statusCode().toInt())
        digest.updateReferenceString(response.httpVersion())
        digest.updateReferenceBytes(response.body())
    }
    return HexFormat.of().formatHex(digest.digest(), 0, 16)
}

private fun MessageDigest.updateReferenceString(value: String) {
    updateReferenceInt(value.length)
    val bounded = if (value.length <= REFERENCE_HASH_STRING_CHARS) {
        value
    } else {
        value.take(REFERENCE_HASH_STRING_CHARS / 2) + value.takeLast(REFERENCE_HASH_STRING_CHARS / 2)
    }
    update(bounded.toByteArray(Charsets.UTF_8))
}

private fun MessageDigest.updateReferenceBytes(value: MontoyaByteArray) {
    val length = value.length()
    updateReferenceInt(length)
    if (length == 0) return
    val firstEnd = minOf(length, REFERENCE_HASH_SAMPLE_BYTES)
    for (index in 0 until firstEnd) update(value.getByte(index))
    if (length > REFERENCE_HASH_SAMPLE_BYTES) {
        val lastStart = (length - REFERENCE_HASH_SAMPLE_BYTES).coerceAtLeast(firstEnd)
        for (index in lastStart until length) update(value.getByte(index))
    }
}

private fun MessageDigest.updateReferenceInt(value: Int) {
    update((value ushr 24).toByte())
    update((value ushr 16).toByte())
    update((value ushr 8).toByte())
    update(value.toByte())
}
