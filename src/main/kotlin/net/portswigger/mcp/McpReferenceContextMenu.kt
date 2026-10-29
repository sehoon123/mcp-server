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
import java.net.URI
import java.security.MessageDigest
import java.util.HexFormat
import java.util.IdentityHashMap
import java.util.Locale
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import javax.swing.JMenuItem

internal const val COPY_MCP_REFERENCE_LABEL = "Copy MCP reference"
internal const val COPY_MCP_REFERENCES_LABEL = "Copy MCP references"
private const val MAX_BATCH_REFERENCES = 8
private const val MAX_BATCH_REFERENCE_BYTES = 16 * 1024
private const val COPY_MCP_REFERENCE_DESCRIPTION =
    "Copies a project-scoped reference for use with ${ProductIdentity.PRODUCT_NAME}. No raw traffic is copied."
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
 * Menu construction binds the project and inspects selection count/type and directly exposed source IDs. Fallback matching and
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
    private val lifecycleLock = Any()

    @Volatile
    private var closed = false

    override fun provideMenuItems(event: ContextMenuEvent): List<Component> = menuFor {
        selectedHttpReference(event)
    }

    override fun provideMenuItems(event: WebSocketContextMenuEvent): List<Component> = menuFor {
        val selected = event.selectedWebSocketMessages().singleOrNull() ?: return@menuFor null
        if (selected is ProxyWebSocketMessage && selected.id() >= 0) {
            SelectedMcpReference.WebSocketId(selected.id())
        } else {
            SelectedMcpReference.WebSocketMessage(selected)
        }
    }

    override fun provideMenuItems(event: AuditIssueContextMenuEvent): List<Component> {
        if (!professionalEdition) return emptyList()
        return menuFor { event.selectedIssues().singleOrNull()?.let(SelectedMcpReference::ScannerIssue) }
    }

    private fun selectedHttpReference(event: ContextMenuEvent): SelectedMcpReference? {
        val items = event.selectedRequestResponses()
        if (items.size !in 1..MAX_BATCH_REFERENCES) return null
        val source = when (event.invocationType()) {
            InvocationType.SITE_MAP_TREE, InvocationType.SITE_MAP_TABLE -> HttpMessageSource.SITE_MAP
            InvocationType.PROXY_HISTORY -> HttpMessageSource.PROXY
            else -> if (event.toolType() == ToolType.ORGANIZER) HttpMessageSource.ORGANIZER else return null
        }
        val selections = items.map { selected ->
            when (source) {
                HttpMessageSource.SITE_MAP -> SelectedMcpReference.SiteMap(selected)
                HttpMessageSource.PROXY -> {
                    val id = (selected as? ProxyHttpRequestResponse)?.id()?.takeIf { it >= 0 }
                    if (id != null) SelectedMcpReference.Http(HttpMessageReference(source, id.toString()))
                    else SelectedMcpReference.ProxyHistory(selected)
                }
                HttpMessageSource.ORGANIZER -> {
                    val id = (selected as? OrganizerItem)?.id()?.takeIf { it >= 0 }
                    if (id != null) SelectedMcpReference.Http(HttpMessageReference(source, id.toString()))
                    else SelectedMcpReference.Organizer(selected)
                }
            }
        }
        return selections.singleOrNull() ?: SelectedMcpReference.HttpBatch(source, selections)
    }

    private fun menuFor(select: () -> SelectedMcpReference?): List<Component> = try {
        if (closed) emptyList() else {
            val projectId = api.project().id()
            check(validMcpProjectId(projectId))
            val selection = select()
            check(api.project().id() == projectId)
            synchronized(lifecycleLock) {
                if (closed || selection == null) emptyList() else listOf(
                    JMenuItem(if (selection is SelectedMcpReference.HttpBatch) COPY_MCP_REFERENCES_LABEL else COPY_MCP_REFERENCE_LABEL).apply {
                        accessibleContext.accessibleDescription = COPY_MCP_REFERENCE_DESCRIPTION
                        toolTipText = COPY_MCP_REFERENCE_DESCRIPTION
                        addActionListener { enqueueCopy(selection, projectId) }
                    },
                )
            }
        }
    } catch (_: Exception) {
        emptyList()
    }

    private fun enqueueCopy(selection: SelectedMcpReference, projectId: String) {
        if (closed) return
        try {
            check(api.project().id() == projectId)
            if (!taskExecutor.submit { copyReference(selection, projectId) }) {
                raiseErrorIfOpen(COPY_MCP_REFERENCE_BUSY)
            }
        } catch (_: Exception) {
            raiseErrorIfOpen(COPY_MCP_REFERENCE_FAILURE)
        }
    }

    private fun copyReference(selection: SelectedMcpReference, projectId: String) {
        try {
            checkCopyActive()
            check(api.project().id() == projectId)
            val reference = when (selection) {
                is SelectedMcpReference.HttpBatch -> copyHttpBatch(selection, projectId)
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
                    canonicalScannerIssueMcpReference(projectId, findCurrentScannerIssueId(selection.issue))
            }
            synchronized(lifecycleLock) {
                check(!closed)
                check(api.project().id() == projectId)
                check(!Thread.currentThread().isInterrupted)
                clipboard.setText(reference)
                raiseInfo(if (selection is SelectedMcpReference.HttpBatch) "MCP references copied" else COPY_MCP_REFERENCE_SUCCESS)
            }
        } catch (_: Exception) {
            raiseErrorIfOpen(COPY_MCP_REFERENCE_FAILURE)
        }
    }

    private fun copyHttpBatch(batch: SelectedMcpReference.HttpBatch, projectId: String): String {
        val refs = arrayOfNulls<HttpMessageReference>(batch.selections.size)
        val identities = IdentityHashMap<Any, Int>()
        batch.selections.forEachIndexed { index, selection ->
            val item = when (selection) {
                is SelectedMcpReference.Http -> { refs[index] = selection.reference; null }
                is SelectedMcpReference.ProxyHistory -> selection.item
                is SelectedMcpReference.Organizer -> selection.item
                is SelectedMcpReference.SiteMap -> selection.item
                else -> error("Unsupported batch selection")
            }
            if (item != null) check(identities.put(item, index) == null)
        }
        check(refs.filterNotNull().distinct().size == refs.count { it != null })
        val items: List<*> = if (identities.isEmpty()) emptyList<Any>() else when (batch.source) {
            HttpMessageSource.PROXY -> api.proxy().history()
            HttpMessageSource.ORGANIZER -> api.organizer().items()
            HttpMessageSource.SITE_MAP -> api.siteMap().requestResponses()
        }
        val size = items.size
        check(size <= MAX_REFERENCE_SOURCE_SCAN)
        val matched = IntArray(refs.size) { -1 }
        val idCounts = HashMap<Int, Int>()
        fun nativeId(item: Any): Int? = when (batch.source) {
            HttpMessageSource.PROXY -> (item as ProxyHttpRequestResponse).id()
            HttpMessageSource.ORGANIZER -> (item as OrganizerItem).id()
            HttpMessageSource.SITE_MAP -> null
        }
        // A sampled content fingerprint is not proof that a different wrapper is the selected object.
        for (index in 0 until size) {
            checkReferenceScanActive(index)
            val item = requireNotNull(items[index])
            val id = nativeId(item)
            if (id != null) idCounts[id] = (idCounts[id] ?: 0) + 1
            val selectedIndex = identities[item] ?: continue
            check(matched[selectedIndex] == -1)
            matched[selectedIndex] = index
            refs[selectedIndex] = HttpMessageReference(
                batch.source,
                id?.also { check(it >= 0) }?.toString()
                    ?: stableSiteMapId(projectId, index, item as HttpRequestResponse),
            )
        }
        val resolved = refs.map { requireNotNull(it) }
        check(resolved.distinct().size == resolved.size)
        if (identities.isNotEmpty() && batch.source != HttpMessageSource.SITE_MAP) {
            check(resolved.all { idCounts[it.id.toInt()] == 1 })
        }
        val text = resolved.joinToString("\n") { canonicalHttpMcpReference(projectId, it) }
        check(text.toByteArray(Charsets.UTF_8).size <= MAX_BATCH_REFERENCE_BYTES)
        checkCopyActive()
        check(items.size == size)
        identities.forEach { item, selectedIndex ->
            val index = matched[selectedIndex]
            check(index >= 0 && items[index] === item)
            nativeId(item)?.let { check(it.toString() == resolved[selectedIndex].id) }
        }
        return text
    }

    private fun findCurrentProxyId(selected: HttpRequestResponse): Int {
        val items = api.proxy().history()
        val selectedAnchor = httpReferenceAnchor(selected.request(), selected.response())
        var match: Int? = null
        for (index in 0 until items.size.coerceAtMost(MAX_REFERENCE_SOURCE_SCAN)) {
            checkReferenceScanActive(index)
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
            checkReferenceScanActive(index)
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
            checkReferenceScanActive(index)
            if (items[index] === selected) return MatchedSiteMapItem(index, items[index])
        }

        val selectedAnchor = httpReferenceAnchor(selected.request(), selected.response())
        var match: MatchedSiteMapItem? = null
        for (index in 0 until scanSize) {
            checkReferenceScanActive(index)
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
            checkReferenceScanActive(index)
            val item = items[index]
            if (item === selected) return item.id()
            if (item.referenceAnchor() != selectedAnchor) continue
            check(match == null)
            match = item.id()
        }
        return requireNotNull(match).also { check(it >= 0) }
    }

    private fun findCurrentScannerIssueId(selected: AuditIssue): String {
        val issues = api.siteMap().issues()
        val scanSize = issues.size.coerceAtMost(MAX_REFERENCE_SOURCE_SCAN)
        val selectedFingerprint = selected.contextMetadataFingerprint()
        var matchIndex: Int? = null
        var matchCount = 0

        for (index in 0 until scanSize) {
            checkReferenceScanActive(index)
            val issue = issues[index]
            if (issue === selected) return issue.stableHistoryId(index)
            if (issue.contextMetadataFingerprint() == selectedFingerprint) {
                matchCount++
                if (matchCount == 1) matchIndex = index
            }
        }

        require(matchCount == 1) { "Scanner issue is missing or ambiguous in the current project" }
        val resolvedIndex = requireNotNull(matchIndex) { "Scanner issue is missing in the current project" }
        return issues[resolvedIndex].stableHistoryId(resolvedIndex)
    }

    private fun checkCopyActive() {
        check(!closed)
        check(!Thread.currentThread().isInterrupted)
    }

    private fun checkReferenceScanActive(index: Int) {
        if (index and 63 == 0) checkCopyActive()
    }

    private fun raiseInfo(message: String) {
        runCatching { api.logging().raiseInfoEvent(message) }
    }

    private fun raiseError(message: String) {
        runCatching { api.logging().raiseErrorEvent(message) }
    }

    private fun raiseErrorIfOpen(message: String) {
        synchronized(lifecycleLock) {
            if (!closed) raiseError(message)
        }
    }

    override fun close() {
        val shouldClose = synchronized(lifecycleLock) {
            if (closed) false else {
                closed = true
                true
            }
        }
        if (shouldClose) taskExecutor.close()
    }
}

private data class MatchedSiteMapItem(val index: Int, val item: HttpRequestResponse)

private sealed interface SelectedMcpReference {
    data class HttpBatch(val source: HttpMessageSource, val selections: List<SelectedMcpReference>) : SelectedMcpReference
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

private fun AuditIssue.contextMetadataFingerprint(): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val service = httpService()
    digest.updateReferenceString(definition().typeIndex().toString())
    digest.updateReferenceString(name().orEmpty().take(512))
    val fallbackUri = if (service == null) {
        runCatching { URI(baseUrl().orEmpty().take(4_096)) }.getOrNull()
    } else null
    val fallbackHost = fallbackUri?.host?.lowercase(Locale.ROOT)
    val fallbackScheme = fallbackUri?.scheme?.lowercase(Locale.ROOT)
    if (service != null) {
        digest.update(1)
        digest.updateReferenceString(service.host().orEmpty().lowercase(Locale.ROOT).take(253))
        digest.updateReferenceInt(service.port())
        digest.update(if (service.secure()) 1.toByte() else 0.toByte())
    } else if (!fallbackHost.isNullOrEmpty() && fallbackScheme in setOf("http", "https")) {
        val secure = fallbackScheme == "https"
        digest.update(1)
        digest.updateReferenceString(fallbackHost.take(253))
        val fallbackPort = requireNotNull(fallbackUri).port
        digest.updateReferenceInt(if (fallbackPort >= 0) fallbackPort else if (secure) 443 else 80)
        digest.update(if (secure) 1.toByte() else 0.toByte())
    } else {
        digest.update(0)
        digest.updateReferenceString(baseUrl().orEmpty().take(4_096))
    }
    digest.updateReferenceString(severity().name)
    digest.updateReferenceString(confidence().name)
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
