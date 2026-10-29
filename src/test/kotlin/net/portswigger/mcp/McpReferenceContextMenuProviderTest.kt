package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.sitemap.SiteMap
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.InvocationType
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent
import burp.api.montoya.ui.contextmenu.WebSocketMessage as ContextWebSocketMessage
import burp.api.montoya.websocket.Direction
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import net.portswigger.mcp.tools.HttpMessageReference
import net.portswigger.mcp.tools.HttpMessageSource
import net.portswigger.mcp.tools.stableHistoryId
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.swing.JMenuItem
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class McpReferenceContextMenuProviderTest {
    private val api = mockk<MontoyaApi>()
    private val project = mockk<Project>()
    private val logging = mockk<Logging>(relaxed = true)
    private val clipboard = CapturingClipboard()

    @BeforeEach
    fun setUp() {
        every { api.project() } returns project
        every { project.id() } returns "project-A"
        every { api.logging() } returns logging
    }

    @Test
    fun `proxy history menu copies only a canonical project scoped reference`() {
        val selected = mockk<HttpRequestResponse>(
            relaxed = true,
            moreInterfaces = arrayOf(ProxyHttpRequestResponse::class),
        )
        every { (selected as ProxyHttpRequestResponse).id() } returns 17
        val event = mockk<ContextMenuEvent>()
        every { event.selectedRequestResponses() } returns listOf(selected)
        every { event.invocationType() } returns InvocationType.PROXY_HISTORY

        val provider = provider()
        val item = provider.provideMenuItems(event).single() as JMenuItem
        item.doClick()

        assertEquals(COPY_MCP_REFERENCE_LABEL, item.text)
        assertTrue(item.accessibleContext.accessibleDescription.contains("No raw traffic"))
        assertEquals("burp://http/project-A/proxy/17", clipboard.value)
        verify(exactly = 0) { selected.request() }
        verify(exactly = 0) { selected.response() }
        verify { logging.raiseInfoEvent("MCP reference copied") }
    }

    @Test
    fun `generic proxy selection is resolved on the background task without blocking menu construction`() {
        val selected = siteMapItem()
        val proxyItem = mockk<ProxyHttpRequestResponse>()
        every { proxyItem.id() } returns 18
        every { proxyItem.request() } returns selected.request()
        every { proxyItem.response() } returns null
        val proxy = mockk<Proxy>()
        every { api.proxy() } returns proxy
        every { proxy.history() } returns listOf(proxyItem)
        val event = mockk<ContextMenuEvent>()
        every { event.selectedRequestResponses() } returns listOf(selected)
        every { event.invocationType() } returns InvocationType.PROXY_HISTORY
        val tasks = DeferredTaskExecutor()
        val provider = provider(tasks = tasks)

        val item = provider.provideMenuItems(event).single() as JMenuItem
        verify(exactly = 0) { api.proxy() }
        item.doClick()
        verify(exactly = 0) { api.proxy() }
        assertNull(clipboard.value)

        tasks.runPending()

        assertEquals("burp://http/project-A/proxy/18", clipboard.value)
        verify(exactly = 1) { proxy.history() }
    }

    @Test
    fun `ambiguous generic history match fails closed`() {
        val selected = siteMapItem()
        val first = mockk<ProxyHttpRequestResponse>()
        val second = mockk<ProxyHttpRequestResponse>()
        listOf(first, second).forEachIndexed { index, item ->
            every { item.id() } returns index + 1
            every { item.request() } returns selected.request()
            every { item.response() } returns null
        }
        val proxy = mockk<Proxy>()
        every { api.proxy() } returns proxy
        every { proxy.history() } returns listOf(first, second)
        val event = mockk<ContextMenuEvent>()
        every { event.selectedRequestResponses() } returns listOf(selected)
        every { event.invocationType() } returns InvocationType.PROXY_HISTORY

        val provider = provider()
        (provider.provideMenuItems(event).single() as JMenuItem).doClick()

        assertNull(clipboard.value)
        verify {
            logging.raiseErrorEvent(
                "MCP reference could not be copied. Run the corresponding MCP search to obtain a current stable reference."
            )
        }
    }

    @Test
    fun `organizer menu uses its stable numeric ID`() {
        val selected = mockk<OrganizerItem>(relaxed = true)
        every { selected.id() } returns 9
        val event = mockk<ContextMenuEvent>()
        every { event.selectedRequestResponses() } returns listOf(selected)
        every { event.invocationType() } returns InvocationType.MESSAGE_VIEWER_REQUEST
        every { event.toolType() } returns ToolType.ORGANIZER

        val provider = provider()
        (provider.provideMenuItems(event).single() as JMenuItem).doClick()

        assertEquals("burp://http/project-A/organizer/9", clipboard.value)
        verify(exactly = 0) { selected.request() }
        verify(exactly = 0) { selected.response() }
    }

    @Test
    fun `site map lookup starts only after click and runs through the task executor`() {
        val selected = siteMapItem()
        val siteMap = mockk<SiteMap>()
        every { api.siteMap() } returns siteMap
        every { siteMap.requestResponses() } returns listOf(selected)
        val event = mockk<ContextMenuEvent>()
        every { event.selectedRequestResponses() } returns listOf(selected)
        every { event.invocationType() } returns InvocationType.SITE_MAP_TABLE
        val tasks = DeferredTaskExecutor()
        val provider = provider(tasks = tasks)

        val item = provider.provideMenuItems(event).single() as JMenuItem
        verify(exactly = 0) { api.siteMap() }
        item.doClick()
        verify(exactly = 0) { api.siteMap() }
        assertNull(clipboard.value)

        tasks.runPending()

        assertTrue(clipboard.value.orEmpty().matches(Regex("burp://http/project-A/site_map/sitemap_0_[0-9a-f]{32}")))
        verify(exactly = 1) { siteMap.requestResponses() }
    }

    @Test
    fun `websocket history copies the original payload reference without reading payload`() {
        val selected = mockk<ProxyWebSocketMessage>(relaxed = true)
        every { selected.id() } returns 23
        val event = mockk<WebSocketContextMenuEvent>()
        every { event.selectedWebSocketMessages() } returns listOf(selected)

        val provider = provider()
        (provider.provideMenuItems(event).single() as JMenuItem).doClick()

        assertEquals("burp://websocket/project-A/23", clipboard.value)
        verify(exactly = 0) { selected.payload() }
        verify(exactly = 0) { selected.editedPayload() }
    }

    @Test
    fun `generic websocket selection is resolved in history after click`() {
        val payload = mockk<MontoyaByteArray>()
        every { payload.length() } returns 0
        val upgradeRequest = siteMapItem().request()
        val selected = mockk<ContextWebSocketMessage>()
        every { selected.direction() } returns Direction.CLIENT_TO_SERVER
        every { selected.upgradeRequest() } returns upgradeRequest
        every { selected.payload() } returns payload
        val historyItem = mockk<ProxyWebSocketMessage>()
        every { historyItem.id() } returns 24
        every { historyItem.direction() } returns Direction.CLIENT_TO_SERVER
        every { historyItem.upgradeRequest() } returns upgradeRequest
        every { historyItem.payload() } returns payload
        val proxy = mockk<Proxy>()
        every { api.proxy() } returns proxy
        every { proxy.webSocketHistory() } returns listOf(historyItem)
        val event = mockk<WebSocketContextMenuEvent>()
        every { event.selectedWebSocketMessages() } returns listOf(selected)
        val tasks = DeferredTaskExecutor()
        val provider = provider(tasks = tasks)

        val item = provider.provideMenuItems(event).single() as JMenuItem
        verify(exactly = 0) { api.proxy() }
        item.doClick()
        verify(exactly = 0) { api.proxy() }

        tasks.runPending()

        assertEquals("burp://websocket/project-A/24", clipboard.value)
        verify(exactly = 1) { proxy.webSocketHistory() }
    }

    @Test
    fun `scanner issue reference resolves the current source issue after click`() {
        val selected = scannerIssue(
            detail = "Context-menu representation",
            baseUrl = "https://example.test/context-view",
        )
        val current = scannerIssue(
            detail = "Current Site Map representation",
            baseUrl = "https://example.test/current-source",
        )
        val siteMap = mockk<SiteMap>()
        every { api.siteMap() } returns siteMap
        every { siteMap.issues() } returns listOf(current)
        val event = mockk<AuditIssueContextMenuEvent>()
        every { event.selectedIssues() } returns listOf(selected)
        val tasks = DeferredTaskExecutor()
        val community = provider(professional = false, tasks = tasks)
        assertTrue(community.provideMenuItems(event).isEmpty())
        verify(exactly = 0) { api.siteMap() }
        verify(exactly = 0) { selected.detail() }
        verify(exactly = 0) { current.detail() }

        val professional = provider(professional = true, tasks = tasks)
        val item = professional.provideMenuItems(event).single() as JMenuItem
        verify(exactly = 0) { api.siteMap() }
        item.doClick()
        verify(exactly = 0) { api.siteMap() }
        verify(exactly = 0) { selected.detail() }
        verify(exactly = 0) { current.detail() }
        tasks.runPending()

        verify(exactly = 1) { siteMap.issues() }
        verify(exactly = 0) { selected.detail() }
        verify(exactly = 0) { current.detail() }
        val expectedId = current.stableHistoryId(0)
        assertEquals("burp://scanner-issue/project-A/$expectedId", clipboard.value)
    }

    @Test
    fun `ambiguous scanner issue source match fails closed`() {
        val selected = scannerIssue(detail = "Context-menu representation")
        val first = scannerIssue(detail = "First current issue")
        val second = scannerIssue(detail = "Second current issue")
        val siteMap = mockk<SiteMap>()
        every { api.siteMap() } returns siteMap
        every { siteMap.issues() } returns listOf(first, second)
        val event = mockk<AuditIssueContextMenuEvent>()
        every { event.selectedIssues() } returns listOf(selected)

        val provider = provider(professional = true)
        (provider.provideMenuItems(event).single() as JMenuItem).doClick()

        assertNull(clipboard.value)
        verify {
            logging.raiseErrorEvent(
                "MCP reference could not be copied. Run the corresponding MCP search to obtain a current stable reference."
            )
        }
    }

    @Test
    fun `project transition fails closed without copying a stale reference`() {
        var projectId = "project-before"
        every { project.id() } answers { projectId }
        val selected = mockk<OrganizerItem>(relaxed = true)
        every { selected.id() } returns 3
        val event = mockk<ContextMenuEvent>()
        every { event.selectedRequestResponses() } returns listOf(selected)
        every { event.invocationType() } returns InvocationType.MESSAGE_VIEWER_REQUEST
        every { event.toolType() } returns ToolType.ORGANIZER

        val tasks = DeferredTaskExecutor()
        val provider = provider(tasks = tasks)
        val item = provider.provideMenuItems(event).single() as JMenuItem
        projectId = "project-after"
        item.doClick()

        assertEquals(0, tasks.submissions)
        assertNull(clipboard.value)
        verify { logging.raiseErrorEvent(any()) }
    }

    @Test
    fun `invalid selection counts and unsupported contexts do not add a menu item`() {
        val first = mockk<OrganizerItem>(relaxed = true)
        val second = mockk<OrganizerItem>(relaxed = true)
        val multiple = mockk<ContextMenuEvent>()
        every { multiple.selectedRequestResponses() } returns List(9) { if (it == 0) first else second }

        val unsupported = mockk<ContextMenuEvent>()
        every { unsupported.selectedRequestResponses() } returns listOf(mockk(relaxed = true))
        every { unsupported.invocationType() } returns InvocationType.INTRUDER_ATTACK_RESULTS
        every { unsupported.toolType() } returns ToolType.INTRUDER

        val provider = provider()
        assertTrue(provider.provideMenuItems(multiple).isEmpty())
        assertTrue(provider.provideMenuItems(unsupported).isEmpty())
    }

    @Test
    fun `fallback source scan stops at the next interruption checkpoint`() {
        val selected = siteMapItem()
        val unmatched = siteMapItem("https://other.test/path")
        val current = mockk<ProxyHttpRequestResponse>()
        every { current.id() } returns 8
        every { current.request() } returns unmatched.request()
        every { current.response() } returns null
        var getCalls = 0
        val history = object : AbstractList<ProxyHttpRequestResponse>() {
            override val size = 100_000

            override fun get(index: Int): ProxyHttpRequestResponse {
                getCalls++
                if (getCalls == 64) Thread.currentThread().interrupt()
                return current
            }
        }
        val proxy = mockk<Proxy>()
        every { api.proxy() } returns proxy
        every { proxy.history() } returns history
        val event = mockk<ContextMenuEvent>()
        every { event.selectedRequestResponses() } returns listOf(selected)
        every { event.invocationType() } returns InvocationType.PROXY_HISTORY

        try {
            val provider = provider()
            (provider.provideMenuItems(event).single() as JMenuItem).doClick()
        } finally {
            Thread.interrupted()
        }

        assertEquals(64, getCalls)
        assertNull(clipboard.value)
        verify { logging.raiseErrorEvent(any()) }
    }

    @Test
    fun `close interrupts active fallback work without later clipboard or logging events`() {
        val selected = siteMapItem()
        val enteredSource = CountDownLatch(1)
        val neverReleased = CountDownLatch(1)
        val current = mockk<ProxyHttpRequestResponse>()
        every { current.id() } returns 8
        every { current.request() } returns siteMapItem("https://other.test/path").request()
        every { current.response() } returns null
        val history = object : AbstractList<ProxyHttpRequestResponse>() {
            override val size = 1

            override fun get(index: Int): ProxyHttpRequestResponse {
                enteredSource.countDown()
                neverReleased.await()
                return current
            }
        }
        val proxy = mockk<Proxy>()
        every { api.proxy() } returns proxy
        every { proxy.history() } returns history
        val event = mockk<ContextMenuEvent>()
        every { event.selectedRequestResponses() } returns listOf(selected)
        every { event.invocationType() } returns InvocationType.PROXY_HISTORY
        val tasks = JoiningTaskExecutor()
        val provider = provider(tasks = tasks)

        (provider.provideMenuItems(event).single() as JMenuItem).doClick()
        assertTrue(enteredSource.await(5, TimeUnit.SECONDS))
        provider.close()
        provider.close()

        assertTrue(provider.provideMenuItems(event).isEmpty())
        assertNull(clipboard.value)
        verify(exactly = 0) { logging.raiseInfoEvent(any()) }
        verify(exactly = 0) { logging.raiseErrorEvent(any()) }
    }

    @Test
    fun `bounded executor rejection reports busy without retaining or copying selection`() {
        val selected = mockk<OrganizerItem>(relaxed = true)
        every { selected.id() } returns 4
        val event = mockk<ContextMenuEvent>()
        every { event.selectedRequestResponses() } returns listOf(selected)
        every { event.invocationType() } returns InvocationType.MESSAGE_VIEWER_REQUEST
        every { event.toolType() } returns ToolType.ORGANIZER
        val provider = provider(tasks = RejectingTaskExecutor)

        (provider.provideMenuItems(event).single() as JMenuItem).doClick()

        assertNull(clipboard.value)
        verify { logging.raiseErrorEvent("MCP reference copy is busy. Try again after the current copy completes.") }
    }

    @Test
    fun `canonical reference builders encode project segments and reject invalid IDs`() {
        assertEquals(
            "burp://http/project%2Fone/proxy/8",
            canonicalHttpMcpReference(
                "project/one",
                HttpMessageReference(HttpMessageSource.PROXY, "8"),
            ),
        )
        assertEquals("burp://websocket/project%20one/2", canonicalWebSocketMcpReference("project one", 2))
        assertFailsWith<IllegalArgumentException> {
            canonicalHttpMcpReference("project", HttpMessageReference(HttpMessageSource.PROXY, "08"))
        }
        assertFailsWith<IllegalArgumentException> { canonicalWebSocketMcpReference("project", -1) }
        assertFailsWith<IllegalArgumentException> {
            canonicalScannerIssueMcpReference("project", "issue_not-hex")
        }
    }

    @Test
    fun `HTTP batches preserve selection order with one bounded clipboard write and no source reads`() {
        for (size in listOf(2, 8)) {
            val ids = (1..size).reversed().toList()
            val selected = ids.map(::proxySelection)
            val before = clipboard.writes
            val item = provider().provideMenuItems(httpEvent(selected)).single() as JMenuItem
            assertEquals(COPY_MCP_REFERENCES_LABEL, item.text)
            item.doClick()
            assertEquals(ids.joinToString("\n") { "burp://http/project-A/proxy/$it" }, clipboard.value)
            assertEquals(before + 1, clipboard.writes)
            selected.forEach {
                verify(exactly = 0) { it.request() }
                verify(exactly = 0) { it.response() }
            }
        }
        verify(exactly = 0) { api.proxy() }
    }

    @Test
    fun `organizer batch copies captured IDs without retaining the caller selection list`() {
        val first = mockk<OrganizerItem>(relaxed = true)
        val second = mockk<OrganizerItem>(relaxed = true)
        every { first.id() } returns 2
        every { second.id() } returns 1
        val selected = mutableListOf<HttpRequestResponse>(first, second)
        val tasks = DeferredTaskExecutor()
        val item = provider(tasks = tasks).provideMenuItems(
            httpEvent(selected, InvocationType.MESSAGE_VIEWER_REQUEST)
        ).single() as JMenuItem
        selected.clear()
        item.doClick()
        tasks.runPending()
        assertEquals("burp://http/project-A/organizer/2\nburp://http/project-A/organizer/1", clipboard.value)
        verify(exactly = 0) { api.organizer() }
    }

    @Test
    fun `project changes during selection or queued work never publish batch references`() {
        var current = "project-A"
        every { project.id() } answers { current }
        val event = httpEvent(listOf(proxySelection(1), proxySelection(2)))
        val tasks = DeferredTaskExecutor()
        val provider = provider(tasks = tasks)
        val item = provider.provideMenuItems(event).single() as JMenuItem
        item.doClick()
        current = "project-B"
        tasks.runPending()
        assertNull(clipboard.value)
        verify(exactly = 0) { api.proxy() }

        every { event.selectedRequestResponses() } answers {
            current = "project-C"
            listOf(proxySelection(1), proxySelection(2))
        }
        assertTrue(provider.provideMenuItems(event).isEmpty())
        assertEquals(1, tasks.submissions)
    }

    @Test
    fun `queued single selection is bound to the original project too`() {
        var current = "project-A"
        every { project.id() } answers { current }
        val tasks = DeferredTaskExecutor()
        val item = provider(tasks = tasks).provideMenuItems(httpEvent(listOf(proxySelection(1)))).single() as JMenuItem
        item.doClick()
        current = "project-B"
        tasks.runPending()
        assertNull(clipboard.value)
    }

    @Test
    fun `site map batch acquires once scans once then rechecks matched slots`() {
        val first = siteMapItem("https://example.test/first")
        val second = siteMapItem("https://example.test/second")
        var reads = 0
        val snapshot = object : AbstractList<HttpRequestResponse>() {
            override val size = 2
            override fun get(index: Int): HttpRequestResponse {
                reads++
                return if (index == 0) second else first
            }
        }
        val siteMap = setSiteMap(snapshot)
        val item = provider().provideMenuItems(httpEvent(listOf(first, second), InvocationType.SITE_MAP_TABLE)).single() as JMenuItem
        assertEquals(0, reads)
        item.doClick()
        val lines = clipboard.value.orEmpty().lines()
        assertEquals(2, lines.size)
        assertTrue(lines[0].startsWith("burp://http/project-A/site_map/sitemap_1_"))
        assertTrue(lines[1].startsWith("burp://http/project-A/site_map/sitemap_0_"))
        assertEquals(4, reads)
        verify(exactly = 1) { siteMap.requestResponses() }
    }

    @Test
    fun `duplicate unresolved and partial batch results preserve the clipboard`() {
        val first = siteMapItem()
        val second = siteMapItem("https://example.test/second")
        clipboard.setText("keep")
        val before = clipboard.writes
        val selections = listOf(
            listOf(first, first),
            listOf(first, siteMapItem("https://example.test/missing")),
            listOf(siteMapItem(), second), // Equal content is not object identity.
        )
        for (selected in selections) {
            setSiteMap(listOf(first, second))
            (provider().provideMenuItems(httpEvent(selected, InvocationType.SITE_MAP_TABLE)).single() as JMenuItem).doClick()
            assertEquals("keep", clipboard.value)
            assertEquals(before, clipboard.writes)
        }
        val duplicateIds = httpEvent(listOf(proxySelection(1), proxySelection(1)))
        (provider().provideMenuItems(duplicateIds).single() as JMenuItem).doClick()
        assertEquals(before, clipboard.writes)
    }

    @Test
    fun `batch rejects later object duplicates over-limit sources and changed slots`() {
        val first = siteMapItem()
        val second = siteMapItem("https://example.test/second")
        val event = httpEvent(listOf(first, second), InvocationType.SITE_MAP_TABLE)
        setSiteMap(listOf(first, second, first))
        (provider().provideMenuItems(event).single() as JMenuItem).doClick()
        assertNull(clipboard.value)

        setSiteMap(object : AbstractList<HttpRequestResponse>() {
            override val size = 100_001
            override fun get(index: Int): HttpRequestResponse = error("over-limit source must not be scanned")
        })
        (provider().provideMenuItems(event).single() as JMenuItem).doClick()
        assertNull(clipboard.value)

        var firstReads = 0
        setSiteMap(object : AbstractList<HttpRequestResponse>() {
            override val size = 2
            override fun get(index: Int): HttpRequestResponse =
                if (index == 1) second else if (firstReads++ == 0) first else second
        })
        (provider().provideMenuItems(event).single() as JMenuItem).doClick()
        assertNull(clipboard.value)
    }

    @Test
    fun `batch scans exact source cap and interruption prevents clipboard publication`() {
        val first = siteMapItem()
        val second = siteMapItem("https://example.test/second")
        val other = siteMapItem("https://example.test/other")
        val event = httpEvent(listOf(first, second), InvocationType.SITE_MAP_TABLE)
        var reads = 0
        var interrupt = false
        setSiteMap(object : AbstractList<HttpRequestResponse>() {
            override val size = 100_000
            override fun get(index: Int): HttpRequestResponse {
                reads++
                if (interrupt && reads == 64) Thread.currentThread().interrupt()
                return when (index) { 0 -> first; 1 -> second; else -> other }
            }
        })
        (provider().provideMenuItems(event).single() as JMenuItem).doClick()
        assertEquals(100_002, reads)
        val previous = clipboard.value
        val writes = clipboard.writes
        reads = 0
        interrupt = true
        try {
            (provider().provideMenuItems(event).single() as JMenuItem).doClick()
        } finally { Thread.interrupted() }
        assertEquals(64, reads)
        assertEquals(previous, clipboard.value)
        assertEquals(writes, clipboard.writes)
    }

    @Test
    fun `project changes during batch lookup preserve clipboard`() {
        val first = siteMapItem()
        val second = siteMapItem("https://example.test/second")
        var current = "project-A"
        every { project.id() } answers { current }
        setSiteMap(object : AbstractList<HttpRequestResponse>() {
            override val size = 2
            override fun get(index: Int): HttpRequestResponse {
                current = "project-B"
                return if (index == 0) first else second
            }
        })
        clipboard.setText("keep")
        (provider().provideMenuItems(httpEvent(listOf(first, second), InvocationType.SITE_MAP_TABLE)).single() as JMenuItem).doClick()
        assertEquals("keep", clipboard.value)
        assertEquals(1, clipboard.writes)
    }

    @Test
    fun `mixed proxy batch rejects native ID collision even before identity match`() {
        var revealId = false
        val fallback = proxySelection(2)
        every { (fallback as ProxyHttpRequestResponse).id() } answers { if (revealId) 2 else -1 }
        val direct = proxySelection(1)
        val collision = proxySelection(2)
        val proxy = mockk<Proxy>()
        every { api.proxy() } returns proxy
        every { proxy.history() } returns listOf(direct, collision, fallback).map { it as ProxyHttpRequestResponse }
        val item = provider().provideMenuItems(httpEvent(listOf(direct, fallback))).single() as JMenuItem
        revealId = true
        item.doClick()
        assertNull(clipboard.value)
        verify(exactly = 1) { proxy.history() }
    }

    @Test
    fun `batch rejects encoded output overflow and preserves clipboard after closure or rejection`() {
        clipboard.setText("keep")
        val before = clipboard.writes
        every { project.id() } returns "한".repeat(256)
        val event = httpEvent((1..8).map(::proxySelection))
        (provider().provideMenuItems(event).single() as JMenuItem).doClick()
        assertEquals(before, clipboard.writes)
        every { project.id() } returns "project-A"
        (provider(tasks = RejectingTaskExecutor).provideMenuItems(event).single() as JMenuItem).doClick()
        val provider = provider()
        val item = provider.provideMenuItems(event).single() as JMenuItem
        provider.close()
        item.doClick()
        assertEquals("keep", clipboard.value)
        assertEquals(before, clipboard.writes)
    }

    @Test
    fun `empty HTTP and multiple WebSocket or Scanner selections remain unsupported`() {
        val provider = provider(professional = true)
        assertTrue(provider.provideMenuItems(httpEvent(emptyList())).isEmpty())
        val ws = mockk<WebSocketContextMenuEvent>()
        every { ws.selectedWebSocketMessages() } returns listOf(mockk(), mockk())
        assertTrue(provider.provideMenuItems(ws).isEmpty())
        val issues = mockk<AuditIssueContextMenuEvent>()
        every { issues.selectedIssues() } returns listOf(mockk(), mockk())
        assertTrue(provider.provideMenuItems(issues).isEmpty())
    }

    private fun proxySelection(id: Int): HttpRequestResponse = mockk<HttpRequestResponse>(
        moreInterfaces = arrayOf(ProxyHttpRequestResponse::class),
    ).also { every { (it as ProxyHttpRequestResponse).id() } returns id }

    private fun httpEvent(items: List<HttpRequestResponse>, invocation: InvocationType = InvocationType.PROXY_HISTORY) =
        mockk<ContextMenuEvent>().also {
            every { it.selectedRequestResponses() } returns items
            every { it.invocationType() } returns invocation
            every { it.toolType() } returns ToolType.ORGANIZER
        }

    private fun setSiteMap(items: List<HttpRequestResponse>) = mockk<SiteMap>().also {
        every { api.siteMap() } returns it
        every { it.requestResponses() } returns items
    }

    private fun provider(
        professional: Boolean = false,
        tasks: McpReferenceTaskExecutor = ImmediateTaskExecutor,
    ) = McpReferenceContextMenuProvider(
        api = api,
        professionalEdition = professional,
        taskExecutor = tasks,
        clipboard = clipboard,
    )

    private fun siteMapItem(url: String = "https://example.test/path"): HttpRequestResponse {
        val body = mockk<MontoyaByteArray>()
        every { body.length() } returns 0
        val request = mockk<HttpRequest>()
        every { request.method() } returns "GET"
        every { request.url() } returns url
        every { request.httpVersion() } returns "HTTP/1.1"
        every { request.headers() } returns emptyList()
        every { request.body() } returns body
        return mockk<HttpRequestResponse>().also { item ->
            every { item.request() } returns request
            every { item.response() } returns null
        }
    }

    private fun scannerIssue(
        detail: String = "Bounded test detail",
        baseUrl: String = "https://example.test",
    ): AuditIssue {
        val definition = mockk<AuditIssueDefinition>()
        every { definition.typeIndex() } returns 1001
        return mockk<AuditIssue>().also { issue ->
            every { issue.definition() } returns definition
            every { issue.name() } returns "Example issue"
            every { issue.baseUrl() } returns baseUrl
            every { issue.httpService() } returns null
            every { issue.severity() } returns AuditIssueSeverity.INFORMATION
            every { issue.confidence() } returns AuditIssueConfidence.CERTAIN
            every { issue.detail() } returns detail
        }
    }
}

private class CapturingClipboard : McpReferenceClipboard {
    var value: String? = null
    var writes = 0
        private set
    override fun setText(value: String) {
        writes++
        this.value = value
    }
}

private object ImmediateTaskExecutor : McpReferenceTaskExecutor {
    override fun submit(task: () -> Unit): Boolean {
        task()
        return true
    }

    override fun close() = Unit
}

private class DeferredTaskExecutor : McpReferenceTaskExecutor {
    private var pending: (() -> Unit)? = null
    var submissions = 0
        private set

    override fun submit(task: () -> Unit): Boolean {
        check(pending == null)
        submissions++
        pending = task
        return true
    }

    fun runPending() {
        val task = requireNotNull(pending)
        pending = null
        task()
    }

    override fun close() {
        pending = null
    }
}

private object RejectingTaskExecutor : McpReferenceTaskExecutor {
    override fun submit(task: () -> Unit): Boolean = false
    override fun close() = Unit
}

private class JoiningTaskExecutor : McpReferenceTaskExecutor {
    @Volatile
    private var worker: Thread? = null

    override fun submit(task: () -> Unit): Boolean {
        check(worker == null)
        worker = Thread(task, "mcp-reference-test-worker").apply { start() }
        return true
    }

    override fun close() {
        worker?.let { thread ->
            thread.interrupt()
            thread.join(5_000)
            check(!thread.isAlive) { "reference task did not stop after interruption" }
        }
    }
}
