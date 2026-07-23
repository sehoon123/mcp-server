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
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
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
    fun `scanner issue reference is professional only and hashing is deferred until click`() {
        val issue = scannerIssue()
        val event = mockk<AuditIssueContextMenuEvent>()
        every { event.selectedIssues() } returns listOf(issue)
        val tasks = DeferredTaskExecutor()
        val community = provider(professional = false, tasks = tasks)
        assertTrue(community.provideMenuItems(event).isEmpty())
        verify(exactly = 0) { issue.detail() }

        val professional = provider(professional = true, tasks = tasks)
        val item = professional.provideMenuItems(event).single() as JMenuItem
        verify(exactly = 0) { issue.detail() }
        item.doClick()
        verify(exactly = 0) { issue.detail() }
        tasks.runPending()

        assertTrue(clipboard.value.orEmpty().matches(Regex("burp://scanner-issue/project-A/issue_[0-9a-f]{32}")))
        verify(exactly = 1) { issue.detail() }
    }

    @Test
    fun `project transition fails closed without copying a stale reference`() {
        every { project.id() } returnsMany listOf("project-before", "project-after")
        val selected = mockk<OrganizerItem>(relaxed = true)
        every { selected.id() } returns 3
        val event = mockk<ContextMenuEvent>()
        every { event.selectedRequestResponses() } returns listOf(selected)
        every { event.invocationType() } returns InvocationType.MESSAGE_VIEWER_REQUEST
        every { event.toolType() } returns ToolType.ORGANIZER

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
    fun `multiple selections and unsupported contexts do not add a menu item`() {
        val first = mockk<OrganizerItem>(relaxed = true)
        val second = mockk<OrganizerItem>(relaxed = true)
        val multiple = mockk<ContextMenuEvent>()
        every { multiple.selectedRequestResponses() } returns listOf(first, second)

        val unsupported = mockk<ContextMenuEvent>()
        every { unsupported.selectedRequestResponses() } returns listOf(mockk(relaxed = true))
        every { unsupported.invocationType() } returns InvocationType.INTRUDER_ATTACK_RESULTS
        every { unsupported.toolType() } returns ToolType.INTRUDER

        val provider = provider()
        assertTrue(provider.provideMenuItems(multiple).isEmpty())
        assertTrue(provider.provideMenuItems(unsupported).isEmpty())
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

    private fun provider(
        professional: Boolean = false,
        tasks: McpReferenceTaskExecutor = ImmediateTaskExecutor,
    ) = McpReferenceContextMenuProvider(
        api = api,
        professionalEdition = professional,
        taskExecutor = tasks,
        clipboard = clipboard,
    )

    private fun siteMapItem(): HttpRequestResponse {
        val body = mockk<MontoyaByteArray>()
        every { body.length() } returns 0
        val request = mockk<HttpRequest>()
        every { request.method() } returns "GET"
        every { request.url() } returns "https://example.test/path"
        every { request.httpVersion() } returns "HTTP/1.1"
        every { request.headers() } returns emptyList()
        every { request.body() } returns body
        return mockk<HttpRequestResponse>().also { item ->
            every { item.request() } returns request
            every { item.response() } returns null
        }
    }

    private fun scannerIssue(): AuditIssue {
        val definition = mockk<AuditIssueDefinition>()
        every { definition.typeIndex() } returns 1001
        return mockk<AuditIssue>().also { issue ->
            every { issue.definition() } returns definition
            every { issue.name() } returns "Example issue"
            every { issue.baseUrl() } returns "https://example.test"
            every { issue.httpService() } returns null
            every { issue.severity() } returns AuditIssueSeverity.INFORMATION
            every { issue.confidence() } returns AuditIssueConfidence.CERTAIN
            every { issue.detail() } returns "Bounded test detail"
        }
    }
}

private class CapturingClipboard : McpReferenceClipboard {
    var value: String? = null
    override fun setText(value: String) {
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

    override fun submit(task: () -> Unit): Boolean {
        check(pending == null)
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
