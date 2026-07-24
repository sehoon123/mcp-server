package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.websocket.Direction
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.ZonedDateTime
import java.util.regex.Pattern
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class WebSocketMessageSearchTest {
    private val api = mockk<MontoyaApi>()
    private val logging = mockk<Logging>(relaxed = true)
    private val project = mockk<Project>()
    private val proxy = mockk<Proxy>()
    private val records = mutableListOf<ProxyWebSocketMessage>()
    private val booleans = mutableMapOf<String, Boolean>()
    private var currentProjectId = "project-ws"
    private lateinit var config: McpConfig
    private lateinit var service: WebSocketMessageSearchService
    private lateinit var originalApprovalHandler: DataAccessApprovalHandler

    @BeforeEach
    fun setUp() {
        originalApprovalHandler = DataAccessSecurity.approvalHandler
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers { booleans[firstArg()] ?: false }
        every { storage.setBoolean(any(), any()) } answers { booleans[firstArg()] = secondArg() }
        every { storage.getString(any()) } returns ""
        every { api.logging() } returns logging
        every { api.project() } returns project
        every { project.id() } answers { currentProjectId }
        every { api.proxy() } returns proxy
        every { proxy.webSocketHistory() } answers { records.toList() }
        config = McpConfig(storage, logging)
        service = WebSocketMessageSearchService(api, config, cursorSecret = ByteArray(32) { 5 })
    }

    @AfterEach
    fun tearDown() {
        DataAccessSecurity.approvalHandler = originalApprovalHandler
    }

    @Test
    fun `search reports fixed monotonic progress without project values`() = runBlocking {
        val events = mutableListOf<Triple<Double, Double?, String?>>()

        val result = service.search(
            SearchWebsocketMessages(projectId = currentProjectId),
        ) { progress, total, message -> events += Triple(progress, total, message) }

        assertEquals(WebSocketSearchStatus.OK, result.status)
        assertEquals((0..5).map(Int::toDouble), events.map { it.first })
        assertTrue(events.all { it.second == 5.0 })
        assertEquals("Validating WebSocket search", events.first().third)
        assertEquals("WebSocket search completed", events.last().third)
        assertTrue(events.none { it.third.orEmpty().contains(currentProjectId) })
    }

    @Test
    fun `search progress cancellation propagates before WebSocket history acquisition`() = runBlocking {
        assertFailsWith<CancellationException> {
            service.search(SearchWebsocketMessages(projectId = currentProjectId)) { progress, _, _ ->
                if (progress == 2.0) throw CancellationException("client cancelled")
            }
        }

        verify(exactly = 0) { proxy.webSocketHistory() }
    }

    @Test
    fun `signed cursor excludes appended messages and can continue without repeated filters`() = runBlocking {
        records += message(1, webSocketId = 7, direction = Direction.CLIENT_TO_SERVER)
        records += message(2, webSocketId = 7, direction = Direction.CLIENT_TO_SERVER)

        val first = service.search(
            SearchWebsocketMessages(
                projectId = currentProjectId,
                webSocketId = 7,
                direction = WebSocketSearchDirection.CLIENT_TO_SERVER,
                newestFirst = false,
                limit = 1,
            )
        )
        assertEquals(WebSocketSearchStatus.OK, first.status)
        assertEquals(listOf(1), first.items.map { it.id })
        val cursor = assertNotNull(first.nextCursor)

        records += message(3, webSocketId = 7, direction = Direction.CLIENT_TO_SERVER)
        val second = service.search(SearchWebsocketMessages(projectId = currentProjectId, cursor = cursor, limit = 1))

        assertEquals(listOf(2), second.items.map { it.id })
        assertFalse(second.hasMore)
        assertEquals(null, second.nextCursor)
    }

    @Test
    fun `cursor tampering is rejected before WebSocket history access`() = runBlocking {
        records += message(1)
        records += message(2)
        val first = service.search(
            SearchWebsocketMessages(projectId = currentProjectId, newestFirst = false, limit = 1)
        )
        val cursor = assertNotNull(first.nextCursor)
        val replacement = if (cursor.first() == 'A') 'B' else 'A'

        val result = service.search(
            SearchWebsocketMessages(projectId = currentProjectId, cursor = replacement + cursor.drop(1))
        )

        assertEquals(WebSocketSearchStatus.INVALID_CURSOR, result.status)
        verify(exactly = 1) { proxy.webSocketHistory() }
    }

    @Test
    fun `cursor rejects a conflicting query before a second source read`() = runBlocking {
        records += message(1)
        records += message(2)
        val first = service.search(
            SearchWebsocketMessages(
                projectId = currentProjectId,
                direction = WebSocketSearchDirection.SERVER_TO_CLIENT,
                newestFirst = false,
                limit = 1,
            )
        )

        val result = service.search(
            SearchWebsocketMessages(
                projectId = currentProjectId,
                cursor = assertNotNull(first.nextCursor),
                direction = WebSocketSearchDirection.CLIENT_TO_SERVER,
                newestFirst = false,
            )
        )

        assertEquals(WebSocketSearchStatus.INVALID_CURSOR, result.status)
        verify(exactly = 1) { proxy.webSocketHistory() }
    }

    @Test
    fun `cursor detects reordered snapshot boundaries`() = runBlocking {
        records += message(1)
        records += message(2)
        records += message(3)
        val first = service.search(
            SearchWebsocketMessages(projectId = currentProjectId, newestFirst = false, limit = 1)
        )
        records.reverse()

        val result = service.search(
            SearchWebsocketMessages(projectId = currentProjectId, cursor = assertNotNull(first.nextCursor))
        )

        assertEquals(WebSocketSearchStatus.STALE_CURSOR, result.status)
        assertTrue(result.error.orEmpty().contains("reordered"))
    }

    @Test
    fun `cursor detects a shrunken snapshot`() = runBlocking {
        records += message(1)
        records += message(2)
        val first = service.search(
            SearchWebsocketMessages(projectId = currentProjectId, newestFirst = false, limit = 1)
        )
        records.removeLast()

        val result = service.search(
            SearchWebsocketMessages(projectId = currentProjectId, cursor = assertNotNull(first.nextCursor))
        )

        assertEquals(WebSocketSearchStatus.STALE_CURSOR, result.status)
        assertTrue(result.error.orEmpty().contains("shrank"))
    }

    @Test
    fun `scan budget returns a cursor at the next raw source index`() = runBlocking {
        records += message(1, webSocketId = 1)
        records += message(2, webSocketId = 2)
        service = WebSocketMessageSearchService(
            api,
            config,
            cursorSecret = ByteArray(32) { 8 },
            maxScannedItems = 1,
        )

        val first = service.search(
            SearchWebsocketMessages(
                projectId = currentProjectId,
                webSocketId = 2,
                newestFirst = false,
            )
        )
        assertTrue(first.scanLimitReached)
        assertEquals(1, first.scanned)
        assertTrue(first.hasMore)

        val second = service.search(
            SearchWebsocketMessages(projectId = currentProjectId, cursor = assertNotNull(first.nextCursor))
        )
        assertEquals(listOf(2), second.items.map { it.id })
        assertEquals(1, second.scanned)
        assertFalse(second.hasMore)
    }

    @Test
    fun `safe regex uses bounded payload accounting and skips individually oversized records`() = runBlocking {
        val oversized = message(1, payloadBytes = 1, editedPayloadBytes = 9)
        val selected = message(2, payloadBytes = 3)
        every { selected.contains(any<Pattern>()) } answers {
            firstArg<Pattern>().matcher("token-42").find()
        }
        records += oversized
        records += selected
        service = WebSocketMessageSearchService(
            api,
            config,
            cursorSecret = ByteArray(32) { 6 },
            maxContentBytes = 5,
        )

        val result = service.search(
            SearchWebsocketMessages(
                projectId = currentProjectId,
                regex = "token-[0-9]+",
                newestFirst = false,
            )
        )

        assertEquals(WebSocketSearchStatus.OK, result.status)
        assertEquals(listOf(2), result.items.map { it.id })
        assertEquals(2, result.scanned)
        assertEquals(3, result.scannedContentBytes)
        assertEquals(1, result.oversizedContentSkipped)
        verify(exactly = 0) { oversized.contains(any<Pattern>()) }
    }

    @Test
    fun `aggregate regex budget returns a cursor at the uninspected record`() = runBlocking {
        val firstMessage = message(1, payloadBytes = 4)
        val secondMessage = message(2, payloadBytes = 4)
        every { secondMessage.contains(any<Pattern>()) } returns true
        records += firstMessage
        records += secondMessage
        service = WebSocketMessageSearchService(
            api,
            config,
            cursorSecret = ByteArray(32) { 7 },
            maxContentBytes = 5,
        )

        val first = service.search(
            SearchWebsocketMessages(
                projectId = currentProjectId,
                regex = "token",
                newestFirst = false,
            )
        )
        assertTrue(first.contentLimitReached)
        assertTrue(first.hasMore)
        assertEquals(0, first.returned)

        val second = service.search(
            SearchWebsocketMessages(projectId = currentProjectId, cursor = assertNotNull(first.nextCursor))
        )
        assertEquals(listOf(2), second.items.map { it.id })
        assertFalse(second.hasMore)
        verify(exactly = 1) { secondMessage.contains(any<Pattern>()) }
    }

    @Test
    fun `unsafe regex and project mismatch fail before source access`() = runBlocking {
        val unsafe = service.search(
            SearchWebsocketMessages(projectId = currentProjectId, regex = "(a+)+")
        )
        val malformed = service.search(
            SearchWebsocketMessages(projectId = currentProjectId, regex = "(")
        )
        val mismatch = service.search(
            SearchWebsocketMessages(projectId = "other-project")
        )

        assertEquals(WebSocketSearchStatus.INVALID_ARGUMENT, unsafe.status)
        assertEquals(WebSocketSearchStatus.INVALID_ARGUMENT, malformed.status)
        assertTrue(malformed.error.orEmpty().length <= 384)
        assertFalse(malformed.error.orEmpty().contains('\n'))
        assertEquals(WebSocketSearchStatus.PROJECT_MISMATCH, mismatch.status)
        verify(exactly = 0) { proxy.webSocketHistory() }
    }

    @Test
    fun `data access denial returns no WebSocket metadata`() = runBlocking {
        config.requireDataAccessApproval = true
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig) = false
        }

        val events = mutableListOf<Double>()
        val result = service.search(SearchWebsocketMessages(projectId = currentProjectId)) { progress, _, _ ->
            events += progress
        }

        assertEquals(WebSocketSearchStatus.ACCESS_DENIED, result.status)
        assertEquals(listOf(0.0, 1.0), events)
        assertTrue(result.items.isEmpty())
        verify(exactly = 0) { proxy.webSocketHistory() }
    }

    @Test
    fun `project switch after materialization discards all summaries`() = runBlocking {
        val item = message(1)
        every { item.annotations() } answers {
            currentProjectId = "project-after"
            mockk<Annotations> { every { notes() } returns null }
        }
        records += item

        val events = mutableListOf<Double>()
        val result = service.search(SearchWebsocketMessages(projectId = "project-ws")) { progress, _, _ ->
            events += progress
        }

        assertEquals(WebSocketSearchStatus.PROJECT_MISMATCH, result.status)
        assertEquals((0..4).map(Int::toDouble), events)
        assertTrue(result.items.isEmpty())
        assertEquals("project-after", result.projectId)
    }

    private fun message(
        id: Int,
        webSocketId: Int = 3,
        direction: Direction = Direction.SERVER_TO_CLIENT,
        listenerPort: Int = 8080,
        payloadBytes: Int = 2,
        editedPayloadBytes: Int? = null,
    ): ProxyWebSocketMessage {
        val item = mockk<ProxyWebSocketMessage>()
        val payload = mockk<MontoyaByteArray>()
        val editedPayload = editedPayloadBytes?.let { mockk<MontoyaByteArray>() }
        val annotations = mockk<Annotations>()
        every { item.id() } returns id
        every { item.webSocketId() } returns webSocketId
        every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z").plusSeconds(id.toLong())
        every { item.direction() } returns direction
        every { item.listenerPort() } returns listenerPort
        every { item.payload() } returns payload
        every { item.editedPayload() } returns editedPayload
        every { item.annotations() } returns annotations
        every { item.contains(any<Pattern>()) } returns false
        every { payload.length() } returns payloadBytes
        if (editedPayload != null) every { editedPayload.length() } returns requireNotNull(editedPayloadBytes)
        every { annotations.notes() } returns null
        return item
    }
}
