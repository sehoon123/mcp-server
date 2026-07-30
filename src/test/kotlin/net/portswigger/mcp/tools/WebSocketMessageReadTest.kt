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
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WebSocketMessageReadTest {
    private val api = mockk<MontoyaApi>()
    private val logging = mockk<Logging>(relaxed = true)
    private val project = mockk<Project>()
    private val proxy = mockk<Proxy>()
    private lateinit var config: McpConfig
    private lateinit var service: WebSocketMessageReadService
    private lateinit var originalApprovalHandler: DataAccessApprovalHandler
    private var currentProjectId = "project-ws"

    @BeforeEach
    fun setUp() {
        originalApprovalHandler = DataAccessSecurity.approvalHandler
        val booleans = mutableMapOf<String, Boolean>()
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers { booleans[firstArg()] ?: false }
        every { storage.setBoolean(any(), any()) } answers { booleans[firstArg()] = secondArg() }
        every { storage.getString(any()) } returns ""
        every { api.logging() } returns logging
        every { api.project() } returns project
        every { project.id() } answers { currentProjectId }
        every { api.proxy() } returns proxy
        config = McpConfig(storage, logging).also { it.requireDataAccessApproval = true }
        service = WebSocketMessageReadService(api, config)
    }

    @AfterEach
    fun tearDown() {
        DataAccessSecurity.approvalHandler = originalApprovalHandler
    }

    @Test
    fun `invalid input returns structured invalid_argument before Burp access`() = runBlocking {
        val result = service.read(GetWebsocketMessageById(id = -1, projectId = "project-ws"))

        assertEquals(HistoryReadStatus.INVALID_ARGUMENT, result.status)
        assertEquals(null, result.projectId)
        assertTrue(result.error.orEmpty().contains("non-negative"))
        verify(exactly = 0) { api.project() }
        verify(exactly = 0) { proxy.webSocketHistory(any()) }
    }

    @Test
    fun `project capture failure does not echo an unverified caller project`() = runBlocking {
        every { api.project() } throws IllegalStateException("synthetic project failure")

        val result = service.read(GetWebsocketMessageById(id = 7, projectId = "caller-project"))

        assertEquals(HistoryReadStatus.BURP_ERROR, result.status)
        assertEquals(null, result.projectId)
        assertTrue(result.error.orEmpty().contains("capture the current project"))
        verify(exactly = 0) { proxy.webSocketHistory(any()) }
    }

    @Test
    fun `Burp accessor failure returns structured burp_error`() = runBlocking {
        config.requireDataAccessApproval = false
        every { api.proxy() } throws IllegalStateException("PRIVATE_SENTINEL")

        val result = service.read(GetWebsocketMessageById(id = 7, projectId = "project-ws"))

        assertEquals(HistoryReadStatus.BURP_ERROR, result.status)
        assertEquals("project-ws", result.projectId)
        assertTrue(result.error.orEmpty().contains("Burp could not read the WebSocket message"))
        assertFalse(result.error.orEmpty().contains("PRIVATE_SENTINEL"))
    }

    @Test
    fun `WebSocket IllegalArgumentException accessor failure is a sanitized Burp error`() = runBlocking {
        config.requireDataAccessApproval = false
        val item = mockk<ProxyWebSocketMessage>()
        every { proxy.webSocketHistory(any()) } answers {
            val filter = firstArg<burp.api.montoya.proxy.ProxyWebSocketHistoryFilter>()
            listOf(item).filter(filter::matches)
        }
        every { item.id() } returns 7
        every { item.annotations() } throws IllegalArgumentException("PRIVATE_SENTINEL token=private-value")

        val result = service.read(GetWebsocketMessageById(id = 7, projectId = "project-ws"))

        assertEquals(HistoryReadStatus.BURP_ERROR, result.status)
        assertEquals("project-ws", result.projectId)
        assertTrue(result.error.orEmpty().contains("Burp could not read the WebSocket message"))
        assertFalse(result.error.orEmpty().contains("PRIVATE_SENTINEL"))
        assertFalse(result.error.orEmpty().contains("private-value"))
        assertEquals(null, result.metadata)
        assertEquals(null, result.content)
    }

    @Test
    fun `offset at and beyond selected WebSocket payload preserves page boundary semantics`() = runBlocking {
        config.requireDataAccessApproval = false
        val item = mockk<ProxyWebSocketMessage>()
        val payload = mockk<MontoyaByteArray>()
        val annotations = mockk<Annotations>()
        every { proxy.webSocketHistory(any()) } answers {
            val filter = firstArg<burp.api.montoya.proxy.ProxyWebSocketHistoryFilter>()
            listOf(item).filter(filter::matches)
        }
        every { item.id() } returns 7
        every { item.webSocketId() } returns 3
        every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z")
        every { item.direction() } returns Direction.SERVER_TO_CLIENT
        every { item.listenerPort() } returns 8080
        every { item.payload() } returns payload
        every { item.annotations() } returns annotations
        every { annotations.notes() } returns null
        every { payload.length() } returns 2

        val input = GetWebsocketMessageById(id = 7, projectId = "project-ws", offset = 2)
        val terminal = service.read(input)
        val beyond = service.read(input.copy(offset = 3))

        assertEquals(HistoryReadStatus.OK, terminal.status)
        assertEquals("", terminal.content?.data)
        assertEquals(0, terminal.content?.returnedBytes)
        assertEquals(2, terminal.content?.totalBytes)
        assertEquals(false, terminal.content?.hasMore)
        assertEquals(null, terminal.content?.nextOffsetBytes)
        assertEquals(HistoryReadStatus.INVALID_ARGUMENT, beyond.status)
        assertEquals("project-ws", beyond.projectId)
        assertTrue(beyond.error.orEmpty().contains("totalBytes (2)"))
        assertEquals(null, beyond.content)
    }

    @Test
    fun `final project check supersedes an out-of-range WebSocket correction`() = runBlocking {
        config.requireDataAccessApproval = false
        every { project.id() } returnsMany listOf(
            "project-ws",
            "project-ws",
            "project-ws",
            "replacement-project",
        )
        val item = mockk<ProxyWebSocketMessage>()
        val payload = mockk<MontoyaByteArray>()
        val annotations = mockk<Annotations>()
        every { proxy.webSocketHistory(any()) } answers {
            val filter = firstArg<burp.api.montoya.proxy.ProxyWebSocketHistoryFilter>()
            listOf(item).filter(filter::matches)
        }
        every { item.id() } returns 7
        every { item.webSocketId() } returns 3
        every { item.time() } returns ZonedDateTime.parse("2026-01-02T03:04:05Z")
        every { item.direction() } returns Direction.SERVER_TO_CLIENT
        every { item.listenerPort() } returns 8080
        every { item.payload() } returns payload
        every { item.annotations() } returns annotations
        every { annotations.notes() } returns null
        every { payload.length() } returns 2

        val result = service.read(
            GetWebsocketMessageById(id = 7, projectId = "project-ws", offset = 3)
        )

        assertEquals(HistoryReadStatus.PROJECT_MISMATCH, result.status)
        assertEquals("replacement-project", result.projectId)
        assertEquals(null, result.metadata)
        assertEquals(null, result.content)
    }

    @Test
    fun `project transition during approval prevents shared tool and resource history access`() = runBlocking {
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                currentProjectId = "replacement-project"
                return true
            }
        }

        val result = service.read(GetWebsocketMessageById(id = 7, projectId = "project-ws"))

        assertEquals(HistoryReadStatus.PROJECT_MISMATCH, result.status)
        assertEquals("replacement-project", result.projectId)
        verify(exactly = 0) { proxy.webSocketHistory(any()) }
    }
}
