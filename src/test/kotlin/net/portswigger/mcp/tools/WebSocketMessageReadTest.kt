package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.Proxy
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
import kotlin.test.assertEquals

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
