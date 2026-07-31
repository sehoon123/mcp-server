package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.*
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import io.mockk.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withTimeout
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.time.ZonedDateTime
import java.util.Base64
import java.util.Optional
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CollaboratorToolsTest {
    private val api = mockk<MontoyaApi>()
    private val collaborator = mockk<Collaborator>()
    private val client = mockk<CollaboratorClient>()
    private val logging = mockk<Logging>(relaxed = true)
    private val project = mockk<Project>()
    private val projectId = "collaborator-project"
    private lateinit var originalDataHandler: DataAccessApprovalHandler

    @BeforeEach
    fun setUp() {
        originalDataHandler = DataAccessSecurity.approvalHandler
        every { api.collaborator() } returns collaborator
        every { collaborator.createClient() } returns client
        every { api.logging() } returns logging
        every { api.project() } returns project
        every { project.id() } returns projectId
    }

    @AfterEach
    fun tearDown() {
        DataAccessSecurity.approvalHandler = originalDataHandler
    }

    @Test
    fun `custom payload data enforces Burp ASCII alphanumeric limit before client creation`() = runBlocking {
        val service = CollaboratorToolService(api, pollIntervalMs = 1)

        val result = service.generate(GenerateCollaboratorPayload(projectId = projectId, customData = "not-valid-data"))

        assertEquals(CollaboratorToolStatus.INVALID_ARGUMENT, result.output.status)
        assertEquals(null, result.output.projectId)
        assertTrue(result.output.error.orEmpty().contains("16 ASCII alphanumeric"))
        verify(exactly = 0) { collaborator.createClient() }
    }

    @Test
    fun `project capture failure does not echo caller ID for Collaborator operations`() = runBlocking {
        every { project.id() } throws IllegalStateException("synthetic project failure")
        val service = CollaboratorToolService(api, pollIntervalMs = 1)

        val generation = service.generate(GenerateCollaboratorPayload(projectId = projectId))
        val interactions = service.interactions(
            GetCollaboratorInteractions(projectId = projectId),
            config(false),
        ) { _, _, _ -> }

        assertEquals(CollaboratorToolStatus.BURP_ERROR, generation.output.status)
        assertEquals(null, generation.output.projectId)
        assertEquals(CollaboratorToolStatus.BURP_ERROR, interactions.output.status)
        assertEquals(null, interactions.output.projectId)
        verify(exactly = 0) { collaborator.createClient() }
    }

    @Test
    fun `project transition during payload generation is execution uncertain and withholds the payload`() = runBlocking {
        var currentProjectId = projectId
        every { project.id() } answers { currentProjectId }
        val payload = mockk<CollaboratorPayload>()
        val server = mockk<CollaboratorServer>()
        every { client.generatePayload() } answers {
            currentProjectId = "replacement-project"
            payload
        }
        every { payload.toString() } returns "generated.example"
        every { payload.id() } returns mockk(relaxed = true)
        every { client.server() } returns server
        every { server.address() } returns "collaborator.example"
        val service = CollaboratorToolService(api, pollIntervalMs = 1)

        val result = service.generate(GenerateCollaboratorPayload(projectId = projectId))

        assertEquals(CollaboratorToolStatus.EXECUTION_UNCERTAIN, result.output.status)
        assertEquals(HttpMessageExecutionState.UNCERTAIN, result.output.executionState)
        assertEquals(ToolRetryGuidance.DO_NOT_RETRY, result.output.retry)
        assertEquals(null, result.output.payload)
        assertTrue(result.output.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
    }

    @Test
    fun `payload generation cancellation after invocation is execution uncertain`() = runBlocking {
        every { client.generatePayload() } throws CancellationException("cancelled")
        val service = CollaboratorToolService(api, pollIntervalMs = 1)

        val result = service.generate(GenerateCollaboratorPayload(projectId = projectId))

        assertEquals(CollaboratorToolStatus.EXECUTION_UNCERTAIN, result.output.status)
        assertEquals(HttpMessageExecutionState.UNCERTAIN, result.output.executionState)
        assertEquals(ToolRetryGuidance.DO_NOT_RETRY, result.output.retry)
    }

    @Test
    fun `caller cancellation during payload generation propagates`() = runBlocking {
        lateinit var invocationJob: Job
        every { client.generatePayload() } answers {
            invocationJob.cancel(CancellationException("caller cancelled"))
            throw CancellationException("caller cancelled")
        }
        val service = CollaboratorToolService(api, pollIntervalMs = 1)

        supervisorScope {
            val invocation = async {
                invocationJob = currentCoroutineContext()[Job]!!
                service.generate(GenerateCollaboratorPayload(projectId = projectId))
            }
            assertFailsWith<CancellationException> { invocation.await() }
        }

        verify(exactly = 1) { client.generatePayload() }
    }

    @Test
    fun `project mismatch is rejected before Collaborator client creation`() = runBlocking {
        every { project.id() } returns "other-project"
        val service = CollaboratorToolService(api, pollIntervalMs = 1)

        val result = service.interactions(
            GetCollaboratorInteractions(projectId),
            config(false),
        ) { _, _, _ -> }

        assertEquals(CollaboratorToolStatus.PROJECT_MISMATCH, result.output.status)
        assertEquals("other-project", result.output.projectId)
        verify(exactly = 0) { collaborator.createClient() }
    }

    @Test
    fun `switching projects rotates the extension-owned Collaborator client`() = runBlocking {
        val secondClient = mockk<CollaboratorClient>()
        every { collaborator.createClient() } returnsMany listOf(client, secondClient)
        every { client.getAllInteractions() } returns emptyList()
        every { secondClient.getAllInteractions() } returns emptyList()
        val service = CollaboratorToolService(api, pollIntervalMs = 1)

        val first = service.interactions(GetCollaboratorInteractions(projectId), config(false)) { _, _, _ -> }
        every { project.id() } returns "second-project"
        val second = service.interactions(GetCollaboratorInteractions("second-project"), config(false)) { _, _, _ -> }

        assertEquals(CollaboratorToolStatus.OK, first.output.status)
        assertEquals(CollaboratorToolStatus.OK, second.output.status)
        verify(exactly = 1) { client.getAllInteractions() }
        verify(exactly = 1) { secondClient.getAllInteractions() }
        verify(exactly = 2) { collaborator.createClient() }
    }

    @Test
    fun `project boundary reset rotates Collaborator client even when the identifier is unchanged`() = runBlocking {
        val secondClient = mockk<CollaboratorClient>()
        every { collaborator.createClient() } returnsMany listOf(client, secondClient)
        every { client.getAllInteractions() } returns emptyList()
        every { secondClient.getAllInteractions() } returns emptyList()
        val service = CollaboratorToolService(api, pollIntervalMs = 1)

        val first = service.interactions(GetCollaboratorInteractions(projectId), config(false)) { _, _, _ -> }
        service.resetForProjectBoundary()
        val second = service.interactions(GetCollaboratorInteractions(projectId), config(false)) { _, _, _ -> }

        assertEquals(CollaboratorToolStatus.OK, first.output.status)
        assertEquals(CollaboratorToolStatus.OK, second.output.status)
        verify(exactly = 1) { client.getAllInteractions() }
        verify(exactly = 1) { secondClient.getAllInteractions() }
        verify(exactly = 2) { collaborator.createClient() }
    }

    @Test
    fun `interaction exactly equal to since is excluded`() = runBlocking {
        val boundary = ZonedDateTime.parse("2025-01-02T00:00:00Z")
        every { client.getAllInteractions() } returns listOf(
            interaction("equal", boundary),
            interaction("after", boundary.plusSeconds(1)),
        )
        val service = CollaboratorToolService(api, pollIntervalMs = 1)

        val result = service.interactions(
            GetCollaboratorInteractions(projectId = projectId, since = boundary.toInstant().toString()),
            config(false),
        ) { _, _, _ -> }

        assertEquals(CollaboratorToolStatus.OK, result.output.status)
        assertEquals(listOf("after"), result.output.interactions.map { it.id })
    }

    @Test
    fun `long poll reports progress and returns as soon as an interaction arrives`() = runBlocking {
        val interaction = interaction("id-1", ZonedDateTime.parse("2025-01-02T00:00:00Z"))
        every { client.getAllInteractions() } returnsMany listOf(emptyList(), listOf(interaction))
        val progress = mutableListOf<String>()
        val service = CollaboratorToolService(api, pollIntervalMs = 1)

        val result = service.interactions(
            GetCollaboratorInteractions(projectId = projectId, waitSeconds = 2, since = "2025-01-01T00:00:00Z"),
            config(false),
        ) { _, _, message -> progress += message.orEmpty() }

        assertEquals(CollaboratorToolStatus.OK, result.output.status)
        assertEquals(listOf("id-1"), result.output.interactions.map { it.id })
        assertTrue(result.output.waitedMillis < 2_000)
        assertTrue(progress.any { it.contains("attempt 2") })
        assertTrue(progress.last().contains("completed"))
        verify(exactly = 2) { client.getAllInteractions() }
        verify(exactly = 1) { collaborator.createClient() }
    }

    @Test
    fun `result count and interaction details are byte bounded`() = runBlocking {
        val first = interaction("new", ZonedDateTime.parse("2025-01-03T00:00:00Z"), customData = "x".repeat(2_000))
        val second = interaction("old", ZonedDateTime.parse("2025-01-01T00:00:00Z"))
        every { client.getAllInteractions() } returns listOf(second, first)
        val service = CollaboratorToolService(api, pollIntervalMs = 1)

        val result = service.interactions(
            GetCollaboratorInteractions(projectId = projectId, maxResults = 1, detailLimitBytes = 8, newestFirst = true),
            config(false),
        ) { _, _, _ -> }

        assertEquals(1, result.output.returned)
        assertEquals(2, result.output.matched)
        assertTrue(result.output.hasMore)
        assertEquals("new", result.output.interactions.single().id)
        assertEquals(1_024, result.output.interactions.single().customData?.length)
        assertTrue(result.output.interactions.single().customDataTruncated)
    }

    @Test
    fun `SMTP text slicing counts UTF-8 bytes without allocating the complete encoded conversation`() = runBlocking {
        val smtp = mockk<SmtpDetails>()
        every { smtp.protocol() } returns SmtpProtocol.SMTP
        every { smtp.conversation() } returns "😀éa"
        val interaction = interaction(
            "smtp",
            ZonedDateTime.parse("2025-01-03T00:00:00Z"),
            type = InteractionType.SMTP,
            smtp = smtp,
        )
        every { client.getAllInteractions() } returns listOf(interaction)
        val service = CollaboratorToolService(api, pollIntervalMs = 1)

        val result = service.interactions(
            GetCollaboratorInteractions(
                projectId = projectId,
                detailLimitBytes = 5,
                detailEncoding = CollaboratorDetailEncoding.BASE64,
            ),
            config(false),
        ) { _, _, _ -> }

        val slice = result.output.interactions.single().smtpDetails!!.conversation!!
        assertEquals(7, slice.totalBytes)
        assertEquals(5, slice.returnedBytes)
        assertTrue(slice.hasMore)
        assertTrue(Base64.getDecoder().decode(slice.data).contentEquals("😀éa".toByteArray().copyOf(5)))
    }

    @Test
    fun `invalid polling bounds fail before creating a Collaborator client`() = runBlocking {
        val service = CollaboratorToolService(api, pollIntervalMs = 1)

        val result = service.interactions(
            GetCollaboratorInteractions(projectId = projectId, waitSeconds = 121),
            config(false),
        ) { _, _, _ -> }

        assertEquals(CollaboratorToolStatus.INVALID_ARGUMENT, result.output.status)
        verify(exactly = 0) { collaborator.createClient() }
    }

    @Test
    fun `scan-window omission does not claim unknown records are matching`() = runBlocking {
        val old = interaction("old", ZonedDateTime.parse("2025-01-01T00:00:00Z"))
        every { client.getAllInteractions() } returns List(10_001) { old }
        val service = CollaboratorToolService(api, pollIntervalMs = 1)

        val result = service.interactions(
            GetCollaboratorInteractions(
                projectId = projectId,
                since = "2026-01-01T00:00:00Z",
            ),
            config(false),
        ) { _, _, _ -> }

        assertEquals(CollaboratorToolStatus.OK, result.output.status)
        assertTrue(result.output.scanLimitReached)
        assertEquals(0, result.output.matched)
        assertFalse(result.output.hasMore)
    }

    @Test
    fun `final project accessor failure returns bounded burp error without interactions`() = runBlocking {
        var projectReads = 0
        every { project.id() } answers {
            projectReads++
            if (projectReads == 4) throw IllegalStateException("PRIVATE_SENTINEL")
            projectId
        }
        every { client.getAllInteractions() } returns emptyList()
        val service = CollaboratorToolService(api, pollIntervalMs = 1)

        val result = service.interactions(GetCollaboratorInteractions(projectId), config(false)) { _, _, _ -> }

        assertEquals(CollaboratorToolStatus.BURP_ERROR, result.output.status)
        assertEquals(projectId, result.output.projectId)
        assertTrue(result.output.interactions.isEmpty())
        assertFalse(result.output.error.orEmpty().contains("PRIVATE_SENTINEL"))
        verify(exactly = 1) { client.getAllInteractions() }
    }

    @Test
    fun `interaction denial after project transition returns mismatch without client access`() = runBlocking {
        var currentProjectId = projectId
        every { project.id() } answers { currentProjectId }
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                currentProjectId = "project-after-denial"
                return false
            }
        }
        val service = CollaboratorToolService(api, pollIntervalMs = 1)

        val result = service.interactions(GetCollaboratorInteractions(projectId), config(true)) { _, _, _ -> }

        assertEquals(CollaboratorToolStatus.PROJECT_MISMATCH, result.output.status)
        assertEquals("project-after-denial", result.output.projectId)
        assertTrue(result.output.interactions.isEmpty())
        verify(exactly = 0) { collaborator.createClient() }
    }

    @Test
    fun `interaction permission denial exposes no Collaborator state`() = runBlocking {
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean = false
        }
        val service = CollaboratorToolService(api, pollIntervalMs = 1)

        val result = service.interactions(GetCollaboratorInteractions(projectId), config(true)) { _, _, _ -> }

        assertEquals(CollaboratorToolStatus.ACCESS_DENIED, result.output.status)
        assertTrue(result.output.interactions.isEmpty())
        verify(exactly = 0) { collaborator.createClient() }
    }

    @Test
    fun `long poll cancellation propagates without a late poll`() = runBlocking {
        every { client.getAllInteractions() } returns emptyList()
        val service = CollaboratorToolService(api, pollIntervalMs = 1_000)

        assertFailsWith<TimeoutCancellationException> {
            withTimeout(30) {
                service.interactions(GetCollaboratorInteractions(projectId = projectId, waitSeconds = 120), config(false)) { _, _, _ -> }
            }
        }
        verify(exactly = 1) { client.getAllInteractions() }
    }

    private fun interaction(
        id: String,
        timestamp: ZonedDateTime,
        customData: String? = null,
        type: InteractionType = InteractionType.DNS,
        smtp: SmtpDetails? = null,
    ): Interaction {
        val interactionId = mockk<InteractionId>()
        every { interactionId.toString() } returns id
        return mockk<Interaction>().also {
            every { it.id() } returns interactionId
            every { it.type() } returns type
            every { it.timeStamp() } returns timestamp
            every { it.clientIp() } returns InetAddress.getByName("127.0.0.1")
            every { it.clientPort() } returns 53
            every { it.customData() } returns Optional.ofNullable(customData)
            every { it.dnsDetails() } returns Optional.empty()
            every { it.httpDetails() } returns Optional.empty()
            every { it.smtpDetails() } returns Optional.ofNullable(smtp)
        }
    }

    private fun config(requireDataApproval: Boolean): McpConfig {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers {
            firstArg<String>() == "requireDataAccessApproval" && requireDataApproval
        }
        every { storage.getString(any()) } returns ""
        return McpConfig(storage, logging, net.portswigger.mcp.testPreferences())
    }

    @Suppress("unused")
    private fun montoyaBytes(raw: ByteArray): MontoyaByteArray = mockk<MontoyaByteArray>().also {
        every { it.length() } returns raw.size
        every { it.getBytes() } returns raw
        every { it.subArray(any(), any()) } answers { montoyaBytes(raw.copyOfRange(firstArg(), secondArg())) }
    }
}
