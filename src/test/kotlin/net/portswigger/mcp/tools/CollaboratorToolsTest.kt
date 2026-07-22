package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.*
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import io.mockk.*
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.runBlocking
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
        assertTrue(result.output.error.orEmpty().contains("16 ASCII alphanumeric"))
        verify(exactly = 0) { collaborator.createClient() }
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
        return McpConfig(storage, logging)
    }

    @Suppress("unused")
    private fun montoyaBytes(raw: ByteArray): MontoyaByteArray = mockk<MontoyaByteArray>().also {
        every { it.length() } returns raw.size
        every { it.getBytes() } returns raw
        every { it.subArray(any(), any()) } answers { montoyaBytes(raw.copyOfRange(firstArg(), secondArg())) }
    }
}
