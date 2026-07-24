package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.scope.Scope
import io.mockk.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.ScopeActionApprovalHandler
import net.portswigger.mcp.security.ScopeActionSecurity
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ScopeToolsTest {
    private val api = mockk<MontoyaApi>()
    private val project = mockk<Project>()
    private val scope = mockk<Scope>()
    private val proxy = mockk<Proxy>()
    private val logging = mockk<Logging>(relaxed = true)
    private lateinit var metadataIndex: HttpMetadataIndex
    private lateinit var service: ScopeToolService
    private lateinit var config: McpConfig
    private lateinit var originalApprovalHandler: ScopeActionApprovalHandler
    private var scopeApprovalRequired = true

    @BeforeEach
    fun setUp() {
        originalApprovalHandler = ScopeActionSecurity.approvalHandler
        scopeApprovalRequired = true
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns false
        every { storage.getBoolean("requireScopeChangeApproval") } answers { scopeApprovalRequired }
        every { storage.setBoolean("requireScopeChangeApproval", any()) } answers {
            scopeApprovalRequired = secondArg()
        }
        every { storage.getString(any()) } returns ""
        every { api.project() } returns project
        every { project.id() } returns "project-123"
        every { api.scope() } returns scope
        every { api.proxy() } returns proxy
        every { proxy.history() } returns emptyList()
        every { api.logging() } returns logging
        config = McpConfig(storage, logging)
        metadataIndex = HttpMetadataIndex(api)
        service = ScopeToolService(api, config, metadataIndex)
    }

    @AfterEach
    fun tearDown() {
        ScopeActionSecurity.approvalHandler = originalApprovalHandler
    }

    @Test
    fun `scope URL normalization is deterministic and rejects ambiguous authorities`() {
        assertEquals(
            "https://example.test/a/../b?q=1",
            normalizeScopeUrl("https://Example.Test:443/a/../b?q=1"),
        )
        assertEquals("http://[::1]/", normalizeScopeUrl("http://[::1]:80"))
        assertEquals("https://xn--tst-qla.de:8443/", normalizeScopeUrl("https://täst.de:8443/"))

        listOf(
            " https://example.test/",
            "https://user:pass@example.test/",
            "https://example.test/#fragment",
            "ftp://example.test/",
        ).forEach { value ->
            val error = runCatching { normalizeScopeUrl(value) }.exceptionOrNull()
            assertTrue(error is IllegalArgumentException, value)
        }
    }

    @Test
    fun `check scope preserves mixed URL and stable reference order`() = runBlocking {
        val item = mockk<ProxyHttpRequestResponse>()
        val request = mockk<HttpRequest>()
        every { proxy.history(any()) } returns listOf(item)
        every { item.id() } returns 42
        every { item.request() } returns request
        every { item.response() } returns null
        every { request.url() } returns "https://api.example.test/items"
        every { scope.isInScope("https://public.example.test/") } returns false
        every { scope.isInScope("https://api.example.test/items") } returns true

        val result = service.check(
            CheckScope(
                projectId = "project-123",
                targets = listOf(
                    ScopeTarget(url = "https://PUBLIC.example.test:443"),
                    ScopeTarget(ref = HttpMessageReference(HttpMessageSource.PROXY, "42")),
                ),
            )
        )

        assertEquals(ScopeToolStatus.OK, result.status)
        assertEquals(listOf(false, true), result.targets.map { it.inScope })
        assertEquals("https://public.example.test/", result.targets[0].url)
        assertEquals("42", result.targets[1].ref?.id)
        verify(exactly = 1) { proxy.history(any()) }
        verify(exactly = 0) { proxy.history() }
    }

    @Test
    fun `scope update denial performs no mutation`() = runBlocking {
        every { scope.isInScope("https://example.test/") } returns false
        metadataIndex.snapshot("project-123", listOf(HttpMessageSource.PROXY))
        ScopeActionSecurity.approvalHandler = approvalHandler(false)

        val result = service.update(
            UpdateScope(
                "project-123",
                ScopeUpdateOperation.INCLUDE,
                listOf(ScopeTarget(url = "https://example.test/")),
            )
        )

        assertEquals(ScopeToolStatus.ACTION_DENIED, result.status)
        assertEquals(ProjectMutationExecutionState.NOT_STARTED, result.executionState)
        assertEquals(0, result.changedCount)
        verify(exactly = 0) { scope.includeInScope(any()) }
        verify(exactly = 0) { scope.excludeFromScope(any()) }
        assertEquals(
            MetadataIndexRefresh.REUSED,
            metadataIndex.snapshot("project-123", listOf(HttpMessageSource.PROXY)).sources.single().refresh,
        )
    }

    @Test
    fun `scope Always Allow policy bypasses prompts but retains mutation verification`() = runBlocking {
        val url = "https://policy.example.test/"
        every { scope.isInScope(url) } returnsMany listOf(false, false, true)
        every { scope.includeInScope(url) } just runs
        val handler = mockk<ScopeActionApprovalHandler>()
        ScopeActionSecurity.approvalHandler = handler
        config.requireScopeChangeApproval = false

        val result = service.update(
            UpdateScope(
                "project-123",
                ScopeUpdateOperation.INCLUDE,
                listOf(ScopeTarget(url = url)),
            )
        )

        assertEquals(ScopeToolStatus.OK, result.status)
        assertEquals(ProjectMutationExecutionState.COMPLETED, result.executionState)
        assertEquals(1, result.changedCount)
        coVerify(exactly = 0) { handler.requestApproval(any(), any(), any(), any(), any()) }
        verify(exactly = 1) { scope.includeInScope(url) }
        verify(exactly = 3) { scope.isInScope(url) }
    }

    @Test
    fun `scope update applies and verifies each normalized URL after one approval`() = runBlocking {
        val url = "https://example.test/path"
        every { scope.isInScope(url) } returnsMany listOf(false, false, true)
        every { scope.includeInScope(url) } answers {
            runBlocking {
                assertFailsWith<HttpMetadataIndexChangingException> {
                    metadataIndex.observeCurrentProject()
                }
            }
        }
        var review = ""
        ScopeActionSecurity.approvalHandler = object : ScopeActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String,
                config: McpConfig,
                api: MontoyaApi,
            ): Boolean {
                review = reviewContent
                return true
            }
        }

        val result = service.update(
            UpdateScope(
                "project-123",
                ScopeUpdateOperation.INCLUDE,
                listOf(ScopeTarget(url = url)),
            )
        )

        assertEquals(ScopeToolStatus.OK, result.status)
        assertEquals(ProjectMutationExecutionState.COMPLETED, result.executionState)
        assertEquals(1, result.changedCount)
        assertTrue(result.targets.single().inScope)
        assertTrue(result.targets.single().changed == true)
        assertEquals("include $url", review)
        verify(exactly = 1) { scope.includeInScope(url) }
        assertEquals("project-123", metadataIndex.observeCurrentProject())
        assertEquals(
            MetadataIndexRefresh.REBUILT,
            metadataIndex.snapshot("project-123", listOf(HttpMessageSource.PROXY)).sources.single().refresh,
        )
    }

    @Test
    fun `project change after approval is not misreported as an attempted mutation`() = runBlocking {
        val url = "https://example.test/"
        every { project.id() } returnsMany listOf("project-123", "project-123", "other-project")
        every { scope.isInScope(url) } returns false
        ScopeActionSecurity.approvalHandler = approvalHandler(true)

        val result = service.update(
            UpdateScope(
                "project-123",
                ScopeUpdateOperation.INCLUDE,
                listOf(ScopeTarget(url = url)),
            )
        )

        assertEquals(ScopeToolStatus.PROJECT_MISMATCH, result.status)
        assertEquals(ProjectMutationExecutionState.NOT_STARTED, result.executionState)
        assertEquals("other-project", result.projectId)
        verify(exactly = 0) { scope.includeInScope(any()) }
    }

    @Test
    fun `partial scope update fails closed as execution uncertain`() = runBlocking {
        val first = "https://one.example.test/"
        val second = "https://two.example.test/"
        every { scope.isInScope(first) } returnsMany listOf(false, false, true)
        every { scope.isInScope(second) } returnsMany listOf(false, false)
        every { scope.includeInScope(first) } just runs
        every { scope.includeInScope(second) } throws IllegalStateException("Burp failure")
        ScopeActionSecurity.approvalHandler = approvalHandler(true)

        val result = service.update(
            UpdateScope(
                "project-123",
                ScopeUpdateOperation.INCLUDE,
                listOf(ScopeTarget(url = first), ScopeTarget(url = second)),
            )
        )

        assertEquals(ScopeToolStatus.EXECUTION_UNCERTAIN, result.status)
        assertEquals(ProjectMutationExecutionState.UNCERTAIN, result.executionState)
        assertEquals(1, result.changedCount)
        assertEquals(1, result.errorTargetIndex)
        assertTrue(result.error.orEmpty().contains("partially"))
        assertTrue(result.error.orEmpty().contains(UNCERTAIN_RETRY_GUIDANCE))
    }

    @Test
    fun `scope mutation cancellation propagates and releases the metadata barrier`() = runBlocking {
        val url = "https://cancel.example.test/"
        every { scope.isInScope(url) } returnsMany listOf(false, false)
        every { scope.includeInScope(url) } throws CancellationException("cancelled")
        ScopeActionSecurity.approvalHandler = approvalHandler(true)

        assertFailsWith<CancellationException> {
            service.update(
                UpdateScope(
                    "project-123",
                    ScopeUpdateOperation.INCLUDE,
                    listOf(ScopeTarget(url = url)),
                )
            )
        }

        verify(exactly = 1) { scope.includeInScope(url) }
        assertEquals("project-123", metadataIndex.observeCurrentProject())
    }

    @Test
    fun `duplicate normalized scope targets are rejected before approval`() = runBlocking {
        val handler = mockk<ScopeActionApprovalHandler>()
        ScopeActionSecurity.approvalHandler = handler

        val result = service.update(
            UpdateScope(
                "project-123",
                ScopeUpdateOperation.EXCLUDE,
                listOf(
                    ScopeTarget(url = "https://EXAMPLE.test:443/a"),
                    ScopeTarget(url = "https://example.test/a"),
                ),
            )
        )

        assertEquals(ScopeToolStatus.INVALID_ARGUMENT, result.status)
        assertFalse(result.error.isNullOrBlank())
        coVerify(exactly = 0) { handler.requestApproval(any(), any(), any(), any(), any()) }
        verify(exactly = 0) { scope.excludeFromScope(any()) }
    }

    private fun approvalHandler(approved: Boolean) = object : ScopeActionApprovalHandler {
        override suspend fun requestApproval(
            action: String,
            summary: String,
            reviewContent: String,
            config: McpConfig,
            api: MontoyaApi,
        ): Boolean = approved
    }
}
