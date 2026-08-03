package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.BurpSuite
import burp.api.montoya.project.Project
import burp.api.montoya.logging.Logging
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull

class BurpOptionsServiceTest {
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val config = mockk<McpConfig>()
    private val burpSuite = mockk<BurpSuite>()
    private val metadataIndex = mockk<HttpMetadataIndex>(relaxed = true)
    private lateinit var service: BurpOptionsService

    @BeforeEach
    fun setUp() {
        every { api.burpSuite() } returns burpSuite
        every { config.approvalYoloMode } returns true
        every { config.configEditingTooling } returns true
        every { config.filterConfigCredentials } returns false
        service = BurpOptionsService(api, config, metadataIndex)
    }

    @Test
    fun `user configuration read remains project independent`() = runBlocking {
        every { burpSuite.exportUserOptionsAsJson() } returns "{\"user_options\":{}}"

        val response = service.get(GetBurpOptions(BurpOptionsLevel.USER))

        assertEquals(StandardToolStatus.OK, response.output.status)
        assertEquals(ToolRetryGuidance.NOT_APPLICABLE, response.output.retry)
        assertEquals("{\"user_options\":{}}", response.output.configuration)
        assertEquals(false, response.output.credentialsFiltered)
        assertEquals(false, response.isError)
        verify(exactly = 0) { api.project() }
    }

    @Test
    fun `project configuration read discards an export after the project changes`() = runBlocking {
        val project = mockk<Project>()
        every { api.project() } returns project
        every { project.id() } returnsMany listOf("project-a", "project-a", "project-b")
        every { burpSuite.exportProjectOptionsAsJson() } returns "{\"project_options\":{}}"

        val response = service.get(GetBurpOptions(BurpOptionsLevel.PROJECT))

        assertEquals(StandardToolStatus.PROJECT_MISMATCH, response.output.status)
        assertEquals(ToolRetryGuidance.AFTER_USER_ACTION, response.output.retry)
        assertNull(response.output.configuration)
        assertEquals(true, response.isError)
        verify(exactly = 1) { burpSuite.exportProjectOptionsAsJson() }
    }

    @Test
    fun `oversized configuration is rejected before approval or Burp access`() = runBlocking {
        val response = service.set(
            SetBurpOptions(BurpOptionsLevel.PROJECT, "x".repeat(1024 * 1024 + 1))
        )

        assertEquals(StandardToolStatus.INVALID_ARGUMENT, response.output.status)
        assertEquals(ToolRetryGuidance.AFTER_CORRECTION, response.output.retry)
        assertEquals(StandardExecutionState.NOT_STARTED, response.output.executionState)
        assertEquals(true, response.isError)
        verify(exactly = 0) { api.project() }
        verify(exactly = 0) { api.burpSuite() }
    }

    @Test
    fun `enabled credential filtering removes exported secret values`() = runBlocking {
        every { config.filterConfigCredentials } returns true
        every { burpSuite.exportUserOptionsAsJson() } returns """
            {"user_options":{"connections":{"platform_authentication":{"credentials":[{"username":"user","password":"secret-value"}]}}}}
        """.trimIndent()

        val response = service.get(GetBurpOptions(BurpOptionsLevel.USER))

        assertEquals(StandardToolStatus.OK, response.output.status)
        assertEquals(true, response.output.credentialsFiltered)
        assertFalse(response.output.configuration.orEmpty().contains("secret-value"))
    }

    @Test
    fun `project import runs once inside the shared metadata mutation barrier`() = runBlocking {
        val project = mockk<Project>()
        val logging = mockk<Logging>(relaxed = true)
        val suppliedJson = "{\"project_options\":{\"secret\":\"secret-value\"}}"
        every { api.project() } returns project
        every { api.logging() } returns logging
        every { project.id() } returns "project-a"
        every { burpSuite.importProjectOptionsFromJson(suppliedJson) } returns Unit
        coEvery { metadataIndex.withMutation<Unit>(any()) } coAnswers {
            firstArg<suspend () -> Unit>().invoke()
        }

        val response = service.set(SetBurpOptions(BurpOptionsLevel.PROJECT, suppliedJson))

        assertEquals(StandardToolStatus.OK, response.output.status)
        assertEquals(ToolRetryGuidance.NOT_APPLICABLE, response.output.retry)
        assertEquals(StandardExecutionState.COMPLETED, response.output.executionState)
        coVerify(exactly = 1) { metadataIndex.withMutation<Unit>(any()) }
        verify(exactly = 1) { burpSuite.importProjectOptionsFromJson(suppliedJson) }
        verify(exactly = 0) { logging.logToOutput(match { "secret-value" in it }) }
    }

    @Test
    fun `Burp cancellation after user import invocation is uncertain`() = runBlocking {
        every { burpSuite.importUserOptionsFromJson(any()) } throws CancellationException("cancelled")

        val response = service.set(
            SetBurpOptions(BurpOptionsLevel.USER, "{\"user_options\":{}}")
        )

        assertEquals(StandardToolStatus.BURP_ERROR, response.output.status)
        assertEquals(ToolRetryGuidance.DO_NOT_RETRY, response.output.retry)
        assertEquals(StandardExecutionState.UNCERTAIN, response.output.executionState)
        assertEquals(true, response.isError)
        verify(exactly = 1) { burpSuite.importUserOptionsFromJson(any()) }
        verify(exactly = 0) { api.project() }
    }
}
