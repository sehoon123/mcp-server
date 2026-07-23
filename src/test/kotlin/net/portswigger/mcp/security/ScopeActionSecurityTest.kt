package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.*
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import javax.swing.SwingUtilities
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ScopeActionSecurityTest {
    private lateinit var config: McpConfig
    private lateinit var originalHandler: ScopeActionApprovalHandler
    private val api = mockk<MontoyaApi>(relaxed = true)

    @BeforeEach
    fun setUp() {
        originalHandler = ScopeActionSecurity.approvalHandler
        val values = mutableMapOf<String, Boolean>()
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers { values[firstArg()] ?: false }
        every { storage.setBoolean(any(), any()) } answers { values[firstArg()] = secondArg() }
        every { storage.getString(any()) } returns ""
        config = McpConfig(storage, mockk<Logging>(relaxed = true))
    }

    @AfterEach
    fun tearDown() {
        ScopeActionSecurity.approvalHandler = originalHandler
    }

    @Test
    fun `disabled scope approval bypasses the handler`() = runBlocking {
        val handler = mockk<ScopeActionApprovalHandler>()
        ScopeActionSecurity.approvalHandler = handler
        config.requireScopeChangeApproval = false

        val allowed = ScopeActionSecurity.checkPermission(
            action = "include 1 URL in Burp Target scope",
            summary = "Project: test\nScope changes: 1",
            reviewContent = "include https://example.test/",
            config = config,
            api = api,
            operation = ScopeChangeApprovalOperation.INCLUDE,
        )

        assertTrue(allowed)
        coVerify(exactly = 0) { handler.requestApproval(any(), any(), any(), any(), any()) }
    }

    @Test
    fun `enabled scope approval forwards only bounded normalized fields`() = runBlocking {
        val handler = mockk<ScopeActionApprovalHandler>()
        ScopeActionSecurity.approvalHandler = handler
        config.requireScopeChangeApproval = true
        coEvery {
            handler.requestApproval(
                "exclude 1 URL from Burp Target scope",
                "Project: test\nScope changes: 1",
                "exclude https://example.test/",
                config,
                api,
            )
        } returns false

        val allowed = ScopeActionSecurity.checkPermission(
            action = "exclude 1 URL from Burp Target scope",
            summary = "Project: test\nScope changes: 1",
            reviewContent = "exclude https://example.test/",
            config = config,
            api = api,
            operation = ScopeChangeApprovalOperation.EXCLUDE,
        )

        assertFalse(allowed)
    }

    @Test
    fun `Always Allow selection disables later include and exclude prompts`() = runBlocking {
        val queuedAction = slot<Runnable>()
        val options = slot<Array<String>>()
        mockkStatic(SwingUtilities::class)
        mockkObject(Dialogs)
        try {
            config.requireScopeChangeApproval = true
            every { SwingUtilities.invokeLater(capture(queuedAction)) } returns Unit
            every { Dialogs.showOptionDialog(any(), any(), capture(options), any(), any()) } returns 2

            val approval = async(start = CoroutineStart.UNDISPATCHED) {
                SwingScopeActionApprovalHandler().requestApproval(
                    action = "include 1 URL in Burp Target scope",
                    summary = "Project: test\nScope changes: 1",
                    reviewContent = "include https://example.test/",
                    config = config,
                    api = api,
                )
            }
            queuedAction.captured.run()

            assertTrue(approval.await())
            assertFalse(config.requireScopeChangeApproval)
            assertTrue(
                options.captured.contentEquals(
                    arrayOf("Allow Once", "Allow for This Session", "Always Allow", "Deny")
                )
            )

            val laterHandler = mockk<ScopeActionApprovalHandler>()
            ScopeActionSecurity.approvalHandler = laterHandler
            assertTrue(
                ScopeActionSecurity.checkPermission(
                    action = "exclude 1 URL from Burp Target scope",
                    summary = "Project: test\nScope changes: 1",
                    reviewContent = "exclude https://example.test/",
                    config = config,
                    api = api,
                    operation = ScopeChangeApprovalOperation.EXCLUDE,
                )
            )
            coVerify(exactly = 0) { laterHandler.requestApproval(any(), any(), any(), any(), any()) }
        } finally {
            unmockkObject(Dialogs)
            unmockkStatic(SwingUtilities::class)
        }
    }

    @Test
    fun `session scope approval covers include and exclude only in the granting session`() = runBlocking {
        val approvals = McpSessionApprovalRegistry(2)
        assertTrue(approvals.activate("scope-session"))
        assertTrue(approvals.activate("other-session"))
        val handler = mockk<ScopeActionApprovalHandler>()
        ScopeActionSecurity.approvalHandler = handler
        config.requireScopeChangeApproval = true
        coEvery { handler.requestApproval(any(), any(), any(), any(), any()) } returns false

        withContext(requireNotNull(approvals.contextFor("scope-session"))) {
            grantCurrentSessionApproval(McpSessionApproval.SCOPE_CHANGES)
            assertTrue(
                ScopeActionSecurity.checkPermission(
                    action = "include 1 URL in Burp Target scope",
                    summary = "Project: test\nScope changes: 1",
                    reviewContent = "include https://example.test/",
                    config = config,
                    api = api,
                    operation = ScopeChangeApprovalOperation.INCLUDE,
                )
            )
            assertTrue(
                ScopeActionSecurity.checkPermission(
                    action = "exclude 1 URL from Burp Target scope",
                    summary = "Project: test\nScope changes: 1",
                    reviewContent = "exclude https://example.test/",
                    config = config,
                    api = api,
                    operation = ScopeChangeApprovalOperation.EXCLUDE,
                )
            )
            assertFalse(isCurrentSessionApproved(McpSessionApproval.REQUEST_ROUTING))
        }
        withContext(requireNotNull(approvals.contextFor("other-session"))) {
            assertFalse(
                ScopeActionSecurity.checkPermission(
                    action = "include 1 URL in Burp Target scope",
                    summary = "Project: test\nScope changes: 1",
                    reviewContent = "include https://example.test/",
                    config = config,
                    api = api,
                    operation = ScopeChangeApprovalOperation.INCLUDE,
                )
            )
        }
        coVerify(exactly = 1) { handler.requestApproval(any(), any(), any(), any(), any()) }
    }

    @Test
    fun `cancellation while the scope dialog is open cannot enable Always Allow`() = runBlocking {
        val queuedAction = slot<Runnable>()
        lateinit var approval: Deferred<Boolean>
        mockkStatic(SwingUtilities::class)
        mockkObject(Dialogs)
        try {
            config.requireScopeChangeApproval = true
            every { SwingUtilities.invokeLater(capture(queuedAction)) } returns Unit
            every { Dialogs.showOptionDialog(any(), any(), any(), any(), any()) } answers {
                approval.cancel()
                2
            }

            approval = async(start = CoroutineStart.UNDISPATCHED) {
                SwingScopeActionApprovalHandler().requestApproval(
                    action = "exclude 1 URL from Burp Target scope",
                    summary = "Project: test\nScope changes: 1",
                    reviewContent = "exclude https://example.test/",
                    config = config,
                    api = api,
                )
            }
            queuedAction.captured.run()
            approval.join()

            assertTrue(approval.isCancelled)
            assertTrue(config.requireScopeChangeApproval)
        } finally {
            unmockkObject(Dialogs)
            unmockkStatic(SwingUtilities::class)
        }
    }

    @Test
    fun `scope approval fields are bounded before reaching the handler`() = runBlocking {
        val handler = mockk<ScopeActionApprovalHandler>()
        ScopeActionSecurity.approvalHandler = handler
        config.requireScopeChangeApproval = true

        assertFailsWith<IllegalArgumentException> {
            ScopeActionSecurity.checkPermission(
                action = "include scope",
                summary = "Project: test",
                reviewContent = "x".repeat(64 * 1024 + 1),
                config = config,
                api = api,
                operation = ScopeChangeApprovalOperation.INCLUDE,
            )
        }
        coVerify(exactly = 0) { handler.requestApproval(any(), any(), any(), any(), any()) }
    }
}
