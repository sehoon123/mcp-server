package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import io.mockk.*
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.Dialogs
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import javax.swing.SwingUtilities
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SensitiveActionSecurityTest {
    private val originalHandler = SensitiveActionSecurity.approvalHandler

    @AfterEach
    fun restoreHandler() {
        SensitiveActionSecurity.approvalHandler = originalHandler
    }

    @Test
    fun `cancelled sensitive approval does not open a queued dialog`() = runBlocking {
        val api = mockk<MontoyaApi>()
        val queued = slot<Runnable>()
        mockkStatic(SwingUtilities::class)
        mockkObject(Dialogs)
        try {
            every { SwingUtilities.invokeLater(capture(queued)) } returns Unit
            every { Dialogs.showOptionDialog(any(), any(), any(), any(), any()) } returns 0

            val approval = async(start = CoroutineStart.UNDISPATCHED) {
                SwingSensitiveActionApprovalHandler().requestApproval("change scope", "Project: test", null, false, api)
            }
            approval.cancelAndJoin()
            queued.captured.run()

            assertTrue(approval.isCancelled)
            verify(exactly = 0) { Dialogs.showOptionDialog(any(), any(), any(), any(), any()) }
        } finally {
            unmockkObject(Dialogs)
            unmockkStatic(SwingUtilities::class)
        }
    }

    @Test
    fun `sensitive action fields are bounded before reaching an approval handler`() = runBlocking {
        val handler = mockk<SensitiveActionApprovalHandler>()
        SensitiveActionSecurity.approvalHandler = handler
        val api = mockk<MontoyaApi>()

        assertFailsWith<IllegalArgumentException> {
            SensitiveActionSecurity.checkPermission("x", "summary", "a".repeat(1024 * 1024 + 1), api = api)
        }
        coVerify(exactly = 0) { handler.requestApproval(any(), any(), any(), any(), any()) }
    }
}
