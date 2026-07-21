package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.*
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import javax.swing.SwingUtilities
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RequestActionSecurityTest {
    private lateinit var config: McpConfig
    private lateinit var originalHandler: RequestActionApprovalHandler
    private val api = mockk<MontoyaApi>()

    @BeforeEach
    fun setUp() {
        originalHandler = RequestActionSecurity.approvalHandler
        val values = mutableMapOf<String, Boolean>()
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers { values[firstArg()] ?: false }
        every { storage.setBoolean(any(), any()) } answers { values[firstArg()] = secondArg() }
        every { storage.getString(any()) } returns ""
        config = McpConfig(storage, mockk<Logging>(relaxed = true))
    }

    @AfterEach
    fun tearDown() {
        RequestActionSecurity.approvalHandler = originalHandler
    }

    @Test
    fun `disabled action approval bypasses the handler`() = runBlocking {
        val handler = mockk<RequestActionApprovalHandler>()
        RequestActionSecurity.approvalHandler = handler
        config.requireRequestActionApproval = false

        val allowed = RequestActionSecurity.checkPermission(
            "create a Repeater tab",
            "proxy:42",
            "example.test:443",
            "none",
            "GET / HTTP/1.1\r\n\r\n",
            config,
            api,
        )

        assertTrue(allowed)
        coVerify(exactly = 0) { handler.requestApproval(any(), any(), any(), any(), any(), any(), any()) }
    }

    @Test
    fun `enabled action approval forwards the normalized operation`() = runBlocking {
        val handler = mockk<RequestActionApprovalHandler>()
        RequestActionSecurity.approvalHandler = handler
        config.requireRequestActionApproval = true
        coEvery {
            handler.requestApproval(
                "send to Intruder",
                "site_map:sitemap_0_deadbeef",
                "example.test:443",
                "set header x-test",
                any(),
                config,
                api,
            )
        } returns false

        val allowed = RequestActionSecurity.checkPermission(
            "send to Intruder",
            "site_map:sitemap_0_deadbeef",
            "example.test:443",
            "set header x-test",
            "GET / HTTP/1.1\r\n\r\n",
            config,
            api,
        )

        assertFalse(allowed)
    }

    @Test
    fun `Always Allow selection disables later request routing prompts`() = runBlocking {
        val queuedAction = slot<Runnable>()
        val options = slot<Array<String>>()
        mockkStatic(SwingUtilities::class)
        mockkObject(Dialogs)
        try {
            config.requireRequestActionApproval = true
            every { SwingUtilities.invokeLater(capture(queuedAction)) } returns Unit
            every { Dialogs.showOptionDialog(any(), any(), capture(options), any(), any()) } returns 1

            val approval = async(start = CoroutineStart.UNDISPATCHED) {
                SwingRequestActionApprovalHandler().requestApproval(
                    "create a Repeater tab from this request",
                    "proxy:1",
                    "example.test:443",
                    "none",
                    "GET / HTTP/1.1\r\n\r\n",
                    config,
                    api,
                )
            }
            queuedAction.captured.run()

            assertTrue(approval.await())
            assertFalse(config.requireRequestActionApproval)
            assertTrue(options.captured.contains("Allow Once"))
            assertTrue(options.captured.contains("Always Allow"))
        } finally {
            unmockkObject(Dialogs)
            unmockkStatic(SwingUtilities::class)
        }
    }

    @Test
    fun `cancellation while the dialog is open cannot enable Always Allow`() = runBlocking {
        val queuedAction = slot<Runnable>()
        lateinit var approval: Deferred<Boolean>
        mockkStatic(SwingUtilities::class)
        mockkObject(Dialogs)
        try {
            config.requireRequestActionApproval = true
            every { SwingUtilities.invokeLater(capture(queuedAction)) } returns Unit
            every { Dialogs.showOptionDialog(any(), any(), any(), any(), any()) } answers {
                approval.cancel()
                1
            }

            approval = async(start = CoroutineStart.UNDISPATCHED) {
                SwingRequestActionApprovalHandler().requestApproval(
                    "send this request to Organizer",
                    "proxy:1",
                    "example.test:443",
                    "none",
                    "GET / HTTP/1.1\r\n\r\n",
                    config,
                    api,
                )
            }
            queuedAction.captured.run()
            approval.join()

            assertTrue(approval.isCancelled)
            assertTrue(config.requireRequestActionApproval)
        } finally {
            unmockkObject(Dialogs)
            unmockkStatic(SwingUtilities::class)
        }
    }

    @Test
    fun `cancelled Swing action approval never opens a queued dialog`() = runBlocking {
        val queuedAction = slot<Runnable>()
        mockkStatic(SwingUtilities::class)
        mockkObject(Dialogs)
        try {
            every { SwingUtilities.invokeLater(capture(queuedAction)) } returns Unit
            every { Dialogs.showOptionDialog(any(), any(), any(), any(), any()) } returns 0

            val approval = async(start = CoroutineStart.UNDISPATCHED) {
                SwingRequestActionApprovalHandler().requestApproval(
                    "send this request to Organizer",
                    "proxy:1",
                    "example.test:443",
                    "none",
                    "GET / HTTP/1.1\r\n\r\n",
                    config,
                    api,
                )
            }
            approval.cancelAndJoin()
            queuedAction.captured.run()

            assertTrue(approval.isCancelled)
            verify(exactly = 0) { Dialogs.showOptionDialog(any(), any(), any(), any(), any()) }
        } finally {
            unmockkObject(Dialogs)
            unmockkStatic(SwingUtilities::class)
        }
    }
}
