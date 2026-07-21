package net.portswigger.mcp.security

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
import org.junit.jupiter.api.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import javax.swing.SwingUtilities

class DataAccessSecurityTest {
    private val originalHandler = DataAccessSecurity.approvalHandler

    @AfterEach
    fun restoreHandler() {
        DataAccessSecurity.approvalHandler = originalHandler
    }

    @Test
    fun `cancelled data approval does not open a queued dialog`() = runBlocking {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns false
        every { storage.getString(any()) } returns ""
        val config = McpConfig(storage, mockk<Logging>(relaxed = true))
        val queuedAction = slot<Runnable>()
        mockkStatic(SwingUtilities::class)
        mockkObject(Dialogs)
        try {
            every { SwingUtilities.invokeLater(capture(queuedAction)) } returns Unit
            every { Dialogs.showOptionDialog(any(), any(), any(), any(), any()) } returns 0

            val approval = async(start = CoroutineStart.UNDISPATCHED) {
                SwingDataAccessApprovalHandler().requestDataAccess(DataAccessType.HTTP_HISTORY, config)
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

    @Test
    fun `cancellation while data approval is open cannot persist Always Allow`() = runBlocking {
        val values = mutableMapOf<String, Boolean>()
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers { values[firstArg()] ?: false }
        every { storage.setBoolean(any(), any()) } answers { values[firstArg()] = secondArg() }
        every { storage.getString(any()) } returns ""
        val config = McpConfig(storage, mockk<Logging>(relaxed = true))
        val queuedAction = slot<Runnable>()
        lateinit var approval: Deferred<Boolean>
        mockkStatic(SwingUtilities::class)
        mockkObject(Dialogs)
        try {
            every { SwingUtilities.invokeLater(capture(queuedAction)) } returns Unit
            every { Dialogs.showOptionDialog(any(), any(), any(), any(), any()) } answers {
                approval.cancel()
                1
            }

            approval = async(start = CoroutineStart.UNDISPATCHED) {
                SwingDataAccessApprovalHandler().requestDataAccess(DataAccessType.SITE_MAP, config)
            }
            queuedAction.captured.run()
            approval.join()

            assertTrue(approval.isCancelled)
            assertFalse(config.alwaysAllowSiteMap)
            verify(exactly = 0) { storage.setBoolean("_alwaysAllowSiteMap", true) }
        } finally {
            unmockkObject(Dialogs)
            unmockkStatic(SwingUtilities::class)
        }
    }

    @Test
    fun `Site Map reads require approval unless explicitly allowed`() = runBlocking {
        val values = mutableMapOf<String, Any>("requireDataAccessApproval" to true)
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers { values[firstArg()] as? Boolean ?: false }
        every { storage.setBoolean(any(), any()) } answers {
            values[firstArg()] = secondArg<Boolean>()
        }
        every { storage.getString(any()) } returns ""
        val config = McpConfig(storage, mockk<Logging>(relaxed = true))
        var approvalRequests = 0
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                approvalRequests++
                assertTrue(accessType == DataAccessType.SITE_MAP)
                return false
            }
        }

        assertFalse(DataAccessSecurity.checkDataAccessPermission(DataAccessType.SITE_MAP, config))
        assertTrue(approvalRequests == 1)

        config.alwaysAllowSiteMap = true
        assertTrue(DataAccessSecurity.checkDataAccessPermission(DataAccessType.SITE_MAP, config))
        assertTrue(approvalRequests == 1)
    }

    @Test
    fun `Scanner issue reads require approval unless explicitly allowed`() = runBlocking {
        val values = mutableMapOf<String, Any>("requireDataAccessApproval" to true)
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers { values[firstArg()] as? Boolean ?: false }
        every { storage.setBoolean(any(), any()) } answers {
            values[firstArg()] = secondArg<Boolean>()
        }
        every { storage.getString(any()) } returns ""
        val config = McpConfig(storage, mockk<Logging>(relaxed = true))
        var approvalRequests = 0
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(
                accessType: DataAccessType,
                config: McpConfig,
            ): Boolean {
                approvalRequests++
                assertTrue(accessType == DataAccessType.SCANNER_ISSUES)
                return false
            }
        }

        assertFalse(DataAccessSecurity.checkDataAccessPermission(DataAccessType.SCANNER_ISSUES, config))
        assertTrue(approvalRequests == 1)

        config.alwaysAllowScannerIssues = true
        assertTrue(DataAccessSecurity.checkDataAccessPermission(DataAccessType.SCANNER_ISSUES, config))
        assertTrue(approvalRequests == 1)
    }
}
