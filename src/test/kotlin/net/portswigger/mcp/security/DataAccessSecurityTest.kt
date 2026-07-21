package net.portswigger.mcp.security

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.*
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DataAccessSecurityTest {
    private val originalHandler = DataAccessSecurity.approvalHandler

    @AfterEach
    fun restoreHandler() {
        DataAccessSecurity.approvalHandler = originalHandler
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
