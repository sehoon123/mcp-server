package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class YoloModeSecurityTest {
    private val originalHttpHandler = HttpRequestSecurity.approvalHandler
    private val originalRequestActionHandler = RequestActionSecurity.approvalHandler
    private val originalScopeHandler = ScopeActionSecurity.approvalHandler
    private val originalDataHandler = DataAccessSecurity.approvalHandler
    private val originalSensitiveHandler = SensitiveActionSecurity.approvalHandler

    @AfterEach
    fun restoreHandlers() {
        HttpRequestSecurity.approvalHandler = originalHttpHandler
        RequestActionSecurity.approvalHandler = originalRequestActionHandler
        ScopeActionSecurity.approvalHandler = originalScopeHandler
        DataAccessSecurity.approvalHandler = originalDataHandler
        SensitiveActionSecurity.approvalHandler = originalSensitiveHandler
    }

    @Test
    fun `YOLO mode bypasses every approval category but not input validation`() = runBlocking {
        val config = config().apply {
            requireHttpRequestApproval = true
            requireRequestActionApproval = true
            requireScopeChangeApproval = true
            requireDataAccessApproval = true
            approvalYoloMode = true
        }
        val api = mockk<MontoyaApi>()
        var promptCount = 0

        HttpRequestSecurity.approvalHandler = object : UserApprovalHandler {
            override suspend fun requestApproval(
                hostname: String,
                port: Int,
                config: McpConfig,
                requestContent: String?,
                api: MontoyaApi?,
            ): Boolean {
                promptCount++
                return false
            }
        }
        RequestActionSecurity.approvalHandler = object : RequestActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                source: String,
                target: String,
                changes: String,
                requestContent: String,
                config: McpConfig,
                api: MontoyaApi,
            ): Boolean {
                promptCount++
                return false
            }
        }
        ScopeActionSecurity.approvalHandler = object : ScopeActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String,
                config: McpConfig,
                api: MontoyaApi,
            ): Boolean {
                promptCount++
                return false
            }
        }
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                promptCount++
                return false
            }
        }
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean {
                promptCount++
                return false
            }
        }

        assertTrue(HttpRequestSecurity.checkHttpRequestPermission("example.test", 443, config))
        var requestMaterialized = false
        assertTrue(
            HttpRequestSecurity.checkHttpRequestPermissionLazy("example.test", 443, config) {
                requestMaterialized = true
                "GET / HTTP/1.1\r\n\r\n"
            }
        )
        assertFalse(requestMaterialized)
        assertTrue(
            RequestActionSecurity.checkPermission(
                action = "open in Repeater",
                source = "proxy:1",
                target = "example.test:443",
                changes = "none",
                requestContent = "GET / HTTP/1.1\r\n\r\n",
                config = config,
                api = api,
            )
        )
        assertTrue(
            ScopeActionSecurity.checkPermission(
                action = "include one URL",
                summary = "one URL",
                reviewContent = "https://example.test/",
                config = config,
                api = api,
                operation = ScopeChangeApprovalOperation.INCLUDE,
            )
        )
        assertTrue(DataAccessSecurity.checkDataAccessPermission(DataAccessType.HTTP_HISTORY, config))
        assertTrue(
            SensitiveActionSecurity.checkPermission(
                action = "change Proxy Intercept state",
                summary = "Set Proxy Intercept to disabled",
                api = api,
                config = config,
                auditOperation = SensitiveActionAuditOperation.PROXY_INTERCEPT,
            )
        )

        assertFalse(HttpRequestSecurity.checkHttpRequestPermission("bad host", 443, config))
        assertFailsWith<IllegalArgumentException> {
            ScopeActionSecurity.checkPermission(
                action = "",
                summary = "one URL",
                reviewContent = "https://example.test/",
                config = config,
                api = api,
                operation = ScopeChangeApprovalOperation.INCLUDE,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ScopeActionSecurity.checkPermission(
                action = "include one URL",
                summary = "",
                reviewContent = "https://example.test/",
                config = config,
                api = api,
                operation = ScopeChangeApprovalOperation.INCLUDE,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ScopeActionSecurity.checkPermission(
                action = "include one URL",
                summary = "one URL",
                reviewContent = "invalid\u0000review",
                config = config,
                api = api,
                operation = ScopeChangeApprovalOperation.INCLUDE,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            SensitiveActionSecurity.checkPermission("", "summary", api = api, config = config)
        }
        assertFailsWith<IllegalArgumentException> {
            SensitiveActionSecurity.checkPermission("change state", "", api = api, config = config)
        }
        assertFailsWith<IllegalArgumentException> {
            SensitiveActionSecurity.checkPermission(
                "change state",
                "summary",
                "x".repeat(2 * 1024 * 1024 + 1),
                api = api,
                config = config,
            )
        }
        assertTrue(promptCount == 0)
    }

    private fun config(): McpConfig {
        val values = mutableMapOf<String, Any>()
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers { values[firstArg()] as? Boolean ?: false }
        every { storage.setBoolean(any(), any()) } answers { values[firstArg()] = secondArg<Boolean>() }
        every { storage.getString(any()) } answers { values[firstArg()] as? String ?: "" }
        every { storage.setString(any(), any()) } answers { values[firstArg()] = secondArg<String>() }
        return McpConfig(storage, mockk<Logging>(relaxed = true))
    }
}
