package net.portswigger.mcp.config

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.persistence.Preferences
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.CancellationException
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class McpConfigTest {

    private val installationTokenKey = "independentMcpBridge.localBearerToken.v1"
    private lateinit var persistedObject: PersistedObject
    private lateinit var preferences: Preferences
    private lateinit var config: McpConfig
    private lateinit var mockLogging: Logging
    private lateinit var projectValues: MutableMap<String, Any>
    private lateinit var preferenceValues: MutableMap<String, String>

    @BeforeEach
    fun setup() {
        projectValues = mutableMapOf()
        preferenceValues = mutableMapOf()
        persistedObject = projectStorage(projectValues)
        preferences = preferenceStorage(preferenceValues)

        mockLogging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
        }

        config = McpConfig(persistedObject, mockLogging, preferences)
    }

    @Test
    fun `addAutoApproveTarget should add new target`() {
        val result = config.addAutoApproveTarget("example.com")

        assertTrue(result)
        assertEquals("example.com", config.autoApproveTargets)
        verify { persistedObject.setString("_autoApproveTargets", "example.com") }
    }

    @Test
    fun `addAutoApproveTarget should not add duplicate target`() {
        config.addAutoApproveTarget("example.com")
        val result = config.addAutoApproveTarget("example.com")

        assertFalse(result)
        assertEquals("example.com", config.autoApproveTargets)
    }

    @Test
    fun `addAutoApproveTarget should trim whitespace`() {
        val result = config.addAutoApproveTarget("  example.com  ")

        assertTrue(result)
        assertEquals("example.com", config.autoApproveTargets)
    }

    @Test
    fun `addAutoApproveTarget should not add empty target`() {
        val result = config.addAutoApproveTarget("   ")

        assertFalse(result)
        assertEquals("", config.autoApproveTargets)
    }

    @Test
    fun `addAutoApproveTarget should handle multiple targets`() {
        config.addAutoApproveTarget("example.com")
        config.addAutoApproveTarget("test.org")

        assertEquals("example.com\ntest.org", config.autoApproveTargets)
        assertEquals(listOf("example.com", "test.org"), config.getAutoApproveTargetsList())
    }

    @Test
    fun `addAutoApproveTarget should reject comma-injected multi-host string`() {
        val poisoned = "example.com,127.0.0.1,*.attacker.com,169.254.169.254"

        val result = config.addAutoApproveTarget(poisoned)

        assertFalse(result)
        assertEquals("", config.autoApproveTargets)
        assertEquals(emptyList<String>(), config.getAutoApproveTargetsList())
    }

    @Test
    fun `addAutoApproveTarget should reject targets containing whitespace`() {
        assertFalse(config.addAutoApproveTarget("evil.com 127.0.0.1"))
        assertFalse(config.addAutoApproveTarget("evil.com\t127.0.0.1"))
        assertFalse(config.addAutoApproveTarget("evil.com\n127.0.0.1"))
        assertEquals("", config.autoApproveTargets)
    }

    @Test
    fun `removeAutoApproveTarget should remove existing target`() {
        config.addAutoApproveTarget("example.com")
        config.addAutoApproveTarget("test.org")

        val result = config.removeAutoApproveTarget("example.com")

        assertTrue(result)
        assertEquals("test.org", config.autoApproveTargets)
        assertEquals(listOf("test.org"), config.getAutoApproveTargetsList())
    }

    @Test
    fun `removeAutoApproveTarget should return false for non-existing target`() {
        config.addAutoApproveTarget("example.com")

        val result = config.removeAutoApproveTarget("notfound.com")

        assertFalse(result)
        assertEquals("example.com", config.autoApproveTargets)
    }

    @Test
    fun `clearAutoApproveTargets should remove all targets`() {
        config.addAutoApproveTarget("example.com")
        config.addAutoApproveTarget("test.org")

        config.clearAutoApproveTargets()

        assertEquals("", config.autoApproveTargets)
        assertEquals(emptyList<String>(), config.getAutoApproveTargetsList())
    }

    @Test
    fun `resetPersistentApprovals restores every approval policy to prompt by default`() {
        config.approvalYoloMode = true
        config.requireHttpRequestApproval = false
        config.addAutoApproveTarget("example.com")
        config.requireRequestActionApproval = false
        config.requireScopeChangeApproval = false
        config.requireDataAccessApproval = false
        config.alwaysAllowHttpHistory = true
        config.alwaysAllowSiteMap = true
        config.alwaysAllowWebSocketHistory = true
        config.alwaysAllowOrganizer = true
        config.alwaysAllowScannerIssues = true
        config.alwaysAllowCollaboratorInteractions = true

        config.resetPersistentApprovals()

        assertFalse(config.approvalYoloMode)
        assertTrue(config.requireHttpRequestApproval)
        assertTrue(config.getAutoApproveTargetsList().isEmpty())
        assertTrue(config.requireRequestActionApproval)
        assertTrue(config.requireScopeChangeApproval)
        assertTrue(config.requireDataAccessApproval)
        assertFalse(config.alwaysAllowHttpHistory)
        assertFalse(config.alwaysAllowSiteMap)
        assertFalse(config.alwaysAllowWebSocketHistory)
        assertFalse(config.alwaysAllowOrganizer)
        assertFalse(config.alwaysAllowScannerIssues)
        assertFalse(config.alwaysAllowCollaboratorInteractions)
    }

    @Test
    fun `YOLO mode reloads only an explicitly persisted enabled value`() {
        val persisted = mockk<PersistedObject>(relaxed = true)
        every { persisted.getBoolean("approvalYoloMode") } returns true
        every { persisted.getString(any()) } returns ""

        val reloaded = McpConfig(persisted, mockLogging, preferences)

        assertTrue(reloaded.approvalYoloMode)
    }

    @Test
    fun `YOLO mode starts disabled when persisted state cannot be read`() {
        val persisted = mockk<PersistedObject>(relaxed = true)
        every { persisted.getBoolean("approvalYoloMode") } throws IllegalStateException("storage unavailable")
        every { persisted.getString(any()) } returns ""

        val reloaded = McpConfig(persisted, mockLogging, preferences)

        assertFalse(reloaded.approvalYoloMode)
    }

    @Test
    fun `failed YOLO enable persistence leaves runtime approval bypass disabled`() {
        val persisted = mockk<PersistedObject>(relaxed = true)
        every { persisted.getBoolean("approvalYoloMode") } returns false
        every { persisted.getString(any()) } returns ""
        every { persisted.setBoolean("approvalYoloMode", true) } throws IllegalStateException("storage unavailable")
        val failClosed = McpConfig(persisted, mockLogging, preferences)

        assertThrows(IllegalStateException::class.java) {
            failClosed.approvalYoloMode = true
        }
        assertFalse(failClosed.approvalYoloMode)
    }

    @Test
    fun `parsed auto approve targets are reused until the raw setting changes`() {
        config.autoApproveTargets = "example.com\ntest.org"

        val first = config.getAutoApproveTargetsList()
        val second = config.getAutoApproveTargetsList()
        assertSame(first, second)

        config.autoApproveTargets = "other.test"
        val changed = config.getAutoApproveTargetsList()
        assertNotSame(first, changed)
        assertEquals(listOf("other.test"), changed)
    }

    @Test
    fun `getAutoApproveTargetsList should handle empty config`() {
        assertEquals(emptyList<String>(), config.getAutoApproveTargetsList())
    }

    @Test
    fun `getAutoApproveTargetsList should parse newline-separated values`() {
        val storage = mutableMapOf<String, Any>("_autoApproveTargets" to "example.com\ntest.org\n*.api.com")
        persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { storage[firstArg()] as? Boolean ?: false }
            every { getString(any()) } answers { storage[firstArg()] as? String ?: "" }
            every { getInteger(any()) } answers { storage[firstArg()] as? Int ?: 0 }
            every { setBoolean(any(), any()) } answers {
                storage[firstArg()] = secondArg<Boolean>()
            }
            every { setString(any(), any()) } answers {
                storage[firstArg()] = secondArg<String>()
            }
            every { setInteger(any(), any()) } answers {
                storage[firstArg()] = secondArg<Int>()
            }
        }
        config = McpConfig(persistedObject, mockLogging, preferences)

        assertEquals(
            listOf("example.com", "test.org", "*.api.com"), config.getAutoApproveTargetsList()
        )
    }

    @Test
    fun `getAutoApproveTargetsList should handle malformed input`() {
        val storage = mutableMapOf<String, Any>("_autoApproveTargets" to "example.com\n\n  \ntest.org")
        persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { storage[firstArg()] as? Boolean ?: false }
            every { getString(any()) } answers { storage[firstArg()] as? String ?: "" }
            every { getInteger(any()) } answers { storage[firstArg()] as? Int ?: 0 }
            every { setBoolean(any(), any()) } answers {
                storage[firstArg()] = secondArg<Boolean>()
            }
            every { setString(any(), any()) } answers {
                storage[firstArg()] = secondArg<String>()
            }
            every { setInteger(any(), any()) } answers {
                storage[firstArg()] = secondArg<Int>()
            }
        }
        config = McpConfig(persistedObject, mockLogging, preferences)

        assertEquals(
            listOf("example.com", "test.org"), config.getAutoApproveTargetsList()
        )
    }

    @Test
    fun `invalid entries are removed from auto-approve list on startup`() {
        val storage = mutableMapOf<String, Any>("_autoApproveTargets" to "example.com\ninvalid,entry\ntest.org\nbad entry")
        persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { storage[firstArg()] as? Boolean ?: false }
            every { getString(any()) } answers { storage[firstArg()] as? String ?: "" }
            every { getInteger(any()) } answers { storage[firstArg()] as? Int ?: 0 }
            every { setBoolean(any(), any()) } answers { storage[firstArg()] = secondArg<Boolean>() }
            every { setString(any(), any()) } answers { storage[firstArg()] = secondArg<String>() }
            every { setInteger(any(), any()) } answers { storage[firstArg()] = secondArg<Int>() }
        }
        config = McpConfig(persistedObject, mockLogging, preferences)

        assertEquals(listOf("example.com", "test.org"), config.getAutoApproveTargetsList())
    }

    @Test
    fun `targets change listener should be notified`() {
        var notificationCount = 0
        val listener = {
            notificationCount++
            Unit
        }

        config.addTargetsChangeListener(listener)
        config.addAutoApproveTarget("example.com")

        assertEquals(1, notificationCount)
    }

    @Test
    fun `targets change listener should handle exceptions`() {
        val badListener = { throw RuntimeException("Test exception") }
        val goodListener = { /* do nothing */ }

        config.addTargetsChangeListener(badListener)
        config.addTargetsChangeListener(goodListener)

        assertDoesNotThrow {
            config.addAutoApproveTarget("example.com")
        }
    }

    @Test
    fun `autoApproveTargets setter should only notify on actual changes`() {
        var notificationCount = 0
        val listener = {
            notificationCount++
            Unit
        }

        config.addTargetsChangeListener(listener)

        config.autoApproveTargets = "example.com"
        assertEquals(1, notificationCount)

        config.autoApproveTargets = "example.com"
        assertEquals(1, notificationCount)

        config.autoApproveTargets = "test.org"
        assertEquals(2, notificationCount)
    }

    @Test
    fun `auto approve targets are canonicalized deduplicated and invalid entries are dropped`() {
        config.autoApproveTargets = "EXAMPLE.COM.\nexample.com\n256.0.0.1\n*.*.com"

        assertEquals("example.com", config.autoApproveTargets)
        assertEquals(listOf("example.com"), config.getAutoApproveTargetsList())
    }

    @Test
    fun `local bearer token is generated once in installation preferences and survives project replacement`() {
        val first = config.localBearerToken
        val second = config.localBearerToken

        assertEquals(first, second)
        assertTrue(first.matches(Regex("[A-Za-z0-9_-]{43}")))
        assertEquals(first, preferenceValues[installationTokenKey])
        assertFalse(projectValues.containsKey("localBearerToken"))
        verify(exactly = 1) { preferences.setString(installationTokenKey, first) }

        val replacementProject = projectStorage(mutableMapOf())
        val reloaded = McpConfig(replacementProject, mockLogging, preferences)
        assertEquals(first, reloaded.localBearerToken)
        verify(exactly = 1) { preferences.setString(installationTokenKey, first) }
    }

    @Test
    fun `valid legacy project token is migrated once and removed from the current project`() {
        val legacy = "a".repeat(43)
        projectValues["localBearerToken"] = legacy

        assertEquals(legacy, config.localBearerToken)
        assertEquals(legacy, preferenceValues[installationTokenKey])
        assertFalse(projectValues.containsKey("localBearerToken"))
        verify(exactly = 1) { preferences.setString(installationTokenKey, legacy) }
        verify(exactly = 1) { persistedObject.deleteString("localBearerToken") }
    }

    @Test
    fun `installation preference is authoritative over a different project token`() {
        val preferred = "p".repeat(43)
        preferenceValues[installationTokenKey] = preferred
        projectValues["localBearerToken"] = "l".repeat(43)

        assertEquals(preferred, config.localBearerToken)
        assertFalse(projectValues.containsKey("localBearerToken"))
        verify(exactly = 0) { preferences.setString(any(), any()) }
    }

    @Test
    fun `corrupt installation preference fails closed instead of silently rotating`() {
        preferenceValues[installationTokenKey] = "corrupt"

        assertThrows(LocalBearerTokenPersistenceException::class.java) { config.localBearerToken }
        verify(exactly = 0) { preferences.setString(any(), any()) }
        assertEquals("corrupt", preferenceValues[installationTokenKey])
    }

    @Test
    fun `corrupt legacy project token fails closed instead of silently rotating`() {
        projectValues["localBearerToken"] = "corrupt"

        assertThrows(LocalBearerTokenPersistenceException::class.java) { config.localBearerToken }
        verify(exactly = 0) { preferences.setString(any(), any()) }
        assertFalse(preferenceValues.containsKey(installationTokenKey))
    }

    @Test
    fun `preference read failure cannot create an ephemeral runtime token`() {
        every { preferences.getString(installationTokenKey) } throws IllegalStateException("unavailable")

        assertThrows(LocalBearerTokenPersistenceException::class.java) { config.localBearerToken }
        verify(exactly = 0) { preferences.setString(any(), any()) }
    }

    @Test
    fun `pre-commit preference write cancellation propagates without cleanup`() {
        every { preferences.setString(installationTokenKey, any()) } throws CancellationException("pre-commit")

        val failure = assertThrows(CancellationException::class.java) {
            config.localBearerToken
        }

        assertEquals("pre-commit", failure.message)
        assertFalse(preferenceValues.containsKey(installationTokenKey))
        verify(exactly = 0) { persistedObject.deleteString(any()) }
    }

    @Test
    fun `definitely failed explicit rotation retains the persisted token`() {
        val original = "o".repeat(43)
        preferenceValues[installationTokenKey] = original
        assertEquals(original, config.localBearerToken)
        every { preferences.setString(installationTokenKey, any()) } throws IllegalStateException("unavailable")

        assertThrows(LocalBearerTokenPersistenceException::class.java) { config.rotateLocalBearerToken() }
        assertEquals(original, config.localBearerToken)
        assertEquals(original, preferenceValues[installationTokenKey])
    }

    @Test
    fun `write exception is reconciled when preferences committed the replacement`() {
        val values = mutableMapOf<String, String>()
        val uncertainPreferences = preferenceStorage(values)
        every { uncertainPreferences.setString(installationTokenKey, any()) } answers {
            values[installationTokenKey] = secondArg()
            throw IllegalStateException("late failure")
        }
        val uncertain = McpConfig(projectStorage(mutableMapOf()), mockLogging, uncertainPreferences)

        val selected = assertDoesNotThrow<String> { uncertain.localBearerToken }
        assertEquals(selected, values[installationTokenKey])
        assertEquals(selected, uncertain.localBearerToken)
    }

    @Test
    fun `unconfirmed committed rotation is recovered from preferences without a stale cached token`() {
        val original = "o".repeat(43)
        val values = mutableMapOf(installationTokenKey to original)
        val readsAvailable = AtomicBoolean(true)
        val uncertainPreferences = preferenceStorage(values)
        every { uncertainPreferences.getString(installationTokenKey) } answers {
            if (!readsAvailable.get()) throw IllegalStateException("reconciliation unavailable")
            values[installationTokenKey]
        }
        every { uncertainPreferences.setString(installationTokenKey, any()) } answers {
            values[installationTokenKey] = secondArg()
            readsAvailable.set(false)
            throw IllegalStateException("late failure")
        }
        val uncertain = McpConfig(projectStorage(mutableMapOf()), mockLogging, uncertainPreferences)

        assertEquals(original, uncertain.localBearerToken)
        assertThrows(LocalBearerTokenPersistenceException::class.java) {
            uncertain.rotateLocalBearerToken()
        }
        val committed = values.getValue(installationTokenKey)
        assertNotEquals(original, committed)

        readsAvailable.set(true)
        assertEquals(committed, uncertain.localBearerToken)
    }

    @Test
    fun `successful preference write followed by a different valid value fails as uncertain`() {
        val original = "o".repeat(43)
        val conflicting = "x".repeat(43)
        val values = mutableMapOf(installationTokenKey to original)
        var returnConflict = false
        val conflictingPreferences = preferenceStorage(values)
        every { conflictingPreferences.getString(installationTokenKey) } answers {
            if (returnConflict) conflicting else values[installationTokenKey]
        }
        every { conflictingPreferences.setString(installationTokenKey, any()) } answers {
            values[installationTokenKey] = secondArg()
            returnConflict = true
        }
        val uncertain = McpConfig(projectStorage(mutableMapOf()), mockLogging, conflictingPreferences)

        assertEquals(original, uncertain.localBearerToken)
        assertThrows(LocalBearerTokenPersistenceException::class.java) {
            uncertain.rotateLocalBearerToken()
        }
        assertNotEquals(conflicting, values[installationTokenKey])

        returnConflict = false
        assertEquals(values[installationTokenKey], uncertain.localBearerToken)
    }

    @Test
    fun `explicit rotation persists across a replacement project and Burp lifetime`() {
        val original = config.localBearerToken
        val rotated = config.rotateLocalBearerToken()

        assertNotEquals(original, rotated)
        assertEquals(rotated, preferenceValues[installationTokenKey])
        assertEquals(rotated, config.localBearerToken)
        val reloaded = McpConfig(projectStorage(mutableMapOf()), mockLogging, preferences)
        assertEquals(rotated, reloaded.localBearerToken)
    }

    @Test
    fun `explicit rotation repairs a corrupt installation preference`() {
        preferenceValues[installationTokenKey] = "corrupt"

        val rotated = config.rotateLocalBearerToken()

        assertTrue(rotated.matches(Regex("[A-Za-z0-9_-]{43}")))
        assertEquals(rotated, preferenceValues[installationTokenKey])
        assertEquals(rotated, config.localBearerToken)
    }

    @Test
    fun `concurrent first access across config objects persists one installation token`() {
        val configs = List(16) {
            McpConfig(projectStorage(mutableMapOf()), mockLogging, preferences)
        }
        val executor = Executors.newFixedThreadPool(8)
        try {
            val results = executor.invokeAll(configs.map { candidate -> Callable { candidate.localBearerToken } })
                .map { future -> future.get(10, TimeUnit.SECONDS) }

            assertEquals(1, results.toSet().size)
            assertEquals(results.singleOrNull() ?: results.first(), preferenceValues[installationTokenKey])
            verify(exactly = 1) { preferences.setString(installationTokenKey, any()) }
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `legacy cleanup failure does not replace or disclose the committed preference`() {
        val preferred = "q".repeat(43)
        preferenceValues[installationTokenKey] = preferred
        every { persistedObject.deleteString("localBearerToken") } throws IllegalStateException("cleanup failed")

        assertEquals(preferred, config.localBearerToken)
        verify {
            mockLogging.logToError(match<String> {
                it.contains("obsolete project-scoped MCP credential") && !it.contains(preferred)
            })
        }
    }

    @Test
    fun `legacy cleanup cancellation does not overturn a committed migration`() {
        val legacy = "m".repeat(43)
        projectValues["localBearerToken"] = legacy
        every { persistedObject.deleteString("localBearerToken") } throws CancellationException("cleanup cancelled")

        assertEquals(legacy, config.localBearerToken)
        assertEquals(legacy, preferenceValues[installationTokenKey])
        assertEquals(legacy, projectValues["localBearerToken"])
        verify {
            mockLogging.logToError(match<String> {
                it.contains("obsolete project-scoped MCP credential") && !it.contains(legacy)
            })
        }
    }

    @Test
    fun `legacy cleanup cancellation does not overturn a committed rotation`() {
        val original = "o".repeat(43)
        val legacy = "l".repeat(43)
        preferenceValues[installationTokenKey] = original
        projectValues["localBearerToken"] = legacy
        every { persistedObject.deleteString("localBearerToken") } throws CancellationException("cleanup cancelled")

        val rotated = config.rotateLocalBearerToken()

        assertNotEquals(original, rotated)
        assertEquals(rotated, preferenceValues[installationTokenKey])
        assertEquals(rotated, config.localBearerToken)
        verify(atLeast = 1) {
            mockLogging.logToError(match<String> {
                it.contains("obsolete project-scoped MCP credential") &&
                    !it.contains(original) && !it.contains(legacy) && !it.contains(rotated)
            })
        }
    }

    @Test
    fun `cleanup logging cancellation does not overturn an authoritative preference`() {
        val preferred = "q".repeat(43)
        preferenceValues[installationTokenKey] = preferred
        every { persistedObject.deleteString("localBearerToken") } throws IllegalStateException("cleanup failed")
        every { mockLogging.logToError(any<String>()) } throws CancellationException("logging cancelled")

        assertEquals(preferred, config.localBearerToken)
        assertEquals(preferred, preferenceValues[installationTokenKey])
    }

    @Test
    fun `new safety settings have secure defaults when absent`() {
        every { persistedObject.getBoolean("emergencyReadOnlyMode") } returns null
        every { persistedObject.getBoolean("auditLoggingEnabled") } returns null
        every { persistedObject.getBoolean("requireScopeChangeApproval") } returns null
        every { persistedObject.getInteger("auditRetentionEntries") } returns null

        assertFalse(config.emergencyReadOnlyMode)
        assertTrue(config.auditLoggingEnabled)
        assertTrue(config.requireScopeChangeApproval)
        assertEquals(250, config.auditRetentionEntries)
    }

    @Test
    fun `emergency read-only and audit settings persist with bounded retention`() {
        config.emergencyReadOnlyMode = true
        config.auditLoggingEnabled = true
        config.auditRetentionEntries = 1

        assertTrue(config.emergencyReadOnlyMode)
        assertTrue(config.auditLoggingEnabled)
        assertEquals(50, config.auditRetentionEntries)
        verify { persistedObject.setBoolean("emergencyReadOnlyMode", true) }
        verify { persistedObject.setBoolean("auditLoggingEnabled", true) }
        verify { persistedObject.setInteger("auditRetentionEntries", 50) }

        config.auditRetentionEntries = 10_000
        assertEquals(1_000, config.auditRetentionEntries)
        verify { persistedObject.setInteger("auditRetentionEntries", 1_000) }
    }

    @Test
    fun `configEditingTooling should persist correctly`() {
        assertFalse(config.configEditingTooling)

        config.configEditingTooling = true
        assertTrue(config.configEditingTooling)
        verify { persistedObject.setBoolean("configEditingTooling", true) }

        config.configEditingTooling = false
        assertFalse(config.configEditingTooling)
        verify { persistedObject.setBoolean("configEditingTooling", false) }
    }

    @Test
    fun `always allow Site Map should persist correctly`() {
        assertFalse(config.alwaysAllowSiteMap)

        config.alwaysAllowSiteMap = true
        assertTrue(config.alwaysAllowSiteMap)
        verify { persistedObject.setBoolean("_alwaysAllowSiteMap", true) }
    }

    @Test
    fun `always allow Scanner issues should persist correctly`() {
        assertFalse(config.alwaysAllowScannerIssues)

        config.alwaysAllowScannerIssues = true
        assertTrue(config.alwaysAllowScannerIssues)
        verify { persistedObject.setBoolean("_alwaysAllowScannerIssues", true) }
    }

    @Test
    fun `always allow Collaborator interactions persists and notifies data access listeners`() {
        var notifications = 0
        config.addDataAccessChangeListener { notifications++ }

        assertFalse(config.alwaysAllowCollaboratorInteractions)
        config.alwaysAllowCollaboratorInteractions = true
        config.alwaysAllowCollaboratorInteractions = true

        assertTrue(config.alwaysAllowCollaboratorInteractions)
        assertEquals(1, notifications)
        verify { persistedObject.setBoolean("_alwaysAllowCollaboratorInteractions", true) }
    }

    @Test
    fun `request action approval should default to enabled and persist`() {
        assertTrue(config.requireRequestActionApproval)

        config.requireRequestActionApproval = false

        assertFalse(config.requireRequestActionApproval)
        verify { persistedObject.setBoolean("requireRequestActionApproval", false) }
    }

    @Test
    fun `request action approval listeners observe actual changes only`() {
        var notificationCount = 0
        val listener = {
            notificationCount++
            Unit
        }
        config.addRequestActionApprovalChangeListener(listener)

        config.requireRequestActionApproval = false
        config.requireRequestActionApproval = false
        config.requireRequestActionApproval = true

        assertEquals(2, notificationCount)
    }

    @Test
    fun `scope change approval defaults to enabled persists and notifies on changes`() {
        var notificationCount = 0
        config.addScopeChangeApprovalChangeListener { notificationCount++ }

        assertTrue(config.requireScopeChangeApproval)
        config.requireScopeChangeApproval = false
        config.requireScopeChangeApproval = false
        config.requireScopeChangeApproval = true

        assertTrue(config.requireScopeChangeApproval)
        assertEquals(2, notificationCount)
        verify { persistedObject.setBoolean("requireScopeChangeApproval", false) }
        verify { persistedObject.setBoolean("requireScopeChangeApproval", true) }
    }

    @Test
    fun `requireHttpRequestApproval should persist correctly`() {
        assertTrue(config.requireHttpRequestApproval)

        config.requireHttpRequestApproval = false
        assertFalse(config.requireHttpRequestApproval)
        verify { persistedObject.setBoolean("requireHttpRequestApproval", false) }

        config.requireHttpRequestApproval = true
        assertTrue(config.requireHttpRequestApproval)
        verify { persistedObject.setBoolean("requireHttpRequestApproval", true) }
    }

    private fun projectStorage(values: MutableMap<String, Any>): PersistedObject =
        mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers {
                val key = firstArg<String>()
                values[key] as? Boolean ?: when (key) {
                    "enabled" -> true
                    "requireHttpRequestApproval", "requireRequestActionApproval", "requireScopeChangeApproval" -> true
                    else -> false
                }
            }
            every { getString(any()) } answers { values[firstArg()] as? String }
            every { getInteger(any()) } answers { values[firstArg()] as? Int ?: 0 }
            every { setBoolean(any(), any()) } answers { values[firstArg<String>()] = secondArg<Boolean>() }
            every { setString(any(), any()) } answers { values[firstArg<String>()] = secondArg<String>() }
            every { setInteger(any(), any()) } answers { values[firstArg<String>()] = secondArg<Int>() }
            every { deleteString(any()) } answers { values.remove(firstArg<String>()); Unit }
        }

    private fun preferenceStorage(values: MutableMap<String, String>): Preferences =
        mockk<Preferences>().apply {
            every { getString(any()) } answers { values[firstArg()] }
            every { setString(any(), any()) } answers { values[firstArg<String>()] = secondArg<String>() }
            every { deleteString(any()) } answers { values.remove(firstArg<String>()); Unit }
        }
}