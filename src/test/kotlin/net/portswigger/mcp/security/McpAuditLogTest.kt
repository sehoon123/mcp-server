package net.portswigger.mcp.security

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import net.portswigger.mcp.config.MAX_AUDIT_RETENTION_ENTRIES
import net.portswigger.mcp.config.MIN_AUDIT_RETENTION_ENTRIES
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.ConcurrentHashMap

class McpAuditLogTest {
    private val fixedClock = Clock.fixed(Instant.parse("2026-07-22T00:00:00Z"), ZoneOffset.UTC)

    @Test
    fun `tool audit persists only argument names hashed session and exception type`() = runBlocking {
        val fixture = auditFixture()
        val log = fixture.log
        val invocation = newToolAuditInvocation(
            sink = log,
            sessionId = "secret-session-identifier",
            tool = "send_http_request_from_id",
            readOnly = false,
            argumentKeys = listOf("projectId", "patch", "Authorization", "requestBody"),
            clock = fixedClock,
        )

        withContext(invocation) {
            recordCurrentToolApproval("http_request", "user_allow")
        }
        invocation.complete(
            "error",
            IllegalArgumentException(
                "Bearer super-secret-token at /home/user/private/request.txt\npassword=hunter2"
            ),
        )
        log.flush()

        val record = log.snapshot().single()
        assertEquals(Instant.parse("2026-07-22T00:00:00Z").toEpochMilli(), record.timestampEpochMillis)
        assertNotEquals("secret-session-identifier", record.sessionCorrelation)
        assertTrue(record.sessionCorrelation.matches(Regex("[a-f0-9]{12}")))
        assertEquals(
            listOf("Authorization", "patch", "projectId", "requestBody"),
            record.argumentKeys,
        )
        assertEquals(listOf(McpAuditApproval("http_request", "user_allow")), record.approvals)
        assertEquals("IllegalArgumentException", record.errorType)

        val persisted = fixture.storage.getValue("redactedAuditV1") as String
        assertFalse(persisted.contains("secret-session-identifier"))
        assertFalse(persisted.contains("super-secret-token"))
        assertFalse(persisted.contains("hunter2"))
        assertFalse(persisted.contains("/home/user"))
        log.close()
    }

    @Test
    fun `retention is bounded and records survive a reload`() {
        val fixture = auditFixture()
        fixture.config.auditRetentionEntries = MIN_AUDIT_RETENTION_ENTRIES
        repeat(MIN_AUDIT_RETENTION_ENTRIES + 10) { index ->
            fixture.log.recordLocalEvent("event_$index", "completed")
        }
        fixture.log.flush()

        assertEquals(MIN_AUDIT_RETENTION_ENTRIES, fixture.log.size())
        assertEquals("event_10", fixture.log.snapshot().first().tool)
        fixture.log.close()

        val reloaded = PersistentMcpAuditLog(
            fixture.persistedObject,
            fixture.config,
            fixture.logging,
            fixedClock,
        )
        assertEquals(MIN_AUDIT_RETENTION_ENTRIES, reloaded.size())
        assertEquals("event_59", reloaded.snapshot().last().tool)
        assertTrue(reloaded.exportJsonLines(100).length <= 64 * 1024)
        reloaded.close()
    }

    @Test
    fun `records older than thirty days expire`() {
        val fixture = auditFixture()
        fixture.log.append(
            McpAuditRecord(
                timestampEpochMillis = fixedClock.millis() - java.util.concurrent.TimeUnit.DAYS.toMillis(31),
                sessionCorrelation = "abcdef123456",
                tool = "expired_event",
                readOnly = true,
                argumentKeys = emptyList(),
                approvals = emptyList(),
                durationMillis = 1,
                outcome = "completed",
            )
        )

        assertEquals(0, fixture.log.size())
        fixture.log.flush()
        assertFalse((fixture.storage.getValue("redactedAuditV1") as String).contains("expired_event"))
        fixture.log.close()
    }

    @Test
    fun `persisted document cap drops oldest complete records`() {
        val fixture = auditFixture()
        fixture.config.auditRetentionEntries = MAX_AUDIT_RETENTION_ENTRIES
        val longKeys = (0 until 16).map { index -> "key_${index}_" + "x".repeat(56) }
        val approvals = (0 until 8).map { index ->
            McpAuditApproval("approval_${index}_" + "x".repeat(48), "decision_" + "y".repeat(48))
        }
        repeat(MAX_AUDIT_RETENTION_ENTRIES) { index ->
            fixture.log.append(
                McpAuditRecord(
                    timestampEpochMillis = fixedClock.millis(),
                    sessionCorrelation = "abcdef123456",
                    tool = "bounded_event_$index",
                    readOnly = false,
                    argumentKeys = longKeys,
                    approvals = approvals,
                    durationMillis = 1,
                    outcome = "completed",
                )
            )
        }
        fixture.log.flush()

        val persisted = fixture.storage.getValue("redactedAuditV1") as String
        assertTrue(persisted.length <= 1024 * 1024)
        assertTrue(fixture.log.size() in 1 until MAX_AUDIT_RETENTION_ENTRIES)
        assertEquals("bounded_event_999", fixture.log.snapshot().last().tool)
        fixture.log.close()
    }

    @Test
    fun `disabled logging records nothing and clear removes persisted records`() {
        val fixture = auditFixture()
        fixture.config.auditLoggingEnabled = false
        fixture.log.recordLocalEvent("disabled_event", "completed")
        assertEquals(0, fixture.log.size())

        fixture.config.auditLoggingEnabled = true
        fixture.log.recordLocalEvent("enabled_event", "completed")
        fixture.log.flush()
        assertEquals(1, fixture.log.size())
        assertTrue(fixture.log.snapshot().single().sessionCorrelation.matches(Regex("[a-f0-9]{12}")))

        fixture.log.clear()
        fixture.log.flush()
        assertEquals(0, fixture.log.size())
        assertFalse((fixture.storage.getValue("redactedAuditV1") as String).contains("enabled_event"))
        fixture.log.close()
    }

    private fun auditFixture(): AuditFixture {
        val storage = ConcurrentHashMap<String, Any>()
        val persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { storage[firstArg<String>()] as? Boolean }
            every { getString(any()) } answers { storage[firstArg<String>()] as? String }
            every { getInteger(any()) } answers { storage[firstArg<String>()] as? Int }
            every { setBoolean(any(), any()) } answers {
                storage[firstArg<String>()] = secondArg<Boolean>()
            }
            every { setString(any(), any()) } answers {
                storage[firstArg<String>()] = secondArg<String>()
            }
            every { setInteger(any(), any()) } answers {
                storage[firstArg<String>()] = secondArg<Int>()
            }
        }
        val logging = mockk<Logging>(relaxed = true)
        val config = McpConfig(persistedObject, logging)
        val log = PersistentMcpAuditLog(persistedObject, config, logging, fixedClock)
        return AuditFixture(storage, persistedObject, logging, config, log)
    }

    private data class AuditFixture(
        val storage: ConcurrentHashMap<String, Any>,
        val persistedObject: PersistedObject,
        val logging: Logging,
        val config: McpConfig,
        val log: PersistentMcpAuditLog,
    )
}
