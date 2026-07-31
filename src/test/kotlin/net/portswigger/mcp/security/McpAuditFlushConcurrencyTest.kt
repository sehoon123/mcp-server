package net.portswigger.mcp.security

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.MAX_AUDIT_RETENTION_ENTRIES
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class McpAuditFlushConcurrencyTest {
    private val fixedClock = Clock.fixed(Instant.parse("2026-07-22T00:00:00Z"), ZoneOffset.UTC)
    private val json = Json { encodeDefaults = true }

    @Test
    fun `linear bounded encoder is byte exact when the complete document fits`() {
        val records = listOf(
            record(1, "first\"tool"),
            record(2, "second\\tool", errorType = "IllegalArgumentException"),
        )

        val encoding = encodeBoundedAuditRecords(records)

        assertEquals(0, encoding.droppedRecords)
        assertEquals(json.encodeToString(TestAuditDocument(records = records)), encoding.text)
    }

    @Test
    fun `linear bounded encoder drops the minimal oldest prefix and keeps complete newest records`() {
        val records = (0 until 10).map { index ->
            record(index.toLong(), "bounded-$index-${"x".repeat(index * 7)}")
        }
        val expectedDrop = 5
        val expected = json.encodeToString(TestAuditDocument(records = records.drop(expectedDrop)))
        val previous = json.encodeToString(TestAuditDocument(records = records.drop(expectedDrop - 1)))
        assertTrue(previous.length > expected.length)

        val encoding = encodeBoundedAuditRecords(records, maxChars = expected.length)

        assertEquals(expectedDrop, encoding.droppedRecords)
        assertEquals(expected, encoding.text)
        assertEquals(records.drop(expectedDrop), json.decodeFromString<TestAuditDocument>(encoding.text).records)
    }

    @Test
    fun `linear bounded encoder handles empty one-record and all-dropped boundaries`() {
        val empty = encodeBoundedAuditRecords(emptyList())
        val single = record(1, "single-${"x".repeat(128)}")
        val one = encodeBoundedAuditRecords(listOf(single))
        val allDropped = encodeBoundedAuditRecords(listOf(single), maxChars = empty.text.length)

        assertEquals(0, empty.droppedRecords)
        assertEquals(emptyList(), json.decodeFromString<TestAuditDocument>(empty.text).records)
        assertEquals(0, one.droppedRecords)
        assertEquals(listOf(single), json.decodeFromString<TestAuditDocument>(one.text).records)
        assertEquals(1, allDropped.droppedRecords)
        assertEquals(empty.text, allDropped.text)
    }

    @Test
    fun `append is not blocked by encoding and a racing append is eventually persisted`() {
        val enteredEncoding = CountDownLatch(1)
        val releaseEncoding = CountDownLatch(1)
        val encodingCalls = AtomicInteger()
        val fixture = fixture(encoder = { records ->
            if (encodingCalls.incrementAndGet() == 1) {
                enteredEncoding.countDown()
                check(releaseEncoding.await(3, TimeUnit.SECONDS)) { "timed out waiting to release audit encoding" }
            }
            encodeBoundedAuditRecords(records)
        })
        val flushExecutor = Executors.newSingleThreadExecutor()
        val appendExecutor = Executors.newSingleThreadExecutor()
        try {
            fixture.log.append(record(1, "before-encoding"))
            val flush = flushExecutor.submit { fixture.log.flush() }
            assertTrue(enteredEncoding.await(2, TimeUnit.SECONDS))

            val append = appendExecutor.submit { fixture.log.append(record(2, "during-encoding")) }
            append.get(2, TimeUnit.SECONDS)
            releaseEncoding.countDown()
            flush.get(5, TimeUnit.SECONDS)

            val persisted = fixture.persistedText()
            assertTrue(persisted.contains("before-encoding"))
            assertTrue(persisted.contains("during-encoding"))
            assertEquals(listOf("before-encoding", "during-encoding"), fixture.log.snapshot().map { it.tool })
            assertTrue(encodingCalls.get() >= 2)
        } finally {
            releaseEncoding.countDown()
            flushExecutor.shutdownNow()
            appendExecutor.shutdownNow()
            fixture.log.close()
        }
    }

    @Test
    fun `clear racing an in-flight encoding cannot resurrect cleared records`() {
        val enteredEncoding = CountDownLatch(1)
        val releaseEncoding = CountDownLatch(1)
        val encodingCalls = AtomicInteger()
        val fixture = fixture(encoder = { records ->
            if (encodingCalls.incrementAndGet() == 1) {
                enteredEncoding.countDown()
                check(releaseEncoding.await(3, TimeUnit.SECONDS)) { "timed out waiting to release audit encoding" }
            }
            encodeBoundedAuditRecords(records)
        })
        val executor = Executors.newSingleThreadExecutor()
        try {
            fixture.log.append(record(1, "must-not-return"))
            val flush = executor.submit { fixture.log.flush() }
            assertTrue(enteredEncoding.await(2, TimeUnit.SECONDS))

            fixture.log.clear()
            releaseEncoding.countDown()
            flush.get(5, TimeUnit.SECONDS)

            assertEquals(0, fixture.log.size())
            assertEquals(emptyList(), json.decodeFromString<TestAuditDocument>(fixture.persistedText()).records)
            assertFalse(fixture.persistedText().contains("must-not-return"))
        } finally {
            releaseEncoding.countDown()
            executor.shutdownNow()
            fixture.log.close()
        }
    }

    @Test
    fun `retention trim racing an in-flight encoding persists only the current newest records`() {
        val enteredEncoding = CountDownLatch(1)
        val releaseEncoding = CountDownLatch(1)
        val encodingCalls = AtomicInteger()
        val fixture = fixture(encoder = { records ->
            if (encodingCalls.incrementAndGet() == 1) {
                enteredEncoding.countDown()
                check(releaseEncoding.await(3, TimeUnit.SECONDS)) { "timed out waiting to release audit encoding" }
            }
            encodeBoundedAuditRecords(records)
        })
        fixture.config.auditRetentionEntries = 60
        repeat(60) { fixture.log.append(record(it.toLong(), "event-$it")) }
        val executor = Executors.newSingleThreadExecutor()
        try {
            val flush = executor.submit { fixture.log.flush() }
            assertTrue(enteredEncoding.await(2, TimeUnit.SECONDS))

            fixture.config.auditRetentionEntries = 50
            fixture.log.trimToConfiguredRetention()
            releaseEncoding.countDown()
            flush.get(5, TimeUnit.SECONDS)

            assertEquals(50, fixture.log.size())
            assertEquals("event-10", fixture.log.snapshot().first().tool)
            assertEquals("event-59", fixture.log.snapshot().last().tool)
            val persisted = json.decodeFromString<TestAuditDocument>(fixture.persistedText()).records
            assertEquals(50, persisted.size)
            assertEquals("event-10", persisted.first().tool)
            assertEquals("event-59", persisted.last().tool)
        } finally {
            releaseEncoding.countDown()
            executor.shutdownNow()
            fixture.log.close()
        }
    }

    @Test
    fun `racing append is retried after an encoding failure`() {
        val enteredEncoding = CountDownLatch(1)
        val releaseEncoding = CountDownLatch(1)
        val encodingCalls = AtomicInteger()
        val fixture = fixture(encoder = { records ->
            if (encodingCalls.incrementAndGet() == 1) {
                enteredEncoding.countDown()
                check(releaseEncoding.await(3, TimeUnit.SECONDS)) { "timed out waiting to release audit encoding" }
                error("synthetic encoding failure")
            }
            encodeBoundedAuditRecords(records)
        })
        val executor = Executors.newSingleThreadExecutor()
        try {
            fixture.log.append(record(1, "before-failure"))
            val flush = executor.submit { fixture.log.flush() }
            assertTrue(enteredEncoding.await(2, TimeUnit.SECONDS))
            fixture.log.append(record(2, "after-snapshot"))
            releaseEncoding.countDown()
            flush.get(5, TimeUnit.SECONDS)

            assertEquals(
                listOf("before-failure", "after-snapshot"),
                json.decodeFromString<TestAuditDocument>(fixture.persistedText()).records.map { it.tool },
            )
            assertTrue(encodingCalls.get() >= 2)
        } finally {
            releaseEncoding.countDown()
            executor.shutdownNow()
            fixture.log.close()
        }
    }

    @Test
    fun `racing clear is retried after a persistence failure`() {
        val enteredEncoding = CountDownLatch(1)
        val releaseEncoding = CountDownLatch(1)
        val fixture = fixture(
            encoder = { records ->
                enteredEncoding.countDown()
                check(releaseEncoding.await(3, TimeUnit.SECONDS)) { "timed out waiting to release audit encoding" }
                encodeBoundedAuditRecords(records)
            },
            failFirstWrites = 1,
        )
        val executor = Executors.newSingleThreadExecutor()
        try {
            fixture.log.append(record(1, "must-stay-cleared"))
            val flush = executor.submit { fixture.log.flush() }
            assertTrue(enteredEncoding.await(2, TimeUnit.SECONDS))
            fixture.log.clear()
            releaseEncoding.countDown()
            flush.get(5, TimeUnit.SECONDS)

            assertEquals(0, fixture.log.size())
            assertEquals(emptyList(), json.decodeFromString<TestAuditDocument>(fixture.persistedText()).records)
        } finally {
            releaseEncoding.countDown()
            executor.shutdownNow()
            fixture.log.close()
        }
    }

    @Test
    fun `failed persistence never applies bounded-document trimming to memory`() {
        val fixture = fixture(failWrites = true)
        fixture.config.auditRetentionEntries = MAX_AUDIT_RETENTION_ENTRIES
        val longKeys = (0 until 16).map { index -> "key_${index}_${"x".repeat(56)}" }
        val approvals = (0 until 8).map { index ->
            McpAuditApproval("approval_${index}_${"x".repeat(48)}", "decision_${"y".repeat(48)}")
        }
        repeat(MAX_AUDIT_RETENTION_ENTRIES) { index ->
            fixture.log.append(
                record(
                    index.toLong(),
                    "bounded-event-$index",
                    argumentKeys = longKeys,
                    approvals = approvals,
                )
            )
        }
        assertTrue(encodeBoundedAuditRecords(fixture.log.snapshot(MAX_AUDIT_RETENTION_ENTRIES)).droppedRecords > 0)

        fixture.log.flush()

        assertEquals(MAX_AUDIT_RETENTION_ENTRIES, fixture.log.size())
        assertEquals("bounded-event-0", fixture.log.snapshot(MAX_AUDIT_RETENTION_ENTRIES).first().tool)
        assertEquals("bounded-event-999", fixture.log.snapshot(MAX_AUDIT_RETENTION_ENTRIES).last().tool)
        fixture.log.close()
    }

    private fun record(
        sequence: Long,
        tool: String,
        errorType: String? = null,
        argumentKeys: List<String> = listOf("projectId"),
        approvals: List<McpAuditApproval> = listOf(McpAuditApproval("source", "allow")),
    ) = McpAuditRecord(
        timestampEpochMillis = fixedClock.millis() + sequence,
        sessionCorrelation = "abcdef123456",
        tool = tool,
        readOnly = true,
        argumentKeys = argumentKeys,
        approvals = approvals,
        durationMillis = sequence,
        outcome = "completed",
        errorType = errorType,
    )

    private fun fixture(
        encoder: (List<McpAuditRecord>) -> BoundedAuditEncoding = ::encodeBoundedAuditRecords,
        failWrites: Boolean = false,
        failFirstWrites: Int = 0,
    ): Fixture {
        val storage = ConcurrentHashMap<String, Any>()
        val remainingWriteFailures = AtomicInteger(failFirstWrites)
        val persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { storage[firstArg<String>()] as? Boolean }
            every { getString(any()) } answers { storage[firstArg<String>()] as? String }
            every { getInteger(any()) } answers { storage[firstArg<String>()] as? Int }
            every { setBoolean(any(), any()) } answers { storage[firstArg<String>()] = secondArg<Boolean>() }
            every { setInteger(any(), any()) } answers { storage[firstArg<String>()] = secondArg<Int>() }
            every { setString(any(), any()) } answers {
                if (failWrites || remainingWriteFailures.getAndUpdate { value -> (value - 1).coerceAtLeast(0) } > 0) {
                    error("synthetic persistence failure")
                }
                storage[firstArg<String>()] = secondArg<String>()
            }
        }
        val logging = mockk<Logging>(relaxed = true)
        val config = McpConfig(persistedObject, logging, net.portswigger.mcp.testPreferences())
        val log = PersistentMcpAuditLog(
            storage = persistedObject,
            config = config,
            logging = logging,
            clock = fixedClock,
            encodeSnapshot = encoder,
        )
        return Fixture(storage, config, log)
    }

    @Serializable
    private data class TestAuditDocument(
        val version: Int = 1,
        val records: List<McpAuditRecord> = emptyList(),
    )

    private data class Fixture(
        val storage: ConcurrentHashMap<String, Any>,
        val config: McpConfig,
        val log: PersistentMcpAuditLog,
    ) {
        fun persistedText(): String = storage.getValue("redactedAuditV1") as String
    }
}
