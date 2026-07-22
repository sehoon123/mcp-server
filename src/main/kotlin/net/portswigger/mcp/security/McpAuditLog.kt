package net.portswigger.mcp.security

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.DEFAULT_AUDIT_RETENTION_ENTRIES
import net.portswigger.mcp.config.MAX_AUDIT_RETENTION_ENTRIES
import net.portswigger.mcp.config.MIN_AUDIT_RETENTION_ENTRIES
import net.portswigger.mcp.config.McpConfig
import java.security.MessageDigest
import java.time.Clock
import java.util.ArrayDeque
import java.util.HexFormat
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext

private const val AUDIT_STORAGE_KEY = "redactedAuditV1"
private const val AUDIT_DOCUMENT_VERSION = 1
private const val MAX_PERSISTED_AUDIT_CHARS = 1024 * 1024
private const val MAX_AUDIT_TOOL_CHARS = 128
private const val MAX_AUDIT_ARGUMENT_KEYS = 16
private const val MAX_AUDIT_ARGUMENT_KEY_CHARS = 64
private const val MAX_AUDIT_APPROVALS = 8
private const val MAX_AUDIT_APPROVAL_FIELD_CHARS = 64
private const val MAX_AUDIT_DETAIL_CHARS = 256
private const val MAX_AUDIT_EXPORT_CHARS = 64 * 1024
private const val AUDIT_FLUSH_DEBOUNCE_MILLIS = 250L
private val AUDIT_MAX_AGE_MILLIS = TimeUnit.DAYS.toMillis(30)
private val AUDIT_CORRELATION = Regex("[a-f0-9]{12}")

private val auditJson = Json {
    encodeDefaults = true
    ignoreUnknownKeys = true
}

@Serializable
internal data class McpAuditApproval(
    val kind: String,
    val decision: String,
)

@Serializable
internal data class McpAuditRecord(
    val timestampEpochMillis: Long,
    val sessionCorrelation: String,
    val tool: String,
    val readOnly: Boolean,
    val argumentKeys: List<String>,
    val approvals: List<McpAuditApproval>,
    val durationMillis: Long,
    val outcome: String,
    val errorType: String? = null,
)

@Serializable
private data class McpAuditDocument(
    val version: Int = AUDIT_DOCUMENT_VERSION,
    val records: List<McpAuditRecord> = emptyList(),
)

internal interface McpAuditSink : AutoCloseable {
    fun append(record: McpAuditRecord)
    fun recordLocalEvent(tool: String, outcome: String)
    fun snapshot(limit: Int = DEFAULT_AUDIT_RETENTION_ENTRIES): List<McpAuditRecord>
    fun size(): Int
    fun clear()
    fun trimToConfiguredRetention()
    fun flush()
    fun exportJsonLines(limit: Int = 100): String
    override fun close()
}

internal object NoOpMcpAuditSink : McpAuditSink {
    override fun append(record: McpAuditRecord) = Unit
    override fun recordLocalEvent(tool: String, outcome: String) = Unit
    override fun snapshot(limit: Int): List<McpAuditRecord> = emptyList()
    override fun size(): Int = 0
    override fun clear() = Unit
    override fun trimToConfiguredRetention() = Unit
    override fun flush() = Unit
    override fun exportJsonLines(limit: Int): String = ""
    override fun close() = Unit
}

/**
 * Durable, bounded, value-redacted audit storage.
 *
 * Tool arguments are represented only by field names. Session identifiers are one-way correlated, and records never
 * contain request/response bodies, header values, credentials, file paths, or raw exception text.
 */
internal class PersistentMcpAuditLog(
    private val storage: PersistedObject,
    private val config: McpConfig,
    private val logging: Logging,
    private val clock: Clock = Clock.systemUTC(),
) : McpAuditSink {
    private val lock = Any()
    private val records = ArrayDeque<McpAuditRecord>()
    private val writer: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "BurpMcpAuditWriter").apply { isDaemon = true }
    }
    private var revision = 0L
    private var flushScheduled = false
    private val closed = AtomicBoolean(false)

    init {
        loadPersistedRecords()
    }

    override fun append(record: McpAuditRecord) {
        runCatching { appendSafely(record) }
            .onFailure { error ->
                runCatching { logging.logToError("MCP audit append failed: ${safeExceptionSummary(error)}") }
            }
    }

    private fun appendSafely(record: McpAuditRecord) {
        if (!config.auditLoggingEnabled || closed.get()) return
        synchronized(lock) {
            if (closed.get() || !config.auditLoggingEnabled) return
            val now = clock.millis()
            pruneExpiredLocked(now)
            records.addLast(sanitizeRecord(record, now))
            trimLocked(config.boundedAuditRetentionEntries())
            revision++
            scheduleFlushLocked()
        }
    }

    override fun recordLocalEvent(tool: String, outcome: String) {
        append(
            McpAuditRecord(
                timestampEpochMillis = clock.millis(),
                sessionCorrelation = correlateSession("local-ui"),
                tool = tool,
                readOnly = false,
                argumentKeys = emptyList(),
                approvals = emptyList(),
                durationMillis = 0,
                outcome = outcome,
            )
        )
    }

    override fun snapshot(limit: Int): List<McpAuditRecord> = synchronized(lock) {
        pruneExpiredAndScheduleLocked()
        val boundedLimit = limit.coerceIn(0, MAX_AUDIT_RETENTION_ENTRIES)
        records.toList().takeLast(boundedLimit)
    }

    override fun size(): Int = synchronized(lock) {
        pruneExpiredAndScheduleLocked()
        records.size
    }

    override fun clear() {
        if (closed.get()) return
        synchronized(lock) {
            if (closed.get()) return
            records.clear()
            revision++
            scheduleFlushLocked()
        }
    }

    override fun trimToConfiguredRetention() {
        if (closed.get()) return
        synchronized(lock) {
            if (closed.get()) return
            val previous = records.size
            pruneExpiredLocked(clock.millis())
            trimLocked(config.boundedAuditRetentionEntries())
            if (records.size != previous) {
                revision++
                scheduleFlushLocked()
            }
        }
    }

    override fun flush() {
        if (closed.get()) return
        runCatching {
            writer.submit {
                synchronized(lock) { flushScheduled = true }
                flushLoop()
            }.get(5, TimeUnit.SECONDS)
        }.onFailure { logging.logToError("MCP audit flush failed: ${safeExceptionSummary(it)}") }
    }

    override fun exportJsonLines(limit: Int): String {
        val selected = snapshot(limit.coerceIn(0, MAX_AUDIT_RETENTION_ENTRIES))
        return buildString {
            for (record in selected) {
                val line = auditJson.encodeToString(record)
                if (length + line.length + 1 > MAX_AUDIT_EXPORT_CHARS) break
                if (isNotEmpty()) append('\n')
                append(line)
            }
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        synchronized(lock) { flushScheduled = true }
        runCatching {
            writer.submit {
                flushLoop()
            }.get(5, TimeUnit.SECONDS)
        }.onFailure { logging.logToError("MCP audit close failed: ${safeExceptionSummary(it)}") }
        writer.shutdownNow()
    }

    private fun loadPersistedRecords() {
        val raw = runCatching { storage.getString(AUDIT_STORAGE_KEY).orEmpty() }
            .onFailure { logging.logToError("MCP audit load failed: ${safeExceptionSummary(it)}") }
            .getOrDefault("")
        if (raw.isBlank()) return
        if (raw.length > MAX_PERSISTED_AUDIT_CHARS) {
            logging.logToError("MCP audit storage exceeded its safety limit and was ignored")
            return
        }
        val loaded = runCatching { auditJson.decodeFromString<McpAuditDocument>(raw) }
            .onFailure { logging.logToError("MCP audit storage was invalid and was ignored") }
            .getOrNull()
            ?.takeIf { it.version == AUDIT_DOCUMENT_VERSION }
            ?.records
            .orEmpty()
            .takeLast(MAX_AUDIT_RETENTION_ENTRIES)
        val now = clock.millis()
        synchronized(lock) {
            loaded.forEach { records.addLast(sanitizeRecord(it, now)) }
            val previous = records.size
            pruneExpiredLocked(now)
            trimLocked(config.boundedAuditRetentionEntries())
            if (records.size != previous) {
                revision++
                scheduleFlushLocked()
            }
        }
    }

    private fun scheduleFlushLocked() {
        if (flushScheduled || closed.get()) return
        flushScheduled = true
        writer.schedule(
            {
                val shouldFlush = synchronized(lock) { flushScheduled }
                if (shouldFlush) flushLoop()
            },
            AUDIT_FLUSH_DEBOUNCE_MILLIS,
            TimeUnit.MILLISECONDS,
        )
    }

    private fun flushLoop() {
        while (true) {
            val targetRevision: Long
            val encoded: String
            synchronized(lock) {
                targetRevision = revision
                encoded = encodeBoundedLocked()
            }
            val succeeded = runCatching { storage.setString(AUDIT_STORAGE_KEY, encoded) }
                .onFailure { logging.logToError("MCP audit persistence failed: ${safeExceptionSummary(it)}") }
                .isSuccess
            synchronized(lock) {
                if (!succeeded || targetRevision == revision) {
                    flushScheduled = false
                    return
                }
            }
        }
    }

    private fun encodeBoundedLocked(): String {
        val snapshot = records.toList()
        val encoded = auditJson.encodeToString(McpAuditDocument(records = snapshot))
        if (encoded.length <= MAX_PERSISTED_AUDIT_CHARS) return encoded

        var minimumDrop = 1
        var maximumDrop = snapshot.size
        while (minimumDrop < maximumDrop) {
            val candidateDrop = minimumDrop + (maximumDrop - minimumDrop) / 2
            val candidate = auditJson.encodeToString(McpAuditDocument(records = snapshot.drop(candidateDrop)))
            if (candidate.length <= MAX_PERSISTED_AUDIT_CHARS) {
                maximumDrop = candidateDrop
            } else {
                minimumDrop = candidateDrop + 1
            }
        }
        val retained = snapshot.drop(minimumDrop)
        records.clear()
        records.addAll(retained)
        return auditJson.encodeToString(McpAuditDocument(records = retained))
    }

    private fun pruneExpiredAndScheduleLocked() {
        if (pruneExpiredLocked(clock.millis())) {
            revision++
            scheduleFlushLocked()
        }
    }

    private fun pruneExpiredLocked(now: Long): Boolean {
        val oldestAllowed = (now - AUDIT_MAX_AGE_MILLIS).coerceAtLeast(0)
        if (records.none { it.timestampEpochMillis < oldestAllowed }) return false
        val retained = records.filterTo(ArrayDeque()) { it.timestampEpochMillis >= oldestAllowed }
        records.clear()
        records.addAll(retained)
        return true
    }

    private fun trimLocked(limit: Int) {
        while (records.size > limit) records.removeFirst()
    }
}

internal class McpToolAuditInvocation(
    private val sink: McpAuditSink,
    private val startedNanos: Long,
    private val timestampEpochMillis: Long,
    private val sessionCorrelation: String,
    private val tool: String,
    private val readOnly: Boolean,
    private val argumentKeys: List<String>,
) : AbstractCoroutineContextElement(Key) {
    companion object Key : CoroutineContext.Key<McpToolAuditInvocation>

    private val lock = Any()
    private val approvals = ArrayList<McpAuditApproval>()
    private val completed = AtomicBoolean(false)

    fun recordApproval(kind: String, decision: String) {
        synchronized(lock) {
            if (approvals.size >= MAX_AUDIT_APPROVALS) return
            approvals += McpAuditApproval(
                kind = safeAuditField(kind, MAX_AUDIT_APPROVAL_FIELD_CHARS),
                decision = safeAuditField(decision, MAX_AUDIT_APPROVAL_FIELD_CHARS),
            )
        }
    }

    fun complete(outcome: String, error: Throwable? = null) {
        if (!completed.compareAndSet(false, true)) return
        val elapsedNanos = (System.nanoTime() - startedNanos).coerceAtLeast(0)
        val record = McpAuditRecord(
            timestampEpochMillis = timestampEpochMillis,
            sessionCorrelation = sessionCorrelation,
            tool = tool,
            readOnly = readOnly,
            argumentKeys = argumentKeys,
            approvals = synchronized(lock) { approvals.toList() },
            durationMillis = TimeUnit.NANOSECONDS.toMillis(elapsedNanos).coerceAtMost(TimeUnit.DAYS.toMillis(1)),
            outcome = safeAuditField(outcome, MAX_AUDIT_APPROVAL_FIELD_CHARS),
            errorType = error?.let { throwable ->
                safeAuditField(throwable::class.simpleName ?: "Exception", MAX_AUDIT_DETAIL_CHARS)
            },
        )
        runCatching { sink.append(record) }
    }
}

internal suspend fun recordCurrentToolApproval(kind: String, decision: String) {
    currentCoroutineContext()[McpToolAuditInvocation]?.recordApproval(kind, decision)
}

internal fun newToolAuditInvocation(
    sink: McpAuditSink,
    sessionId: String,
    tool: String,
    readOnly: Boolean,
    argumentKeys: Collection<String>,
    clock: Clock = Clock.systemUTC(),
): McpToolAuditInvocation = McpToolAuditInvocation(
    sink = sink,
    startedNanos = System.nanoTime(),
    timestampEpochMillis = clock.millis(),
    sessionCorrelation = correlateSession(sessionId),
    tool = safeAuditField(tool, MAX_AUDIT_TOOL_CHARS),
    readOnly = readOnly,
    argumentKeys = argumentKeys.asSequence()
        .take(MAX_AUDIT_ARGUMENT_KEYS * 4)
        .map { safeAuditField(it, MAX_AUDIT_ARGUMENT_KEY_CHARS) }
        .filter(String::isNotEmpty)
        .distinct()
        .sorted()
        .take(MAX_AUDIT_ARGUMENT_KEYS)
        .toList(),
)

private fun correlateSession(sessionId: String): String {
    val source = sessionId.ifBlank { "unknown" }
    val digest = MessageDigest.getInstance("SHA-256").digest(source.toByteArray(Charsets.UTF_8))
    return HexFormat.of().formatHex(digest).take(12)
}

private fun sanitizeRecord(record: McpAuditRecord, now: Long): McpAuditRecord = record.copy(
    timestampEpochMillis = record.timestampEpochMillis.coerceIn(0, now.coerceAtLeast(0) + TimeUnit.DAYS.toMillis(1)),
    sessionCorrelation = record.sessionCorrelation
        .takeIf(AUDIT_CORRELATION::matches)
        ?: correlateSession(record.sessionCorrelation),
    tool = safeAuditField(record.tool, MAX_AUDIT_TOOL_CHARS),
    argumentKeys = record.argumentKeys.asSequence()
        .take(MAX_AUDIT_ARGUMENT_KEYS * 4)
        .map { safeAuditField(it, MAX_AUDIT_ARGUMENT_KEY_CHARS) }
        .filter(String::isNotEmpty)
        .distinct()
        .sorted()
        .take(MAX_AUDIT_ARGUMENT_KEYS)
        .toList(),
    approvals = record.approvals.take(MAX_AUDIT_APPROVALS).map {
        McpAuditApproval(
            safeAuditField(it.kind, MAX_AUDIT_APPROVAL_FIELD_CHARS),
            safeAuditField(it.decision, MAX_AUDIT_APPROVAL_FIELD_CHARS),
        )
    },
    durationMillis = record.durationMillis.coerceIn(0, TimeUnit.DAYS.toMillis(1)),
    outcome = safeAuditField(record.outcome, MAX_AUDIT_APPROVAL_FIELD_CHARS),
    errorType = record.errorType?.let { safeAuditField(it, MAX_AUDIT_DETAIL_CHARS) },
)

private fun safeAuditField(value: String, limit: Int): String = safeSingleLine(value, limit)
    .map { character ->
        if (character in 'a'..'z' || character in 'A'..'Z' || character in '0'..'9' || character in "._:-") {
            character
        } else {
            '_'
        }
    }
    .joinToString("")

internal fun McpConfig.boundedAuditRetentionEntries(): Int =
    auditRetentionEntries.coerceIn(MIN_AUDIT_RETENTION_ENTRIES, MAX_AUDIT_RETENTION_ENTRIES)
