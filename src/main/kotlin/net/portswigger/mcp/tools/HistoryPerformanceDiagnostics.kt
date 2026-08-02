package net.portswigger.mcp.tools

import kotlinx.coroutines.CancellationException
import kotlinx.serialization.Serializable
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicLongArray

@Serializable
enum class HistoryPerformanceMetric {
    INDEX_PROXY_ACQUISITION,
    INDEX_PROXY_PROCESSING,
    INDEX_SITE_MAP_ACQUISITION,
    INDEX_SITE_MAP_PROCESSING,
    INDEX_ORGANIZER_ACQUISITION,
    INDEX_ORGANIZER_PROCESSING,
    HTTP_SEARCH_PROXY_ACQUISITION,
    HTTP_SEARCH_SITE_MAP_ACQUISITION,
    HTTP_SEARCH_ORGANIZER_ACQUISITION,
    HTTP_SEARCH_PROCESSING,
    WEBSOCKET_SEARCH_ACQUISITION,
    WEBSOCKET_SEARCH_PROCESSING,
    RELATED_CORRELATION_MONTOYA_ACQUISITION,
    RELATED_CORRELATION_EXTENSION_PROCESSING,
    SCANNER_DELTA_MONTOYA_ACQUISITION,
    SCANNER_DELTA_EXTENSION_PROCESSING,
}

enum class HistoryPerformanceOutcome {
    COMPLETED,
    FAILED,
    CANCELLED,
}

@Serializable
data class HistoryPerformanceMetricSnapshot(
    val metric: HistoryPerformanceMetric,
    val active: Int,
    val attempts: Long,
    val completed: Long,
    val failed: Long,
    val cancelled: Long,
    val latencyBuckets: List<Long>,
    val totalNanos: Long,
    val maxNanos: Long,
)

@Serializable
data class HistoryPerformanceSnapshot(
    val metrics: List<HistoryPerformanceMetricSnapshot>,
) {
    companion object {
        fun empty(): HistoryPerformanceSnapshot = HistoryPerformanceSnapshot(
            HistoryPerformanceMetric.entries.map { metric ->
                HistoryPerformanceMetricSnapshot(
                    metric = metric,
                    active = 0,
                    attempts = 0,
                    completed = 0,
                    failed = 0,
                    cancelled = 0,
                    latencyBuckets = List(HISTORY_PERFORMANCE_BUCKET_COUNT) { 0 },
                    totalNanos = 0,
                    maxNanos = 0,
                )
            },
        )
    }
}

internal const val HISTORY_PERFORMANCE_BUCKET_COUNT = 11
private const val UNAVAILABLE_NANO_TIME = Long.MIN_VALUE
private const val HISTORY_PERFORMANCE_SNAPSHOT_READ_ATTEMPTS = 4
internal val HISTORY_PERFORMANCE_BUCKET_UPPER_MILLIS =
    listOf(1L, 5L, 10L, 25L, 50L, 100L, 250L, 500L, 1_000L, 5_000L)

/**
 * Fixed-cardinality, value-free timing diagnostics for local performance attribution.
 *
 * Only aggregate counters and elapsed monotonic time are retained. No traffic, project, client, filter, exception, or
 * Montoya value is accepted by this API. Each per-metric read is validated with a bounded retry, but a returned metric
 * may still be torn under sustained writes and the complete fixed metric set is never cross-metric atomic.
 */
internal class HistoryPerformanceDiagnostics private constructor(
    private val enabled: Boolean,
    private val nanoTime: () -> Long,
) {
    constructor(nanoTime: () -> Long = System::nanoTime) : this(true, nanoTime)

    private val counters = Array(HistoryPerformanceMetric.entries.size) { MetricCounters() }

    suspend fun <T> measure(
        metric: HistoryPerformanceMetric,
        block: suspend () -> T,
    ): T = measure(metric, { HistoryPerformanceOutcome.COMPLETED }, block)

    suspend fun <T> measure(
        metric: HistoryPerformanceMetric,
        outcomeForResult: (T) -> HistoryPerformanceOutcome,
        block: suspend () -> T,
    ): T {
        if (!enabled) return block()
        val start = safeNanoTime()
        val metricCounters = counters[metric.ordinal]
        metricCounters.enter()
        var outcome = HistoryPerformanceOutcome.COMPLETED
        try {
            val result = block()
            outcome = runCatching { outcomeForResult(result) }
                .getOrDefault(HistoryPerformanceOutcome.COMPLETED)
            return result
        } catch (error: CancellationException) {
            outcome = HistoryPerformanceOutcome.CANCELLED
            throw error
        } catch (error: Throwable) {
            outcome = HistoryPerformanceOutcome.FAILED
            throw error
        } finally {
            runCatching {
                val elapsed = elapsedNanos(start, safeNanoTime())
                metricCounters.record(outcome, elapsed)
            }
            metricCounters.leave()
        }
    }

    fun snapshot(): HistoryPerformanceSnapshot = if (!enabled) {
        HistoryPerformanceSnapshot.empty()
    } else {
        HistoryPerformanceSnapshot(
            HistoryPerformanceMetric.entries.map { metric -> counters[metric.ordinal].snapshot(metric) },
        )
    }

    private fun safeNanoTime(): Long = runCatching(nanoTime).getOrDefault(UNAVAILABLE_NANO_TIME)

    companion object {
        val NO_OP = HistoryPerformanceDiagnostics(false, { 0 })
    }
}

private class MetricCounters {
    private val active = AtomicInteger()
    private val attempts = AtomicLong()
    private val completed = AtomicLong()
    private val failed = AtomicLong()
    private val cancelled = AtomicLong()
    private val latencyBuckets = AtomicLongArray(HISTORY_PERFORMANCE_BUCKET_COUNT)
    private val totalNanos = AtomicLong()
    private val maxNanos = AtomicLong()

    fun enter() {
        active.incrementAndGet()
    }

    fun leave() {
        active.decrementAndGet()
    }

    fun record(outcome: HistoryPerformanceOutcome, elapsedNanos: Long) {
        when (outcome) {
            HistoryPerformanceOutcome.COMPLETED -> completed.incrementSaturated()
            HistoryPerformanceOutcome.FAILED -> failed.incrementSaturated()
            HistoryPerformanceOutcome.CANCELLED -> cancelled.incrementSaturated()
        }
        latencyBuckets.incrementSaturated(bucketIndex(elapsedNanos))
        totalNanos.addSaturated(elapsedNanos.coerceAtLeast(0))
        maxNanos.updateMaximum(elapsedNanos)
        // Publish the record only after every counter contributing to the validated snapshot has been updated.
        attempts.incrementSaturated()
    }

    fun snapshot(metric: HistoryPerformanceMetric): HistoryPerformanceMetricSnapshot {
        var observed = readSnapshot(metric)
        repeat(HISTORY_PERFORMANCE_SNAPSHOT_READ_ATTEMPTS - 1) {
            if (historyPerformanceCountersSettled(observed)) return observed
            observed = readSnapshot(metric)
        }
        return observed
    }

    private fun readSnapshot(metric: HistoryPerformanceMetric): HistoryPerformanceMetricSnapshot {
        val observedAttempts = attempts.get()
        // Read timing before the outcome counters. If this read observes a writer's timing update, its preceding outcome
        // and bucket writes happen-before the reads below and cannot make a partial first record look settled.
        val observedMaximum = maxNanos.get()
        val observedTotal = totalNanos.get()
        val observedCompleted = completed.get()
        val observedFailed = failed.get()
        val observedCancelled = cancelled.get()
        val observedBuckets = List(HISTORY_PERFORMANCE_BUCKET_COUNT, latencyBuckets::get)
        return HistoryPerformanceMetricSnapshot(
            metric = metric,
            active = active.get().coerceAtLeast(0),
            attempts = observedAttempts,
            completed = observedCompleted,
            failed = observedFailed,
            cancelled = observedCancelled,
            latencyBuckets = observedBuckets,
            totalNanos = observedTotal,
            maxNanos = observedMaximum,
        )
    }
}

internal fun historyPerformanceCountersSettled(snapshot: HistoryPerformanceMetricSnapshot): Boolean = with(snapshot) {
    completed.saturatedPlus(failed).saturatedPlus(cancelled) == attempts &&
        latencyBuckets.fold(0L) { total, count -> total.saturatedPlus(count) } == attempts &&
        maxNanos <= totalNanos &&
        (attempts != 0L || (totalNanos == 0L && maxNanos == 0L))
}

private val HISTORY_PERFORMANCE_BUCKET_UPPER_NANOS =
    HISTORY_PERFORMANCE_BUCKET_UPPER_MILLIS.map { millis -> millis * 1_000_000L }

private fun bucketIndex(elapsedNanos: Long): Int {
    val bounded = elapsedNanos.coerceAtLeast(0)
    val index = HISTORY_PERFORMANCE_BUCKET_UPPER_NANOS.indexOfFirst { upperBound -> bounded < upperBound }
    return if (index >= 0) index else HISTORY_PERFORMANCE_BUCKET_COUNT - 1
}

private fun Long.saturatedPlus(other: Long): Long =
    if (this >= Long.MAX_VALUE - other.coerceAtLeast(0)) Long.MAX_VALUE else this + other.coerceAtLeast(0)

private fun AtomicLong.incrementSaturated() {
    while (true) {
        val current = get()
        if (current == Long.MAX_VALUE || compareAndSet(current, current + 1)) return
    }
}

private fun AtomicLongArray.incrementSaturated(index: Int) {
    while (true) {
        val current = get(index)
        if (current == Long.MAX_VALUE || compareAndSet(index, current, current + 1)) return
    }
}

private fun AtomicLong.addSaturated(increment: Long) {
    val bounded = increment.coerceAtLeast(0)
    while (true) {
        val current = get()
        val next = if (current >= Long.MAX_VALUE - bounded) Long.MAX_VALUE else current + bounded
        if (current == Long.MAX_VALUE || compareAndSet(current, next)) return
    }
}

private fun AtomicLong.updateMaximum(value: Long) {
    val bounded = value.coerceAtLeast(0)
    while (true) {
        val current = get()
        if (bounded <= current || compareAndSet(current, bounded)) return
    }
}

private fun elapsedNanos(start: Long, end: Long): Long =
    if (start == UNAVAILABLE_NANO_TIME || end == UNAVAILABLE_NANO_TIME) 0 else (end - start).coerceAtLeast(0)
