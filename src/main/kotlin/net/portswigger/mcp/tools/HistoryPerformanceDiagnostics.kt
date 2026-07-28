package net.portswigger.mcp.tools

import kotlinx.coroutines.CancellationException
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicLongArray

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
}

enum class HistoryPerformanceOutcome {
    COMPLETED,
    FAILED,
    CANCELLED,
}

data class HistoryPerformanceMetricSnapshot(
    val metric: HistoryPerformanceMetric,
    val attempts: Long,
    val completed: Long,
    val failed: Long,
    val cancelled: Long,
    val latencyBuckets: List<Long>,
    val maxNanos: Long,
)

data class HistoryPerformanceSnapshot(
    val metrics: List<HistoryPerformanceMetricSnapshot>,
) {
    companion object {
        fun empty(): HistoryPerformanceSnapshot = HistoryPerformanceSnapshot(
            HistoryPerformanceMetric.entries.map { metric ->
                HistoryPerformanceMetricSnapshot(
                    metric = metric,
                    attempts = 0,
                    completed = 0,
                    failed = 0,
                    cancelled = 0,
                    latencyBuckets = List(HISTORY_PERFORMANCE_BUCKET_COUNT) { 0 },
                    maxNanos = 0,
                )
            },
        )
    }
}

internal const val HISTORY_PERFORMANCE_BUCKET_COUNT = 11
internal val HISTORY_PERFORMANCE_BUCKET_UPPER_MILLIS =
    listOf(1L, 5L, 10L, 25L, 50L, 100L, 250L, 500L, 1_000L, 5_000L)

/**
 * Fixed-cardinality, value-free timing diagnostics for local performance attribution.
 *
 * Only aggregate counters and elapsed monotonic time are retained. No traffic, project, client, filter, exception, or
 * Montoya value is accepted by this API.
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
                counters[metric.ordinal].record(outcome, elapsed)
            }
        }
    }

    fun snapshot(): HistoryPerformanceSnapshot = if (!enabled) {
        HistoryPerformanceSnapshot.empty()
    } else {
        HistoryPerformanceSnapshot(
            HistoryPerformanceMetric.entries.map { metric -> counters[metric.ordinal].snapshot(metric) },
        )
    }

    private fun safeNanoTime(): Long = runCatching(nanoTime).getOrDefault(0)

    companion object {
        val NO_OP = HistoryPerformanceDiagnostics(false, { 0 })
    }
}

private class MetricCounters {
    private val attempts = AtomicLong()
    private val completed = AtomicLong()
    private val failed = AtomicLong()
    private val cancelled = AtomicLong()
    private val latencyBuckets = AtomicLongArray(HISTORY_PERFORMANCE_BUCKET_COUNT)
    private val maxNanos = AtomicLong()

    fun record(outcome: HistoryPerformanceOutcome, elapsedNanos: Long) {
        attempts.incrementSaturated()
        when (outcome) {
            HistoryPerformanceOutcome.COMPLETED -> completed.incrementSaturated()
            HistoryPerformanceOutcome.FAILED -> failed.incrementSaturated()
            HistoryPerformanceOutcome.CANCELLED -> cancelled.incrementSaturated()
        }
        latencyBuckets.incrementSaturated(bucketIndex(elapsedNanos))
        maxNanos.updateMaximum(elapsedNanos)
    }

    fun snapshot(metric: HistoryPerformanceMetric) = HistoryPerformanceMetricSnapshot(
        metric = metric,
        attempts = attempts.get(),
        completed = completed.get(),
        failed = failed.get(),
        cancelled = cancelled.get(),
        latencyBuckets = List(HISTORY_PERFORMANCE_BUCKET_COUNT, latencyBuckets::get),
        maxNanos = maxNanos.get(),
    )
}

private val HISTORY_PERFORMANCE_BUCKET_UPPER_NANOS =
    HISTORY_PERFORMANCE_BUCKET_UPPER_MILLIS.map { millis -> millis * 1_000_000L }

private fun bucketIndex(elapsedNanos: Long): Int {
    val bounded = elapsedNanos.coerceAtLeast(0)
    val index = HISTORY_PERFORMANCE_BUCKET_UPPER_NANOS.indexOfFirst { upperBound -> bounded < upperBound }
    return if (index >= 0) index else HISTORY_PERFORMANCE_BUCKET_COUNT - 1
}

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

private fun AtomicLong.updateMaximum(value: Long) {
    val bounded = value.coerceAtLeast(0)
    while (true) {
        val current = get()
        if (bounded <= current || compareAndSet(current, bounded)) return
    }
}

private fun elapsedNanos(start: Long, end: Long): Long = (end - start).coerceAtLeast(0)
