package net.portswigger.mcp.tools

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicLongArray

class HistoryPerformanceDiagnosticsTest {
    @Test
    fun `fixed metrics and elapsed bucket edges are exact`() = runBlocking {
        var now = 0L
        val diagnostics = HistoryPerformanceDiagnostics { now }
        val elapsed = listOf(
            999_999L,
            1_000_000L,
            5_000_000L,
            10_000_000L,
            25_000_000L,
            50_000_000L,
            100_000_000L,
            250_000_000L,
            500_000_000L,
            1_000_000_000L,
            5_000_000_000L,
        )

        elapsed.forEach { duration ->
            diagnostics.measure(HistoryPerformanceMetric.INDEX_PROXY_ACQUISITION) {
                now += duration
            }
        }

        val snapshot = diagnostics.snapshot()
        assertEquals(HistoryPerformanceMetric.entries.size, snapshot.metrics.size)
        assertEquals(HistoryPerformanceMetric.entries.toList(), snapshot.metrics.map { it.metric })
        val metric = snapshot.metrics.single { it.metric == HistoryPerformanceMetric.INDEX_PROXY_ACQUISITION }
        assertEquals(11, metric.attempts)
        assertEquals(11, metric.completed)
        assertEquals(0, metric.failed)
        assertEquals(0, metric.cancelled)
        assertEquals(List(HISTORY_PERFORMANCE_BUCKET_COUNT) { 1L }, metric.latencyBuckets)
        assertEquals(5_000_000_000L, metric.maxNanos)
        snapshot.metrics.filterNot { it.metric == metric.metric }.forEach {
            assertEquals(0, it.attempts)
            assertEquals(List(HISTORY_PERFORMANCE_BUCKET_COUNT) { 0L }, it.latencyBuckets)
        }
    }

    @Test
    fun `completion failure and cancellation are classified and rethrown unchanged`() = runBlocking {
        var now = 0L
        val diagnostics = HistoryPerformanceDiagnostics { now }
        val failure = IllegalStateException("sentinel")
        val cancellation = CancellationException("cancelled")

        diagnostics.measure(HistoryPerformanceMetric.HTTP_SEARCH_PROCESSING) { now += 1 }
        val observedFailure = assertThrows(IllegalStateException::class.java) {
            runBlocking {
                diagnostics.measure(HistoryPerformanceMetric.HTTP_SEARCH_PROCESSING) {
                    now += 2
                    throw failure
                }
            }
        }
        val observedCancellation = assertThrows(CancellationException::class.java) {
            runBlocking {
                diagnostics.measure(HistoryPerformanceMetric.HTTP_SEARCH_PROCESSING) {
                    now += 3
                    throw cancellation
                }
            }
        }

        assertSame(failure, observedFailure)
        assertSame(cancellation, observedCancellation)
        val metric = diagnostics.snapshot().metrics.single {
            it.metric == HistoryPerformanceMetric.HTTP_SEARCH_PROCESSING
        }
        assertEquals(3, metric.attempts)
        assertEquals(1, metric.completed)
        assertEquals(1, metric.failed)
        assertEquals(1, metric.cancelled)
        assertEquals(3, metric.latencyBuckets.sum())
    }

    @Test
    fun `returned non-success outcome is classified without changing the result`() = runBlocking {
        val diagnostics = HistoryPerformanceDiagnostics()
        val result = diagnostics.measure(
            metric = HistoryPerformanceMetric.WEBSOCKET_SEARCH_PROCESSING,
            outcomeForResult = { HistoryPerformanceOutcome.FAILED },
        ) { "structured-error" }

        assertEquals("structured-error", result)
        val metric = diagnostics.snapshot().metrics.single {
            it.metric == HistoryPerformanceMetric.WEBSOCKET_SEARCH_PROCESSING
        }
        assertEquals(1, metric.attempts)
        assertEquals(0, metric.completed)
        assertEquals(1, metric.failed)
        assertEquals(0, metric.cancelled)
    }

    @Test
    fun `concurrent recording stays exact and fixed cardinality`() = runBlocking {
        val diagnostics = HistoryPerformanceDiagnostics()
        val workers = 100
        val perWorker = 1_000
        (0 until workers).map {
            async(Dispatchers.Default) {
                repeat(perWorker) {
                    diagnostics.measure(HistoryPerformanceMetric.WEBSOCKET_SEARCH_PROCESSING) { Unit }
                }
            }
        }.awaitAll()

        val snapshot = diagnostics.snapshot()
        assertEquals(HistoryPerformanceMetric.entries.size, snapshot.metrics.size)
        val metric = snapshot.metrics.single {
            it.metric == HistoryPerformanceMetric.WEBSOCKET_SEARCH_PROCESSING
        }
        assertEquals(100_000, metric.attempts)
        assertEquals(100_000, metric.completed)
        assertEquals(100_000, metric.latencyBuckets.sum())
    }

    @Test
    fun `counter saturation and negative clock deltas cannot wrap`() = runBlocking {
        var now = 100L
        val diagnostics = HistoryPerformanceDiagnostics { now }
        val countersField = HistoryPerformanceDiagnostics::class.java.getDeclaredField("counters").apply {
            isAccessible = true
        }
        val counters = countersField.get(diagnostics) as Array<*>
        val metricCounters = counters[HistoryPerformanceMetric.INDEX_SITE_MAP_PROCESSING.ordinal]!!
        for (fieldName in listOf("attempts", "completed")) {
            val field = metricCounters.javaClass.getDeclaredField(fieldName).apply { isAccessible = true }
            (field.get(metricCounters) as AtomicLong).set(Long.MAX_VALUE)
        }
        val bucketsField = metricCounters.javaClass.getDeclaredField("latencyBuckets").apply { isAccessible = true }
        val buckets = bucketsField.get(metricCounters) as AtomicLongArray
        buckets.set(0, Long.MAX_VALUE)

        diagnostics.measure(HistoryPerformanceMetric.INDEX_SITE_MAP_PROCESSING) {
            now = 0 // negative monotonic delta is coerced to zero and enters the first bucket
        }

        val metric = diagnostics.snapshot().metrics.single {
            it.metric == HistoryPerformanceMetric.INDEX_SITE_MAP_PROCESSING
        }
        assertEquals(Long.MAX_VALUE, metric.attempts)
        assertEquals(Long.MAX_VALUE, metric.completed)
        assertEquals(Long.MAX_VALUE, metric.latencyBuckets[0])
        assertFalse(metric.latencyBuckets.any { it < 0 })
    }

    @Test
    fun `clock failures and disabled recorder never alter operation results`() = runBlocking {
        val diagnostics = HistoryPerformanceDiagnostics { error("clock") }
        assertEquals("ok", diagnostics.measure(HistoryPerformanceMetric.INDEX_ORGANIZER_ACQUISITION) { "ok" })
        assertEquals(1, diagnostics.snapshot().metrics.single {
            it.metric == HistoryPerformanceMetric.INDEX_ORGANIZER_ACQUISITION
        }.attempts)

        assertEquals("disabled", HistoryPerformanceDiagnostics.NO_OP.measure(
            HistoryPerformanceMetric.HTTP_SEARCH_PROXY_ACQUISITION,
        ) { "disabled" })
        assertEquals(HistoryPerformanceSnapshot.empty(), HistoryPerformanceDiagnostics.NO_OP.snapshot())
    }
}
