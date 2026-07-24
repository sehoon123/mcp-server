package net.portswigger.mcp

import java.awt.EventQueue
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

private const val EDT_WATCHDOG_SAMPLE_INTERVAL_MILLIS = 500L
private val EDT_DELAY_100_MILLIS_NANOS = TimeUnit.MILLISECONDS.toNanos(100)
private val EDT_DELAY_250_MILLIS_NANOS = TimeUnit.MILLISECONDS.toNanos(250)
private val EDT_DELAY_1_SECOND_NANOS = TimeUnit.SECONDS.toNanos(1)

internal data class EdtWatchdogSnapshot(
    val samples: Long = 0,
    val coalescedProbes: Long = 0,
    val delaysAtLeast100Millis: Long = 0,
    val delaysAtLeast250Millis: Long = 0,
    val delaysAtLeast1Second: Long = 0,
    val maxDelayMillis: Long = 0,
    val errors: Long = 0,
)

/**
 * Samples Swing event-queue delay without ever waiting for the EDT.
 *
 * At most one probe may be queued. A stalled EDT therefore increments a fixed counter instead of accumulating
 * runnables, traffic data, or per-event state.
 */
internal class EdtWatchdog(
    private val enqueue: (Runnable) -> Unit = EventQueue::invokeLater,
    private val nanoTime: () -> Long = System::nanoTime,
    private val sampleIntervalMillis: Long = EDT_WATCHDOG_SAMPLE_INTERVAL_MILLIS,
) : AutoCloseable {
    private val started = AtomicBoolean(false)
    private val closed = AtomicBoolean(false)
    private val probePending = AtomicBoolean(false)
    private val samples = AtomicLong(0)
    private val coalescedProbes = AtomicLong(0)
    private val delaysAtLeast100Millis = AtomicLong(0)
    private val delaysAtLeast250Millis = AtomicLong(0)
    private val delaysAtLeast1Second = AtomicLong(0)
    private val maxDelayNanos = AtomicLong(0)
    private val errors = AtomicLong(0)
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "burp-mcp-edt-watchdog").apply { isDaemon = true }
    }

    init {
        require(sampleIntervalMillis > 0) { "EDT watchdog sample interval must be positive" }
    }

    fun start() {
        if (closed.get() || !started.compareAndSet(false, true)) return
        try {
            scheduler.scheduleWithFixedDelay(
                { requestProbe() },
                sampleIntervalMillis,
                sampleIntervalMillis,
                TimeUnit.MILLISECONDS,
            )
        } catch (_: RuntimeException) {
            if (!closed.get()) errors.incrementAndGet()
        }
    }

    internal fun requestProbe(): Boolean {
        if (closed.get()) return false
        if (!probePending.compareAndSet(false, true)) {
            coalescedProbes.incrementAndGet()
            return false
        }

        val enqueuedAt = try {
            nanoTime()
        } catch (_: RuntimeException) {
            probePending.set(false)
            errors.incrementAndGet()
            return false
        }

        return try {
            enqueue(Runnable {
                probePending.set(false)
                if (closed.get()) return@Runnable
                try {
                    recordDelay((nanoTime() - enqueuedAt).coerceAtLeast(0))
                } catch (_: RuntimeException) {
                    errors.incrementAndGet()
                }
            })
            true
        } catch (_: RuntimeException) {
            probePending.set(false)
            errors.incrementAndGet()
            false
        }
    }

    fun snapshot(): EdtWatchdogSnapshot = EdtWatchdogSnapshot(
        samples = samples.get(),
        coalescedProbes = coalescedProbes.get(),
        delaysAtLeast100Millis = delaysAtLeast100Millis.get(),
        delaysAtLeast250Millis = delaysAtLeast250Millis.get(),
        delaysAtLeast1Second = delaysAtLeast1Second.get(),
        maxDelayMillis = TimeUnit.NANOSECONDS.toMillis(maxDelayNanos.get()),
        errors = errors.get(),
    )

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        probePending.set(false)
        scheduler.shutdownNow()
    }

    private fun recordDelay(delayNanos: Long) {
        samples.incrementAndGet()
        if (delayNanos >= EDT_DELAY_100_MILLIS_NANOS) delaysAtLeast100Millis.incrementAndGet()
        if (delayNanos >= EDT_DELAY_250_MILLIS_NANOS) delaysAtLeast250Millis.incrementAndGet()
        if (delayNanos >= EDT_DELAY_1_SECOND_NANOS) delaysAtLeast1Second.incrementAndGet()
        maxDelayNanos.accumulateAndGet(delayNanos, ::maxOf)
    }
}
