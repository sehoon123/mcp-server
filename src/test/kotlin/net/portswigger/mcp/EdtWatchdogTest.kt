package net.portswigger.mcp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.ArrayDeque
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

class EdtWatchdogTest {
    @Test
    fun `one pending probe coalesces backlog and records fixed delay buckets`() {
        val now = AtomicLong(10)
        val queued = ArrayDeque<Runnable>()
        val watchdog = EdtWatchdog(
            enqueue = queued::addLast,
            nanoTime = now::get,
            sampleIntervalMillis = 60_000,
        )

        assertTrue(watchdog.requestProbe())
        assertFalse(watchdog.requestProbe())
        assertEquals(1, queued.size)

        now.addAndGet(TimeUnit.MILLISECONDS.toNanos(1_500))
        queued.removeFirst().run()

        assertTrue(watchdog.requestProbe())
        now.addAndGet(TimeUnit.MILLISECONDS.toNanos(125))
        queued.removeFirst().run()

        val snapshot = watchdog.snapshot()
        assertEquals(2, snapshot.samples)
        assertEquals(1, snapshot.coalescedProbes)
        assertEquals(2, snapshot.delaysAtLeast100Millis)
        assertEquals(1, snapshot.delaysAtLeast250Millis)
        assertEquals(1, snapshot.delaysAtLeast1Second)
        assertEquals(1_500, snapshot.maxDelayMillis)
        assertEquals(0, snapshot.errors)
        watchdog.close()
    }

    @Test
    fun `enqueue failure clears the pending lease and remains recoverable`() {
        val now = AtomicLong(0)
        val queued = ArrayDeque<Runnable>()
        var reject = true
        val watchdog = EdtWatchdog(
            enqueue = { task ->
                if (reject) throw IllegalStateException("synthetic enqueue failure")
                queued.addLast(task)
            },
            nanoTime = now::get,
            sampleIntervalMillis = 60_000,
        )

        assertFalse(watchdog.requestProbe())
        assertEquals(1, watchdog.snapshot().errors)

        reject = false
        assertTrue(watchdog.requestProbe())
        now.set(TimeUnit.MILLISECONDS.toNanos(25))
        queued.removeFirst().run()

        val snapshot = watchdog.snapshot()
        assertEquals(1, snapshot.samples)
        assertEquals(25, snapshot.maxDelayMillis)
        assertEquals(1, snapshot.errors)
        watchdog.close()
    }

    @Test
    fun `close prevents probes and makes an already queued probe inert`() {
        val now = AtomicLong(0)
        val queued = ArrayDeque<Runnable>()
        val watchdog = EdtWatchdog(
            enqueue = queued::addLast,
            nanoTime = now::get,
            sampleIntervalMillis = 60_000,
        )

        assertTrue(watchdog.requestProbe())
        watchdog.close()
        now.set(TimeUnit.SECONDS.toNanos(2))
        queued.removeFirst().run()

        assertFalse(watchdog.requestProbe())
        assertEquals(EdtWatchdogSnapshot(0, 0, 0, 0, 0, 0, 0), watchdog.snapshot())
    }

    @Test
    fun `start schedules probes and close stops later samples`() {
        val sampled = CountDownLatch(1)
        val watchdog = EdtWatchdog(
            enqueue = { task ->
                task.run()
                sampled.countDown()
            },
            sampleIntervalMillis = 5,
        )

        try {
            watchdog.start()
            watchdog.start()
            assertTrue(sampled.await(1, TimeUnit.SECONDS))
        } finally {
            watchdog.close()
        }

        assertTrue(watchdog.snapshot().samples >= 1)
        assertFalse(watchdog.requestProbe())
    }

    @Test
    fun `new watchdog exposes only an empty fixed-cardinality snapshot`() {
        val watchdog = EdtWatchdog(sampleIntervalMillis = 60_000)

        assertEquals(EdtWatchdogSnapshot(), watchdog.snapshot())
        watchdog.close()
    }
}
