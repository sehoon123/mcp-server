package net.portswigger.mcp.tools

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLongArray
import kotlin.test.assertEquals

class MetadataChangeSignalsTest {
    @Test
    fun `revisions are fixed isolated and exact under concurrent bursts`() = runBlocking {
        val signals = MetadataChangeSignals()

        (0 until 100).map {
            async(Dispatchers.Default) {
                repeat(1_000) { signals.markChanged(MetadataChangeSource.PROXY_HTTP) }
            }
        }.awaitAll()
        signals.markChanged(MetadataChangeSource.ORGANIZER)

        assertEquals(100_000L, signals.revision(MetadataChangeSource.PROXY_HTTP))
        assertEquals(1L, signals.revision(MetadataChangeSource.ORGANIZER))
        assertEquals(0L, signals.revision(MetadataChangeSource.SITE_MAP))
        assertEquals(0L, signals.revision(MetadataChangeSource.WEBSOCKET))
        assertEquals(0L, signals.revision(MetadataChangeSource.SCANNER_ISSUES))
        val field = MetadataChangeSignals::class.java.getDeclaredField("revisions").apply { isAccessible = true }
        assertEquals(MetadataChangeSource.entries.size, (field.get(signals) as AtomicLongArray).length())
    }

    @Test
    fun `close and no-op signals reject later changes`() {
        val signals = MetadataChangeSignals()
        signals.markChanged(MetadataChangeSource.SITE_MAP)
        signals.close()
        signals.markChanged(MetadataChangeSource.SITE_MAP)
        signals.close()

        assertEquals(1L, signals.revision(MetadataChangeSource.SITE_MAP))
        MetadataChangeSignals.NO_OP.markChanged(MetadataChangeSource.PROXY_HTTP)
        assertEquals(0L, MetadataChangeSignals.NO_OP.revision(MetadataChangeSource.PROXY_HTTP))
    }

    @Test
    fun `close linearizes against in-flight markers`() = runBlocking {
        val signals = MetadataChangeSignals()
        val running = AtomicBoolean(true)
        val started = CountDownLatch(1)
        val workers = (0 until 1).map {
            async(Dispatchers.Default) {
                started.countDown()
                while (running.get()) signals.markChanged(MetadataChangeSource.PROXY_HTTP)
            }
        }
        started.await()

        signals.close()
        val revisionAfterClose = signals.revision(MetadataChangeSource.PROXY_HTTP)
        running.set(false)
        workers.awaitAll()
        repeat(100_000) { signals.markChanged(MetadataChangeSource.PROXY_HTTP) }

        assertEquals(revisionAfterClose, signals.revision(MetadataChangeSource.PROXY_HTTP))
    }

    @Test
    fun `revisions saturate without wrapping`() {
        val signals = MetadataChangeSignals()
        val field = MetadataChangeSignals::class.java.getDeclaredField("revisions").apply { isAccessible = true }
        val revisions = field.get(signals) as AtomicLongArray
        revisions.set(MetadataChangeSource.SCANNER_ISSUES.ordinal, Long.MAX_VALUE)

        signals.markChanged(MetadataChangeSource.SCANNER_ISSUES)

        assertEquals(Long.MAX_VALUE, signals.revision(MetadataChangeSource.SCANNER_ISSUES))
    }
}
