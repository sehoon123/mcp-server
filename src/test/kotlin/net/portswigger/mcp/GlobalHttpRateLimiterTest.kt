package net.portswigger.mcp

import burp.api.montoya.core.ToolType
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import io.mockk.verify
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

@Timeout(10)
class GlobalHttpRateLimiterTest {
    private lateinit var config: McpConfig
    private lateinit var limiter: GlobalHttpRateLimiter
    private val continued = mockk<RequestToBeSentAction>()
    private val dropped = mockk<RequestToBeSentAction>()

    @BeforeEach
    fun setup() {
        config = McpConfig(mockk(relaxed = true), mockk(relaxed = true), testPreferences())
        limiter = GlobalHttpRateLimiter(config)
        mockkStatic(RequestToBeSentAction::class, ResponseReceivedAction::class)
        every { RequestToBeSentAction.continueWith(any(), any()) } returns continued
        every { RequestToBeSentAction.drop() } returns dropped
    }

    @AfterEach
    fun cleanup() {
        limiter.close()
        unmockkStatic(RequestToBeSentAction::class, ResponseReceivedAction::class)
    }

    @Test
    fun `disabled handler preserves requests annotations and responses without reading their contents`() {
        val request = mockk<HttpRequestToBeSent>(relaxed = true)
        val response = mockk<HttpResponseReceived>(relaxed = true)
        val responseAction = mockk<ResponseReceivedAction>()
        every { ResponseReceivedAction.continueWith(response, response.annotations()) } returns responseAction
        assertSame(continued, limiter.handleHttpRequestToBeSent(request))
        assertSame(responseAction, limiter.handleHttpResponseReceived(response))
        verify(exactly = 1) { RequestToBeSentAction.continueWith(request, request.annotations()) }
        verify(exactly = 0) { request.body(); request.httpService(); request.toolSource() }

        Thread.currentThread().interrupt()
        try {
            assertSame(continued, limiter.handleHttpRequestToBeSent(request))
            assertTrue(Thread.currentThread().isInterrupted)
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun `concurrent sources share one budget even with MCP off and approval bypass on`() {
        config.enabled = false
        config.approvalYoloMode = true
        config.httpRequestsPerSecond = 20
        config.httpRateLimitEnabled = true
        val sources = listOf(ToolType.PROXY, ToolType.REPEATER, ToolType.INTRUDER, ToolType.SCANNER,
            ToolType.EXTENSIONS, ToolType.TARGET, ToolType.SEQUENCER, ToolType.BURP_AI)
        val pool = Executors.newFixedThreadPool(sources.size)
        val start = CountDownLatch(1)
        try {
            val futures = sources.map { source ->
                val request = mockk<HttpRequestToBeSent>(relaxed = true)
                every { request.toolSource().toolType() } returns source
                pool.submit<Long> {
                    start.await()
                    assertSame(continued, limiter.handleHttpRequestToBeSent(request))
                    System.nanoTime()
                }
            }
            val before = System.nanoTime()
            start.countDown()
            futures.forEach { it.get(5, TimeUnit.SECONDS) }
            assertTrue(System.nanoTime() - before >= TimeUnit.MILLISECONDS.toNanos(350),
                "Eight requests at 20 RPS must span at least seven 50ms intervals")
            assertEquals(8L, limiter.snapshot().pacedAdmissions)
            assertEquals(0, limiter.snapshot().waitingRequests)
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun `idle time earns no burst credit`() {
        config.httpRequestsPerSecond = 20
        config.httpRateLimitEnabled = true
        limiter.awaitPermit()
        Thread.sleep(150)
        val start = System.nanoTime()
        limiter.awaitPermit()
        limiter.awaitPermit()
        assertTrue(System.nanoTime() - start >= TimeUnit.MILLISECONDS.toNanos(50))
    }

    @Test
    fun `disabling or closing promptly releases all waiting requests`() {
        for (close in listOf(false, true)) {
            config.httpRequestsPerSecond = 1
            config.httpRateLimitEnabled = true
            limiter.awaitPermit()
            val done = CountDownLatch(3)
            val waiters = List(3) { thread { limiter.awaitPermit(); done.countDown() } }
            try {
                waiters.forEach(::awaitWaiting)
                if (close) limiter.close() else config.httpRateLimitEnabled = false
                assertTrue(done.await(500, TimeUnit.MILLISECONDS), "Disable/unload must wake every waiter")
                waiters.forEach { it.join(500) }
            } finally {
                waiters.forEach { it.interrupt(); it.join(1000) }
            }
        }
        limiter.close()
        limiter.awaitPermit()
    }

    @Test
    fun `live rate increase wakes waiters and rate decrease keeps last admission`() {
        config.httpRequestsPerSecond = 1
        config.httpRateLimitEnabled = true
        limiter.awaitPermit()
        val done = CountDownLatch(1)
        val waiter = thread { limiter.awaitPermit(); done.countDown() }
        try {
            awaitWaiting(waiter)
            config.httpRequestsPerSecond = 1000
            assertTrue(done.await(500, TimeUnit.MILLISECONDS))
            waiter.join(500)
            config.httpRequestsPerSecond = 1
            val next = thread { limiter.awaitPermit() }
            try {
                awaitWaiting(next)
                assertTrue(next.isAlive, "Lowering the rate must not reset the last admission")
            } finally {
                config.httpRateLimitEnabled = false
                next.join(1000)
            }
        } finally {
            waiter.interrupt()
            waiter.join(1000)
        }
    }

    @Test
    fun `interrupted waiter drops the request and restores interruption without reserving capacity`() {
        config.httpRequestsPerSecond = 1
        config.httpRateLimitEnabled = true
        limiter.awaitPermit()
        val result = AtomicReference<RequestToBeSentAction>()
        val interrupted = AtomicBoolean()
        val waiter = thread {
            result.set(limiter.handleHttpRequestToBeSent(mockk(relaxed = true)))
            interrupted.set(Thread.currentThread().isInterrupted)
        }
        try {
            awaitWaiting(waiter)
            waiter.interrupt()
            waiter.join(1000)
            assertFalse(waiter.isAlive)
            assertSame(dropped, result.get())
            assertTrue(interrupted.get())
            verify(exactly = 0) { RequestToBeSentAction.continueWith(any(), any()) }
            config.httpRateLimitEnabled = false
            config.httpRequestsPerSecond = 10
            config.httpRateLimitEnabled = true
            limiter.awaitPermit()
        } finally {
            waiter.interrupt()
            waiter.join(1000)
        }
    }

    @Test
    fun `snapshot reports complete monotonic buckets not stale idle traffic or disabled passes`() {
        limiter.close()
        val clock = java.util.concurrent.atomic.AtomicLong(0)
        limiter = GlobalHttpRateLimiter(config, clock::get)
        limiter.awaitPermit()
        assertEquals(0L, limiter.snapshot().pacedAdmissions)
        assertEquals(null, limiter.snapshot().lastCompleteSecondAdmissions)
        config.httpRequestsPerSecond = 1000
        config.httpRateLimitEnabled = true
        limiter.awaitPermit()
        clock.set(1_000_000)
        repeat(10) { limiter.snapshot() }
        limiter.awaitPermit()
        assertEquals(2L, limiter.snapshot().pacedAdmissions)
        clock.set(1_000_000_000)
        repeat(10) { assertEquals(2L, limiter.snapshot().lastCompleteSecondAdmissions) }
        limiter.awaitPermit()
        assertEquals(2L, limiter.snapshot().lastCompleteSecondAdmissions)
        clock.set(2_000_000_000)
        assertEquals(1L, limiter.snapshot().lastCompleteSecondAdmissions)
        clock.set(5_000_000_000)
        assertEquals(0L, limiter.snapshot().lastCompleteSecondAdmissions)
        config.httpRateLimitEnabled = false
        limiter.awaitPermit()
        assertEquals(3L, limiter.snapshot().pacedAdmissions)
        limiter.close()
        assertTrue(limiter.snapshot().closed)
    }

    @Test
    fun `finished wait accounting includes interruption disable and close without counting extra admissions`() {
        for (exit in listOf("interrupt", "disable", "close")) {
            limiter.close()
            config.httpRequestsPerSecond = 1
            config.httpRateLimitEnabled = true
            limiter = GlobalHttpRateLimiter(config)
            limiter.awaitPermit()
            val waiter = thread { runCatching { limiter.awaitPermit() } }
            try {
                awaitWaiting(waiter)
                val pending = limiter.snapshot()
                assertEquals(1, pending.waitingRequests)
                assertEquals(0L, pending.finishedWaits)
                assertEquals(1L, pending.pacedAdmissions)
                when (exit) {
                    "interrupt" -> waiter.interrupt()
                    "disable" -> config.httpRateLimitEnabled = false
                    else -> limiter.close()
                }
                waiter.join(1000)
                assertFalse(waiter.isAlive)
                val finished = limiter.snapshot()
                assertEquals(0, finished.waitingRequests)
                assertEquals(1L, finished.finishedWaits)
                assertEquals(1L, finished.pacedAdmissions)
                assertTrue(finished.averageWaitMillis > 0)
                assertEquals(finished.averageWaitMillis, finished.maxWaitMillis)
                assertEquals(if (exit == "interrupt") 1L else 0L, finished.interruptedRequests)
            } finally {
                waiter.interrupt()
                waiter.join(1000)
            }
        }
    }

    @Test
    fun `interruption before lock acquisition is counted without a condition wait`() {
        config.httpRateLimitEnabled = true
        Thread.currentThread().interrupt()
        try {
            assertSame(dropped, limiter.handleHttpRequestToBeSent(mockk(relaxed = true)))
            assertTrue(Thread.currentThread().isInterrupted)
        } finally {
            Thread.interrupted()
        }
        assertEquals(1L, limiter.snapshot().interruptedRequests)
        assertEquals(0L, limiter.snapshot().pacedAdmissions)
        assertEquals(0L, limiter.snapshot().finishedWaits)
        assertEquals(0, limiter.snapshot().waitingRequests)
    }

    private fun awaitWaiting(worker: Thread) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (worker.state != Thread.State.TIMED_WAITING && worker.isAlive && System.nanoTime() < deadline) {
            Thread.sleep(1)
        }
        assertEquals(Thread.State.TIMED_WAITING, worker.state)
    }
}
