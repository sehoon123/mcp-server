package net.portswigger.mcp

import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.McpConfig
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

@Serializable
data class HttpRateLimitSnapshot(
    val enabled: Boolean,
    val requestsPerSecond: Int,
    val closed: Boolean,
    val pacedAdmissions: Long,
    val lastCompleteSecondAdmissions: Long?,
    val waitingRequests: Int,
    val finishedWaits: Long,
    val averageWaitMillis: Double,
    val maxWaitMillis: Double,
    val interruptedRequests: Long,
)

/** One pacing budget for every Burp HTTP callback, not one budget per tool, target, or MCP session. */
internal class GlobalHttpRateLimiter(
    private val config: McpConfig,
    private val nanoTime: () -> Long = System::nanoTime,
) : HttpHandler, AutoCloseable {
    private val lock = ReentrantLock(true)
    private val changed = lock.newCondition()
    @Volatile
    private var enabled = config.httpRateLimitEnabled
    private var requestsPerSecond = config.httpRequestsPerSecond
    private var lastAdmissionNanos: Long? = null
    @Volatile
    private var closed = false
    private val startedNanos = nanoTime()
    private var bucket = 0L
    private var bucketAdmissions = 0L
    private var previousBucketAdmissions = 0L
    private var pacedAdmissions = 0L
    private var waitingRequests = 0
    private var finishedWaits = 0L
    private var totalWaitNanos = 0L
    private var maxWaitNanos = 0L
    private val interruptedRequests = AtomicLong()
    private val configListener: () -> Unit = {
        lock.withLock {
            enabled = config.httpRateLimitEnabled
            requestsPerSecond = config.httpRequestsPerSecond
            if (!enabled) lastAdmissionNanos = null
            changed.signalAll()
        }
    }
    private val listenerHandle = config.addHttpRateLimitChangeListener(configListener)

    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
        return try {
            awaitPermit()
            RequestToBeSentAction.continueWith(requestToBeSent, requestToBeSent.annotations())
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            // A cancelled waiter must not send an unpaced request or consume a future permit.
            RequestToBeSentAction.drop()
        }
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction =
        ResponseReceivedAction.continueWith(responseReceived, responseReceived.annotations())

    @Throws(InterruptedException::class)
    internal fun awaitPermit() {
        if (closed || !enabled) return
        try {
            lock.lockInterruptibly()
            try {
                var waitStarted: Long? = null
                try {
                    while (!closed && enabled) {
                        val now = nanoTime()
                        val intervalNanos = (1_000_000_000L + requestsPerSecond - 1) / requestsPerSecond
                        val remaining = lastAdmissionNanos?.let { intervalNanos - (now - it) } ?: 0L
                        if (remaining <= 0) {
                            // Do not accumulate idle credit or release overdue reservations in a catch-up burst.
                            lastAdmissionNanos = now
                            recordAdmission(now)
                            return
                        }
                        if (waitStarted == null) {
                            waitStarted = now
                            waitingRequests++
                        }
                        changed.awaitNanos(remaining)
                    }
                } finally {
                    waitStarted?.let { start ->
                        waitingRequests--
                        val waited = (nanoTime() - start).coerceAtLeast(0)
                        finishedWaits = saturatedAdd(finishedWaits, 1)
                        totalWaitNanos = saturatedAdd(totalWaitNanos, waited)
                        maxWaitNanos = maxOf(maxWaitNanos, waited)
                    }
                }
            } finally {
                lock.unlock()
            }
        } catch (e: InterruptedException) {
            interruptedRequests.updateAndGet { saturatedAdd(it, 1) }
            throw e
        }
    }

    private fun recordAdmission(now: Long) {
        val currentBucket = (now - startedNanos).coerceAtLeast(0) / 1_000_000_000L
        if (currentBucket != bucket) {
            previousBucketAdmissions = if (currentBucket == bucket + 1) bucketAdmissions else 0
            bucketAdmissions = 0
            bucket = currentBucket
        }
        bucketAdmissions = saturatedAdd(bucketAdmissions, 1)
        pacedAdmissions = saturatedAdd(pacedAdmissions, 1)
    }

    fun snapshot(): HttpRateLimitSnapshot = lock.withLock {
        val currentBucket = (nanoTime() - startedNanos).coerceAtLeast(0) / 1_000_000_000L
        HttpRateLimitSnapshot(
            enabled = enabled,
            requestsPerSecond = requestsPerSecond,
            closed = closed,
            pacedAdmissions = pacedAdmissions,
            lastCompleteSecondAdmissions = when {
                currentBucket == 0L -> null
                currentBucket == bucket -> previousBucketAdmissions
                currentBucket == bucket + 1 -> bucketAdmissions
                else -> 0
            },
            waitingRequests = waitingRequests,
            finishedWaits = finishedWaits,
            averageWaitMillis = if (finishedWaits == 0L) 0.0 else totalWaitNanos.toDouble() / finishedWaits / 1_000_000,
            maxWaitMillis = maxWaitNanos / 1_000_000.0,
            interruptedRequests = interruptedRequests.get(),
        )
    }

    override fun close() {
        lock.withLock {
            closed = true
            changed.signalAll()
        }
        listenerHandle.remove()
    }
}

private fun saturatedAdd(value: Long, increment: Long): Long =
    if (increment > Long.MAX_VALUE - value) Long.MAX_VALUE else value + increment
