package net.portswigger.mcp

import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import net.portswigger.mcp.config.McpConfig
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** One pacing budget for every Burp HTTP callback, not one budget per tool, target, or MCP session. */
internal class GlobalHttpRateLimiter(private val config: McpConfig) : HttpHandler, AutoCloseable {
    private val lock = ReentrantLock(true)
    private val changed = lock.newCondition()
    @Volatile
    private var enabled = config.httpRateLimitEnabled
    private var requestsPerSecond = config.httpRequestsPerSecond
    private var lastAdmissionNanos: Long? = null
    @Volatile
    private var closed = false
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
        lock.lockInterruptibly()
        try {
            while (!closed && enabled) {
                val now = System.nanoTime()
                val intervalNanos = (1_000_000_000L + requestsPerSecond - 1) / requestsPerSecond
                val remaining = lastAdmissionNanos?.let { intervalNanos - (now - it) } ?: 0L
                if (remaining <= 0) {
                    // Do not accumulate idle credit or release overdue reservations in a catch-up burst.
                    lastAdmissionNanos = now
                    return
                }
                changed.awaitNanos(remaining)
            }
        } finally {
            lock.unlock()
        }
    }

    override fun close() {
        lock.withLock {
            closed = true
            changed.signalAll()
        }
        listenerHandle.remove()
    }
}
