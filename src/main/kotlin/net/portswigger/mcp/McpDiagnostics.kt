package net.portswigger.mcp

import java.time.Clock
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

internal const val PRODUCTION_MCP_PROTOCOL_VERSION = "2025-11-25"

data class McpDiagnosticsSnapshot(
    val state: String,
    val serverVersion: String,
    val protocolVersion: String,
    val endpoint: String?,
    val startedAtEpochMillis: Long?,
    val lastActivityEpochMillis: Long?,
    val activeHttpCalls: Int,
    val peakHttpCalls: Int,
    val pendingSessions: Int,
    val activeSessions: Int,
    val totalRequests: Long,
    val initializedSessions: Long,
    val idleEvictions: Long,
    val hostOriginRejections: Long,
    val metadataRejections: Long,
    val authenticationRejections: Long,
    val overloadRejections: Long,
    val sessionCapacityRejections: Long,
    val lastError: String?,
    val maxHttpCalls: Int,
    val maxSessions: Int,
    val activeEventStreams: Int = 0,
    val openedEventStreams: Long = 0,
    val closedEventStreams: Long = 0,
    val reopenedEventStreams: Long = 0,
    val livenessPingsSent: Long = 0,
    val livenessResponses: Long = 0,
    val livenessTimeouts: Long = 0,
    val livenessErrors: Long = 0,
    val heartbeatFailures: Long = 0,
    val sessionDeleteRequests: Long = 0,
    val pressureEvictions: Long = 0,
)

internal fun unavailableMcpDiagnosticsSnapshot(): McpDiagnosticsSnapshot =
    McpRuntimeMetrics("unavailable", maxHttpCalls = 64, maxSessions = 32).snapshot()

/** Thread-safe, secret-free runtime counters for the local diagnostics UI. */
internal class McpRuntimeMetrics(
    private val serverVersion: String,
    private val maxHttpCalls: Int,
    private val maxSessions: Int,
    private val clock: Clock = Clock.systemUTC(),
) {
    private val state = AtomicReference("stopped")
    private val endpoint = AtomicReference<String?>(null)
    private val startedAt = AtomicLong(0)
    private val lastActivity = AtomicLong(0)
    private val activeHttpCalls = AtomicInteger(0)
    private val peakHttpCalls = AtomicInteger(0)
    private val activeEventStreams = AtomicInteger(0)
    private val openedEventStreams = AtomicLong(0)
    private val closedEventStreams = AtomicLong(0)
    private val reopenedEventStreams = AtomicLong(0)
    private val livenessPingsSent = AtomicLong(0)
    private val livenessResponses = AtomicLong(0)
    private val livenessTimeouts = AtomicLong(0)
    private val livenessErrors = AtomicLong(0)
    private val heartbeatFailures = AtomicLong(0)
    private val sessionDeleteRequests = AtomicLong(0)
    private val pressureEvictions = AtomicLong(0)
    private val pendingSessions = AtomicInteger(0)
    private val activeSessions = AtomicInteger(0)
    private val totalRequests = AtomicLong(0)
    private val initializedSessions = AtomicLong(0)
    private val idleEvictions = AtomicLong(0)
    private val hostOriginRejections = AtomicLong(0)
    private val metadataRejections = AtomicLong(0)
    private val authenticationRejections = AtomicLong(0)
    private val overloadRejections = AtomicLong(0)
    private val sessionCapacityRejections = AtomicLong(0)
    private val lastError = AtomicReference<String?>(null)

    fun markStarting(endpointValue: String?) {
        state.set("starting")
        endpoint.set(endpointValue)
        startedAt.set(0)
        lastActivity.set(0)
        activeHttpCalls.set(0)
        peakHttpCalls.set(0)
        activeEventStreams.set(0)
        openedEventStreams.set(0)
        closedEventStreams.set(0)
        reopenedEventStreams.set(0)
        livenessPingsSent.set(0)
        livenessResponses.set(0)
        livenessTimeouts.set(0)
        livenessErrors.set(0)
        heartbeatFailures.set(0)
        sessionDeleteRequests.set(0)
        pressureEvictions.set(0)
        pendingSessions.set(0)
        activeSessions.set(0)
        totalRequests.set(0)
        initializedSessions.set(0)
        idleEvictions.set(0)
        hostOriginRejections.set(0)
        metadataRejections.set(0)
        authenticationRejections.set(0)
        overloadRejections.set(0)
        sessionCapacityRejections.set(0)
        lastError.set(null)
    }

    fun markRunning() {
        state.set("running")
        startedAt.compareAndSet(0, clock.millis())
    }

    fun markStopping() {
        state.set("stopping")
    }

    fun markStopped() {
        state.set("stopped")
        activeHttpCalls.set(0)
        activeEventStreams.set(0)
        pendingSessions.set(0)
        activeSessions.set(0)
    }

    fun markFailed(safeError: String) {
        state.set("failed")
        lastError.set(safeError)
        activeHttpCalls.set(0)
        activeEventStreams.set(0)
        pendingSessions.set(0)
        activeSessions.set(0)
    }

    fun onRequest() {
        totalRequests.incrementAndGet()
        lastActivity.set(clock.millis())
    }

    fun onCallStarted(): Int {
        val current = activeHttpCalls.incrementAndGet()
        peakHttpCalls.accumulateAndGet(current, ::maxOf)
        return current
    }

    fun onCallFinished() {
        activeHttpCalls.updateAndGet { current -> (current - 1).coerceAtLeast(0) }
    }

    fun onEventStreamOpened() {
        activeEventStreams.incrementAndGet()
        openedEventStreams.incrementAndGet()
    }

    fun onEventStreamClosed() {
        activeEventStreams.updateAndGet { current -> (current - 1).coerceAtLeast(0) }
        closedEventStreams.incrementAndGet()
    }

    fun onEventStreamReopened() {
        reopenedEventStreams.incrementAndGet()
    }

    fun onLivenessPingSent() {
        livenessPingsSent.incrementAndGet()
    }

    fun onLivenessResponse() {
        livenessResponses.incrementAndGet()
    }

    fun onLivenessTimeout() {
        livenessTimeouts.incrementAndGet()
    }

    fun onLivenessError() {
        livenessErrors.incrementAndGet()
    }

    fun onHeartbeatFailure() {
        heartbeatFailures.incrementAndGet()
    }

    fun onSessionDeleteRequest() {
        sessionDeleteRequests.incrementAndGet()
    }

    fun onPressureEvicted() {
        pressureEvictions.incrementAndGet()
    }

    fun updateSessions(pending: Int, active: Int) {
        pendingSessions.set(pending.coerceIn(0, maxSessions))
        activeSessions.set(active.coerceIn(0, maxSessions))
    }

    fun onSessionInitialized() {
        initializedSessions.incrementAndGet()
    }

    fun onIdleEvicted(count: Int) {
        if (count > 0) idleEvictions.addAndGet(count.toLong())
    }

    fun onHostOriginRejected() {
        hostOriginRejections.incrementAndGet()
    }

    fun onMetadataRejected() {
        metadataRejections.incrementAndGet()
    }

    fun onAuthenticationRejected() {
        authenticationRejections.incrementAndGet()
    }

    fun onOverloadRejected() {
        overloadRejections.incrementAndGet()
    }

    fun onSessionCapacityRejected() {
        sessionCapacityRejections.incrementAndGet()
    }

    fun snapshot(): McpDiagnosticsSnapshot = McpDiagnosticsSnapshot(
        state = state.get(),
        serverVersion = serverVersion,
        protocolVersion = PRODUCTION_MCP_PROTOCOL_VERSION,
        endpoint = endpoint.get(),
        startedAtEpochMillis = startedAt.get().takeIf { it > 0 },
        lastActivityEpochMillis = lastActivity.get().takeIf { it > 0 },
        activeHttpCalls = activeHttpCalls.get(),
        peakHttpCalls = peakHttpCalls.get(),
        pendingSessions = pendingSessions.get(),
        activeSessions = activeSessions.get(),
        totalRequests = totalRequests.get(),
        initializedSessions = initializedSessions.get(),
        idleEvictions = idleEvictions.get(),
        hostOriginRejections = hostOriginRejections.get(),
        metadataRejections = metadataRejections.get(),
        authenticationRejections = authenticationRejections.get(),
        overloadRejections = overloadRejections.get(),
        sessionCapacityRejections = sessionCapacityRejections.get(),
        lastError = lastError.get(),
        maxHttpCalls = maxHttpCalls,
        maxSessions = maxSessions,
        activeEventStreams = activeEventStreams.get(),
        openedEventStreams = openedEventStreams.get(),
        closedEventStreams = closedEventStreams.get(),
        reopenedEventStreams = reopenedEventStreams.get(),
        livenessPingsSent = livenessPingsSent.get(),
        livenessResponses = livenessResponses.get(),
        livenessTimeouts = livenessTimeouts.get(),
        livenessErrors = livenessErrors.get(),
        heartbeatFailures = heartbeatFailures.get(),
        sessionDeleteRequests = sessionDeleteRequests.get(),
        pressureEvictions = pressureEvictions.get(),
    )
}
