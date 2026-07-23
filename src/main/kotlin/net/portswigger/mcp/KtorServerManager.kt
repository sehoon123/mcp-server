package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.sse.ServerSentEvent
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.ApplicationStopped
import io.ktor.server.application.ApplicationStopping
import io.ktor.server.application.install
import io.ktor.server.cio.CIO
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.applicationEnvironment
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.cors.routing.CORS
import io.ktor.server.request.header
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.request.uri
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.delete
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.server.sse.SSE
import io.ktor.server.sse.sse
import io.ktor.util.AttributeKey
import io.modelcontextprotocol.kotlin.sdk.server.DnsRebindingProtection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.ServerSession
import io.modelcontextprotocol.kotlin.sdk.server.StreamableHttpServerTransport
import io.modelcontextprotocol.kotlin.sdk.types.EmptyResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.JSONRPCError
import io.modelcontextprotocol.kotlin.sdk.types.McpJson
import io.modelcontextprotocol.kotlin.sdk.types.PingRequest
import io.modelcontextprotocol.kotlin.sdk.types.RPCError
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import net.portswigger.mcp.config.ConfigValidation
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.McpAuditSink
import net.portswigger.mcp.security.NoOpMcpAuditSink
import net.portswigger.mcp.security.safeExceptionSummary
import net.portswigger.mcp.tools.ToolServices
import net.portswigger.mcp.tools.registerTools
import net.portswigger.mcp.tools.unbindToolRuntimePolicy
import java.net.BindException
import java.security.MessageDigest
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

private const val MCP_PATH = "/mcp"
private const val MCP_SESSION_ID_HEADER = "Mcp-Session-Id"
private const val MCP_PROTOCOL_VERSION_HEADER = "Mcp-Protocol-Version"
private const val MCP_MAX_REQUEST_BODY_BYTES = 2L * 1024 * 1024
private const val MCP_MAX_REQUEST_URI_CHARS = 8 * 1024
private const val MCP_MAX_HEADER_COUNT = 64
private const val MCP_MAX_HEADER_CHARS = 32 * 1024
private const val MCP_MAX_CONCURRENT_HTTP_CALLS = 64
private const val MCP_MAX_SESSIONS = 32
private const val MCP_SESSION_IDLE_MILLIS = 15L * 60 * 1000
private const val MCP_SESSION_SWEEP_MILLIS = 60L * 1000
private const val CIO_IDLE_TIMEOUT_SECONDS = 180
private const val MCP_SSE_HEARTBEAT_MILLIS = 15_000L
private const val MCP_SSE_CLIENT_LIVENESS_TIMEOUT_MILLIS = 2_000L
private const val MCP_SSE_INITIAL_LIVENESS_DELAY_MILLIS = 250L
private const val MCP_SESSION_SHUTDOWN_TIMEOUT_MILLIS = 2_000L
private val MCP_HTTP_CALL_LEASE_KEY = AttributeKey<McpHttpCallLease>("McpHttpCallLease")
private val LOOPBACK_HOSTS = setOf("localhost", "127.0.0.1", "::1")
private val DNS_ALLOWED_HOSTS = listOf("localhost", "127.0.0.1", "[::1]")
private val DNS_ALLOWED_ORIGINS = listOf("http://localhost", "http://127.0.0.1", "http://[::1]")

internal enum class McpClientLivenessOutcome {
    RESPONDED,
    TIMED_OUT,
    ERROR,
}

/**
 * Installs the single authenticated Streamable HTTP endpoint.
 *
 * A null [bearerToken] is reserved for local conformance tests. Production startup always supplies the
 * per-installation token from [McpConfig].
 */
internal fun Application.configureMcpHttpEndpoint(
    mcpServer: Server,
    port: Int,
    bearerToken: String? = null,
    runtimeMetrics: McpRuntimeMetrics? = null,
    maxSessions: Int = MCP_MAX_SESSIONS,
    sseHeartbeatMillis: Long = MCP_SSE_HEARTBEAT_MILLIS,
    sseClientLivenessTimeoutMillis: Long = MCP_SSE_CLIENT_LIVENESS_TIMEOUT_MILLIS,
) {
    require(maxSessions > 0) { "maxSessions must be positive" }
    require(sseHeartbeatMillis > 0) { "sseHeartbeatMillis must be positive" }
    require(sseClientLivenessTimeoutMillis > 0) { "SSE client liveness timeout must be positive" }
    if (bearerToken != null) {
        require(bearerToken.length in 32..128 && bearerToken.none { it.isWhitespace() || it.isISOControl() }) {
            "local MCP bearer token is invalid"
        }
    }

    install(CORS) {
        allowHost("localhost:$port")
        allowHost("127.0.0.1:$port")
        allowHost("[::1]:$port")
        allowOrigins(::isLoopbackOrigin)

        allowMethod(HttpMethod.Options)
        allowMethod(HttpMethod.Get)
        allowMethod(HttpMethod.Post)
        allowMethod(HttpMethod.Delete)

        allowHeader(HttpHeaders.Authorization)
        allowHeader(HttpHeaders.ContentType)
        allowHeader(HttpHeaders.Accept)
        allowHeader("Last-Event-ID")
        allowHeader(MCP_SESSION_ID_HEADER)
        allowHeader(MCP_PROTOCOL_VERSION_HEADER)
        exposeHeader(MCP_SESSION_ID_HEADER)
        exposeHeader(MCP_PROTOCOL_VERSION_HEADER)

        allowCredentials = false
        allowNonSimpleContentTypes = true
        maxAgeInSeconds = 3600
    }
    install(ContentNegotiation) {
        json(McpJson)
    }
    install(SSE)

    intercept(ApplicationCallPipeline.Setup) {
        context.response.header("X-Frame-Options", "DENY")
        context.response.header("X-Content-Type-Options", "nosniff")
        context.response.header("Referrer-Policy", "no-referrer")
        context.response.header("Content-Security-Policy", "default-src 'none'")
        context.response.header(HttpHeaders.CacheControl, "no-store")

        if (context.request.path() == MCP_PATH) {
            runtimeMetrics?.onRequest()
            val hosts = context.request.headers.getAll(HttpHeaders.Host).orEmpty()
            val origins = context.request.headers.getAll(HttpHeaders.Origin).orEmpty()
            if (hosts.size != 1 || !isLoopbackHostHeader(hosts.single(), port) ||
                origins.size > 1 || (origins.size == 1 && !isLoopbackOrigin(origins.single()))
            ) {
                runtimeMetrics?.onHostOriginRejected()
                context.respondText("Forbidden", status = HttpStatusCode.Forbidden)
                finish()
            }
        }
    }

    val activeCalls = java.util.concurrent.atomic.AtomicInteger()
    intercept(ApplicationCallPipeline.Call) {
        if (context.request.path() != MCP_PATH) {
            proceed()
            return@intercept
        }

        validateRequestMetadata(context)?.let { rejection ->
            runtimeMetrics?.onMetadataRejected()
            context.respondText(rejection.message, status = rejection.status)
            finish()
            return@intercept
        }

        if (activeCalls.incrementAndGet() > MCP_MAX_CONCURRENT_HTTP_CALLS) {
            activeCalls.decrementAndGet()
            runtimeMetrics?.onOverloadRejected()
            context.response.header(HttpHeaders.RetryAfter, "1")
            context.respondText("MCP endpoint is busy", status = HttpStatusCode.TooManyRequests)
            finish()
            return@intercept
        }
        val callLease = McpHttpCallLease(activeCalls, runtimeMetrics)
        context.attributes.put(MCP_HTTP_CALL_LEASE_KEY, callLease)
        runtimeMetrics?.onCallStarted()
        try {
            proceed()
        } finally {
            callLease.close()
        }
    }

    val sessions = BoundedMcpSessionRegistry(maxSessions, MCP_SESSION_IDLE_MILLIS, runtimeMetrics)
    monitor.subscribe(ApplicationStopping) {
        runtimeMetrics?.markStopping()
        runBlocking {
            withTimeoutOrNull(MCP_SESSION_SHUTDOWN_TIMEOUT_MILLIS) { sessions.closeAll() }
        }
    }
    monitor.subscribe(ApplicationStopped) {
        runtimeMetrics?.markStopped()
    }
    launch(CoroutineName("McpSessionIdleCleanup")) {
        while (isActive) {
            delay(MCP_SESSION_SWEEP_MILLIS)
            sessions.evictIdle()
        }
    }

    routing {
        route(MCP_PATH) {
            install(DnsRebindingProtection) {
                allowedHosts = DNS_ALLOWED_HOSTS
                allowedOrigins = DNS_ALLOWED_ORIGINS
            }

            intercept(ApplicationCallPipeline.Plugins) {
                if (context.request.path() == MCP_PATH &&
                    context.request.httpMethod != HttpMethod.Options &&
                    bearerToken != null && !hasValidBearerToken(context, bearerToken)
                ) {
                    runtimeMetrics?.onAuthenticationRejected()
                    context.response.header(HttpHeaders.WWWAuthenticate, "Bearer")
                    context.respondText("Unauthorized", status = HttpStatusCode.Unauthorized)
                    finish()
                }
            }

            route("", HttpMethod.Get) {
                sse {
                    val lease = sessions.acquireExisting(call) ?: return@sse
                    val streamJob = currentCoroutineContext()[Job]
                    if (
                        streamJob == null || !lease.registerStream(
                            streamJob,
                            onReopened = { runtimeMetrics?.onEventStreamReopened() },
                        )
                    ) {
                        lease.close()
                        call.rejectMcp(
                            HttpStatusCode.NotFound,
                            RPCError.ErrorCode.CONNECTION_CLOSED,
                            "Session not found",
                        )
                        return@sse
                    }

                    call.response.header(MCP_SESSION_ID_HEADER, lease.sessionId)
                    val sseSession = this
                    val streamMetricsLease = McpEventStreamMetricsLease(runtimeMetrics)
                    suspend fun detachStream(reason: String) {
                        runCatching { sseSession.close() }
                        lease.unregisterStream(streamJob)
                        lease.close()
                        streamMetricsLease.close()
                        call.attributes.getOrNull(MCP_HTTP_CALL_LEASE_KEY)?.close()
                        streamJob.cancel(CancellationException(reason))
                    }
                    val heartbeatJob = launch(CoroutineName("McpSseHeartbeat")) {
                        while (isActive) {
                            delay(sseHeartbeatMillis)
                            try {
                                sseSession.send(ServerSentEvent(comments = "mcp-keepalive"))
                            } catch (e: CancellationException) {
                                detachStream("MCP SSE stream cancelled")
                                throw e
                            } catch (_: Exception) {
                                runtimeMetrics?.onHeartbeatFailure()
                                detachStream("MCP SSE client disconnected")
                                return@launch
                            }
                        }
                    }
                    val livenessJob = launch(CoroutineName("McpSseClientLiveness")) {
                        // CIO's request-close callback is not reliable for a graceful FIN on every supported JVM/OS.
                        // A core MCP ping proves that the client still receives this stream without large heartbeat
                        // writes or cancelling POST tool calls. A timeout closes only this optional GET stream; a
                        // compliant client reconnects and the session itself remains available.
                        delay(minOf(MCP_SSE_INITIAL_LIVENESS_DELAY_MILLIS, sseHeartbeatMillis))
                        while (isActive) {
                            runtimeMetrics?.onLivenessPingSent()
                            val outcome = lease.pingClient(sseClientLivenessTimeoutMillis)
                            when (outcome) {
                                McpClientLivenessOutcome.RESPONDED -> runtimeMetrics?.onLivenessResponse()
                                McpClientLivenessOutcome.TIMED_OUT -> runtimeMetrics?.onLivenessTimeout()
                                McpClientLivenessOutcome.ERROR -> runtimeMetrics?.onLivenessError()
                            }
                            if (outcome != McpClientLivenessOutcome.RESPONDED) {
                                // On some Windows CIO paths the network writer closes but the response coroutine does
                                // not resume its finally block. Detach the bounded-registry and admission leases before
                                // cancellation; both are idempotent when normal coroutine cleanup also runs.
                                detachStream("MCP SSE client did not respond to ping")
                                return@launch
                            }
                            delay(sseHeartbeatMillis)
                        }
                    }
                    try {
                        lease.transport.handleRequest(sseSession, call)
                    } finally {
                        livenessJob.cancel()
                        heartbeatJob.cancel()
                        lease.unregisterStream(streamJob)
                        lease.close()
                        streamMetricsLease.close()
                    }
                }
            }

            post {
                val sessionId = call.request.header(MCP_SESSION_ID_HEADER)
                if (sessionId != null) {
                    val lease = sessions.acquireExisting(call) ?: return@post
                    try {
                        lease.transport.handleRequest(null, call)
                    } finally {
                        lease.close()
                    }
                    return@post
                }

                val transport = StreamableHttpServerTransport(
                    StreamableHttpServerTransport.Configuration(
                        enableJsonResponse = true,
                        maxRequestBodySize = MCP_MAX_REQUEST_BODY_BYTES,
                    )
                )
                val reservation = sessions.reserve(transport)
                if (reservation == null) {
                    runtimeMetrics?.onSessionCapacityRejected()
                    runCatching { transport.close() }
                    call.response.header(HttpHeaders.RetryAfter, "60")
                    call.rejectMcp(
                        HttpStatusCode.ServiceUnavailable,
                        RPCError.ErrorCode.CONNECTION_CLOSED,
                        "MCP session capacity is full",
                    )
                    return@post
                }
                val pending = reservation.pending

                transport.setOnSessionInitialized { initializedSessionId ->
                    sessions.activate(pending, initializedSessionId)
                }
                transport.setOnSessionClosed {
                    sessions.remove(pending)
                }

                var completedNormally = false
                try {
                    reservation.displaced?.let { displaced ->
                        withContext(NonCancellable) {
                            withTimeoutOrNull(MCP_SESSION_SHUTDOWN_TIMEOUT_MILLIS) {
                                runCatching { displaced.closeTransport() }
                            }
                        }
                    }
                    val serverSession = mcpServer.createSession(transport)
                    pending.attachServerSession(serverSession)
                    transport.handleRequest(null, call)
                    completedNormally = true
                } finally {
                    if (!completedNormally) {
                        sessions.remove(pending)
                        pending.closeTransport()
                    } else if (!pending.isActive()) {
                        sessions.abandon(pending)
                        pending.closeTransport()
                    }
                }
            }

            delete {
                runtimeMetrics?.onSessionDeleteRequest()
                val lease = sessions.acquireExisting(call) ?: return@delete
                try {
                    lease.transport.handleRequest(null, call)
                } finally {
                    lease.close()
                }
            }
        }
    }
}

private class McpEventStreamMetricsLease(
    private val runtimeMetrics: McpRuntimeMetrics?,
) {
    private val closed = AtomicBoolean(false)

    init {
        runtimeMetrics?.onEventStreamOpened()
    }

    fun close() {
        if (closed.compareAndSet(false, true)) runtimeMetrics?.onEventStreamClosed()
    }
}

private class McpHttpCallLease(
    private val activeCalls: java.util.concurrent.atomic.AtomicInteger,
    private val runtimeMetrics: McpRuntimeMetrics?,
) {
    private val closed = AtomicBoolean(false)

    fun close() {
        if (closed.compareAndSet(false, true)) {
            activeCalls.decrementAndGet()
            runtimeMetrics?.onCallFinished()
        }
    }
}

private data class HttpRejection(val status: HttpStatusCode, val message: String)

private fun validateRequestMetadata(call: ApplicationCall): HttpRejection? {
    if (call.request.uri.length > MCP_MAX_REQUEST_URI_CHARS) {
        return HttpRejection(HttpStatusCode.RequestURITooLong, "Request URI is too long")
    }

    var headerCount = 0
    var headerChars = 0L
    for (name in call.request.headers.names()) {
        val values = call.request.headers.getAll(name).orEmpty()
        headerCount += values.size.coerceAtLeast(1)
        headerChars += name.utf8Length()
        values.forEach { value -> headerChars += value.utf8Length() }
        if (headerCount > MCP_MAX_HEADER_COUNT || headerChars > MCP_MAX_HEADER_CHARS) {
            return HttpRejection(HttpStatusCode.RequestHeaderFieldTooLarge, "Request headers are too large")
        }
    }

    val contentLengths = call.request.headers.getAll(HttpHeaders.ContentLength).orEmpty()
    val transferEncodings = call.request.headers.getAll(HttpHeaders.TransferEncoding).orEmpty()
    if (contentLengths.size > 1 || (contentLengths.isNotEmpty() && transferEncodings.isNotEmpty())) {
        return HttpRejection(HttpStatusCode.BadRequest, "Ambiguous request body framing")
    }
    if (contentLengths.isNotEmpty()) {
        val contentLength = contentLengths.single().toLongOrNull()
            ?: return HttpRejection(HttpStatusCode.BadRequest, "Invalid Content-Length header")
        if (contentLength < 0) {
            return HttpRejection(HttpStatusCode.BadRequest, "Invalid Content-Length header")
        }
        if (contentLength > MCP_MAX_REQUEST_BODY_BYTES) {
            return HttpRejection(HttpStatusCode.PayloadTooLarge, "Request body is too large")
        }
    }
    return null
}

private fun String.utf8Length(): Long {
    var bytes = 0L
    for (character in this) {
        bytes += when {
            character.code <= 0x7f -> 1
            character.code <= 0x7ff -> 2
            character.isHighSurrogate() || character.isLowSurrogate() -> 2
            else -> 3
        }
    }
    return bytes
}

private fun hasValidBearerToken(call: ApplicationCall, expected: String): Boolean {
    val values = call.request.headers.getAll(HttpHeaders.Authorization) ?: return false
    if (values.size != 1) return false
    val value = values.single()
    val separator = value.indexOf(' ')
    if (separator <= 0 || !value.substring(0, separator).equals("Bearer", ignoreCase = true)) return false
    val supplied = value.substring(separator + 1)
    if (supplied.isEmpty() || supplied.any { it.isWhitespace() || it.isISOControl() }) return false
    return MessageDigest.isEqual(supplied.toByteArray(Charsets.UTF_8), expected.toByteArray(Charsets.UTF_8))
}

private fun isLoopbackHostHeader(value: String, port: Int): Boolean {
    val normalized = value.lowercase()
    return normalized == "localhost" || normalized == "127.0.0.1" || normalized == "[::1]" ||
        normalized == "localhost:$port" || normalized == "127.0.0.1:$port" || normalized == "[::1]:$port"
}

private fun isLoopbackOrigin(origin: String): Boolean = runCatching {
    val uri = java.net.URI(origin)
    val scheme = uri.scheme?.lowercase()
    val host = uri.host?.removePrefix("[")?.removeSuffix("]")?.lowercase()
    val authorityHost = if (host == "::1") "[::1]" else host
    val expectedAuthority = when {
        authorityHost == null -> null
        uri.port == -1 -> authorityHost
        uri.port in 1..65_535 -> "$authorityHost:${uri.port}"
        else -> null
    }
    (scheme == "http" || scheme == "https") &&
        host in LOOPBACK_HOSTS &&
        uri.rawAuthority?.lowercase() == expectedAuthority &&
        uri.rawUserInfo == null &&
        uri.rawQuery == null &&
        uri.rawFragment == null &&
        uri.rawPath.isNullOrEmpty()
}.getOrDefault(false)

private suspend fun ApplicationCall.rejectMcp(status: HttpStatusCode, code: Int, message: String) {
    respond(
        status,
        JSONRPCError(
            id = null,
            error = RPCError(code = code, message = message),
        ),
    )
}

internal data class McpSessionReservation(
    val pending: ManagedMcpSession,
    val displaced: ManagedMcpSession? = null,
)

internal class BoundedMcpSessionRegistry(
    maxSessions: Int,
    private val idleMillis: Long,
    private val runtimeMetrics: McpRuntimeMetrics? = null,
) {
    private val lock = Any()
    private val slots = Semaphore(maxSessions, true)
    private val sessions = HashMap<String, ManagedMcpSession>()
    private val entries = HashSet<ManagedMcpSession>()
    private var closed = false

    fun reserve(transport: StreamableHttpServerTransport): McpSessionReservation? = synchronized(lock) {
        if (closed) return null

        var displaced: ManagedMcpSession? = null
        if (!slots.tryAcquire()) {
            displaced = sessions.values
                .mapNotNull { entry -> entry.capacityEvictionOrder()?.let { order -> entry to order } }
                .minByOrNull { (_, order) -> order }
                ?.first
                ?: return null
            displaced.sessionId()?.let { sessionId -> sessions.remove(sessionId, displaced) }
            entries.remove(displaced)
            displaced.releaseSlot()
            runtimeMetrics?.onPressureEvicted()
            check(slots.tryAcquire()) { "displaced MCP session did not release its capacity slot" }
        }

        val pending = ManagedMcpSession(transport, slots)
        entries += pending
        updateMetricsLocked()
        McpSessionReservation(pending = pending, displaced = displaced)
    }

    fun activate(entry: ManagedMcpSession, sessionId: String) {
        val accepted = synchronized(lock) {
            if (closed || sessionId.isBlank() || sessionId.length > 128 || sessions.containsKey(sessionId)) {
                false
            } else {
                entry.activate(sessionId)
                sessions[sessionId] = entry
                updateMetricsLocked()
                true
            }
        }
        if (!accepted) {
            synchronized(lock) {
                entries.remove(entry)
                updateMetricsLocked()
            }
            entry.releaseSlot()
        } else {
            runtimeMetrics?.onSessionInitialized()
        }
    }

    suspend fun acquireExisting(call: ApplicationCall): ManagedMcpSessionLease? {
        val sessionIds = call.request.headers.getAll(MCP_SESSION_ID_HEADER).orEmpty()
        val sessionId = sessionIds.singleOrNull()
        if (sessionId.isNullOrEmpty() || sessionId.length > 128 || sessionId.any(Char::isISOControl)) {
            call.rejectMcp(
                HttpStatusCode.BadRequest,
                RPCError.ErrorCode.CONNECTION_CLOSED,
                "Bad Request: No valid session ID provided",
            )
            return null
        }
        val entry = synchronized(lock) {
            sessions[sessionId]?.also { it.acquire() }
        }
        if (entry == null) {
            call.rejectMcp(
                HttpStatusCode.NotFound,
                RPCError.ErrorCode.CONNECTION_CLOSED,
                "Session not found",
            )
            return null
        }
        return ManagedMcpSessionLease(entry, sessionId)
    }

    fun remove(entry: ManagedMcpSession) {
        synchronized(lock) {
            entry.sessionId()?.let { id -> sessions.remove(id, entry) }
            entries.remove(entry)
            updateMetricsLocked()
        }
        entry.cancelStreams()
        entry.releaseSlot()
    }

    fun abandon(entry: ManagedMcpSession) {
        if (!entry.isActive()) {
            synchronized(lock) {
                entries.remove(entry)
                updateMetricsLocked()
            }
            entry.releaseSlot()
        }
    }

    suspend fun evictIdle() {
        val now = System.nanoTime()
        val expired = synchronized(lock) {
            val stale = sessions.values.filter { it.isIdle(now, idleMillis) }
            stale.forEach { entry ->
                entry.sessionId()?.let { sessions.remove(it, entry) }
                entries.remove(entry)
            }
            updateMetricsLocked()
            stale
        }
        runtimeMetrics?.onIdleEvicted(expired.size)
        expired.forEach { entry ->
            entry.releaseSlot()
            try {
                entry.closeTransport()
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // Idle cleanup is best-effort; the slot is already reclaimed and no request can reacquire this entry.
            }
        }
    }

    suspend fun closeAll() {
        val abandoned = synchronized(lock) {
            if (closed) return
            closed = true
            val snapshot = entries.toList()
            sessions.clear()
            entries.clear()
            updateMetricsLocked()
            snapshot
        }
        abandoned.forEach { entry ->
            entry.releaseSlot()
            runCatching { entry.closeTransport() }
        }
    }

    private fun updateMetricsLocked() {
        runtimeMetrics?.updateSessions(
            pending = (entries.size - sessions.size).coerceAtLeast(0),
            active = sessions.size,
        )
    }
}

internal class ManagedMcpSession(
    val transport: StreamableHttpServerTransport,
    private val slots: Semaphore,
) {
    private val slotReleased = AtomicBoolean(false)
    private val transportClosed = AtomicBoolean(false)
    private val streamJobs = HashSet<Job>()
    private var streamRegistrationClosed = false
    private var hasRegisteredStream = false
    private var activeSessionId: String? = null
    private var serverSession: ServerSession? = null
    private var activeCalls = 0
    private var lastActivityNanos = System.nanoTime()

    @Synchronized
    fun activate(sessionId: String) {
        activeSessionId = sessionId
        lastActivityNanos = System.nanoTime()
    }

    @Synchronized
    fun attachServerSession(session: ServerSession) {
        check(serverSession == null) { "MCP server session is already attached" }
        serverSession = session
    }

    @Synchronized
    fun acquire() {
        activeCalls++
        lastActivityNanos = System.nanoTime()
    }

    @Synchronized
    fun release() {
        if (activeCalls > 0) activeCalls--
        lastActivityNanos = System.nanoTime()
    }

    @Synchronized
    fun registerStream(job: Job, onReopened: () -> Unit = {}): Boolean {
        if (streamRegistrationClosed) return false
        val reopened = hasRegisteredStream && streamJobs.isEmpty()
        hasRegisteredStream = true
        streamJobs += job
        if (reopened) onReopened()
        return true
    }

    @Synchronized
    fun unregisterStream(job: Job) {
        streamJobs -= job
        lastActivityNanos = System.nanoTime()
    }

    fun cancelStreams() {
        val jobs = synchronized(this) {
            streamRegistrationClosed = true
            streamJobs.toList().also { streamJobs.clear() }
        }
        jobs.forEach { it.cancel(CancellationException("MCP session closed")) }
    }

    @Synchronized
    fun isIdle(nowNanos: Long, idleMillis: Long): Boolean =
        activeCalls == 0 && nowNanos - lastActivityNanos >= TimeUnit.MILLISECONDS.toNanos(idleMillis)

    @Synchronized
    fun sessionId(): String? = activeSessionId

    /**
     * Only sessions whose optional event stream was observed and has since disconnected are displaced under
     * capacity pressure. Sessions with active calls, an open stream, or no stream history retain their slot until
     * explicit termination or the normal idle timeout.
     */
    @Synchronized
    fun capacityEvictionOrder(): Long? =
        lastActivityNanos.takeIf { hasRegisteredStream && streamJobs.isEmpty() && activeCalls == 0 }

    fun isActive(): Boolean = sessionId() != null

    suspend fun pingClient(timeoutMillis: Long): McpClientLivenessOutcome {
        val session = synchronized(this) { serverSession } ?: return McpClientLivenessOutcome.ERROR
        return try {
            val responded = withTimeoutOrNull(timeoutMillis) {
                session.request<EmptyResult>(PingRequest())
                true
            }
            if (responded == true) McpClientLivenessOutcome.RESPONDED else McpClientLivenessOutcome.TIMED_OUT
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            McpClientLivenessOutcome.ERROR
        }
    }

    fun releaseSlot() {
        if (slotReleased.compareAndSet(false, true)) slots.release()
    }

    suspend fun closeTransport() {
        cancelStreams()
        if (transportClosed.compareAndSet(false, true)) transport.close()
    }
}

internal class ManagedMcpSessionLease(
    private val entry: ManagedMcpSession,
    val sessionId: String,
) {
    private val closed = AtomicBoolean(false)
    private val streamRegistered = AtomicBoolean(false)

    val transport: StreamableHttpServerTransport get() = entry.transport

    fun registerStream(job: Job, onReopened: () -> Unit = {}): Boolean {
        val registered = entry.registerStream(job, onReopened)
        if (registered) streamRegistered.set(true)
        return registered
    }

    fun unregisterStream(job: Job) {
        if (streamRegistered.compareAndSet(true, false)) entry.unregisterStream(job)
    }

    suspend fun pingClient(timeoutMillis: Long): McpClientLivenessOutcome = entry.pingClient(timeoutMillis)

    fun close() {
        if (closed.compareAndSet(false, true)) entry.release()
    }
}

class KtorServerManager internal constructor(
    private val api: MontoyaApi,
    private val auditSink: McpAuditSink,
) : ServerManager {

    constructor(api: MontoyaApi) : this(api, NoOpMcpAuditSink)

    private val serverVersion = KtorServerManager::class.java.`package`.implementationVersion ?: "dev"
    @Volatile
    private var runtimeMetrics = McpRuntimeMetrics(serverVersion, MCP_MAX_CONCURRENT_HTTP_CALLS, MCP_MAX_SESSIONS)
    private var server: EmbeddedServer<*, *>? = null
    private var mcpServer: Server? = null
    private val toolServices = ToolServices(api)
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()

    override fun start(config: McpConfig, callback: (ServerState) -> Unit) {
        val requestedHost = config.host
        val requestedPort = config.port
        val normalizedRequestedHost = ConfigValidation.normalizeLoopbackHost(requestedHost)
        val metrics = McpRuntimeMetrics(serverVersion, MCP_MAX_CONCURRENT_HTTP_CALLS, MCP_MAX_SESSIONS)
        val endpointPreview = normalizedRequestedHost
            ?.takeIf { requestedPort in 1..65_535 }
            ?.let { "http://${formatHostForUrl(it)}:$requestedPort/mcp" }
        metrics.markStarting(endpointPreview)
        runtimeMetrics = metrics
        callback(ServerState.Starting)

        executor.submit {
            try {
                stopCurrentServer()

                val bindHost = normalizedRequestedHost
                    ?: throw IllegalArgumentException(
                        "MCP server host must be 127.0.0.1 or ::1; non-loopback listeners are not supported"
                    )
                val newMcpServer = Server(
                    serverInfo = Implementation("burp-suite", serverVersion),
                    options = ServerOptions(
                        capabilities = ServerCapabilities(
                            tools = ServerCapabilities.Tools(listChanged = false)
                        )
                    )
                )
                newMcpServer.registerTools(api, config, toolServices, auditSink)
                mcpServer = newMcpServer

                val environment = applicationEnvironment()
                val newEngine = embeddedServer(
                    factory = CIO,
                    environment = environment,
                    configure = {
                        connector {
                            host = bindHost
                            port = requestedPort
                        }
                        connectionIdleTimeoutSeconds = CIO_IDLE_TIMEOUT_SECONDS
                    },
                ) {
                    configureMcpHttpEndpoint(
                        newMcpServer,
                        requestedPort,
                        config.localBearerToken,
                        metrics,
                    )
                }
                server = newEngine
                newEngine.start(wait = false)
                metrics.markRunning()

                api.logging().logToOutput(
                    "Started authenticated MCP Streamable HTTP server at http://${formatHostForUrl(bindHost)}:$requestedPort/mcp"
                )
                callback(ServerState.Running)

            } catch (e: Exception) {
                runCatching { stopCurrentServer() }
                val failure = normalizeMcpServerStartFailure(e, normalizedRequestedHost, requestedPort)
                val summary = safeExceptionSummary(failure)
                metrics.markFailed(summary)
                api.logging().logToError("MCP server failed: $summary")
                callback(ServerState.Failed(failure))
            }
        }
    }

    override fun stop(callback: (ServerState) -> Unit) {
        val metrics = runtimeMetrics
        metrics.markStopping()
        callback(ServerState.Stopping)

        executor.submit {
            try {
                stopCurrentServer()
                metrics.markStopped()
                api.logging().logToOutput("Stopped MCP server")
                callback(ServerState.Stopped)
            } catch (e: Exception) {
                val summary = safeExceptionSummary(e)
                metrics.markFailed(summary)
                api.logging().logToError("MCP server stop failed: $summary")
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun diagnostics(): McpDiagnosticsSnapshot = runtimeMetrics.snapshot()

    private fun stopCurrentServer() {
        val currentEngine = server
        server = null
        try {
            currentEngine?.stop(1000, 5000)
        } finally {
            val currentMcpServer = mcpServer
            mcpServer = null
            if (currentMcpServer != null) {
                currentMcpServer.unbindToolRuntimePolicy()
                try {
                    runBlocking {
                        withTimeoutOrNull(MCP_SESSION_SHUTDOWN_TIMEOUT_MILLIS) { currentMcpServer.close() }
                    }
                } catch (e: CancellationException) {
                    if (e.hasNonCancellationCause()) throw e
                    // Closing an MCP server cancels its own transport jobs. That is successful shutdown, not a failure.
                }
            }
        }
    }

    override fun shutdown() {
        val metrics = runtimeMetrics
        metrics.markStopping()
        runCatching {
            executor.submit { stopCurrentServer() }.get(10, TimeUnit.SECONDS)
            metrics.markStopped()
        }.onFailure {
            val summary = safeExceptionSummary(it)
            metrics.markFailed(summary)
            api.logging().logToError("MCP shutdown failed: $summary")
        }

        executor.shutdown()
        if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
            executor.shutdownNow()
        }
        toolServices.close()
    }
}

internal class McpServerStartupException(message: String, cause: Throwable) : Exception(message, cause)

internal fun normalizeMcpServerStartFailure(
    error: Throwable,
    bindHost: String?,
    port: Int,
): Throwable {
    if (error.causeChain().any { it is BindException }) {
        val endpoint = bindHost?.let { "${formatHostForUrl(it)}:$port" } ?: "the configured local endpoint"
        return McpServerStartupException(
            "Cannot start the MCP server because $endpoint is already in use. " +
                "Stop the existing listener or choose another local port.",
            error,
        )
    }
    if (error is CancellationException) {
        val underlying = error.causeChain().firstOrNull { it !== error && it !is CancellationException }
        val message = underlying?.let { "MCP server startup failed: ${safeExceptionSummary(it)}" }
            ?: "MCP server startup was cancelled before the listener became ready"
        return McpServerStartupException(message, error)
    }
    return error
}

private fun Throwable.hasNonCancellationCause(): Boolean =
    causeChain().any { it !is CancellationException }

private fun Throwable.causeChain(): Sequence<Throwable> = sequence {
    val seen = HashSet<Throwable>()
    var current: Throwable? = this@causeChain
    while (current != null && seen.size < 32 && seen.add(current)) {
        yield(current)
        current = current.cause
    }
}

private fun formatHostForUrl(host: String): String = if (':' in host) "[$host]" else host
