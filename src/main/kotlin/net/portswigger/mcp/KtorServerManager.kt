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
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import net.portswigger.mcp.config.ConfigValidation
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.McpAuditSink
import net.portswigger.mcp.security.McpSessionApprovalRegistry
import net.portswigger.mcp.security.NoOpMcpAuditSink
import net.portswigger.mcp.security.safeExceptionSummary
import net.portswigger.mcp.security.safeSingleLine
import net.portswigger.mcp.presets.WorkflowPresetStore
import net.portswigger.mcp.tools.ToolServices
import net.portswigger.mcp.tools.activateToolExecutionSession
import net.portswigger.mcp.tools.cancelAllToolExecutions
import net.portswigger.mcp.tools.cancelToolExecutionSession
import net.portswigger.mcp.tools.enableToolExecutionSessionTracking
import net.portswigger.mcp.tools.registerTools
import net.portswigger.mcp.tools.unbindToolRuntimePolicy
import java.net.BindException
import java.security.MessageDigest
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

private const val MCP_PATH = "/mcp"
internal const val MCP_SERVER_INSTRUCTIONS =
    "For existing Burp HTTP traffic, reuse a projectId and {source,id} ref from a producing result; otherwise call " +
        "search_http_messages. Use get_http_message only when compact metadata is insufficient. Send variants via " +
        "send_http_request_from_id or route via route_http_message_from_id, passing only changed patch fields. " +
        "Omitted fields come from the stored source; every call restarts there, so patches are not cumulative. Never " +
        "rebuild stored traffic as raw HTTP; use raw tools only for genuinely new requests."
internal const val MCP_SESSION_ID_HEADER = "Mcp-Session-Id"
internal const val MCP_MAX_SESSION_ID_CHARS = 128
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
private const val MCP_PROJECT_STATE_CLEANUP_TIMEOUT_MILLIS = 2_000L
private val MCP_HTTP_CALL_LEASE_KEY = AttributeKey<McpHttpCallLease>("McpHttpCallLease")
private val MCP_PROJECT_GENERATION_KEY = AttributeKey<Long>("McpProjectGeneration")
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
    sessionApprovals: McpSessionApprovalRegistry = McpSessionApprovalRegistry(maxSessions),
    sseHeartbeatMillis: Long = MCP_SSE_HEARTBEAT_MILLIS,
    sseClientLivenessTimeoutMillis: Long = MCP_SSE_CLIENT_LIVENESS_TIMEOUT_MILLIS,
    projectIdProvider: (() -> String)? = null,
    onProjectBoundary: suspend () -> Unit = {},
) {
    require(maxSessions > 0) { "maxSessions must be positive" }
    require(sseHeartbeatMillis > 0) { "sseHeartbeatMillis must be positive" }
    require(sseClientLivenessTimeoutMillis > 0) { "SSE client liveness timeout must be positive" }
    if (bearerToken != null) {
        require(bearerToken.length in 32..128 && bearerToken.none { it.isWhitespace() || it.isISOControl() }) {
            "local MCP bearer token is invalid"
        }
    }
    val expectedBearerTokenBytes = bearerToken?.toByteArray(Charsets.UTF_8)

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

    mcpServer.enableToolExecutionSessionTracking()
    val sessions = BoundedMcpSessionRegistry(
        maxSessions,
        MCP_SESSION_IDLE_MILLIS,
        runtimeMetrics,
        sessionApprovals,
        onSessionActivated = mcpServer::activateToolExecutionSession,
        onSessionTerminating = mcpServer::cancelToolExecutionSession,
    )
    val projectGuard = projectIdProvider?.let { provider ->
        McpProjectEpochGuard(provider) { projectGeneration ->
            sessions.resetForProjectBoundary(projectGeneration)
            val stateCleanupCompleted = withTimeoutOrNull(MCP_PROJECT_STATE_CLEANUP_TIMEOUT_MILLIS) {
                onProjectBoundary()
                true
            } ?: false
            if (!stateCleanupCompleted) throw McpProjectStateCleanupException()
            runtimeMetrics?.onProjectBoundaryReset()
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
            // Keep project observation inside the 64-call lease; transition cleanup is time-bounded and fail-closed.
            if (context.request.httpMethod != HttpMethod.Options && projectGuard != null) {
                val alignment = projectGuard.alignRequest()
                if (alignment.status == McpProjectBindingStatus.UNAVAILABLE) {
                    context.response.header(HttpHeaders.RetryAfter, "1")
                    context.rejectMcp(
                        HttpStatusCode.ServiceUnavailable,
                        RPCError.ErrorCode.CONNECTION_CLOSED,
                        "Burp project binding is unavailable",
                    )
                    finish()
                    return@intercept
                }
                context.attributes.put(MCP_PROJECT_GENERATION_KEY, alignment.generation)
            }
            proceed()
        } finally {
            callLease.close()
        }
    }
    monitor.subscribe(ApplicationStopping) {
        runtimeMetrics?.markStopping()
        mcpServer.cancelAllToolExecutions()
        runBlocking {
            // closeAll owns the aggregate non-cancellable transport-close deadline.
            sessions.closeAll()
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
                    expectedBearerTokenBytes != null && !hasValidBearerToken(context, expectedBearerTokenBytes)
                ) {
                    runtimeMetrics?.onAuthenticationRejected()
                    context.response.header(HttpHeaders.WWWAuthenticate, "Bearer")
                    context.respondText("Unauthorized", status = HttpStatusCode.Unauthorized)
                    finish()
                    return@intercept
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
                val reservation = try {
                    sessions.reserve(transport, call.attributes.getOrNull(MCP_PROJECT_GENERATION_KEY))
                } catch (_: McpProjectGenerationMismatchException) {
                    runCatching { transport.close() }
                    call.rejectMcp(
                        HttpStatusCode.Conflict,
                        RPCError.ErrorCode.CONNECTION_CLOSED,
                        "Burp project changed; initialize a new MCP session",
                    )
                    return@post
                }
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

                val observedProtocolVersion = call.request.header(MCP_PROTOCOL_VERSION_HEADER)
                transport.setOnSessionInitialized { initializedSessionId ->
                    sessions.activate(pending, initializedSessionId, observedProtocolVersion)
                }
                transport.setOnSessionClosed {
                    sessions.remove(pending)
                }

                var completedNormally = false
                try {
                    reservation.displaced?.let { displaced -> sessions.closeDetached(displaced) }
                    val serverSession = mcpServer.createSession(transport)
                    pending.attachServerSession(serverSession)
                    transport.handleRequest(null, call)
                    completedNormally = true
                } finally {
                    if (!completedNormally) {
                        sessions.remove(pending)
                        sessions.closeDetached(pending)
                    } else if (!pending.isActive()) {
                        sessions.abandon(pending)
                        sessions.closeDetached(pending)
                    }
                }
            }

            delete {
                runtimeMetrics?.onSessionDeleteRequest()
                val lease = sessions.acquireExisting(call) ?: return@delete
                try {
                    lease.cancelExecutions()
                    lease.transport.handleRequest(null, call)
                } finally {
                    lease.cancelExecutions()
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

private fun hasValidBearerToken(call: ApplicationCall, expected: ByteArray): Boolean {
    val values = call.request.headers.getAll(HttpHeaders.Authorization) ?: return false
    if (values.size != 1) return false
    val value = values.single()
    val separator = value.indexOf(' ')
    if (separator != 6 || !value.regionMatches(0, "Bearer", 0, separator, ignoreCase = true)) return false
    val supplied = value.substring(separator + 1)
    if (supplied.isEmpty() || supplied.any { it.isWhitespace() || it.isISOControl() }) return false
    return MessageDigest.isEqual(supplied.toByteArray(Charsets.UTF_8), expected)
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

internal enum class McpProjectBindingStatus {
    READY,
    TRANSITIONED,
    UNAVAILABLE,
}

internal data class McpProjectAlignment(
    val status: McpProjectBindingStatus,
    val generation: Long,
)

/**
 * Retains only a fixed-size digest of the observed Burp project ID.
 *
 * Alignment is serialized with stale-session cleanup, so a request for a new project cannot pass this boundary until
 * every old session has been detached, its event streams have been cancelled, and its approvals have been revoked.
 * The opaque generation closes the gap between this check and later session reservation or lookup.
 */
internal class McpProjectEpochGuard(
    private val projectIdProvider: () -> String,
    private val resetSessions: suspend (Long) -> Unit,
) {
    private val lock = Mutex()
    // MessageDigest is mutable and not thread-safe; every use remains inside alignRequest's lock.withLock block.
    private val fingerprintDigest = MessageDigest.getInstance("SHA-256")
    private var projectFingerprint: ByteArray? = null
    private var generation = 0L
    private var pendingGeneration: Long? = null

    suspend fun align(): McpProjectBindingStatus = alignRequest().status

    suspend fun alignRequest(): McpProjectAlignment = lock.withLock {
        val currentFingerprint = try {
            projectIdProvider()
                .takeIf(::validMcpProjectId)
                ?.toByteArray(Charsets.UTF_8)
                ?.let(fingerprintDigest::digest)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            null
        }

        if (pendingGeneration != null) {
            if (!completePendingReset()) {
                return@withLock McpProjectAlignment(McpProjectBindingStatus.UNAVAILABLE, generation)
            }
            projectFingerprint = currentFingerprint
            val status = if (currentFingerprint == null) {
                McpProjectBindingStatus.UNAVAILABLE
            } else {
                McpProjectBindingStatus.TRANSITIONED
            }
            return@withLock McpProjectAlignment(status, generation)
        }

        if (currentFingerprint == null) {
            if (projectFingerprint != null && !resetForNextGeneration()) {
                return@withLock McpProjectAlignment(McpProjectBindingStatus.UNAVAILABLE, generation)
            }
            projectFingerprint = null
            return@withLock McpProjectAlignment(McpProjectBindingStatus.UNAVAILABLE, generation)
        }

        val previous = projectFingerprint
        if (previous == null) {
            projectFingerprint = currentFingerprint
            return@withLock McpProjectAlignment(McpProjectBindingStatus.READY, generation)
        }
        if (MessageDigest.isEqual(previous, currentFingerprint)) {
            return@withLock McpProjectAlignment(McpProjectBindingStatus.READY, generation)
        }

        if (!resetForNextGeneration()) {
            return@withLock McpProjectAlignment(McpProjectBindingStatus.UNAVAILABLE, generation)
        }
        projectFingerprint = currentFingerprint
        McpProjectAlignment(McpProjectBindingStatus.TRANSITIONED, generation)
    }

    private suspend fun resetForNextGeneration(): Boolean {
        check(pendingGeneration == null) { "project cleanup is already pending" }
        pendingGeneration = generation + 1
        return completePendingReset()
    }

    private suspend fun completePendingReset(): Boolean {
        val targetGeneration = checkNotNull(pendingGeneration)
        return try {
            resetSessions(targetGeneration)
            generation = targetGeneration
            pendingGeneration = null
            true
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            false
        }
    }
}

private class McpProjectStateCleanupException : Exception()
internal class McpProjectGenerationMismatchException : Exception()

internal data class McpSessionReservation(
    val pending: ManagedMcpSession,
    val displaced: ManagedMcpSession? = null,
)

internal class BoundedMcpSessionRegistry(
    maxSessions: Int,
    private val idleMillis: Long,
    private val runtimeMetrics: McpRuntimeMetrics? = null,
    private val sessionApprovals: McpSessionApprovalRegistry = McpSessionApprovalRegistry(maxSessions),
    private val onSessionActivated: (String, String?) -> Boolean = { _, _ -> true },
    private val onSessionTerminating: (String) -> Unit = {},
) {
    private val lock = Any()
    private val slots = Semaphore(maxSessions, true)
    private val sessions = HashMap<String, ManagedMcpSession>()
    private val entries = HashSet<ManagedMcpSession>()
    private var projectGeneration = 0L
    private var closed = false

    fun reserve(
        transport: StreamableHttpServerTransport,
        expectedProjectGeneration: Long? = null,
    ): McpSessionReservation? = synchronized(lock) {
        if (closed) return null
        if (expectedProjectGeneration != null && expectedProjectGeneration != projectGeneration) {
            throw McpProjectGenerationMismatchException()
        }

        var displaced: ManagedMcpSession? = null
        if (!slots.tryAcquire()) {
            displaced = sessions.values
                .mapNotNull { entry -> entry.capacityEvictionOrder()?.let { order -> entry to order } }
                .minByOrNull { (_, order) -> order }
                ?.first
                ?: return null
            displaced.sessionId()?.let { sessionId ->
                if (sessions.remove(sessionId, displaced)) sessionApprovals.remove(sessionId)
            }
            entries.remove(displaced)
            displaced.releaseSlot()
            runtimeMetrics?.onPressureEvicted()
            check(slots.tryAcquire()) { "displaced MCP session did not release its capacity slot" }
        }

        val pending = ManagedMcpSession(transport, slots, projectGeneration, onSessionTerminating)
        entries += pending
        updateMetricsLocked()
        McpSessionReservation(pending = pending, displaced = displaced)
    }

    fun activate(entry: ManagedMcpSession, sessionId: String, observedProtocolVersion: String? = null) {
        val accepted = synchronized(lock) {
            if (closed || entry !in entries || entry.projectGeneration != projectGeneration ||
                sessionId.isBlank() || sessionId.length > 128 || sessions.containsKey(sessionId)
            ) {
                false
            } else if (!sessionApprovals.activate(sessionId)) {
                false
            } else {
                val serverSession = entry.attachedServerSession()
                if (serverSession != null && !sessionApprovals.attachServerSession(sessionId, serverSession.sessionId)) {
                    sessionApprovals.remove(sessionId)
                    false
                } else if (!onSessionActivated(sessionId, serverSession?.sessionId)) {
                    sessionApprovals.remove(sessionId)
                    false
                } else {
                    entry.activate(sessionId)
                    sessions[sessionId] = entry
                    updateMetricsLocked()
                    true
                }
            }
        }
        if (!accepted) {
            synchronized(lock) {
                entries.remove(entry)
                updateMetricsLocked()
            }
            entry.releaseSlot()
        } else {
            runtimeMetrics?.onSessionInitialized(observedProtocolVersion)
        }
    }

    suspend fun acquireExisting(call: ApplicationCall): ManagedMcpSessionLease? {
        val sessionIds = call.request.headers.getAll(MCP_SESSION_ID_HEADER).orEmpty()
        val sessionId = sessionIds.singleOrNull()
        if (
            sessionId.isNullOrEmpty() ||
            sessionId.length > MCP_MAX_SESSION_ID_CHARS ||
            sessionId.any(Char::isISOControl)
        ) {
            call.rejectMcp(
                HttpStatusCode.BadRequest,
                RPCError.ErrorCode.CONNECTION_CLOSED,
                "Bad Request: No valid session ID provided",
            )
            return null
        }
        val expectedProjectGeneration = call.attributes.getOrNull(MCP_PROJECT_GENERATION_KEY)
        val entry = synchronized(lock) {
            if (expectedProjectGeneration != null && expectedProjectGeneration != projectGeneration) {
                null
            } else {
                sessions[sessionId]
                    ?.takeIf { it.projectGeneration == projectGeneration }
                    ?.also { it.acquire() }
            }
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
            entry.sessionId()?.let { id ->
                if (sessions.remove(id, entry)) sessionApprovals.remove(id)
            }
            entries.remove(entry)
            updateMetricsLocked()
        }
        entry.cancelExecutions()
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
                entry.sessionId()?.let { sessionId ->
                    if (sessions.remove(sessionId, entry)) sessionApprovals.remove(sessionId)
                }
                entries.remove(entry)
            }
            updateMetricsLocked()
            stale
        }
        runtimeMetrics?.onIdleEvicted(expired.size)
        closeDetachedEntries(expired)
    }

    /**
     * Detaches all pending and active sessions without closing the registry itself.
     *
     * A Burp project transition is a hard authority boundary: old event streams and memory-only approvals must
     * disappear before a new-project request can be admitted. Wire resource subscriptions remain disabled.
     */
    suspend fun resetForProjectBoundary() {
        val nextGeneration = synchronized(lock) { projectGeneration + 1 }
        resetForProjectBoundary(nextGeneration)
    }

    suspend fun resetForProjectBoundary(newProjectGeneration: Long) {
        val stale = synchronized(lock) {
            if (closed) return
            require(newProjectGeneration >= projectGeneration) { "project generation cannot move backwards" }
            projectGeneration = newProjectGeneration
            val snapshot = entries.toList()
            sessions.clear()
            sessionApprovals.clearSessions()
            entries.clear()
            updateMetricsLocked()
            snapshot
        }
        closeDetachedEntries(stale)
    }

    suspend fun closeAll() {
        val abandoned = synchronized(lock) {
            if (closed) return
            closed = true
            val snapshot = entries.toList()
            sessions.clear()
            sessionApprovals.clearSessions()
            entries.clear()
            updateMetricsLocked()
            snapshot
        }
        closeDetachedEntries(abandoned)
    }

    suspend fun closeDetached(entry: ManagedMcpSession) {
        closeDetachedEntries(listOf(entry))
    }

    private suspend fun closeDetachedEntries(detached: List<ManagedMcpSession>) {
        if (detached.isEmpty()) return
        detached.forEach { entry ->
            entry.cancelExecutions()
            entry.cancelStreams()
            entry.releaseSlot()
        }
        withContext(NonCancellable) {
            withTimeoutOrNull(MCP_SESSION_SHUTDOWN_TIMEOUT_MILLIS) {
                supervisorScope {
                    detached.map { entry ->
                        launch {
                            try {
                                entry.closeTransport()
                            } catch (e: CancellationException) {
                                throw e
                            } catch (_: Exception) {
                                // Detached entries cannot be reacquired; transport cleanup is bounded and best-effort.
                            }
                        }
                    }.joinAll()
                }
            }
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
    val projectGeneration: Long = 0L,
    private val onSessionTerminating: (String) -> Unit = {},
) {
    private val slotReleased = AtomicBoolean(false)
    private val transportClosed = AtomicBoolean(false)
    private val executionCancellationIssued = AtomicBoolean(false)
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
    fun attachedServerSession(): ServerSession? = serverSession

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

    fun cancelExecutions() {
        val sessionId = sessionId() ?: return
        if (executionCancellationIssued.compareAndSet(false, true)) onSessionTerminating(sessionId)
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
        cancelExecutions()
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

    fun cancelExecutions() {
        entry.cancelExecutions()
    }

    fun close() {
        if (closed.compareAndSet(false, true)) entry.release()
    }
}

private fun defaultWorkflowPresetStore(api: MontoyaApi): WorkflowPresetStore {
    val extensionStorage = api.persistence().extensionData()
    return WorkflowPresetStore(extensionStorage)
}

class KtorServerManager internal constructor(
    private val api: MontoyaApi,
    private val auditSink: McpAuditSink,
    private val projectIdProvider: (() -> String)? = { api.project().id() },
    workflowPresetStore: WorkflowPresetStore,
    private val shutdownTimeoutMillis: Long = 10_000,
) : ServerManager {

    internal constructor(
        api: MontoyaApi,
        auditSink: McpAuditSink,
        projectIdProvider: (() -> String)? = { api.project().id() },
    ) : this(api, auditSink, projectIdProvider, defaultWorkflowPresetStore(api))

    constructor(api: MontoyaApi) : this(api, NoOpMcpAuditSink)

    init {
        require(shutdownTimeoutMillis in 1..10_000) { "Shutdown timeout is out of range" }
    }

    private val serverVersion = KtorServerManager::class.java.`package`.implementationVersion ?: "dev"
    private val lifecycleThread = AtomicReference<Thread?>()
    private val lifecycleSubmissionLock = Any()
    private val executor: ExecutorService = Executors.newSingleThreadExecutor { task ->
        Thread(task, "independent-mcp-lifecycle").apply { isDaemon = true }.also(lifecycleThread::set)
    }
    private val shutdownStarted = AtomicBoolean()
    private val loadedArtifactSha256 = executor.submit<String?> {
        LoadedArtifactIdentity.currentSha256(KtorServerManager::class.java)
    }
    private val sessionApprovals = McpSessionApprovalRegistry(MCP_MAX_SESSIONS)
    @Volatile
    private var runtimeMetrics = McpRuntimeMetrics(serverVersion, MCP_MAX_CONCURRENT_HTTP_CALLS, MCP_MAX_SESSIONS)
    private val serverStateLock = Any()
    private var server: EmbeddedServer<*, *>? = null
    private var mcpServer: Server? = null
    private var startingServer: EmbeddedServer<*, *>? = null
    private var startingMcpServer: Server? = null
    private val toolServices = ToolServices(api, workflowPresetStore)

    override fun start(config: McpConfig, callback: (ServerState) -> Unit) {
        if (shutdownStarted.get()) {
            callback(ServerState.Failed(IllegalStateException("MCP server manager is shut down")))
            return
        }

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

        if (!submitLifecycle {
            if (shutdownStarted.get()) {
                metrics.markStopped()
                callback(ServerState.Stopped)
                return@submitLifecycle
            }
            var untrackedMcpServer: Server? = null
            var untrackedServer: EmbeddedServer<*, *>? = null
            fun cleanupUntrackedCandidates() {
                untrackedServer?.let { candidate -> runCatching { candidate.stop(1000, 5000) } }
                untrackedServer = null
                untrackedMcpServer?.let { candidate ->
                    synchronized(serverStateLock) {
                        if (startingMcpServer === candidate) startingMcpServer = null
                    }
                    runCatching { closeMcpServer(candidate) }
                }
                untrackedMcpServer = null
            }
            try {
                stopCurrentServer()
                metrics.setLoadedArtifactSha256(loadedArtifactSha256.get(30, TimeUnit.SECONDS))
                ensureStartupAllowed()

                val bindHost = normalizedRequestedHost
                    ?: throw IllegalArgumentException(
                        "MCP server host must be 127.0.0.1 or ::1; non-loopback listeners are not supported"
                    )
                val newMcpServer = Server(
                    serverInfo = Implementation(ProductIdentity.MCP_SERVER_NAME, serverVersion),
                    options = ServerOptions(
                        // Catalogs are immutable for one listener lifetime. SDK 0.14.0 subscriptions lack bounded,
                        // project-aware admission; see docs/PROJECT_BOUND_NOTIFICATIONS.md.
                        capabilities = ServerCapabilities(
                            tools = ServerCapabilities.Tools(listChanged = false),
                            resources = ServerCapabilities.Resources(listChanged = false, subscribe = false),
                            prompts = ServerCapabilities.Prompts(listChanged = false),
                        )
                    ),
                    instructions = MCP_SERVER_INSTRUCTIONS,
                )
                untrackedMcpServer = newMcpServer
                synchronized(serverStateLock) {
                    ensureStartupAllowed()
                    check(startingMcpServer == null) { "Another MCP startup candidate is already current" }
                    startingMcpServer = newMcpServer
                }
                newMcpServer.registerTools(api, config, toolServices, auditSink, sessionApprovals)
                ensureStartupAllowed()
                newMcpServer.registerMcpResources(api, config, ::diagnostics)
                ensureStartupAllowed()
                newMcpServer.registerMcpPrompts(api)
                ensureStartupAllowed()

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
                        sessionApprovals = sessionApprovals,
                        projectIdProvider = projectIdProvider,
                        onProjectBoundary = toolServices::resetForProjectBoundary,
                    )
                }
                untrackedServer = newEngine
                synchronized(serverStateLock) {
                    ensureStartupAllowed()
                    check(startingMcpServer === newMcpServer) {
                        "MCP startup candidate is no longer current"
                    }
                    startingServer = newEngine
                    untrackedServer = null
                    untrackedMcpServer = null
                }
                newEngine.start(wait = false)
                synchronized(serverStateLock) {
                    ensureStartupAllowed()
                    check(startingServer === newEngine && startingMcpServer === newMcpServer) {
                        "MCP startup candidate is no longer current"
                    }
                    startingServer = null
                    startingMcpServer = null
                    server = newEngine
                    mcpServer = newMcpServer
                }
                val runningPublished = synchronized(lifecycleSubmissionLock) {
                    if (shutdownStarted.get()) {
                        false
                    } else {
                        metrics.markRunning()
                        api.logging().logToOutput(
                            "Started authenticated MCP Streamable HTTP server at " +
                                "http://${formatHostForUrl(bindHost)}:$requestedPort/mcp"
                        )
                        callback(ServerState.Running)
                        true
                    }
                }
                if (!runningPublished || shutdownStarted.get()) {
                    stopCurrentServer()
                    metrics.markStopped()
                    callback(ServerState.Stopped)
                    return@submitLifecycle
                }

            } catch (_: ServerManagerShutdownException) {
                cleanupUntrackedCandidates()
                runCatching { stopCurrentServer() }
                metrics.markStopped()
                callback(ServerState.Stopped)
            } catch (e: Exception) {
                cleanupUntrackedCandidates()
                runCatching { stopCurrentServer() }
                val failure = normalizeMcpServerStartFailure(e, normalizedRequestedHost, requestedPort)
                val summary = if (failure is McpServerStartupException) {
                    safeSingleLine(failure.message.orEmpty())
                } else {
                    safeExceptionSummary(failure)
                }
                val failurePublished = synchronized(lifecycleSubmissionLock) {
                    if (shutdownStarted.get()) {
                        false
                    } else {
                        metrics.markFailed(summary)
                        api.logging().logToError("MCP server failed: $summary")
                        callback(ServerState.Failed(failure))
                        true
                    }
                }
                if (!failurePublished || shutdownStarted.get()) {
                    metrics.markStopped()
                    callback(ServerState.Stopped)
                }
            }
        }) {
            metrics.markStopped()
            callback(ServerState.Stopped)
        }
    }

    override fun stop(callback: (ServerState) -> Unit) {
        if (shutdownStarted.get()) {
            callback(ServerState.Stopped)
            return
        }

        val metrics = runtimeMetrics
        metrics.markStopping()
        callback(ServerState.Stopping)

        if (!submitLifecycle {
            if (shutdownStarted.get()) {
                metrics.markStopped()
                callback(ServerState.Stopped)
                return@submitLifecycle
            }
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
        }) {
            metrics.markStopped()
            callback(ServerState.Stopped)
        }
    }

    private fun ensureStartupAllowed() {
        if (shutdownStarted.get()) throw ServerManagerShutdownException()
    }

    private fun submitLifecycle(action: () -> Unit): Boolean = synchronized(lifecycleSubmissionLock) {
        if (shutdownStarted.get()) return@synchronized false
        try {
            executor.submit { action() }
            true
        } catch (_: RejectedExecutionException) {
            false
        }
    }

    override fun diagnostics(): McpDiagnosticsSnapshot {
        val approvalSummary = sessionApprovals.summary()
        val performance = toolServices.performanceSnapshot()
        val webSocketOutcomes = performance.webSocketSearchOutcomeSummary()
        return runtimeMetrics.snapshot().copy(
            sessionsWithApprovals = approvalSummary.sessionsWithApprovals,
            sessionApprovalGrants = approvalSummary.approvalGrants,
            webSocketSearchActive = webSocketOutcomes.active,
            webSocketSearchCompleted = webSocketOutcomes.completed,
            webSocketSearchCancelled = webSocketOutcomes.cancelled,
            historyPerformance = performance,
        )
    }

    internal fun clearSessionApprovals(): Int = sessionApprovals.clearApprovals()

    private fun stopCurrentServer() {
        val (engines, mcpServers, registeringMcpServers) = synchronized(serverStateLock) {
            val detachedEngines = listOfNotNull(server, startingServer).distinct()
            val detachedMcpServers = listOfNotNull(
                mcpServer,
                startingMcpServer.takeIf { startingServer != null },
            ).distinct()
            val detachedRegisteringMcpServers = listOfNotNull(
                startingMcpServer.takeIf { startingServer == null },
            )
            server = null
            mcpServer = null
            startingServer = null
            startingMcpServer = null
            Triple(detachedEngines, detachedMcpServers, detachedRegisteringMcpServers)
        }
        var failure: Throwable? = null
        fun cleanup(action: () -> Unit) {
            try {
                action()
            } catch (error: Throwable) {
                if (failure == null) failure = error
            }
        }

        engines.forEach { engine -> cleanup { engine.stop(1000, 5000) } }
        mcpServers.forEach { candidate -> cleanup { closeMcpServer(candidate) } }
        registeringMcpServers.forEach { candidate -> cleanup { candidate.unbindToolRuntimePolicy() } }
        cleanup { sessionApprovals.clearSessions() }
        failure?.let { throw it }
    }

    private fun closeMcpServer(candidate: Server) {
        candidate.unbindToolRuntimePolicy()
        try {
            runBlocking {
                withTimeoutOrNull(MCP_SESSION_SHUTDOWN_TIMEOUT_MILLIS) { candidate.close() }
            }
        } catch (e: CancellationException) {
            if (e.hasNonCancellationCause()) throw e
            // Closing an MCP server cancels its own transport jobs. That is successful shutdown, not a failure.
        }
    }

    override fun shutdown() {
        val shutdownWon = synchronized(lifecycleSubmissionLock) {
            shutdownStarted.compareAndSet(false, true)
        }
        if (!shutdownWon) return

        val metrics = runtimeMetrics
        metrics.markStopping()
        val calledFromLifecycleThread = Thread.currentThread() === lifecycleThread.get()
        var interrupted = false
        var shutdownError: Throwable? = null
        try {
            try {
                if (calledFromLifecycleThread) {
                    stopCurrentServer()
                } else {
                    executor.submit { stopCurrentServer() }.get(shutdownTimeoutMillis, TimeUnit.MILLISECONDS)
                }
            } catch (error: Throwable) {
                shutdownError = error
                if (error is InterruptedException) interrupted = true
            } finally {
                executor.shutdown()
                if (!calledFromLifecycleThread) {
                    try {
                        if (!executor.awaitTermination(shutdownTimeoutMillis, TimeUnit.MILLISECONDS)) {
                            executor.shutdownNow()
                        }
                    } catch (error: InterruptedException) {
                        interrupted = true
                        if (shutdownError == null) shutdownError = error
                        executor.shutdownNow()
                    }
                }
            }

            val finalCleanupError = runCatching { stopCurrentServer() }.exceptionOrNull()
            val effectiveError = finalCleanupError ?: shutdownError?.takeUnless { it is TimeoutException }
            if (effectiveError == null) {
                metrics.markStopped()
            } else {
                val summary = safeExceptionSummary(effectiveError)
                metrics.markFailed(summary)
                runCatching { api.logging().logToError("MCP shutdown failed: $summary") }
            }
        } finally {
            try {
                toolServices.close()
            } finally {
                if (interrupted) Thread.currentThread().interrupt()
            }
        }
    }
}

private class ServerManagerShutdownException : Exception()

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
