package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.execution.ExecutionStats
import burp.api.montoya.http.execution.RequestEngineOptions
import burp.api.montoya.http.execution.RequestExecution
import burp.api.montoya.http.execution.ResourcePool
import burp.api.montoya.http.execution.ResponseHandler
import burp.api.montoya.http.execution.Retention
import burp.api.montoya.http.message.requests.HttpRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.JsonSchemaExactlyOneOf
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.RequestActionSecurity
import net.portswigger.mcp.security.RequestRoutingAuditOperation
import net.portswigger.mcp.security.SensitiveActionAuditOperation
import net.portswigger.mcp.security.SensitiveActionSecurity
import net.portswigger.mcp.security.safeExceptionSummary
import java.time.Duration
import java.util.UUID

private const val MAX_REQUEST_EXECUTION_START_ITEMS = 16
private const val MAX_REQUEST_EXECUTION_QUEUE_ITEMS = 16
private const val MAX_REQUEST_EXECUTION_ITEMS = 64
private const val MAX_REQUEST_EXECUTIONS = 4
private const val MAX_REQUEST_EXECUTION_TOTAL_BYTES = 16 * 1024 * 1024
private const val MAX_REQUEST_EXECUTION_NAME_CHARS = 128
private const val MAX_REQUEST_EXECUTION_LABEL_CHARS = 128
private const val MAX_RESOURCE_POOL_NAME_CHARS = 128
private const val MAX_REQUEST_EXECUTION_CONCURRENCY = 10
private const val MAX_REQUEST_EXECUTION_THROTTLE_MS = 60_000L
private const val MAX_REQUEST_EXECUTION_RETRIES = 2
private const val MIN_REQUEST_EXECUTION_TIMEOUT_MS = 100L
private const val MAX_REQUEST_EXECUTION_TIMEOUT_MS = 120_000L
private const val MAX_REQUEST_EXECUTION_WAIT_MS = 30_000L
private val REQUEST_EXECUTION_ID = Regex("reqexec-[a-f0-9]{32}")

private class RequestExecutionFenceException(
    val status: NativeToolStatus,
    val projectId: String?,
    message: String,
) : IllegalStateException(message)

private class RequestExecutionCleanupPendingException :
    IllegalStateException("request execution cleanup is not yet confirmed")

@Serializable
data class StoredRequestExecutionSource(
    @JsonSchemaMetadata(description = "Complete project-bound reference from a producing HTTP result.")
    val ref: HttpMessageReference,
    @JsonSchemaMetadata(description = "Optional bounded patch applied to a fresh copy of the stored request.")
    val patch: HttpRequestPatch? = null,
)

@Serializable
data class RawRequestExecutionSource(
    @JsonSchemaMetadata(description = "Protocol to send; provide only the matching http1 or http2 object.")
    val protocol: RawHttpProtocol,
    @JsonSchemaMetadata(description = "Required only for protocol=http_1.")
    val http1: RawHttp1Input? = null,
    @JsonSchemaMetadata(description = "Required only for protocol=http_2.")
    val http2: RawHttp2Input? = null,
    @JsonSchemaMetadata(description = "Exact DNS or IP destination host.", minLength = 1, maxLength = 253)
    val targetHostname: String,
    @JsonSchemaMetadata(description = "Destination port.", minimum = 1, maximum = 65535)
    val targetPort: Int,
    @JsonSchemaMetadata(description = "Connect using TLS.")
    val usesHttps: Boolean,
)

@Serializable
@JsonSchemaExactlyOneOf("stored", "raw")
data class HttpRequestExecutionItem(
    @JsonSchemaMetadata(description = "Stored request and optional bounded patch; exactly one of stored or raw is required.")
    val stored: StoredRequestExecutionSource? = null,
    @JsonSchemaMetadata(description = "Caller-supplied HTTP/1 or HTTP/2 request; exactly one of stored or raw is required.")
    val raw: RawRequestExecutionSource? = null,
    @JsonSchemaMetadata(description = "Optional correlation label echoed in completion-order results.", maxLength = MAX_REQUEST_EXECUTION_LABEL_CHARS)
    val label: String? = null,
)

@Serializable
enum class RequestExecutionResourcePool {
    @SerialName("private")
    PRIVATE,

    @SerialName("default")
    DEFAULT,

    @SerialName("existing")
    EXISTING,
}

@Serializable
data class StartHttpRequestExecution(
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Initial requests to queue and immediately send.", minItems = 1, maxItems = MAX_REQUEST_EXECUTION_START_ITEMS)
    val requests: List<HttpRequestExecutionItem>,
    @JsonSchemaMetadata(description = "Optional Burp Request Execution Engine name.", maxLength = MAX_REQUEST_EXECUTION_NAME_CHARS)
    val name: String? = null,
    @JsonSchemaMetadata(description = "Private tunable pool, Burp's shared default pool, or an existing named pool.", defaultJson = "\"private\"")
    val resourcePool: RequestExecutionResourcePool? = null,
    @JsonSchemaMetadata(description = "Required only for resourcePool=existing.", maxLength = MAX_RESOURCE_POOL_NAME_CHARS)
    val existingResourcePoolName: String? = null,
    @JsonSchemaMetadata(description = "Private-pool concurrent request limit.", minimum = 1, maximum = 10)
    val concurrentRequestLimit: Int? = null,
    @JsonSchemaMetadata(description = "Private-pool delay between consecutive sends in milliseconds.", minimum = 0, maximum = MAX_REQUEST_EXECUTION_THROTTLE_MS)
    val throttleMillis: Long? = null,
    @JsonSchemaMetadata(description = "Private-pool connection-failure retry count per request.", minimum = 0, maximum = 2)
    val maxRetries: Int? = null,
    @JsonSchemaMetadata(description = "Per-request native timeout in milliseconds.", minimum = MIN_REQUEST_EXECUTION_TIMEOUT_MS, maximum = MAX_REQUEST_EXECUTION_TIMEOUT_MS, defaultJson = "30000")
    val requestTimeoutMillis: Long? = null,
)

@Serializable
data class QueueHttpRequestExecution(
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Opaque handle returned by start_http_request_execution.", minLength = 40, maxLength = 40)
    val executionId: String,
    @JsonSchemaMetadata(description = "Additional requests for a running execution.", minItems = 1, maxItems = MAX_REQUEST_EXECUTION_QUEUE_ITEMS)
    val requests: List<HttpRequestExecutionItem>,
)

@Serializable
data class GetHttpRequestExecution(
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Opaque handle returned by start_http_request_execution.", minLength = 40, maxLength = 40)
    val executionId: String,
    @JsonSchemaMetadata(description = "Optionally wait this many milliseconds for completion without changing the execution.", minimum = 0, maximum = MAX_REQUEST_EXECUTION_WAIT_MS, defaultJson = "0")
    val waitMillis: Long? = null,
)

@Serializable
enum class HttpRequestExecutionControl {
    @SerialName("pause")
    PAUSE,

    @SerialName("resume")
    RESUME,

    @SerialName("cancel")
    CANCEL,

    @SerialName("delete")
    DELETE,
}

@Serializable
data class ControlHttpRequestExecution(
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Opaque handle returned by start_http_request_execution.", minLength = 40, maxLength = 40)
    val executionId: String,
    @JsonSchemaMetadata(description = "Pause, resume, cancel, or cancel-and-delete the retained execution.")
    val control: HttpRequestExecutionControl,
)

@Serializable
data class HttpRequestExecutionStats(
    @JsonSchemaMetadata(minimum = 0, maximum = 64)
    val requested: Int,
    @JsonSchemaMetadata(minimum = 0, maximum = 64)
    val completed: Int,
    @JsonSchemaMetadata(minimum = 0, maximum = 64)
    val failed: Int,
    @JsonSchemaMetadata(minimum = 0, maximum = 64)
    val inFlight: Int,
    @JsonSchemaMetadata(minimum = 0, maximum = 64)
    val pending: Int,
    @JsonSchemaMetadata(minimum = 0)
    val elapsedMillis: Long,
)

@Serializable
data class HttpRequestExecutionItemResult(
    @JsonSchemaMetadata(maxLength = MAX_REQUEST_EXECUTION_LABEL_CHARS)
    val label: String?,
    @JsonSchemaMetadata(description = "Native request status, or unavailable when result metadata could not be read.", maxLength = 32)
    val status: String,
    @JsonSchemaMetadata(minimum = 0, maximum = 2097152)
    val requestBytes: Int?,
    val responseStatusCode: Int?,
    @JsonSchemaMetadata(minimum = 0)
    val responseBytes: Int?,
)

@Serializable
internal data class HttpRequestExecutionActionResult(
    @JsonSchemaMetadata(description = TOOL_STATUS_RETRY_DESCRIPTION)
    val status: NativeToolStatus,
    @JsonSchemaMetadata(description = TOOL_RETRY_DESCRIPTION)
    val retry: ToolRetryGuidance,
    @JsonSchemaMetadata(description = TOOL_EXECUTION_STATE_DESCRIPTION)
    val executionState: StandardExecutionState,
    val projectId: String?,
    val executionId: String?,
    @JsonSchemaMetadata(minimum = 0, maximum = 64)
    val queued: Int,
    val control: HttpRequestExecutionControl? = null,
    val stats: HttpRequestExecutionStats? = null,
    @JsonSchemaMetadata(maxLength = MAX_STANDARD_TOOL_ERROR_CHARS)
    val error: String? = null,
)

@Serializable
internal data class HttpRequestExecutionStatusResult(
    @JsonSchemaMetadata(description = READ_STATUS_RETRY_DESCRIPTION)
    val status: NativeToolStatus,
    @JsonSchemaMetadata(description = TOOL_RETRY_DESCRIPTION)
    val retry: ToolRetryGuidance,
    val projectId: String?,
    val executionId: String?,
    val finished: Boolean?,
    val cancelled: Boolean?,
    val stats: HttpRequestExecutionStats?,
    @JsonSchemaMetadata(description = "Bounded completion-order result metadata retained without request or response content.", maxItems = MAX_REQUEST_EXECUTION_ITEMS)
    val results: List<HttpRequestExecutionItemResult>,
    val resultsTruncated: Boolean,
    @JsonSchemaMetadata(maxLength = MAX_STANDARD_TOOL_ERROR_CHARS)
    val error: String? = null,
)

private data class PreparedExecutionRequest(
    val request: HttpRequest,
    val requestBytes: Int,
    val target: HttpActionTarget,
    val label: String?,
    val source: String,
    val changes: String,
    val derived: Boolean,
    val review: () -> String,
)

private class ExecutionCapture {
    private val lock = Any()
    private val results = ArrayList<HttpRequestExecutionItemResult>()
    private var truncated = false

    fun capture(result: burp.api.montoya.http.execution.RequestResult) {
        val captured = try {
            val exchange = result.requestResponse()
            val response = exchange.response()
            HttpRequestExecutionItemResult(
                label = result.label()?.take(MAX_REQUEST_EXECUTION_LABEL_CHARS),
                status = result.status().name.lowercase().take(32),
                requestBytes = requestByteLength(exchange.request()).coerceAtMost(MAX_ACTION_REQUEST_BYTES),
                responseStatusCode = response?.statusCode()?.toInt(),
                responseBytes = response?.let(::responseByteLength),
            )
        } catch (_: Exception) {
            HttpRequestExecutionItemResult(null, "unavailable", null, null, null)
        }
        synchronized(lock) {
            if (results.size < MAX_REQUEST_EXECUTION_ITEMS) results += captured else truncated = true
        }
    }

    fun snapshot(): Pair<List<HttpRequestExecutionItemResult>, Boolean> = synchronized(lock) {
        results.toList() to truncated
    }
}

private class OwnedRequestExecution(
    val projectId: String,
    val execution: RequestExecution,
    val capture: ExecutionCapture,
    initialQueued: Int,
    initialBytes: Int,
) {
    var queued: Int = initialQueued
    var totalBytes: Int = initialBytes
}

internal class HttpRequestExecutionService(
    private val api: MontoyaApi,
    @Volatile private var config: McpConfig,
) : AutoCloseable {
    @Volatile private var resolver = HttpMessageResolver(api, config)
    private val stateLock = Any()
    private val lifecycleMutation = Mutex()
    private val executions = LinkedHashMap<String, OwnedRequestExecution>()
    private val cleanupReservations = ArrayList<RequestExecution>()
    private var startsInFlight = 0
    private var generation = 0L
    private var closed = false

    @Synchronized
    fun updateConfig(config: McpConfig) {
        this.config = config
        resolver = HttpMessageResolver(api, config)
    }

    suspend fun start(input: StartHttpRequestExecution): HttpRequestExecutionActionResult {
        val callGeneration = synchronized(stateLock) { generation }
        val validationError = validateStart(input)
        if (validationError != null) return actionFailure(NativeToolStatus.INVALID_ARGUMENT, null, null, 0, validationError)
        val prepared = when (val outcome = prepareRequests(input.projectId, input.requests)) {
            is PreparedRequests.Failed -> return actionFailure(outcome.status, outcome.projectId, null, 0, outcome.error)
            is PreparedRequests.Found -> outcome
        }
        val approved = approveBatch(
            projectId = prepared.projectId,
            requests = prepared.requests,
            action = "start a native HTTP request execution",
            auditOperation = SensitiveActionAuditOperation.REQUEST_EXECUTION_START,
            summary = "Start ${prepared.requests.size} request(s) with pool=" +
                (input.resourcePool ?: RequestExecutionResourcePool.PRIVATE).name.lowercase() +
                (input.existingResourcePoolName?.let { "($it)" } ?: "") +
                ", concurrency=${input.concurrentRequestLimit ?: "pool default"}, " +
                "throttleMs=${input.throttleMillis ?: "pool default"}, maxRetries=${input.maxRetries ?: "pool default"}",
        )
        if (approved != null) return approved

        retryCleanupReservations()
        val startGeneration = synchronized(stateLock) {
            if (closed || generation != callGeneration ||
                executions.size + cleanupReservations.size + startsInFlight >= MAX_REQUEST_EXECUTIONS
            ) null
            else {
                startsInFlight++
                generation
            }
        }
        if (startGeneration == null) {
            val boundaryCrossed = synchronized(stateLock) { generation } != callGeneration
            return actionFailure(
                if (boundaryCrossed) NativeToolStatus.STALE_STATE else NativeToolStatus.LIMIT_EXCEEDED,
                prepared.projectId,
                null,
                0,
                if (boundaryCrossed) {
                    "the request execution crossed a project lifecycle boundary"
                } else {
                    "at most $MAX_REQUEST_EXECUTIONS request executions may be retained or pending confirmed cleanup"
                },
            )
        }

        return try {
            lifecycleMutation.withLock {
                var execution: RequestExecution? = null
                var publishedId: String? = null
                try {
                    recheckProject(prepared.projectId)?.let { return it }
                    val engine = try {
                        createEngine(input)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        return actionFailure(
                            NativeToolStatus.BURP_ERROR,
                            prepared.projectId,
                            null,
                            0,
                            "Burp could not create the request execution engine: ${safeExceptionSummary(e)}",
                        )
                    }
                    try {
                        // RequestExecutionEngine has no close operation; before sendAll it owns only this local queue and has
                        // started no network work, so a queue failure is safely abandoned as a not-started preparation error.
                        prepared.requests.forEach { request ->
                            if (request.label == null) engine.queue(request.request) else engine.queue(request.request, request.label)
                        }
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        return actionFailure(
                            NativeToolStatus.BURP_ERROR,
                            prepared.projectId,
                            null,
                            0,
                            "Burp could not queue the initial requests: ${safeExceptionSummary(e)}",
                        )
                    }
                    val capture = ExecutionCapture()
                    val handler = ResponseHandler { result, _ ->
                        capture.capture(result)
                        Retention.DROP
                    }
                    val timeout = Duration.ofMillis(input.requestTimeoutMillis ?: 30_000L)
                    currentCoroutineContext().ensureActive()
                    recheckProject(prepared.projectId)?.let { return it }
                    val id = newExecutionId()
                    execution = try {
                        synchronized(stateLock) {
                            if (closed || generation != startGeneration) {
                                throw RequestExecutionFenceException(
                                    NativeToolStatus.STALE_STATE,
                                    prepared.projectId,
                                    "the request execution crossed a lifecycle boundary before sending",
                                )
                            }
                            if (config.emergencyReadOnlyMode) {
                                throw RequestExecutionFenceException(
                                    NativeToolStatus.DISABLED,
                                    prepared.projectId,
                                    "Emergency read-only mode was enabled before request execution started",
                                )
                            }
                            engine.sendAll(handler, timeout).also { started ->
                                executions[id] = OwnedRequestExecution(
                                    prepared.projectId,
                                    started,
                                    capture,
                                    prepared.requests.size,
                                    prepared.totalBytes,
                                )
                                publishedId = id
                            }
                        }
                    } catch (e: RequestExecutionFenceException) {
                        return actionFailure(e.status, e.projectId, null, 0, e.message.orEmpty())
                    } catch (e: CancellationException) {
                        if (!currentCoroutineContext().isActive) throw e
                        return actionUncertain(prepared.projectId, null, 0, null, e, "Burp may have started the request execution")
                    } catch (e: Exception) {
                        return actionUncertain(prepared.projectId, null, 0, null, e, "Burp may have started the request execution")
                    }
                    currentCoroutineContext().ensureActive()
                    val postProject = currentProjectIdOrNull(api)
                    if (postProject != prepared.projectId || config.emergencyReadOnlyMode ||
                        ownedExecution(prepared.projectId, id)?.execution !== execution
                    ) {
                        synchronized(stateLock) { executions.remove(id) }
                        cancelOrReserve(execution)
                        return actionUncertain(
                            prepared.projectId,
                            null,
                            prepared.requests.size,
                            null,
                            IllegalStateException("a request execution fence changed while sending started"),
                            "Burp may have started requests before project, emergency, or lifecycle policy changed",
                        )
                    }
                    val stats = runCatching { execution.stats().toDto() }.getOrNull()
                    return HttpRequestExecutionActionResult(
                        status = NativeToolStatus.OK,
                        retry = ToolRetryGuidance.NOT_APPLICABLE,
                        executionState = StandardExecutionState.COMPLETED,
                        projectId = prepared.projectId,
                        executionId = id,
                        queued = prepared.requests.size,
                        stats = stats,
                    )
                } catch (e: CancellationException) {
                    publishedId?.let { id -> synchronized(stateLock) { executions.remove(id) } }
                    execution?.let(::cancelOrReserve)
                    throw e
                }
            }
        } finally {
            synchronized(stateLock) { startsInFlight-- }
        }
    }

    suspend fun queue(input: QueueHttpRequestExecution): HttpRequestExecutionActionResult {
        val handleError = validateHandleInput(input.projectId, input.executionId)
        if (handleError != null) return actionFailure(NativeToolStatus.INVALID_ARGUMENT, null, null, 0, handleError)
        if (input.requests.isEmpty() || input.requests.size > MAX_REQUEST_EXECUTION_QUEUE_ITEMS) {
            return actionFailure(
                NativeToolStatus.INVALID_ARGUMENT,
                null,
                input.executionId,
                0,
                "requests must contain between 1 and $MAX_REQUEST_EXECUTION_QUEUE_ITEMS items",
            )
        }
        val owned = ownedExecution(input.projectId, input.executionId)
            ?: return actionFailure(NativeToolStatus.NOT_FOUND, input.projectId, null, 0, "request execution was not found")
        if (runCatching { owned.execution.lifetime().finished() }.getOrDefault(true)) {
            return actionFailure(NativeToolStatus.NOT_AVAILABLE, input.projectId, input.executionId, 0, "request execution is already finished")
        }
        val prepared = when (val outcome = prepareRequests(input.projectId, input.requests)) {
            is PreparedRequests.Failed -> return actionFailure(outcome.status, outcome.projectId, input.executionId, 0, outcome.error)
            is PreparedRequests.Found -> outcome
        }
        val approved = approveBatch(
            projectId = prepared.projectId,
            requests = prepared.requests,
            action = "queue requests into a running native HTTP execution",
            auditOperation = SensitiveActionAuditOperation.REQUEST_EXECUTION_QUEUE,
            summary = "Queue ${prepared.requests.size} additional request(s) into ${input.executionId}",
            executionId = input.executionId,
        )
        if (approved != null) return approved

        return lifecycleMutation.withLock {
            val current = ownedExecution(input.projectId, input.executionId)
            if (current !== owned) {
                return@withLock actionFailure(NativeToolStatus.NOT_FOUND, input.projectId, null, 0, "request execution was removed")
            }
            if (owned.queued + prepared.requests.size > MAX_REQUEST_EXECUTION_ITEMS ||
                owned.totalBytes.toLong() + prepared.totalBytes > MAX_REQUEST_EXECUTION_TOTAL_BYTES
            ) {
                return@withLock actionFailure(
                    NativeToolStatus.LIMIT_EXCEEDED,
                    input.projectId,
                    input.executionId,
                    0,
                    "an execution accepts at most $MAX_REQUEST_EXECUTION_ITEMS requests and $MAX_REQUEST_EXECUTION_TOTAL_BYTES request bytes",
                )
            }
            recheckProject(input.projectId, input.executionId)?.let { return@withLock it }
            if (config.emergencyReadOnlyMode) {
                return@withLock actionFailure(
                    NativeToolStatus.DISABLED,
                    input.projectId,
                    input.executionId,
                    0,
                    "Emergency read-only mode was enabled before requests were queued",
                )
            }
            if (runCatching { owned.execution.lifetime().finished() }.getOrDefault(true)) {
                return@withLock actionFailure(
                    NativeToolStatus.NOT_AVAILABLE,
                    input.projectId,
                    input.executionId,
                    0,
                    "request execution finished before queueing",
                )
            }
            var queued = 0
            try {
                prepared.requests.forEach { request ->
                    currentCoroutineContext().ensureActive()
                    queueUnderFence(input.projectId, input.executionId, owned, request)
                    queued++
                }
                owned.queued += queued
                owned.totalBytes += prepared.totalBytes
            } catch (e: RequestExecutionFenceException) {
                if (queued == 0) {
                    return@withLock actionFailure(e.status, e.projectId, input.executionId, 0, e.message.orEmpty())
                }
                owned.queued = (owned.queued + prepared.requests.size).coerceAtMost(MAX_REQUEST_EXECUTION_ITEMS)
                owned.totalBytes = (owned.totalBytes.toLong() + prepared.totalBytes)
                    .coerceAtMost(MAX_REQUEST_EXECUTION_TOTAL_BYTES.toLong()).toInt()
                return@withLock actionUncertain(
                    input.projectId,
                    input.executionId,
                    queued,
                    null,
                    e,
                    "Burp may have queued requests before an execution fence changed",
                )
            } catch (e: CancellationException) {
                owned.queued = (owned.queued + prepared.requests.size).coerceAtMost(MAX_REQUEST_EXECUTION_ITEMS)
                owned.totalBytes = (owned.totalBytes.toLong() + prepared.totalBytes)
                    .coerceAtMost(MAX_REQUEST_EXECUTION_TOTAL_BYTES.toLong()).toInt()
                if (!currentCoroutineContext().isActive) throw e
                return@withLock actionUncertain(
                    input.projectId,
                    input.executionId,
                    queued,
                    null,
                    e,
                    "Burp may have queued additional requests",
                )
            } catch (e: Exception) {
                owned.queued = (owned.queued + prepared.requests.size).coerceAtMost(MAX_REQUEST_EXECUTION_ITEMS)
                owned.totalBytes = (owned.totalBytes.toLong() + prepared.totalBytes)
                    .coerceAtMost(MAX_REQUEST_EXECUTION_TOTAL_BYTES.toLong()).toInt()
                return@withLock actionUncertain(
                    input.projectId,
                    input.executionId,
                    queued,
                    null,
                    e,
                    "Burp may have queued additional requests",
                )
            }
            val postProject = currentProjectIdOrNull(api)
            if (postProject != input.projectId || config.emergencyReadOnlyMode ||
                ownedExecution(input.projectId, input.executionId) !== owned
            ) {
                return@withLock actionUncertain(
                    input.projectId,
                    input.executionId,
                    queued,
                    null,
                    IllegalStateException("a request execution fence changed while requests were queued"),
                    "Burp may have queued requests before project or emergency policy changed",
                )
            }
            HttpRequestExecutionActionResult(
                status = NativeToolStatus.OK,
                retry = ToolRetryGuidance.NOT_APPLICABLE,
                executionState = StandardExecutionState.COMPLETED,
                projectId = input.projectId,
                executionId = input.executionId,
                queued = queued,
                stats = runCatching { owned.execution.stats().toDto() }.getOrNull(),
            )
        }
    }

    suspend fun get(input: GetHttpRequestExecution): HttpRequestExecutionStatusResult {
        val wait = input.waitMillis ?: 0L
        val handleError = validateHandleInput(input.projectId, input.executionId)
        if (handleError != null || wait !in 0..MAX_REQUEST_EXECUTION_WAIT_MS) {
            return statusFailure(
                NativeToolStatus.INVALID_ARGUMENT,
                null,
                null,
                handleError ?: "waitMillis is out of range",
            )
        }
        val currentProject = currentProjectIdOrNull(api)
            ?: return statusFailure(NativeToolStatus.BURP_ERROR, null, null, "Burp could not read the current project")
        if (currentProject != input.projectId) {
            return statusFailure(NativeToolStatus.PROJECT_MISMATCH, currentProject, null, "request execution belongs to a different Burp project")
        }
        val owned = ownedExecution(input.projectId, input.executionId)
            ?: return statusFailure(NativeToolStatus.NOT_FOUND, input.projectId, null, "request execution was not found")
        return try {
            if (wait > 0) {
                val deadline = System.nanoTime() + wait * 1_000_000L
                while (!owned.execution.lifetime().finished() && System.nanoTime() < deadline) {
                    delay(50)
                }
            }
            currentCoroutineContext().ensureActive()
            val postProject = currentProjectIdOrNull(api)
                ?: return statusFailure(
                    NativeToolStatus.BURP_ERROR,
                    input.projectId,
                    input.executionId,
                    "Burp could not recheck the project",
                )
            if (postProject != input.projectId) {
                return statusFailure(
                    NativeToolStatus.PROJECT_MISMATCH,
                    postProject,
                    null,
                    "Burp project changed while execution status was read",
                )
            }
            val finished = owned.execution.lifetime().finished()
            val cancelled = if (finished) owned.execution.lifetime().awaitCompletion().cancelled() else null
            val captured = owned.capture.snapshot()
            val stats = owned.execution.stats().toDto()
            currentCoroutineContext().ensureActive()
            val finalProject = currentProjectIdOrNull(api)
                ?: return statusFailure(
                    NativeToolStatus.BURP_ERROR,
                    input.projectId,
                    input.executionId,
                    "Burp could not perform the final project check after reading execution status",
                )
            if (finalProject != input.projectId) {
                return statusFailure(
                    NativeToolStatus.PROJECT_MISMATCH,
                    finalProject,
                    null,
                    "Burp project changed while execution result metadata was read",
                )
            }
            if (ownedExecution(input.projectId, input.executionId) !== owned) {
                return statusFailure(
                    NativeToolStatus.STALE_STATE,
                    input.projectId,
                    null,
                    "request execution crossed a lifecycle boundary while status was read",
                )
            }
            HttpRequestExecutionStatusResult(
                status = NativeToolStatus.OK,
                retry = ToolRetryGuidance.NOT_APPLICABLE,
                projectId = input.projectId,
                executionId = input.executionId,
                finished = finished,
                cancelled = cancelled,
                stats = stats,
                results = captured.first,
                resultsTruncated = captured.second,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            statusFailure(
                NativeToolStatus.BURP_ERROR,
                input.projectId,
                input.executionId,
                "Burp could not read request execution status: ${safeExceptionSummary(e)}",
            )
        }
    }

    suspend fun control(input: ControlHttpRequestExecution): HttpRequestExecutionActionResult {
        val handleError = validateHandleInput(input.projectId, input.executionId)
        if (handleError != null) return actionFailure(NativeToolStatus.INVALID_ARGUMENT, null, null, 0, handleError, input.control)
        val owned = ownedExecution(input.projectId, input.executionId)
            ?: return actionFailure(NativeToolStatus.NOT_FOUND, input.projectId, null, 0, "request execution was not found", input.control)
        val approved = try {
            SensitiveActionSecurity.checkPermission(
                action = "${input.control.name.lowercase()} a native HTTP request execution",
                summary = "Apply ${input.control.name.lowercase()} to retained handle ${input.executionId}; delete cancels an unfinished run before removing its handle",
                api = api,
                config = config,
                auditOperation = SensitiveActionAuditOperation.REQUEST_EXECUTION_CONTROL,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return actionFailure(
                NativeToolStatus.BURP_ERROR,
                input.projectId,
                input.executionId,
                0,
                "Burp could not request execution-control approval: ${safeExceptionSummary(e)}",
                input.control,
            )
        }
        recheckProject(input.projectId, input.executionId)?.let { return it.copy(control = input.control) }
        if (!approved) {
            return actionFailure(
                NativeToolStatus.ACCESS_DENIED,
                input.projectId,
                input.executionId,
                0,
                "request execution control denied by Burp Suite",
                input.control,
            )
        }

        return lifecycleMutation.withLock {
            val current = ownedExecution(input.projectId, input.executionId)
            if (current !== owned) {
                return@withLock actionFailure(NativeToolStatus.NOT_FOUND, input.projectId, null, 0, "request execution was removed", input.control)
            }
            recheckProject(input.projectId, input.executionId)?.let { return@withLock it.copy(control = input.control) }
            currentCoroutineContext().ensureActive()
            if (config.emergencyReadOnlyMode) {
                return@withLock actionFailure(
                    NativeToolStatus.DISABLED,
                    input.projectId,
                    input.executionId,
                    0,
                    "Emergency read-only mode was enabled before request execution control",
                    input.control,
                )
            }
            try {
                synchronized(stateLock) {
                    if (closed || executions[input.executionId] !== owned) {
                        throw RequestExecutionFenceException(
                            NativeToolStatus.STALE_STATE,
                            input.projectId,
                            "request execution crossed a lifecycle boundary before control",
                        )
                    }
                    when (input.control) {
                        HttpRequestExecutionControl.PAUSE -> owned.execution.lifetime().pause()
                        HttpRequestExecutionControl.RESUME -> owned.execution.lifetime().resume()
                        HttpRequestExecutionControl.CANCEL -> owned.execution.lifetime().cancel()
                        HttpRequestExecutionControl.DELETE -> {
                            if (!owned.execution.lifetime().finished()) owned.execution.lifetime().cancel()
                            executions.remove(input.executionId, owned)
                            val cleanupConfirmed = runCatching { owned.execution.lifetime().finished() }
                                .getOrDefault(false)
                            if (!cleanupConfirmed) {
                                reserveCleanup(owned.execution)
                                throw RequestExecutionCleanupPendingException()
                            }
                        }
                    }
                }
            } catch (e: RequestExecutionFenceException) {
                return@withLock actionFailure(
                    e.status,
                    e.projectId,
                    input.executionId,
                    0,
                    e.message.orEmpty(),
                    input.control,
                )
            } catch (e: RequestExecutionCleanupPendingException) {
                return@withLock actionUncertain(
                    input.projectId,
                    null,
                    0,
                    input.control,
                    e,
                    "The execution handle was deleted, but native request termination is not yet confirmed",
                )
            } catch (e: CancellationException) {
                if (!currentCoroutineContext().isActive) throw e
                return@withLock actionUncertain(
                    input.projectId,
                    input.executionId,
                    0,
                    input.control,
                    e,
                    "Burp may have applied request execution control",
                )
            } catch (e: Exception) {
                return@withLock actionUncertain(
                    input.projectId,
                    input.executionId,
                    0,
                    input.control,
                    e,
                    "Burp may have applied request execution control",
                )
            }
            val postProject = currentProjectIdOrNull(api)
            val lifecycleCurrent = input.control == HttpRequestExecutionControl.DELETE ||
                ownedExecution(input.projectId, input.executionId) === owned
            if (postProject != input.projectId || config.emergencyReadOnlyMode || !lifecycleCurrent) {
                return@withLock actionUncertain(
                    input.projectId,
                    input.executionId,
                    0,
                    input.control,
                    IllegalStateException("a request execution fence changed during control"),
                    "Burp may have applied request execution control before project or emergency policy changed",
                )
            }
            HttpRequestExecutionActionResult(
                status = NativeToolStatus.OK,
                retry = ToolRetryGuidance.NOT_APPLICABLE,
                executionState = StandardExecutionState.COMPLETED,
                projectId = input.projectId,
                executionId = if (input.control == HttpRequestExecutionControl.DELETE) null else input.executionId,
                queued = 0,
                control = input.control,
                stats = if (input.control == HttpRequestExecutionControl.DELETE) null else runCatching {
                    owned.execution.stats().toDto()
                }.getOrNull(),
            )
        }
    }

    suspend fun resetForProjectBoundary() {
        lifecycleMutation.withLock {
            val detached = synchronized(stateLock) {
                generation++
                executions.values.toList().also { executions.clear() }
            }
            detached.forEach { cancelOrReserve(it.execution) }
            retryCleanupReservationsLocked()
        }
    }

    override fun close() = runBlocking {
        lifecycleMutation.withLock {
            val detached = synchronized(stateLock) {
                if (closed) emptyList() else {
                    closed = true
                    generation++
                    (executions.values.map { it.execution } + cleanupReservations).also {
                        executions.clear()
                        cleanupReservations.clear()
                    }
                }
            }
            detached.forEach { runCatching { it.lifetime().cancel() } }
        }
    }

    private suspend fun prepareRequests(
        projectId: String,
        items: List<HttpRequestExecutionItem>,
    ): PreparedRequests {
        if (!isValidProjectId(projectId)) {
            return PreparedRequests.Failed(NativeToolStatus.INVALID_ARGUMENT, null, "projectId is invalid")
        }
        val structuralError = validateItems(items)
        if (structuralError != null) return PreparedRequests.Failed(NativeToolStatus.INVALID_ARGUMENT, null, structuralError)

        val rawPrepared = HashMap<Int, PreparedRawHttpRequest>()
        try {
            items.forEachIndexed { index, item ->
                item.raw?.let { raw ->
                    rawPrepared[index] = prepareRawHttpRequest(
                        raw.protocol,
                        raw.http1,
                        raw.http2,
                        raw.targetHostname,
                        raw.targetPort,
                        raw.usesHttps,
                    )
                }
            }
        } catch (e: RawHttpInputValidationException) {
            return PreparedRequests.Failed(NativeToolStatus.INVALID_ARGUMENT, null, e.message.orEmpty())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return PreparedRequests.Failed(
                NativeToolStatus.BURP_ERROR,
                null,
                "Burp could not prepare a raw execution request: ${safeExceptionSummary(e)}",
            )
        }

        val storedRefs = items.mapNotNull { it.stored?.ref }
        val storedMessages = if (storedRefs.isEmpty()) {
            emptyList()
        } else {
            when (val resolution = resolver.resolveAll(projectId, storedRefs, MAX_REQUEST_EXECUTION_QUEUE_ITEMS)) {
                is HttpMessageBatchResolution.Failed -> return PreparedRequests.Failed(
                    resolution.status.toNativeToolStatus(),
                    resolution.projectId,
                    resolution.error,
                )
                is HttpMessageBatchResolution.Found -> resolution.messages
            }
        }
        val resolvedIterator = storedMessages.iterator()
        val prepared = ArrayList<PreparedExecutionRequest>(items.size)
        var totalBytes = 0L
        try {
            items.forEachIndexed { index, item ->
                val candidate = if (item.stored != null) {
                    val resolved = resolvedIterator.next()
                    val patched = applyPatch(resolved.request, item.stored.patch)
                    PreparedExecutionRequest(
                        request = patched.request,
                        requestBytes = patched.requestBytes,
                        target = patched.target,
                        label = item.label,
                        source = "${resolved.ref.source.name.lowercase()}:${resolved.ref.id}",
                        changes = patched.summary,
                        derived = true,
                        review = { patched.requestContent },
                    )
                } else {
                    val raw = requireNotNull(rawPrepared[index])
                    val target = requireNotNull(item.raw)
                    PreparedExecutionRequest(
                        request = raw.request,
                        requestBytes = raw.requestBytes,
                        target = HttpActionTarget(target.targetHostname.take(MAX_HTTP_SEARCH_HOST_CHARS), target.targetPort, target.usesHttps),
                        label = item.label,
                        source = "raw MCP request",
                        changes = "${target.protocol.name.lowercase()} request",
                        derived = false,
                        review = { raw.review },
                    )
                }
                totalBytes += candidate.requestBytes
                if (totalBytes > MAX_REQUEST_EXECUTION_TOTAL_BYTES) {
                    return PreparedRequests.Failed(
                        NativeToolStatus.LIMIT_EXCEEDED,
                        projectId,
                        "execution requests exceed the $MAX_REQUEST_EXECUTION_TOTAL_BYTES-byte aggregate limit",
                    )
                }
                prepared += candidate
            }
        } catch (e: HttpRequestPatchValidationException) {
            return PreparedRequests.Failed(NativeToolStatus.INVALID_ARGUMENT, projectId, e.message.orEmpty())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return PreparedRequests.Failed(
                NativeToolStatus.BURP_ERROR,
                projectId,
                "Burp could not prepare a stored execution request: ${safeExceptionSummary(e)}",
            )
        }
        return PreparedRequests.Found(projectId, prepared, totalBytes.toInt())
    }

    private suspend fun approveBatch(
        projectId: String,
        requests: List<PreparedExecutionRequest>,
        action: String,
        auditOperation: SensitiveActionAuditOperation,
        summary: String,
        executionId: String? = null,
    ): HttpRequestExecutionActionResult? {
        val batchApproved = try {
            SensitiveActionSecurity.checkPermission(
                action = action,
                summary = summary,
                api = api,
                config = config,
                auditOperation = auditOperation,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return actionFailure(
                NativeToolStatus.BURP_ERROR,
                projectId,
                executionId,
                0,
                "Burp could not request batch-execution approval: ${safeExceptionSummary(e)}",
            )
        }
        recheckProject(projectId, executionId)?.let { return it }
        if (!batchApproved) {
            return actionFailure(
                NativeToolStatus.ACCESS_DENIED,
                projectId,
                executionId,
                0,
                "HTTP request execution denied by Burp Suite",
            )
        }

        for (request in requests) {
            if (request.derived) {
                val approved = try {
                    RequestActionSecurity.checkPermissionLazy(
                        action = "queue this derived request in the HTTP Request Execution Engine",
                        source = request.source,
                        target = "${request.target.host}:${request.target.port} (${if (request.target.secure) "HTTPS" else "HTTP"})",
                        changes = request.changes,
                        config = config,
                        api = api,
                        auditOperation = RequestRoutingAuditOperation.REQUEST_EXECUTION,
                        requestContent = request.review,
                    )
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    return actionFailure(
                        NativeToolStatus.BURP_ERROR,
                        projectId,
                        executionId,
                        0,
                        "Burp could not request derived-request approval: ${safeExceptionSummary(e)}",
                    )
                }
                recheckProject(projectId, executionId)?.let { return it }
                if (!approved) {
                    return actionFailure(
                        NativeToolStatus.ACCESS_DENIED,
                        projectId,
                        executionId,
                        0,
                        "derived request execution denied by Burp Suite",
                    )
                }
            }
            val outboundApproved = try {
                HttpRequestSecurity.checkHttpRequestPermissionLazy(
                    request.target.host,
                    request.target.port,
                    config,
                    api,
                    request.review,
                )
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return actionFailure(
                    NativeToolStatus.BURP_ERROR,
                    projectId,
                    executionId,
                    0,
                    "Burp could not request outbound approval: ${safeExceptionSummary(e)}",
                )
            }
            recheckProject(projectId, executionId)?.let { return it }
            if (!outboundApproved) {
                return actionFailure(
                    NativeToolStatus.ACCESS_DENIED,
                    projectId,
                    executionId,
                    0,
                    "outbound request execution denied by Burp Suite",
                )
            }
        }
        return null
    }

    private fun createEngine(input: StartHttpRequestExecution): burp.api.montoya.http.execution.RequestExecutionEngine {
        val mode = input.resourcePool ?: RequestExecutionResourcePool.PRIVATE
        if (mode == RequestExecutionResourcePool.PRIVATE && input.name == null &&
            input.concurrentRequestLimit == null && input.throttleMillis == null && input.maxRetries == null
        ) {
            return api.http().createRequestEngine()
        }
        val pool = when (mode) {
            RequestExecutionResourcePool.PRIVATE -> {
                var value = ResourcePool.resourcePool()
                input.concurrentRequestLimit?.let { value = value.withConcurrentRequestLimit(it) }
                input.throttleMillis?.let { value = value.withThrottle(Duration.ofMillis(it)) }
                input.maxRetries?.let { value = value.withMaxRetries(it) }
                value
            }
            RequestExecutionResourcePool.DEFAULT -> ResourcePool.defaultResourcePool()
            RequestExecutionResourcePool.EXISTING -> ResourcePool.existingResourcePool(requireNotNull(input.existingResourcePoolName))
        }
        var options = RequestEngineOptions.requestEngineOptions().withResourcePool(pool)
        input.name?.let { options = options.withName(it) }
        return api.http().createRequestEngine(options)
    }

    private fun validateStart(input: StartHttpRequestExecution): String? {
        if (!isValidProjectId(input.projectId)) return "projectId is invalid"
        if (input.requests.isEmpty() || input.requests.size > MAX_REQUEST_EXECUTION_START_ITEMS) {
            return "requests must contain between 1 and $MAX_REQUEST_EXECUTION_START_ITEMS items"
        }
        if (input.name != null && (input.name.isBlank() || input.name.length > MAX_REQUEST_EXECUTION_NAME_CHARS || input.name.any(Char::isISOControl))) {
            return "name is empty, too long, or contains control characters"
        }
        val mode = input.resourcePool ?: RequestExecutionResourcePool.PRIVATE
        if (mode == RequestExecutionResourcePool.EXISTING) {
            val name = input.existingResourcePoolName
            if (name.isNullOrBlank() || name.length > MAX_RESOURCE_POOL_NAME_CHARS || name.any(Char::isISOControl)) {
                return "existingResourcePoolName is required and invalid"
            }
        } else if (input.existingResourcePoolName != null) {
            return "existingResourcePoolName is supported only for resourcePool=existing"
        }
        if (mode != RequestExecutionResourcePool.PRIVATE &&
            (input.concurrentRequestLimit != null || input.throttleMillis != null || input.maxRetries != null)
        ) {
            return "concurrency, throttle, and retries are supported only for a private resource pool"
        }
        if (input.concurrentRequestLimit != null && input.concurrentRequestLimit !in 1..MAX_REQUEST_EXECUTION_CONCURRENCY) {
            return "concurrentRequestLimit is out of range"
        }
        if (input.throttleMillis != null && input.throttleMillis !in 0..MAX_REQUEST_EXECUTION_THROTTLE_MS) {
            return "throttleMillis is out of range"
        }
        if (input.maxRetries != null && input.maxRetries !in 0..MAX_REQUEST_EXECUTION_RETRIES) {
            return "maxRetries is out of range"
        }
        if ((input.requestTimeoutMillis ?: 30_000L) !in MIN_REQUEST_EXECUTION_TIMEOUT_MS..MAX_REQUEST_EXECUTION_TIMEOUT_MS) {
            return "requestTimeoutMillis is out of range"
        }
        return validateItems(input.requests)
    }

    private fun validateItems(items: List<HttpRequestExecutionItem>): String? {
        for ((index, item) in items.withIndex()) {
            if ((item.stored == null) == (item.raw == null)) return "request ${index + 1} must provide exactly one of stored or raw"
            if (item.label != null && (item.label.length > MAX_REQUEST_EXECUTION_LABEL_CHARS || item.label.any(Char::isISOControl))) {
                return "request ${index + 1} label is too long or contains control characters"
            }
            if (item.stored != null && canonicalHttpReferenceIdentity(item.stored.ref) == null) {
                return "request ${index + 1} stored reference is invalid"
            }
            if (item.raw != null) {
                try {
                    validateRawHttpRequestInput(
                        item.raw.protocol,
                        item.raw.http1,
                        item.raw.http2,
                        item.raw.targetHostname,
                        item.raw.targetPort,
                    )
                } catch (e: RawHttpInputValidationException) {
                    return "request ${index + 1}: ${e.message.orEmpty()}"
                }
            }
        }
        return null
    }

    private fun validateHandleInput(projectId: String, executionId: String): String? = when {
        !isValidProjectId(projectId) -> "projectId is invalid"
        !REQUEST_EXECUTION_ID.matches(executionId) -> "executionId is invalid"
        else -> null
    }

    private fun ownedExecution(projectId: String, executionId: String): OwnedRequestExecution? = synchronized(stateLock) {
        executions[executionId]?.takeIf { it.projectId == projectId }
    }

    private suspend fun retryCleanupReservations() {
        lifecycleMutation.withLock { retryCleanupReservationsLocked() }
    }

    private fun retryCleanupReservationsLocked() {
        val pending = synchronized(stateLock) { cleanupReservations.toList() }
        pending.forEach { execution ->
            val finished = runCatching {
                execution.lifetime().cancel()
                execution.lifetime().finished()
            }.getOrDefault(false)
            if (finished) {
                synchronized(stateLock) { cleanupReservations.removeAll { it === execution } }
            }
        }
    }

    private fun cancelOrReserve(execution: RequestExecution) {
        val finished = runCatching {
            execution.lifetime().cancel()
            execution.lifetime().finished()
        }.getOrDefault(false)
        if (!finished) reserveCleanup(execution)
    }

    private fun reserveCleanup(execution: RequestExecution) {
        synchronized(stateLock) {
            if (!closed && cleanupReservations.none { it === execution }) cleanupReservations += execution
        }
    }

    private fun queueUnderFence(
        projectId: String,
        executionId: String,
        expected: OwnedRequestExecution,
        request: PreparedExecutionRequest,
    ) {
        if (config.emergencyReadOnlyMode) {
            throw RequestExecutionFenceException(
                NativeToolStatus.DISABLED,
                projectId,
                "Emergency read-only mode was enabled before native queueing",
            )
        }
        val currentProject = currentProjectIdOrNull(api) ?: throw RequestExecutionFenceException(
            NativeToolStatus.BURP_ERROR,
            projectId,
            "Burp could not recheck the project before native queueing",
        )
        if (currentProject != projectId) {
            throw RequestExecutionFenceException(
                NativeToolStatus.PROJECT_MISMATCH,
                currentProject,
                "Burp project changed before native queueing",
            )
        }
        synchronized(stateLock) {
            if (closed || executions[executionId] !== expected) {
                throw RequestExecutionFenceException(
                    NativeToolStatus.STALE_STATE,
                    projectId,
                    "request execution crossed a lifecycle boundary before native queueing",
                )
            }
            if (request.label == null) expected.execution.queue(request.request)
            else expected.execution.queue(request.request, request.label)
        }
    }

    private fun newExecutionId(): String {
        while (true) {
            val candidate = "reqexec-${UUID.randomUUID().toString().replace("-", "")}"
            synchronized(stateLock) { if (candidate !in executions) return candidate }
        }
    }

    private fun recheckProject(
        projectId: String,
        executionId: String? = null,
    ): HttpRequestExecutionActionResult? {
        val current = currentProjectIdOrNull(api) ?: return actionFailure(
            NativeToolStatus.BURP_ERROR,
            projectId,
            executionId,
            0,
            "Burp could not recheck the current project",
        )
        if (current == projectId) return null
        return actionFailure(
            NativeToolStatus.PROJECT_MISMATCH,
            current,
            executionId,
            0,
            "Burp project changed before the request execution action started",
        )
    }

    private fun actionFailure(
        status: NativeToolStatus,
        projectId: String?,
        executionId: String?,
        queued: Int,
        error: String,
        control: HttpRequestExecutionControl? = null,
    ) = HttpRequestExecutionActionResult(
        status = status,
        retry = status.defaultRetry(),
        executionState = StandardExecutionState.NOT_STARTED,
        projectId = projectId?.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
        executionId = executionId,
        queued = queued.coerceIn(0, MAX_REQUEST_EXECUTION_ITEMS),
        control = control,
        error = nativeToolError(error),
    )

    private fun actionUncertain(
        projectId: String,
        executionId: String?,
        queued: Int,
        control: HttpRequestExecutionControl?,
        error: Exception,
        summary: String,
    ) = HttpRequestExecutionActionResult(
        status = NativeToolStatus.EXECUTION_UNCERTAIN,
        retry = ToolRetryGuidance.DO_NOT_RETRY,
        executionState = StandardExecutionState.UNCERTAIN,
        projectId = projectId,
        executionId = executionId,
        queued = queued.coerceIn(0, MAX_REQUEST_EXECUTION_ITEMS),
        control = control,
        error = uncertainExecutionError(
            summary,
            error,
            preserveCancellation = false,
            maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
        ),
    )

    private fun statusFailure(
        status: NativeToolStatus,
        projectId: String?,
        executionId: String?,
        error: String,
    ) = HttpRequestExecutionStatusResult(
        status = status,
        retry = status.defaultRetry(),
        projectId = projectId?.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
        executionId = executionId,
        finished = null,
        cancelled = null,
        stats = null,
        results = emptyList(),
        resultsTruncated = false,
        error = nativeToolError(error),
    )

    private sealed interface PreparedRequests {
        data class Found(
            val projectId: String,
            val requests: List<PreparedExecutionRequest>,
            val totalBytes: Int,
        ) : PreparedRequests
        data class Failed(val status: NativeToolStatus, val projectId: String?, val error: String) : PreparedRequests
    }
}

private fun ExecutionStats.toDto() = HttpRequestExecutionStats(
    requested = requested().coerceIn(0, MAX_REQUEST_EXECUTION_ITEMS),
    completed = completed().coerceIn(0, MAX_REQUEST_EXECUTION_ITEMS),
    failed = failed().coerceIn(0, MAX_REQUEST_EXECUTION_ITEMS),
    inFlight = inFlight().coerceIn(0, MAX_REQUEST_EXECUTION_ITEMS),
    pending = pending().coerceIn(0, MAX_REQUEST_EXECUTION_ITEMS),
    elapsedMillis = elapsed().toMillis().coerceAtLeast(0),
)

private fun responseByteLength(response: burp.api.montoya.http.message.responses.HttpResponse): Int {
    val total = response.bodyOffset().toLong() + response.body().length()
    require(total in 0..Int.MAX_VALUE.toLong()) { "response reported an invalid byte length" }
    return total.toInt()
}
