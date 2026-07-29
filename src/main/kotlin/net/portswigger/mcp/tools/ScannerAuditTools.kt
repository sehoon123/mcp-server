package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.audit.Audit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.SensitiveActionSecurity
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.HexFormat
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

private const val MAX_ACTIVE_SCANNER_AUDITS = 8
private const val MAX_RETAINED_SCANNER_AUDITS = 32
private const val MAX_ACTIVE_SCANNER_TARGETS = 4
private const val MAX_PASSIVE_SCANNER_TARGETS = 16
private const val MAX_TOTAL_SCANNER_INSERTION_POINTS = 64
private const val MAX_SCANNER_REQUEST_BYTES = 512 * 1024
private const val MAX_SCANNER_TOTAL_REQUEST_BYTES = 4 * 1024 * 1024
private const val DEFAULT_SCANNER_TASK_ISSUE_LIMIT = 25
private const val MAX_SCANNER_TASK_ISSUE_LIMIT = 50
private const val MAX_SCANNER_TASK_ID_CHARS = 128
private const val MAX_SCANNER_STATUS_MESSAGE_CHARS = 512
private const val SCANNER_CLEANUP_SHUTDOWN_MILLIS = 2_000L
private const val MAX_RETAINED_RESULT_SNAPSHOT_ATTEMPTS = 16
private val SCANNER_TASK_ID_PATTERN = Regex("scanner_audit_[0-9a-f]{32}")

private data class ScannerProjectObservation(
    val sequence: Long,
    val projectId: String?,
)

private data class ScannerProjectSnapshot(
    val projectId: String,
    val boundaryGeneration: Long,
)

private data class ScannerRecordBoundaryResult(
    val retained: Boolean,
    val currentProjectId: String?,
)

private data class ScannerStatusObservationUpdate(
    val state: ScannerAuditTaskState,
    val cleanupReservationReleased: Boolean,
)

private data class ScannerIssueObservationUpdate(
    val accepted: Boolean,
    val count: Int?,
)

private data class ScannerRecordResultSnapshot(
    val result: ScannerAuditResult,
    val version: Long,
)

private class StaleScannerProjectObservationException : IllegalStateException()

internal data class ScannerAuditRetentionPolicy(
    val unpublishedTaskRetention: Duration = Duration.ofMinutes(5),
    val idleTaskRetention: Duration = Duration.ofHours(6),
    val maximumTaskLifetime: Duration = Duration.ofHours(24),
    val terminalRecordRetention: Duration = Duration.ofHours(1),
    val sweepInterval: Duration = Duration.ofMinutes(1),
) {
    init {
        listOf(
            unpublishedTaskRetention,
            idleTaskRetention,
            maximumTaskLifetime,
            terminalRecordRetention,
            sweepInterval,
        ).forEach { require(!it.isZero && !it.isNegative) { "Scanner retention durations must be positive" } }
        require(maximumTaskLifetime >= idleTaskRetention) {
            "Scanner maximum task lifetime must not be shorter than its idle retention"
        }
    }
}

private fun newScannerCleanupExecutor(): ScheduledExecutorService {
    val threadNumber = AtomicInteger()
    return Executors.newScheduledThreadPool(MAX_ACTIVE_SCANNER_AUDITS) { task ->
        Thread(task, "burp-mcp-scanner-cleanup-${threadNumber.incrementAndGet()}").apply { isDaemon = true }
    }
}

@Serializable
data class ScannerAuditTarget(
    @JsonSchemaMetadata(description = "Existing project-scoped HTTP message reference.")
    val ref: HttpMessageReference,
    @JsonSchemaMetadata(description = "Required semantic insertion points for active audit; omitted for passive audit. Up to 64 are allowed across all targets.", minItems = 1, maxItems = 32)
    val insertionPoints: List<HttpInsertionPointSelector>? = null,
)

@Serializable
data class StartScannerAuditFromIds(
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Passive or focused active audit mode.")
    val mode: ScannerAuditMode,
    @JsonSchemaMetadata(description = "Existing in-scope messages; active allows 4 and passive allows 16.", minItems = 1, maxItems = 16)
    val targets: List<ScannerAuditTarget>,
)

@Serializable
data class GetScannerAudit(
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Extension-owned Scanner task ID.", maxLength = 128, pattern = "^scanner_audit_[0-9a-f]{32}$")
    val taskId: String,
    @JsonSchemaMetadata(description = "Maximum issue summaries; zero skips issue access.", minimum = 0, maximum = 50, defaultJson = "25")
    val issueLimit: Int? = null,
)

@Serializable
data class CancelScannerAudit(
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "Extension-owned Scanner task ID.", maxLength = 128, pattern = "^scanner_audit_[0-9a-f]{32}$")
    val taskId: String,
)

@Serializable
enum class ScannerAuditMode {
    @SerialName("passive")
    PASSIVE,

    @SerialName("active")
    ACTIVE,
}

@Serializable
enum class ScannerAuditToolStatus {
    @SerialName("ok")
    OK,

    @SerialName("access_denied")
    ACCESS_DENIED,

    @SerialName("action_denied")
    ACTION_DENIED,

    @SerialName("invalid_argument")
    INVALID_ARGUMENT,

    @SerialName("invalid_id")
    INVALID_ID,

    @SerialName("project_mismatch")
    PROJECT_MISMATCH,

    @SerialName("not_found")
    NOT_FOUND,

    @SerialName("request_unavailable")
    REQUEST_UNAVAILABLE,

    @SerialName("out_of_scope")
    OUT_OF_SCOPE,

    @SerialName("capacity_exceeded")
    CAPACITY_EXCEEDED,

    @SerialName("burp_error")
    BURP_ERROR,

    @SerialName("execution_uncertain")
    EXECUTION_UNCERTAIN,
}

@Serializable
enum class ScannerAuditActionState {
    @SerialName("not_started")
    NOT_STARTED,

    @SerialName("completed")
    COMPLETED,

    @SerialName("uncertain")
    UNCERTAIN,
}

@Serializable
enum class ScannerAuditTaskState {
    @SerialName("starting")
    STARTING,

    @SerialName("running")
    RUNNING,

    @SerialName("paused")
    PAUSED,

    @SerialName("finished")
    FINISHED,

    @SerialName("cancelled")
    CANCELLED,

    @SerialName("failed")
    FAILED,

    @SerialName("unknown")
    UNKNOWN,
}

@Serializable
data class ScannerAuditTargetSummary(
    val ref: HttpMessageReference,
    val method: String,
    val url: String,
    val insertionPointCount: Int,
)

@Serializable
data class ScannerAuditResult(
    @JsonSchemaMetadata(description = "Outcome category; burp_error alone does not determine whether a Scanner side effect occurred.")
    val status: ScannerAuditToolStatus,
    @JsonSchemaMetadata(description = "Authoritative Scanner side-effect state; uncertain must not be retried automatically.")
    val actionState: ScannerAuditActionState,
    val projectId: String?,
    val taskId: String? = null,
    val mode: ScannerAuditMode? = null,
    val taskState: ScannerAuditTaskState? = null,
    val statusMessage: String? = null,
    val startedAt: String? = null,
    val cancelledAt: String? = null,
    @JsonSchemaMetadata(description = "Validated audit targets retained by this extension; always present and possibly empty.")
    val targets: List<ScannerAuditTargetSummary>,
    @JsonSchemaMetadata(description = "Number of retained targets.", minimum = 0, maximum = 16)
    val targetCount: Int,
    @JsonSchemaMetadata(description = "Total selected insertion points across retained targets.", minimum = 0)
    val insertionPointCount: Int,
    val auditedInsertionPointCount: Int? = null,
    val requestCount: Int? = null,
    val errorCount: Int? = null,
    val discoveredIssueCount: Int? = null,
    @JsonSchemaMetadata(description = "Bounded issue summaries requested for this status read; always present and possibly empty.")
    val issues: List<ScannerIssueSummary>,
    @JsonSchemaMetadata(description = "True when additional issue summaries were omitted by the result limit.")
    val issuesTruncated: Boolean,
    @JsonSchemaMetadata(description = "True when issue-summary access was denied; an empty issues list alone does not imply denial.")
    val issuesAccessDenied: Boolean,
    @JsonSchemaMetadata(description = "True when requested issue summaries could not be read because access failed technically, the audit was already cancelled, or Burp could not expose issue objects.")
    val issuesUnavailable: Boolean,
    val errorTargetIndex: Int? = null,
    @JsonSchemaMetadata(maxLength = MAX_STRUCTURED_TOOL_ERROR_CHARS)
    val error: String? = null,
)

internal class ScannerAuditService(
    private val api: MontoyaApi,
    private val clock: () -> Instant = { Instant.now() },
    private val ticker: () -> Long = System::nanoTime,
    private val retention: ScannerAuditRetentionPolicy = ScannerAuditRetentionPolicy(),
    cleanupExecutor: ScheduledExecutorService? = newScannerCleanupExecutor(),
    private val retainedResultPublicationHook: (() -> Unit)? = null,
) {
    private val records = ConcurrentHashMap<String, ScannerAuditRecord>()
    private val startMutex = Mutex()
    private val random = SecureRandom()
    private val projectObservationSequence = AtomicLong()
    private val projectObservationLock = Any()
    private var latestProjectObservationSequence = 0L
    private var projectBoundaryGeneration = 0L
    private var observedProject: ScannerProjectObservation? = null
    private val cleanupReservations = AtomicInteger()
    private val cleanupExecutor = cleanupExecutor
    private val cleanupLifecycle = Any()
    @Volatile
    private var closed = false

    init {
        val intervalMillis = retention.sweepInterval.toMillis().coerceAtLeast(1L)
        cleanupExecutor?.scheduleWithFixedDelay(
            {
                try {
                    cleanupExpired()
                } catch (_: Exception) {
                    runCatching { api.logging().logToError("MCP Scanner cleanup failed") }
                }
            },
            intervalMillis,
            intervalMillis,
            TimeUnit.MILLISECONDS,
        )
    }

    suspend fun start(input: StartScannerAuditFromIds, config: McpConfig): ScannerAuditResult {
        val targetLimit = when (input.mode) {
            ScannerAuditMode.ACTIVE -> MAX_ACTIVE_SCANNER_TARGETS
            ScannerAuditMode.PASSIVE -> MAX_PASSIVE_SCANNER_TARGETS
        }
        if (!validProjectId(input.projectId)) {
            return scannerAuditError(
                ScannerAuditToolStatus.INVALID_ARGUMENT,
                ScannerAuditActionState.NOT_STARTED,
                null,
                input.mode,
                "projectId is empty, too long, or contains control characters",
            )
        }
        if (input.targets.isEmpty() || input.targets.size > targetLimit) {
            return scannerAuditError(
                ScannerAuditToolStatus.INVALID_ARGUMENT,
                ScannerAuditActionState.NOT_STARTED,
                null,
                input.mode,
                "${input.mode.name.lowercase()} audit targets must contain between 1 and $targetLimit items",
            )
        }
        val refs = input.targets.map { it.ref }
        if (refs.distinct().size != refs.size) {
            return scannerAuditError(
                ScannerAuditToolStatus.INVALID_ARGUMENT,
                ScannerAuditActionState.NOT_STARTED,
                null,
                input.mode,
                "audit targets must not contain duplicate references",
            )
        }

        val resolution = HttpMessageResolver(api, config).resolveAll(input.projectId, refs, targetLimit)
        val messages = when (resolution) {
            is HttpMessageBatchResolution.Failed -> return scannerAuditError(
                resolution.status.toScannerAuditStatus(),
                ScannerAuditActionState.NOT_STARTED,
                resolution.projectId,
                input.mode,
                resolution.error,
                resolution.refIndex,
            )

            is HttpMessageBatchResolution.Found -> resolution.messages
        }
        val prepared = ArrayList<PreparedScannerAuditTarget>(messages.size)
        var totalBytes = 0L
        var totalInsertionPoints = 0
        messages.forEachIndexed { index, message ->
            currentCoroutineContext().ensureActive()
            val size = try {
                scannerRequestBytes(message)
            } catch (e: ScannerAuditValidationException) {
                return scannerAuditError(
                    ScannerAuditToolStatus.INVALID_ARGUMENT,
                    ScannerAuditActionState.NOT_STARTED,
                    input.projectId,
                    input.mode,
                    e.message.orEmpty(),
                    index,
                )
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                return scannerAuditError(
                    ScannerAuditToolStatus.BURP_ERROR,
                    ScannerAuditActionState.NOT_STARTED,
                    input.projectId,
                    input.mode,
                    "Burp could not read the Scanner target request size",
                    index,
                )
            }
            if (size > MAX_SCANNER_REQUEST_BYTES) {
                return scannerAuditError(
                    ScannerAuditToolStatus.INVALID_ARGUMENT,
                    ScannerAuditActionState.NOT_STARTED,
                    input.projectId,
                    input.mode,
                    "audit target request exceeds the $MAX_SCANNER_REQUEST_BYTES-byte limit",
                    index,
                )
            }
            totalBytes += size
            if (totalBytes > MAX_SCANNER_TOTAL_REQUEST_BYTES) {
                return scannerAuditError(
                    ScannerAuditToolStatus.INVALID_ARGUMENT,
                    ScannerAuditActionState.NOT_STARTED,
                    input.projectId,
                    input.mode,
                    "audit target requests exceed the $MAX_SCANNER_TOTAL_REQUEST_BYTES-byte total limit",
                    index,
                )
            }
            val projectBeforeScope = try {
                captureProjectId()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return scannerAuditError(
                    ScannerAuditToolStatus.BURP_ERROR,
                    ScannerAuditActionState.NOT_STARTED,
                    input.projectId,
                    input.mode,
                    "Burp could not recheck the project before Scanner scope inspection: ${safeScannerAuditException(e)}",
                    index,
                )
            }
            if (projectBeforeScope != input.projectId) {
                return scannerAuditError(
                    ScannerAuditToolStatus.PROJECT_MISMATCH,
                    ScannerAuditActionState.NOT_STARTED,
                    projectBeforeScope,
                    input.mode,
                    "Burp project changed before Scanner target scope was inspected",
                    index,
                )
            }
            val inScope = try {
                api.scope().isInScope(message.request.url())
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return scannerAuditError(
                    ScannerAuditToolStatus.BURP_ERROR,
                    ScannerAuditActionState.NOT_STARTED,
                    input.projectId,
                    input.mode,
                    "Burp could not check Scanner target scope: ${safeScannerAuditException(e)}",
                    index,
                )
            }
            val projectAfterScope = try {
                captureProjectId()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return scannerAuditError(
                    ScannerAuditToolStatus.BURP_ERROR,
                    ScannerAuditActionState.NOT_STARTED,
                    input.projectId,
                    input.mode,
                    "Burp could not recheck the project after Scanner scope inspection: ${safeScannerAuditException(e)}",
                    index,
                )
            }
            if (projectAfterScope != input.projectId) {
                return scannerAuditError(
                    ScannerAuditToolStatus.PROJECT_MISMATCH,
                    ScannerAuditActionState.NOT_STARTED,
                    projectAfterScope,
                    input.mode,
                    "Burp project changed while Scanner target scope was inspected",
                    index,
                )
            }
            if (!inScope) {
                return scannerAuditError(
                    ScannerAuditToolStatus.OUT_OF_SCOPE,
                    ScannerAuditActionState.NOT_STARTED,
                    input.projectId,
                    input.mode,
                    "audit target is outside Burp Target scope",
                    index,
                )
            }

            val selectors = input.targets[index].insertionPoints
            val insertionPoints = when (input.mode) {
                ScannerAuditMode.ACTIVE -> {
                    if (selectors.isNullOrEmpty()) {
                        return scannerAuditError(
                            ScannerAuditToolStatus.INVALID_ARGUMENT,
                            ScannerAuditActionState.NOT_STARTED,
                            input.projectId,
                            input.mode,
                            "each active audit target requires at least one semantic insertion point",
                            index,
                        )
                    }
                    try {
                        val resolved = prepareInsertionPoints(message.request, selectors)
                        if (totalInsertionPoints + resolved.ranges.size > MAX_TOTAL_SCANNER_INSERTION_POINTS) {
                            return scannerAuditError(
                                ScannerAuditToolStatus.INVALID_ARGUMENT,
                                ScannerAuditActionState.NOT_STARTED,
                                input.projectId,
                                input.mode,
                                "active audit targets can contain at most $MAX_TOTAL_SCANNER_INSERTION_POINTS total insertion points",
                                index,
                            )
                        }
                        totalInsertionPoints += resolved.ranges.size
                        resolved
                    } catch (e: HttpInsertionPointValidationException) {
                        return scannerAuditError(
                            ScannerAuditToolStatus.INVALID_ARGUMENT,
                            ScannerAuditActionState.NOT_STARTED,
                            input.projectId,
                            input.mode,
                            e.message.orEmpty(),
                            index,
                        )
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        return scannerAuditError(
                            ScannerAuditToolStatus.BURP_ERROR,
                            ScannerAuditActionState.NOT_STARTED,
                            input.projectId,
                            input.mode,
                            "Burp could not resolve audit insertion points: ${safeScannerAuditException(e)}",
                            index,
                        )
                    }
                }

                ScannerAuditMode.PASSIVE -> {
                    if (selectors != null) {
                        return scannerAuditError(
                            ScannerAuditToolStatus.INVALID_ARGUMENT,
                            ScannerAuditActionState.NOT_STARTED,
                            input.projectId,
                            input.mode,
                            "passive audit targets must not specify insertionPoints",
                            index,
                        )
                    }
                    null
                }
            }
            val requestResponse = if (input.mode == ScannerAuditMode.PASSIVE) {
                val response = message.response ?: return scannerAuditError(
                    ScannerAuditToolStatus.REQUEST_UNAVAILABLE,
                    ScannerAuditActionState.NOT_STARTED,
                    input.projectId,
                    input.mode,
                    "passive audit target does not have a response",
                    index,
                )
                message.envelope ?: try {
                    HttpRequestResponse.httpRequestResponse(message.request, response)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    return scannerAuditError(
                        ScannerAuditToolStatus.BURP_ERROR,
                        ScannerAuditActionState.NOT_STARTED,
                        input.projectId,
                        input.mode,
                        "Burp could not prepare passive audit evidence: ${safeScannerAuditException(e)}",
                        index,
                    )
                }
            } else {
                null
            }
            prepared += PreparedScannerAuditTarget(message, insertionPoints, requestResponse)
        }

        val approvalMaterial = try {
            Triple(
                prepared.map { it.summary() },
                buildScannerReview(input.mode, prepared),
                buildScannerApprovalSummary(input.projectId, input.mode, prepared),
            )
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return scannerAuditError(
                ScannerAuditToolStatus.BURP_ERROR,
                ScannerAuditActionState.NOT_STARTED,
                input.projectId,
                input.mode,
                "Burp could not prepare Scanner approval material",
            )
        }
        val (targetSummaries, review, approvalSummary) = approvalMaterial
        val approved = try {
            SensitiveActionSecurity.checkPermission(
                action = "start a focused ${input.mode.name.lowercase()} Scanner audit",
                summary = approvalSummary,
                reviewContent = review.content,
                renderContentAsHttp = review.renderAsHttp,
                api = api,
                config = config,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return scannerAuditError(
                ScannerAuditToolStatus.BURP_ERROR,
                ScannerAuditActionState.NOT_STARTED,
                input.projectId,
                input.mode,
                "Burp could not request Scanner approval: ${safeScannerAuditException(e)}",
            )
        }
        val projectAfterApproval = try {
            captureProjectId()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return scannerAuditError(
                ScannerAuditToolStatus.BURP_ERROR,
                ScannerAuditActionState.NOT_STARTED,
                input.projectId,
                input.mode,
                "Burp could not recheck the project after Scanner approval: ${safeScannerAuditException(e)}",
            )
        }
        if (projectAfterApproval != input.projectId) {
            return scannerAuditError(
                ScannerAuditToolStatus.PROJECT_MISMATCH,
                ScannerAuditActionState.NOT_STARTED,
                projectAfterApproval,
                input.mode,
                "Burp project changed during Scanner approval",
            )
        }
        if (!approved) {
            auditScanner(input.mode, prepared.size, null, "denied")
            return ScannerAuditResult(
                status = ScannerAuditToolStatus.ACTION_DENIED,
                actionState = ScannerAuditActionState.NOT_STARTED,
                projectId = input.projectId,
                mode = input.mode,
                targets = targetSummaries,
                targetCount = prepared.size,
                insertionPointCount = targetSummaries.sumOf { it.insertionPointCount },
                issues = emptyList(),
                issuesTruncated = false,
                issuesAccessDenied = false,
                issuesUnavailable = false,
                error = "Scanner audit denied by Burp Suite",
            )
        }

        val callContext = currentCoroutineContext()
        callContext.ensureActive()
        return startMutex.withLock {
            callContext.ensureActive()
            var boundaryBeforeStart = try {
                captureProject()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return@withLock scannerAuditError(
                    ScannerAuditToolStatus.BURP_ERROR,
                    ScannerAuditActionState.NOT_STARTED,
                    null,
                    input.mode,
                    "Burp could not recheck the project before Scanner start: ${safeScannerAuditException(e)}",
                )
            }
            if (boundaryBeforeStart.projectId != input.projectId) {
                return@withLock scannerAuditError(
                    ScannerAuditToolStatus.PROJECT_MISMATCH,
                    ScannerAuditActionState.NOT_STARTED,
                    boundaryBeforeStart.projectId,
                    input.mode,
                    "Burp project changed before the Scanner audit started",
                )
            }
            refreshAndTrimRecords()
            if (records.values.count { !it.lastState.isTerminal() } + cleanupReservations.get() >= MAX_ACTIVE_SCANNER_AUDITS) {
                return@withLock scannerAuditError(
                    ScannerAuditToolStatus.CAPACITY_EXCEEDED,
                    ScannerAuditActionState.NOT_STARTED,
                    input.projectId,
                    input.mode,
                    "at most $MAX_ACTIVE_SCANNER_AUDITS MCP-started Scanner audits may be active or awaiting confirmed cleanup",
                )
            }
            prepared.forEachIndexed { index, target ->
                callContext.ensureActive()
                val stillInScope = try {
                    api.scope().isInScope(target.message.request.url())
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    return@withLock scannerAuditError(
                        ScannerAuditToolStatus.BURP_ERROR,
                        ScannerAuditActionState.NOT_STARTED,
                        input.projectId,
                        input.mode,
                        "Burp could not recheck Scanner target scope: ${safeScannerAuditException(e)}",
                        index,
                    )
                }
                val projectAfterScopeRecheck = try {
                    captureProject()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    return@withLock scannerAuditError(
                        ScannerAuditToolStatus.BURP_ERROR,
                        ScannerAuditActionState.NOT_STARTED,
                        input.projectId,
                        input.mode,
                        "Burp could not recheck the project after final Scanner scope inspection: ${safeScannerAuditException(e)}",
                        index,
                    )
                }
                boundaryBeforeStart = projectAfterScopeRecheck
                if (projectAfterScopeRecheck.projectId != input.projectId) {
                    return@withLock scannerAuditError(
                        ScannerAuditToolStatus.PROJECT_MISMATCH,
                        ScannerAuditActionState.NOT_STARTED,
                        projectAfterScopeRecheck.projectId,
                        input.mode,
                        "Burp project changed during final Scanner scope inspection",
                        index,
                    )
                }
                if (!stillInScope) {
                    return@withLock scannerAuditError(
                        ScannerAuditToolStatus.OUT_OF_SCOPE,
                        ScannerAuditActionState.NOT_STARTED,
                        input.projectId,
                        input.mode,
                        "audit target left Burp Target scope before the Scanner audit started",
                        index,
                    )
                }
            }

            val taskId = nextTaskId()
            val configuration = try {
                AuditConfiguration.auditConfiguration(input.mode.builtInConfiguration())
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return@withLock scannerAuditError(
                    ScannerAuditToolStatus.BURP_ERROR,
                    ScannerAuditActionState.NOT_STARTED,
                    input.projectId,
                    input.mode,
                    "Burp could not prepare the Scanner audit configuration: ${safeScannerAuditException(e)}",
                )
            }
            callContext.ensureActive()
            val audit: Audit = try {
                api.scanner().startAudit(configuration)
            } catch (e: CancellationException) {
                if (!callContext.isActive) {
                    auditScanner(input.mode, prepared.size, null, "start cancelled by caller")
                    throw e
                }
                auditScanner(input.mode, prepared.size, null, "start cancellation uncertain")
                return@withLock uncertainStartWithoutHandleResult(
                    projectId = input.projectId,
                    mode = input.mode,
                    callContext = callContext,
                    error = uncertainExecutionError(
                        "Burp may have started the Scanner audit but did not return a task handle",
                        e,
                        preserveCancellation = false,
                    ),
                )
            } catch (e: Exception) {
                auditScanner(input.mode, prepared.size, null, "start execution uncertain")
                return@withLock uncertainStartWithoutHandleResult(
                    projectId = input.projectId,
                    mode = input.mode,
                    callContext = callContext,
                    error = uncertainExecutionError(
                        "Burp may have started the Scanner audit but did not return a task handle",
                        e,
                    ),
                )
            }

            val startedTick = ticker()
            val record = ScannerAuditRecord(
                taskId = taskId,
                projectId = input.projectId,
                mode = input.mode,
                audit = audit,
                targets = targetSummaries,
                startedAt = clock(),
                startedTick = startedTick,
                boundaryGeneration = boundaryBeforeStart.boundaryGeneration,
            )
            val attachment = attachRecordAtBoundary(record)
            if (!attachment.retained) {
                return@withLock startedRecordBoundaryFailure(
                    record,
                    attachment.currentProjectId,
                    "Scanner audit started after its authenticated project boundary was superseded",
                )
            }

            try {
                prepared.forEach { target ->
                    callContext.ensureActive()
                    when (input.mode) {
                        ScannerAuditMode.PASSIVE -> audit.addRequestResponse(requireNotNull(target.requestResponse))
                        ScannerAuditMode.ACTIVE -> audit.addRequest(
                            target.message.request,
                            requireNotNull(target.insertionPoints).ranges,
                        )
                    }
                }
                record.updateState(ScannerAuditTaskState.RUNNING, ticker())
            } catch (e: CancellationException) {
                record.updateState(ScannerAuditTaskState.UNKNOWN, ticker())
                if (!callContext.isActive) {
                    auditScanner(input.mode, prepared.size, taskId, "target submission cancelled by caller")
                    val deleted = cleanupOwnedAuditOnce(record)
                    if (deleted) detachRecord(record)
                    throw e
                }
                auditScanner(input.mode, prepared.size, taskId, "target submission cancellation uncertain")
                return@withLock uncertainStartedRecordResult(
                    record = record,
                    callContext = callContext,
                    error = uncertainExecutionError(
                        "Scanner audit started, but one or more targets may not have been submitted",
                        e,
                        preserveCancellation = false,
                    ),
                    projectFailureSummary =
                        "Scanner audit target submission became uncertain and the project boundary could not be rechecked",
                    projectTransitionSummary =
                        "Scanner audit target submission became uncertain while the Burp project changed",
                )
            } catch (e: Exception) {
                record.updateState(ScannerAuditTaskState.UNKNOWN, ticker())
                auditScanner(input.mode, prepared.size, taskId, "target submission uncertain")
                return@withLock uncertainStartedRecordResult(
                    record = record,
                    callContext = callContext,
                    error = uncertainExecutionError(
                        "Scanner audit started, but one or more targets may not have been submitted",
                        e,
                    ),
                    projectFailureSummary =
                        "Scanner audit target submission became uncertain and the project boundary could not be rechecked",
                    projectTransitionSummary =
                        "Scanner audit target submission became uncertain while the Burp project changed",
                )
            }

            val projectAfterStart = try {
                captureProject()
            } catch (e: CancellationException) {
                record.updateState(ScannerAuditTaskState.UNKNOWN, ticker())
                if (!callContext.isActive) {
                    auditScanner(input.mode, prepared.size, taskId, "post-start project check cancelled by caller")
                    val deleted = cleanupOwnedAuditOnce(record)
                    if (deleted) detachRecord(record)
                    throw e
                }
                auditScanner(input.mode, prepared.size, taskId, "post-start project check uncertain")
                return@withLock startedRecordBoundaryFailure(
                    record,
                    null,
                    "Scanner audit started, but the project boundary could not be rechecked",
                    uncertainExecutionError(
                        "Scanner audit started, but its returned task handle could not be safely retained",
                        e,
                        preserveCancellation = false,
                    ),
                )
            } catch (e: Exception) {
                record.updateState(ScannerAuditTaskState.UNKNOWN, ticker())
                auditScanner(input.mode, prepared.size, taskId, "post-start project check uncertain")
                return@withLock startedRecordBoundaryFailure(
                    record,
                    null,
                    "Scanner audit started, but the project boundary could not be rechecked",
                    uncertainExecutionError(
                        "Scanner audit started, but its returned task handle could not be safely retained",
                        e,
                        preserveCancellation = false,
                    ),
                )
            }
            if (projectAfterStart.projectId != input.projectId) {
                record.updateState(ScannerAuditTaskState.UNKNOWN, ticker())
                auditScanner(input.mode, prepared.size, taskId, "project changed during start")
                return@withLock cancellationProjectTransition(
                    record,
                    projectAfterStart.projectId,
                    "Scanner audit started while the Burp project changed",
                )
            }
            val publication = publishRecordAtBoundary(record)
            if (!publication.retained) {
                return@withLock startedRecordBoundaryFailure(
                    record,
                    publication.currentProjectId,
                    "Scanner audit completed target submission after its authenticated project boundary was superseded",
                )
            }
            auditScanner(input.mode, prepared.size, taskId, "started")
            retainedRecordResult(record, "Scanner audit task was detached before its start result was published") {
                record.toResult(
                    status = ScannerAuditToolStatus.OK,
                    actionState = ScannerAuditActionState.COMPLETED,
                )
            }
        }
    }

    suspend fun get(input: GetScannerAudit, config: McpConfig): ScannerAuditResult {
        val validation = validateTaskInput(input.projectId, input.taskId)
        if (validation != null) return validation
        val issueLimit = input.issueLimit ?: DEFAULT_SCANNER_TASK_ISSUE_LIMIT
        if (issueLimit !in 0..MAX_SCANNER_TASK_ISSUE_LIMIT) {
            return scannerAuditError(
                ScannerAuditToolStatus.INVALID_ARGUMENT,
                ScannerAuditActionState.NOT_STARTED,
                input.projectId,
                error = "issueLimit must be between 0 and $MAX_SCANNER_TASK_ISSUE_LIMIT",
            )
        }
        val record = claimRecord(input.taskId) ?: return scannerAuditError(
            ScannerAuditToolStatus.NOT_FOUND,
            ScannerAuditActionState.NOT_STARTED,
            input.projectId,
            error = "Scanner audit task was not found; only current retained tasks started by this extension instance are available",
        )
        if (record.projectId != input.projectId) {
            return scannerAuditError(
                ScannerAuditToolStatus.PROJECT_MISMATCH,
                ScannerAuditActionState.NOT_STARTED,
                input.projectId,
                error = "Scanner audit task belongs to a different Burp project",
            )
        }
        val initialBoundary = currentRecordBoundary(record)
        if (!initialBoundary.retained) {
            return retainedRecordBoundaryFailure(
                record,
                initialBoundary.currentProjectId,
                "Scanner audit task was detached at a concurrent project boundary",
            )
        }

        val statusObservationSequence = record.nextStatusObservationSequence()
        val stateBeforeProbe = record.lastState
        if (stateBeforeProbe == ScannerAuditTaskState.CANCELLED) {
            return retainedRecordResult(record, "Scanner audit task was detached before its status result was published") {
                record.toResult(
                    ScannerAuditToolStatus.OK,
                    ScannerAuditActionState.COMPLETED,
                    issuesRequested = issueLimit > 0,
                    issuesUnavailable = issueLimit > 0,
                )
            }
        }
        val errors = ArrayList<String>(4)
        val statusMessage = runCatchingPreservingCancellation {
            record.audit.statusMessage().take(MAX_SCANNER_STATUS_MESSAGE_CHARS)
        }
            .onFailure { errors += "status unavailable: ${safeScannerAuditException(it.asException())}" }
            .getOrNull()
        val auditedInsertionPointCount = runCatchingPreservingCancellation { record.audit.insertionPointCount() }
            .onFailure { errors += "insertion-point count unavailable: ${safeScannerAuditException(it.asException())}" }
            .getOrNull()
        val requestCount = runCatchingPreservingCancellation { record.audit.requestCount() }
            .onFailure { errors += "request count unavailable: ${safeScannerAuditException(it.asException())}" }
            .getOrNull()
        val errorCount = runCatchingPreservingCancellation { record.audit.errorCount() }
            .onFailure { errors += "error count unavailable: ${safeScannerAuditException(it.asException())}" }
            .getOrNull()
        val observedState = classifyTaskState(statusMessage, stateBeforeProbe)
        val observation = record.updateObservation(
            sequence = statusObservationSequence,
            state = observedState,
            now = ticker(),
            statusMessage = statusMessage,
            auditedInsertionPointCount = auditedInsertionPointCount,
            requestCount = requestCount,
            errorCount = errorCount,
        )
        if (observation.cleanupReservationReleased) cleanupReservations.decrementAndGet()
        val effectiveState = observation.state

        var issuePermissionDenied = false
        var issueAccessUnavailable = issueLimit > 0 && effectiveState == ScannerAuditTaskState.CANCELLED
        var issuesAllowed = if (issueLimit == 0 || effectiveState == ScannerAuditTaskState.CANCELLED) {
            false
        } else try {
            DataAccessSecurity.checkDataAccessPermission(DataAccessType.SCANNER_ISSUES, config).also { allowed ->
                issuePermissionDenied = !allowed
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            errors += "issue access check failed: ${safeScannerAuditException(e)}"
            issueAccessUnavailable = true
            false
        }
        val projectBeforeIssues = try {
            captureProjectId()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            errors += "project recheck failed: ${safeScannerAuditException(e)}"
            null
        }
        if (projectBeforeIssues == null) {
            if (issueLimit > 0) issueAccessUnavailable = true
            issuesAllowed = false
        } else if (projectBeforeIssues != record.projectId) {
            return cancellationProjectTransition(
                record,
                projectBeforeIssues,
                "Scanner audit cleanup may have been scheduled while the project changed during a status read",
            )
        }
        val preIssueBoundary = currentRecordBoundary(record)
        if (!preIssueBoundary.retained) {
            return retainedRecordBoundaryFailure(
                record,
                preIssueBoundary.currentProjectId,
                "Scanner audit task was detached at a concurrent project boundary during a status read",
            )
        }

        var issueCount: Int? = null
        var issues = emptyList<ScannerIssueSummary>()
        var truncated = false
        var issueWarning: String? = null
        var acceptedIssueObservationSequence: Long? = null
        var issueObservationSuperseded = false
        if (issuesAllowed) {
            try {
                val allIssues = record.audit.issues()
                issueCount = allIssues.size
                issues = buildList(minOf(issueLimit, allIssues.size)) {
                    allIssues.take(issueLimit).forEachIndexed { index, issue ->
                        if (index and 15 == 0) currentCoroutineContext().ensureActive()
                        add(issue.toHistorySummary())
                    }
                }
                truncated = allIssues.size > issues.size
                val issueObservation = record.updateIssueCount(statusObservationSequence, issueCount)
                issueCount = issueObservation.count
                if (issueObservation.accepted) {
                    acceptedIssueObservationSequence = statusObservationSequence
                } else {
                    issueObservationSuperseded = true
                    issues = emptyList()
                    truncated = false
                    issueWarning = "issues unavailable: superseded by a newer Scanner status observation"
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: UnsupportedOperationException) {
                issueWarning = "issues unavailable: unsupported by this Burp runtime"
            } catch (e: Exception) {
                issueWarning = "issues unavailable: ${safeScannerAuditException(e)}"
            }
        }

        val projectAfterIssues = try {
            captureProjectId()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return record.toScrubbedResult(
                ScannerAuditToolStatus.BURP_ERROR,
                ScannerAuditActionState.NOT_STARTED,
                null,
                "Burp could not recheck the project after reading Scanner audit issues: ${safeScannerAuditException(e)}",
            )
        }
        if (projectAfterIssues != record.projectId) {
            return cancellationProjectTransition(
                record,
                projectAfterIssues,
                "Scanner audit cleanup may have been scheduled while the project changed during issue materialization",
            )
        }
        val finalBoundary = currentRecordBoundary(record)
        if (!finalBoundary.retained) {
            return retainedRecordBoundaryFailure(
                record,
                finalBoundary.currentProjectId,
                "Scanner audit task was detached at a concurrent project boundary during issue materialization",
            )
        }

        return retainedRecordResult(record, "Scanner audit task was detached before its status result was published") {
            val issueObservationCurrent = !issueObservationSuperseded &&
                acceptedIssueObservationSequence?.let(record::isCurrentIssueObservation) != false
            val publishedIssueWarning = if (issueObservationCurrent) {
                issueWarning
            } else {
                "issues unavailable: superseded by a newer Scanner status observation"
            }
            record.toResult(
                status = if (errors.isEmpty()) ScannerAuditToolStatus.OK else ScannerAuditToolStatus.BURP_ERROR,
                actionState = ScannerAuditActionState.COMPLETED,
                issues = issues.takeIf { issueObservationCurrent } ?: emptyList(),
                discoveredIssueCount = issueCount.takeIf { issueObservationCurrent } ?: record.lastIssueCount,
                issuesTruncated = truncated && issueObservationCurrent,
                issuesAccessDenied = issuePermissionDenied,
                issuesUnavailable = issueAccessUnavailable || publishedIssueWarning != null,
                issuesRequested = issueLimit > 0,
                preserveFailureAfterCancellation = true,
                error = (errors + listOfNotNull(publishedIssueWarning)).takeIf { it.isNotEmpty() }
                    ?.joinToString("; ")?.take(MAX_STRUCTURED_TOOL_ERROR_CHARS),
            )
        }
    }

    suspend fun cancel(input: CancelScannerAudit, config: McpConfig): ScannerAuditResult {
        val validation = validateTaskInput(input.projectId, input.taskId)
        if (validation != null) return validation
        val record = claimRecord(input.taskId) ?: return scannerAuditError(
            ScannerAuditToolStatus.NOT_FOUND,
            ScannerAuditActionState.NOT_STARTED,
            input.projectId,
            error = "Scanner audit task was not found; only current retained tasks started by this extension instance are available",
        )
        if (record.projectId != input.projectId) {
            return scannerAuditError(
                ScannerAuditToolStatus.PROJECT_MISMATCH,
                ScannerAuditActionState.NOT_STARTED,
                input.projectId,
                error = "Scanner audit task belongs to a different Burp project",
            )
        }
        val initialBoundary = currentRecordBoundary(record)
        if (!initialBoundary.retained) {
            return retainedRecordBoundaryFailure(
                record,
                initialBoundary.currentProjectId,
                "Scanner audit task was detached at a concurrent project boundary before cancellation",
            )
        }
        if (record.lastState == ScannerAuditTaskState.CANCELLED) {
            return retainedRecordResult(record, "Scanner audit task was detached before its cancellation result was published") {
                record.toResult(ScannerAuditToolStatus.OK, ScannerAuditActionState.COMPLETED)
            }
        }

        val approved = try {
            SensitiveActionSecurity.checkPermission(
                action = "cancel an MCP-started Scanner audit",
                summary = "Project: ${record.projectId}\nTask: ${record.taskId}\nMode: ${record.mode.name.lowercase()}\n" +
                    "Targets: ${record.targets.size}",
                api = api,
                config = config,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            val projectAfterFailure = try {
                captureProjectId()
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                return record.toScrubbedResult(
                    ScannerAuditToolStatus.BURP_ERROR,
                    ScannerAuditActionState.NOT_STARTED,
                    null,
                    "Burp could not safely establish the project after Scanner cancellation approval failed",
                )
            }
            if (projectAfterFailure != record.projectId) {
                return cancellationProjectTransition(
                    record,
                    projectAfterFailure,
                    "Scanner audit cleanup may have been scheduled after cancellation approval failed during a project transition",
                )
            }
            val approvalFailureBoundary = currentRecordBoundary(record)
            if (!approvalFailureBoundary.retained) {
                return retainedRecordBoundaryFailure(
                    record,
                    approvalFailureBoundary.currentProjectId,
                    "Scanner audit task was detached after cancellation approval failed",
                )
            }
            return retainedRecordResult(record, "Scanner audit task was detached after cancellation approval failed") {
                record.toResult(
                    ScannerAuditToolStatus.BURP_ERROR,
                    ScannerAuditActionState.NOT_STARTED,
                    error = "Burp could not request Scanner cancellation approval",
                )
            }
        }
        val projectAfterApproval = try {
            captureProjectId()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return record.toScrubbedResult(
                ScannerAuditToolStatus.BURP_ERROR,
                ScannerAuditActionState.NOT_STARTED,
                null,
                "Burp could not safely recheck the project after Scanner cancellation approval",
            )
        }
        if (projectAfterApproval != record.projectId) {
            return cancellationProjectTransition(
                record,
                projectAfterApproval,
                "Scanner audit cleanup may have been scheduled while the project changed during cancellation approval",
            )
        }
        val postApprovalBoundary = currentRecordBoundary(record)
        if (!postApprovalBoundary.retained) {
            return retainedRecordBoundaryFailure(
                record,
                postApprovalBoundary.currentProjectId,
                "Scanner audit task was detached at a concurrent project boundary during cancellation approval",
            )
        }
        if (!approved) {
            auditScanner(record.mode, record.targets.size, record.taskId, "cancellation denied")
            return retainedRecordResult(record, "Scanner audit task was detached before cancellation denial was published") {
                record.toResult(
                    ScannerAuditToolStatus.ACTION_DENIED,
                    ScannerAuditActionState.NOT_STARTED,
                    error = "Scanner audit cancellation denied by Burp Suite",
                )
            }
        }

        val callContext = currentCoroutineContext()
        callContext.ensureActive()
        val currentProjectId = try {
            captureProjectId()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return record.toScrubbedResult(
                ScannerAuditToolStatus.BURP_ERROR,
                ScannerAuditActionState.NOT_STARTED,
                null,
                "Burp could not safely recheck the project before Scanner cancellation",
            )
        }
        if (currentProjectId != record.projectId) {
            return cancellationProjectTransition(
                record,
                currentProjectId,
                "Scanner audit cleanup may have been scheduled while the project changed before cancellation",
            )
        }
        val preDeleteBoundary = currentRecordBoundary(record)
        if (!preDeleteBoundary.retained) {
            return retainedRecordBoundaryFailure(
                record,
                preDeleteBoundary.currentProjectId,
                "Scanner audit task was detached at a concurrent project boundary before cancellation",
            )
        }
        callContext.ensureActive()
        if (!record.claimCleanup()) {
            record.updateState(ScannerAuditTaskState.UNKNOWN, ticker())
            return retainedRecordResult(record, "Scanner audit task was detached while cleanup was already in progress") {
                record.toResult(
                    ScannerAuditToolStatus.EXECUTION_UNCERTAIN,
                    ScannerAuditActionState.UNCERTAIN,
                    error = uncertainExecutionError("Scanner audit cleanup was already attempted"),
                )
            }
        }
        return try {
            val reservationReleased = record.deleteAndMarkCancelled(ticker(), clock())
            if (reservationReleased) cleanupReservations.decrementAndGet()
            val projectAfterDelete = try {
                captureProjectId()
            } catch (e: CancellationException) {
                if (!callContext.isActive) throw e
                record.updateState(ScannerAuditTaskState.UNKNOWN, ticker())
                val uncertainty = uncertainExecutionError(
                    "Scanner audit may have been cancelled but the project boundary could not be rechecked",
                    e,
                    preserveCancellation = false,
                )
                record.retainActionUncertainty(uncertainty)
                auditScanner(record.mode, record.targets.size, record.taskId, "post-cancellation project check failed")
                return record.toScrubbedResult(
                    ScannerAuditToolStatus.BURP_ERROR,
                    ScannerAuditActionState.COMPLETED,
                    null,
                    uncertainty,
                )
            } catch (e: Exception) {
                record.updateState(ScannerAuditTaskState.UNKNOWN, ticker())
                val uncertainty = uncertainExecutionError(
                    "Scanner audit may have been cancelled but the project boundary could not be rechecked",
                    e,
                    preserveCancellation = false,
                )
                record.retainActionUncertainty(uncertainty)
                auditScanner(record.mode, record.targets.size, record.taskId, "post-cancellation project check failed")
                return record.toScrubbedResult(
                    ScannerAuditToolStatus.BURP_ERROR,
                    ScannerAuditActionState.COMPLETED,
                    null,
                    uncertainty,
                )
            }
            if (projectAfterDelete != record.projectId) {
                record.updateState(ScannerAuditTaskState.UNKNOWN, ticker())
                auditScanner(record.mode, record.targets.size, record.taskId, "project changed during cancellation")
                return cancellationProjectTransition(
                    record,
                    projectAfterDelete,
                    "Scanner audit may have been cancelled while the Burp project changed",
                )
            }
            val postDeleteBoundary = currentRecordBoundary(record)
            if (!postDeleteBoundary.retained) {
                return retainedRecordBoundaryFailure(
                    record,
                    postDeleteBoundary.currentProjectId,
                    "Scanner audit may have been cancelled while a concurrent project boundary detached its task",
                )
            }
            auditScanner(record.mode, record.targets.size, record.taskId, "cancelled")
            retainedRecordResult(record, "Scanner audit task was detached before cancellation was published") {
                record.toResult(ScannerAuditToolStatus.OK, ScannerAuditActionState.COMPLETED)
            }
        } catch (e: CancellationException) {
            val uncertainty = uncertainExecutionError(
                "Scanner audit may have been cancelled",
                e,
                preserveCancellation = false,
            )
            record.updateState(ScannerAuditTaskState.UNKNOWN, ticker())
            if (!callContext.isActive) {
                record.retainActionUncertainty(uncertainty)
                auditScanner(record.mode, record.targets.size, record.taskId, "cancellation interrupted by caller")
                throw e
            }
            auditScanner(record.mode, record.targets.size, record.taskId, "cancellation interrupted with uncertain outcome")
            uncertainCancellationRecordResult(record, callContext, uncertainty)
        } catch (e: Exception) {
            record.updateState(ScannerAuditTaskState.UNKNOWN, ticker())
            auditScanner(record.mode, record.targets.size, record.taskId, "cancellation uncertain")
            uncertainCancellationRecordResult(
                record,
                callContext,
                uncertainExecutionError("Scanner audit may have been cancelled", e),
            )
        }
    }

    private fun uncertainStartWithoutHandleResult(
        projectId: String,
        mode: ScannerAuditMode,
        callContext: kotlin.coroutines.CoroutineContext,
        error: String,
    ): ScannerAuditResult {
        val currentProjectId = try {
            captureProjectId()
        } catch (e: CancellationException) {
            if (!callContext.isActive) throw e
            return scannerAuditError(
                status = ScannerAuditToolStatus.EXECUTION_UNCERTAIN,
                actionState = ScannerAuditActionState.UNCERTAIN,
                projectId = null,
                error = "$error; Burp could not safely recheck the project after the uncertain Scanner start"
                    .take(MAX_STRUCTURED_TOOL_ERROR_CHARS),
            )
        } catch (_: Exception) {
            return scannerAuditError(
                status = ScannerAuditToolStatus.EXECUTION_UNCERTAIN,
                actionState = ScannerAuditActionState.UNCERTAIN,
                projectId = null,
                error = "$error; Burp could not safely recheck the project after the uncertain Scanner start"
                    .take(MAX_STRUCTURED_TOOL_ERROR_CHARS),
            )
        }
        if (currentProjectId != projectId) {
            return scannerAuditError(
                status = ScannerAuditToolStatus.PROJECT_MISMATCH,
                actionState = ScannerAuditActionState.UNCERTAIN,
                projectId = currentProjectId,
                error = "$error; the Burp project changed before the uncertain Scanner start could be reconciled"
                    .take(MAX_STRUCTURED_TOOL_ERROR_CHARS),
            )
        }
        callContext.ensureActive()
        return scannerAuditError(
            status = ScannerAuditToolStatus.EXECUTION_UNCERTAIN,
            actionState = ScannerAuditActionState.UNCERTAIN,
            projectId = projectId,
            mode = mode,
            error = error,
        )
    }

    private fun cancellationProjectTransition(
        record: ScannerAuditRecord,
        currentProjectId: String,
        summary: String,
    ): ScannerAuditResult {
        val error = uncertainExecutionError(summary)
        record.retainActionUncertainty(error)
        return record.toScrubbedResult(
            ScannerAuditToolStatus.PROJECT_MISMATCH,
            ScannerAuditActionState.UNCERTAIN,
            currentProjectId,
            error,
        )
    }

    private fun retainedRecordBoundaryFailure(
        record: ScannerAuditRecord,
        currentProjectId: String?,
        summary: String,
    ): ScannerAuditResult {
        val error = uncertainExecutionError(summary)
        record.retainActionUncertainty(error)
        return record.toScrubbedResult(
            ScannerAuditToolStatus.PROJECT_MISMATCH,
            ScannerAuditActionState.UNCERTAIN,
            currentProjectId,
            error,
        )
    }

    private fun startedRecordBoundaryFailure(
        record: ScannerAuditRecord,
        currentProjectId: String?,
        summary: String,
        priorError: String? = null,
    ): ScannerAuditResult {
        record.updateState(ScannerAuditTaskState.UNKNOWN, ticker())
        detachRecord(record)
        val reserved = reserveCleanupSlot(record)
        enqueueCleanup(record, "superseded project boundary", reserved)
        val boundaryError = uncertainExecutionError(summary)
        val error = if (priorError == null) {
            boundaryError
        } else {
            "$priorError; $boundaryError".take(MAX_STRUCTURED_TOOL_ERROR_CHARS)
        }
        record.retainActionUncertainty(error)
        auditScanner(record.mode, record.targets.size, record.taskId, "project boundary superseded")
        return record.toScrubbedResult(
            status = if (currentProjectId != null && currentProjectId != record.projectId) {
                ScannerAuditToolStatus.PROJECT_MISMATCH
            } else {
                ScannerAuditToolStatus.EXECUTION_UNCERTAIN
            },
            actionState = ScannerAuditActionState.UNCERTAIN,
            projectId = currentProjectId,
            error = error,
        )
    }

    private fun uncertainStartedRecordResult(
        record: ScannerAuditRecord,
        callContext: kotlin.coroutines.CoroutineContext,
        error: String,
        projectFailureSummary: String,
        projectTransitionSummary: String,
    ): ScannerAuditResult {
        record.retainActionUncertainty(error)
        val currentProject = try {
            captureProject()
        } catch (e: CancellationException) {
            if (!callContext.isActive) {
                val deleted = cleanupOwnedAuditOnce(record)
                if (deleted) detachRecord(record)
                throw e
            }
            return startedRecordBoundaryFailure(
                record,
                null,
                projectFailureSummary,
                "$error; ${safeScannerAuditException(e)}".take(MAX_STRUCTURED_TOOL_ERROR_CHARS),
            )
        } catch (e: Exception) {
            return startedRecordBoundaryFailure(
                record,
                null,
                projectFailureSummary,
                "$error; ${safeScannerAuditException(e)}".take(MAX_STRUCTURED_TOOL_ERROR_CHARS),
            )
        }
        if (currentProject.projectId != record.projectId) {
            return cancellationProjectTransition(record, currentProject.projectId, projectTransitionSummary)
        }
        if (!callContext.isActive) {
            val deleted = cleanupOwnedAuditOnce(record)
            if (deleted) detachRecord(record)
            callContext.ensureActive()
        }
        val publication = publishRecordAtBoundary(record)
        if (!publication.retained) {
            return startedRecordBoundaryFailure(record, publication.currentProjectId, projectTransitionSummary)
        }
        return retainedRecordResult(record, "Scanner audit task was detached before its uncertain start result was published") {
            record.toResult(
                ScannerAuditToolStatus.EXECUTION_UNCERTAIN,
                ScannerAuditActionState.UNCERTAIN,
                error = error,
            )
        }
    }

    private fun uncertainCancellationRecordResult(
        record: ScannerAuditRecord,
        callContext: kotlin.coroutines.CoroutineContext,
        error: String,
    ): ScannerAuditResult {
        record.retainActionUncertainty(error)
        val currentProjectId = try {
            captureProjectId()
        } catch (e: CancellationException) {
            if (!callContext.isActive) throw e
            val projectError = uncertainExecutionError(
                "Scanner audit cleanup became uncertain and the project boundary could not be rechecked",
                e,
                preserveCancellation = false,
            )
            return record.toScrubbedResult(
                ScannerAuditToolStatus.EXECUTION_UNCERTAIN,
                ScannerAuditActionState.UNCERTAIN,
                null,
                projectError,
            )
        } catch (e: Exception) {
            val projectError = uncertainExecutionError(
                "Scanner audit cleanup became uncertain and the project boundary could not be rechecked",
                e,
                preserveCancellation = false,
            )
            return record.toScrubbedResult(
                ScannerAuditToolStatus.EXECUTION_UNCERTAIN,
                ScannerAuditActionState.UNCERTAIN,
                null,
                projectError,
            )
        }
        if (currentProjectId != record.projectId) {
            return cancellationProjectTransition(
                record,
                currentProjectId,
                "Scanner audit cleanup became uncertain while the Burp project changed",
            )
        }
        val boundary = currentRecordBoundary(record)
        if (!boundary.retained) {
            return retainedRecordBoundaryFailure(
                record,
                boundary.currentProjectId,
                "Scanner audit cleanup became uncertain while a concurrent project boundary detached its task",
            )
        }
        return retainedRecordResult(record, "Scanner audit task was detached before its uncertain cancellation result was published") {
            record.toResult(
                ScannerAuditToolStatus.EXECUTION_UNCERTAIN,
                ScannerAuditActionState.UNCERTAIN,
                error = error,
            )
        }
    }

    private fun validateTaskInput(projectId: String, taskId: String): ScannerAuditResult? {
        if (!validProjectId(projectId)) {
            return scannerAuditError(
                ScannerAuditToolStatus.INVALID_ARGUMENT,
                ScannerAuditActionState.NOT_STARTED,
                null,
                error = "projectId is empty, too long, or contains control characters",
            )
        }
        if (taskId.length !in 1..MAX_SCANNER_TASK_ID_CHARS || !taskId.matches(SCANNER_TASK_ID_PATTERN)) {
            return scannerAuditError(
                ScannerAuditToolStatus.INVALID_ID,
                ScannerAuditActionState.NOT_STARTED,
                null,
                error = "taskId must be copied from start_scanner_audit_from_ids",
            )
        }
        val matchingRecord = records[taskId]?.takeIf { it.projectId == projectId }
        val taskMayRequireBoundaryCleanup = matchingRecord?.lastState?.isTerminal() == false
        val currentProjectId = try {
            captureProjectId()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = if (e is StaleScannerProjectObservationException) {
                "Burp project observation was superseded by a newer concurrent boundary check"
            } else {
                "Burp could not read the current project"
            }
            return matchingRecord?.toScrubbedResult(
                ScannerAuditToolStatus.BURP_ERROR,
                ScannerAuditActionState.NOT_STARTED,
                null,
                error,
            ) ?: scannerAuditError(
                ScannerAuditToolStatus.BURP_ERROR,
                ScannerAuditActionState.NOT_STARTED,
                null,
                error = error,
            )
        }
        if (currentProjectId != projectId) {
            val error = if (taskMayRequireBoundaryCleanup) {
                uncertainExecutionError(
                    "Scanner audit cleanup may have been scheduled when the current project changed",
                )
            } else {
                "Scanner audit task belongs to a different Burp project"
            }
            if (taskMayRequireBoundaryCleanup) matchingRecord?.retainActionUncertainty(error)
            return matchingRecord?.toScrubbedResult(
                ScannerAuditToolStatus.PROJECT_MISMATCH,
                if (taskMayRequireBoundaryCleanup) ScannerAuditActionState.UNCERTAIN else ScannerAuditActionState.NOT_STARTED,
                currentProjectId,
                error,
            ) ?: scannerAuditError(
                ScannerAuditToolStatus.PROJECT_MISMATCH,
                ScannerAuditActionState.NOT_STARTED,
                currentProjectId,
                error = error,
            )
        }
        return null
    }

    private fun captureProjectId(): String = captureProject().projectId

    private fun captureProject(): ScannerProjectSnapshot {
        val sequence = projectObservationSequence.incrementAndGet()
        val projectId = try {
            api.project().id()
        } catch (e: CancellationException) {
            supersedeFailedProjectObservation(sequence)
            throw e
        } catch (e: Exception) {
            supersedeFailedProjectObservation(sequence)
            throw e
        }
        return observeProject(ScannerProjectObservation(sequence, projectId))
            ?: throw StaleScannerProjectObservationException()
    }

    /**
     * Advances the ordering watermark and invalidates in-flight attachment tokens. A failed accessor establishes no
     * project identity, but an older read or start must not become authoritative after the newer failure returned.
     * Existing retained records stay inaccessible to that failed request and can be reconciled by a later safe capture.
     */
    private fun supersedeFailedProjectObservation(sequence: Long) {
        synchronized(projectObservationLock) {
            if (sequence > latestProjectObservationSequence) {
                latestProjectObservationSequence = sequence
                projectBoundaryGeneration++
            }
        }
    }

    private fun observeProject(observation: ScannerProjectObservation): ScannerProjectSnapshot? {
        var detached = emptyList<Pair<ScannerAuditRecord, Boolean>>()
        val snapshot = synchronized(projectObservationLock) {
            if (observation.sequence <= latestProjectObservationSequence) return@synchronized null
            latestProjectObservationSequence = observation.sequence
            val previousProjectId = observedProject?.projectId
            val currentProjectId = requireNotNull(observation.projectId)
            if (previousProjectId != null && previousProjectId != currentProjectId) {
                projectBoundaryGeneration++
                detached = detachRecordsAtBoundary { it.projectId != currentProjectId }
            }
            observedProject = observation
            ScannerProjectSnapshot(currentProjectId, projectBoundaryGeneration)
        }
        detached.forEach { (record, provisional) ->
            enqueueBoundaryCleanup(record, "project transition", provisional)
        }
        return snapshot
    }

    private fun attachRecordAtBoundary(record: ScannerAuditRecord): ScannerRecordBoundaryResult =
        synchronized(projectObservationLock) {
            val currentProjectId = observedProject?.projectId
            val retained = currentProjectId == record.projectId &&
                projectBoundaryGeneration == record.boundaryGeneration
            if (retained) {
                records[record.taskId] = record
                record.markAttached()
            }
            ScannerRecordBoundaryResult(retained, currentProjectId)
        }

    private fun publishRecordAtBoundary(record: ScannerAuditRecord): ScannerRecordBoundaryResult {
        val boundary = synchronized(projectObservationLock) {
            val currentProjectId = observedProject?.projectId
            ScannerRecordBoundaryResult(
                retained = currentProjectId == record.projectId &&
                    projectBoundaryGeneration == record.boundaryGeneration &&
                    records[record.taskId] === record &&
                    record.isAttached(),
                currentProjectId = currentProjectId,
            )
        }
        if (boundary.retained) record.markPublished(ticker())
        return boundary
    }

    private fun currentRecordBoundary(record: ScannerAuditRecord): ScannerRecordBoundaryResult =
        synchronized(projectObservationLock) {
            val currentProjectId = observedProject?.projectId
            ScannerRecordBoundaryResult(
                retained = currentProjectId == record.projectId &&
                    records[record.taskId] === record &&
                    record.isAttached(),
                currentProjectId = currentProjectId,
            )
        }

    /**
     * Publishes only a record snapshot that remained current through the final boundary check.
     * A bounded retry canonicalizes cancellation or newer telemetry that committed while the
     * project identity was being checked, without nesting the project and record monitors.
     */
    private fun retainedRecordResult(
        record: ScannerAuditRecord,
        boundaryFailureSummary: String,
        result: () -> ScannerAuditResult,
    ): ScannerAuditResult {
        repeat(MAX_RETAINED_RESULT_SNAPSHOT_ATTEMPTS) {
            val snapshot = record.snapshotResult(result)
            val boundary = currentRecordBoundary(record)
            if (!boundary.retained) {
                return retainedRecordBoundaryFailure(record, boundary.currentProjectId, boundaryFailureSummary)
            }
            retainedResultPublicationHook?.invoke()
            if (record.resultVersionMatches(snapshot.version) && record.isAttached()) return snapshot.result
        }

        val boundary = currentRecordBoundary(record)
        if (!boundary.retained) {
            return retainedRecordBoundaryFailure(record, boundary.currentProjectId, boundaryFailureSummary)
        }
        val error = uncertainExecutionError(
            "Scanner audit state changed concurrently before result publication; reconcile task status before retrying",
        )
        record.retainActionUncertainty(error)
        return record.toScrubbedResult(
            ScannerAuditToolStatus.BURP_ERROR,
            ScannerAuditActionState.UNCERTAIN,
            boundary.currentProjectId,
            error,
        )
    }

    /** Detaches every retained task atomically with the authenticated project-boundary tombstone. */
    fun resetForProjectBoundary() {
        val detached = synchronized(projectObservationLock) {
            val sequence = projectObservationSequence.incrementAndGet()
            latestProjectObservationSequence = sequence
            projectBoundaryGeneration++
            observedProject = ScannerProjectObservation(sequence, null)
            detachRecordsAtBoundary { true }
        }
        detached.forEach { (record, provisional) ->
            enqueueBoundaryCleanup(record, "project transition", provisional)
        }
    }

    /** Invalidates result publication before removing the record; it never enters the record monitor. */
    private fun detachRecord(record: ScannerAuditRecord): Boolean {
        record.markDetached()
        return records.remove(record.taskId, record)
    }

    /** Called only while holding projectObservationLock; reserves capacity without entering the record monitor. */
    private fun detachRecordsAtBoundary(
        predicate: (ScannerAuditRecord) -> Boolean,
    ): List<Pair<ScannerAuditRecord, Boolean>> = buildList {
        records.values.forEach { record ->
            if (!predicate(record)) return@forEach
            val provisional = !record.lastState.isTerminal()
            if (provisional) cleanupReservations.incrementAndGet()
            if (!detachRecord(record)) {
                if (provisional) cleanupReservations.decrementAndGet()
                return@forEach
            }
            add(record to provisional)
        }
    }

    private fun enqueueBoundaryCleanup(record: ScannerAuditRecord, reason: String, provisional: Boolean) {
        if (!provisional) {
            enqueueCleanup(record, reason)
            return
        }
        if (!record.reserveCleanup()) {
            cleanupReservations.decrementAndGet()
            return
        }
        enqueueCleanup(record, reason, slotReserved = true)
    }

    private fun detachRecords(
        predicate: (ScannerAuditRecord) -> Boolean,
    ): List<Pair<ScannerAuditRecord, Boolean>> = buildList {
        records.values.forEach { record ->
            if (!predicate(record)) return@forEach
            val reserved = reserveCleanupSlot(record)
            if (detachRecord(record) || reserved) add(record to reserved)
        }
    }

    private fun claimRecord(taskId: String): ScannerAuditRecord? {
        val now = ticker()
        var expired: Triple<ScannerAuditRecord, ScannerRecordExpiration, Boolean>? = null
        val retained = records.computeIfPresent(taskId) { _, record ->
            val reason = record.expirationReason(now, retention)
            if (reason != null) {
                expired = Triple(record, reason, reserveCleanupSlot(record))
                record.markDetached()
                null
            } else {
                record.markObserved(now)
                record
            }
        }
        expired?.let { (record, reason, reserved) -> enqueueCleanup(record, reason.outcome, reserved) }
        return retained
    }

    internal fun cleanupExpired(): Int {
        val now = ticker()
        val expired = ArrayList<Triple<ScannerAuditRecord, ScannerRecordExpiration, Boolean>>()
        records.keys.toList().forEach { taskId ->
            records.computeIfPresent(taskId) { _, record ->
                val reason = record.expirationReason(now, retention)
                if (reason != null) {
                    expired += Triple(record, reason, reserveCleanupSlot(record))
                    record.markDetached()
                    null
                } else {
                    record
                }
            }
        }
        expired.forEach { (record, reason, reserved) -> enqueueCleanup(record, reason.outcome, reserved) }
        return expired.size
    }

    private fun refreshAndTrimRecords() {
        cleanupExpired()
        records.values.forEach { record ->
            if (!record.lastState.isTerminal()) {
                val sequence = record.nextStatusObservationSequence()
                val stateBeforeProbe = record.lastState
                val status = runCatchingPreservingCancellation {
                    record.audit.statusMessage().take(MAX_SCANNER_STATUS_MESSAGE_CHARS)
                }.getOrNull()
                if (status != null) {
                    val reservationReleased = record.updateStatusObservation(
                        sequence,
                        classifyTaskState(status, stateBeforeProbe),
                        ticker(),
                        status,
                    )
                    if (reservationReleased) cleanupReservations.decrementAndGet()
                }
            }
        }
        if (records.size < MAX_RETAINED_SCANNER_AUDITS) return
        val removable = records.values.filter { it.lastState.isTerminal() }.sortedBy { it.startedAt }
        val removeCount = (records.size - MAX_RETAINED_SCANNER_AUDITS + 1).coerceAtLeast(0)
        removable.take(removeCount).forEach(::detachRecord)
    }

    private fun reserveCleanupSlot(record: ScannerAuditRecord): Boolean {
        if (!record.reserveCleanup()) return false
        cleanupReservations.incrementAndGet()
        return true
    }

    private fun completeCleanup(record: ScannerAuditRecord) {
        if (record.completeCleanup()) cleanupReservations.decrementAndGet()
    }

    private fun releaseCleanupReservation(record: ScannerAuditRecord) {
        if (record.releaseCleanupReservation()) cleanupReservations.decrementAndGet()
    }

    private fun enqueueCleanup(record: ScannerAuditRecord, reason: String, slotReserved: Boolean = false) {
        if (record.lastState.isTerminal()) {
            if (slotReserved) releaseCleanupReservation(record)
            return
        }
        if (!slotReserved && !reserveCleanupSlot(record)) return
        val mode = record.mode
        val targetCount = record.targets.size
        val taskId = record.taskId
        if (!record.claimCleanup()) {
            auditScanner(mode, targetCount, taskId, "$reason cleanup already claimed")
            return
        }
        val audit = record.audit
        val cleanup = Runnable {
            val completed = try {
                audit.delete()
                true
            } catch (_: Exception) {
                false
            }
            if (completed) completeCleanup(record)
            val outcome = if (completed) "$reason cleanup completed" else "$reason cleanup unresolved"
            auditScanner(mode, targetCount, taskId, outcome)
        }
        val scheduled = synchronized(cleanupLifecycle) {
            val executor = cleanupExecutor
            if (executor == null || closed) {
                false
            } else {
                try {
                    executor.execute(cleanup)
                    true
                } catch (_: Exception) {
                    false
                }
            }
        }
        if (!scheduled) cleanup.run()
    }

    private fun cleanupOwnedAuditOnce(record: ScannerAuditRecord): Boolean {
        if (!record.claimCleanup()) return false
        return try {
            record.audit.delete()
            completeCleanup(record)
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun nextTaskId(): String {
        while (true) {
            val bytes = ByteArray(16).also(random::nextBytes)
            val id = "scanner_audit_${HexFormat.of().formatHex(bytes)}"
            if (!records.containsKey(id)) return id
        }
    }

    /** Cancels extension-owned work during extension unload and releases all retained handles. */
    fun close() {
        detachRecords { true }
            .forEach { (record, reserved) -> enqueueCleanup(record, "extension shutdown", reserved) }
        val executor = synchronized(cleanupLifecycle) {
            closed = true
            cleanupExecutor?.also { it.shutdown() }
        } ?: return
        try {
            if (!executor.awaitTermination(SCANNER_CLEANUP_SHUTDOWN_MILLIS, TimeUnit.MILLISECONDS)) {
                executor.shutdownNow()
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            executor.shutdownNow()
        }
    }

    private fun auditScanner(mode: ScannerAuditMode, targets: Int, taskId: String?, outcome: String) {
        runCatching {
            api.logging().logToOutput(
                "MCP Scanner action: mode=${mode.name.lowercase()} targets=$targets task=${taskId ?: "unavailable"} " +
                    "outcome=$outcome"
            )
        }
    }
}

private data class PreparedScannerAuditTarget(
    val message: ResolvedHttpMessage,
    val insertionPoints: PreparedInsertionPoints?,
    val requestResponse: HttpRequestResponse?,
) {
    fun summary() = ScannerAuditTargetSummary(
        ref = message.ref,
        method = message.request.method().take(32),
        url = message.request.url().take(MAX_HTTP_SEARCH_URL_CHARS),
        insertionPointCount = insertionPoints?.ranges?.size ?: 0,
    )
}

private data class ScannerReview(
    val content: String,
    val renderAsHttp: Boolean,
)

private fun buildScannerApprovalSummary(
    projectId: String,
    mode: ScannerAuditMode,
    targets: List<PreparedScannerAuditTarget>,
): String = buildString {
    appendLine("Project: $projectId")
    appendLine("Mode: ${mode.name.lowercase()}")
    appendLine("Targets: ${targets.size}")
    appendLine("Insertion points: ${targets.sumOf { it.insertionPoints?.ranges?.size ?: 0 }}")
    targets.forEachIndexed { index, target ->
        append(index + 1)
        append(". ")
        append(target.message.request.method().take(32))
        append(' ')
        appendLine(target.message.request.url().take(256))
        target.insertionPoints?.let {
            append("   ")
            appendLine(it.summary.take(256))
        }
    }
}.trimEnd().take(4_096)

private fun buildScannerReview(
    mode: ScannerAuditMode,
    targets: List<PreparedScannerAuditTarget>,
): ScannerReview {
    if (targets.size == 1) {
        return ScannerReview(targets.single().message.request.toString(), renderAsHttp = true)
    }
    return ScannerReview(
        content = buildString {
            targets.forEachIndexed { index, target ->
                append(index + 1)
                append(". ")
                append(target.message.request.method().take(32))
                append(' ')
                appendLine(target.message.request.url().take(MAX_HTTP_SEARCH_URL_CHARS))
                if (mode == ScannerAuditMode.ACTIVE) {
                    append("   ")
                    appendLine(requireNotNull(target.insertionPoints).summary)
                }
            }
        }.trimEnd(),
        renderAsHttp = false,
    )
}

private enum class ScannerRecordExpiration(val outcome: String) {
    UNPUBLISHED("unreturned task expired"),
    IDLE("idle task expired"),
    MAXIMUM_LIFETIME("maximum lifetime expired"),
    TERMINAL("terminal record expired"),
}

private class ScannerAuditRecord(
    val taskId: String,
    val projectId: String,
    val mode: ScannerAuditMode,
    val audit: Audit,
    val targets: List<ScannerAuditTargetSummary>,
    val startedAt: Instant,
    private val startedTick: Long,
    val boundaryGeneration: Long,
) {
    private var cleanupClaimed = false
    private var cleanupReserved = false
    private var cleanupCompleted = false
    private val attached = AtomicBoolean(false)
    @Volatile
    private var published = false
    @Volatile
    private var lastObservedTick = startedTick
    @Volatile
    private var terminalTick: Long? = null
    @Volatile
    var lastState: ScannerAuditTaskState = ScannerAuditTaskState.STARTING
    @Volatile
    var lastStatusMessage: String? = null
        private set
    @Volatile
    var lastAuditedInsertionPointCount: Int? = null
        private set
    @Volatile
    var lastRequestCount: Int? = null
        private set
    @Volatile
    var lastErrorCount: Int? = null
        private set
    @Volatile
    var lastIssueCount: Int? = null
        private set
    @Volatile
    var cancelledAt: Instant? = null
        private set
    @Volatile
    private var unresolvedActionError: String? = null
    private val statusObservationSequence = AtomicLong()
    private var lastAppliedStatusObservationSequence = 0L
    private var lastAppliedIssueObservationSequence = 0L
    private var resultVersion = 0L

    fun markAttached() {
        attached.set(true)
    }

    fun markDetached() {
        attached.set(false)
    }

    fun isAttached(): Boolean = attached.get()

    @Synchronized
    fun markPublished(now: Long) {
        if (now > lastObservedTick) lastObservedTick = now
        published = true
    }

    @Synchronized
    fun markObserved(now: Long) {
        if (now > lastObservedTick) lastObservedTick = now
    }

    fun nextStatusObservationSequence(): Long = statusObservationSequence.incrementAndGet()

    @Synchronized
    fun updateState(state: ScannerAuditTaskState, now: Long) {
        if (updateStateLocked(state, now)) {
            if (lastState == ScannerAuditTaskState.CANCELLED) clearCancelledTelemetryLocked()
            resultVersion++
        }
    }

    @Synchronized
    fun updateObservation(
        sequence: Long,
        state: ScannerAuditTaskState,
        now: Long,
        statusMessage: String?,
        auditedInsertionPointCount: Int?,
        requestCount: Int?,
        errorCount: Int?,
    ): ScannerStatusObservationUpdate {
        if (sequence <= lastAppliedStatusObservationSequence) {
            return ScannerStatusObservationUpdate(lastState, cleanupReservationReleased = false)
        }
        lastAppliedStatusObservationSequence = sequence
        if (!updateStateLocked(state, now)) {
            resultVersion++
            return ScannerStatusObservationUpdate(lastState, cleanupReservationReleased = false)
        }
        if (lastState == ScannerAuditTaskState.CANCELLED) {
            clearCancelledTelemetryLocked()
        } else {
            lastStatusMessage = statusMessage
            lastAuditedInsertionPointCount = auditedInsertionPointCount
            lastRequestCount = requestCount
            lastErrorCount = errorCount
        }
        resultVersion++
        return ScannerStatusObservationUpdate(lastState, releaseReservedTerminalCleanupLocked())
    }

    @Synchronized
    fun updateStatusObservation(
        sequence: Long,
        state: ScannerAuditTaskState,
        now: Long,
        statusMessage: String,
    ): Boolean {
        if (sequence <= lastAppliedStatusObservationSequence) return false
        lastAppliedStatusObservationSequence = sequence
        if (!updateStateLocked(state, now)) {
            resultVersion++
            return false
        }
        if (lastState == ScannerAuditTaskState.CANCELLED) {
            clearCancelledTelemetryLocked()
        } else {
            lastStatusMessage = statusMessage
        }
        resultVersion++
        return releaseReservedTerminalCleanupLocked()
    }

    @Synchronized
    fun updateIssueCount(sequence: Long, issueCount: Int): ScannerIssueObservationUpdate {
        if (
            lastState == ScannerAuditTaskState.CANCELLED ||
            sequence < lastAppliedStatusObservationSequence ||
            sequence <= lastAppliedIssueObservationSequence
        ) {
            return ScannerIssueObservationUpdate(accepted = false, count = lastIssueCount)
        }
        lastAppliedIssueObservationSequence = sequence
        lastIssueCount = issueCount
        resultVersion++
        return ScannerIssueObservationUpdate(accepted = true, count = lastIssueCount)
    }

    @Synchronized
    fun markCancelled(now: Long, at: Instant) {
        markCancelledLocked(now, at)
    }

    /** Holds the record monitor across Burp delete success and authoritative cancellation publication. */
    @Synchronized
    fun deleteAndMarkCancelled(now: Long, at: Instant): Boolean {
        audit.delete()
        val reservationReleased = completeCleanupLocked()
        markCancelledLocked(now, at)
        return reservationReleased
    }

    private fun markCancelledLocked(now: Long, at: Instant) {
        updateStateLocked(ScannerAuditTaskState.CANCELLED, now)
        cancelledAt = at
        clearCancelledTelemetryLocked()
        resultVersion++
    }

    private fun clearCancelledTelemetryLocked() {
        lastStatusMessage = null
        lastAuditedInsertionPointCount = null
        lastRequestCount = null
        lastErrorCount = null
        lastIssueCount = null
    }

    private fun updateStateLocked(state: ScannerAuditTaskState, now: Long): Boolean {
        if (lastState == ScannerAuditTaskState.CANCELLED && state != ScannerAuditTaskState.CANCELLED) return false
        if (lastState.isTerminal() && !state.isTerminal()) return false
        lastState = state
        if (state.isTerminal()) {
            if (terminalTick == null) terminalTick = now
        } else {
            terminalTick = null
        }
        if (state == ScannerAuditTaskState.CANCELLED) unresolvedActionError = null
        return true
    }

    fun expirationReason(now: Long, policy: ScannerAuditRetentionPolicy): ScannerRecordExpiration? {
        if (lastState.isTerminal()) {
            val terminalSince = terminalTick ?: return null
            return ScannerRecordExpiration.TERMINAL.takeIf {
                retentionElapsed(now, terminalSince, policy.terminalRecordRetention)
            }
        }
        if (!published && retentionElapsed(now, startedTick, policy.unpublishedTaskRetention)) {
            return ScannerRecordExpiration.UNPUBLISHED
        }
        if (retentionElapsed(now, startedTick, policy.maximumTaskLifetime)) {
            return ScannerRecordExpiration.MAXIMUM_LIFETIME
        }
        if (published && retentionElapsed(now, lastObservedTick, policy.idleTaskRetention)) {
            return ScannerRecordExpiration.IDLE
        }
        return null
    }

    @Synchronized
    fun claimCleanup(): Boolean {
        if (cleanupClaimed || cleanupCompleted) return false
        cleanupClaimed = true
        return true
    }

    @Synchronized
    fun reserveCleanup(): Boolean {
        if (lastState.isTerminal() || cleanupCompleted || cleanupReserved) return false
        cleanupReserved = true
        return true
    }

    /** Returns true when the caller must release this record's global capacity reservation. */
    @Synchronized
    fun completeCleanup(): Boolean = completeCleanupLocked()

    private fun completeCleanupLocked(): Boolean {
        cleanupCompleted = true
        if (!cleanupReserved) return false
        cleanupReserved = false
        return true
    }

    /** A detached task that is now definitively terminal no longer consumes active cleanup capacity. */
    private fun releaseReservedTerminalCleanupLocked(): Boolean {
        if (!lastState.isTerminal() || !cleanupReserved) return false
        cleanupCompleted = true
        cleanupReserved = false
        return true
    }

    @Synchronized
    fun releaseCleanupReservation(): Boolean {
        if (!cleanupReserved) return false
        cleanupReserved = false
        return true
    }

    @Synchronized
    fun retainActionUncertainty(error: String) {
        if (lastState != ScannerAuditTaskState.CANCELLED) {
            val bounded = error.take(MAX_STRUCTURED_TOOL_ERROR_CHARS)
            if (unresolvedActionError != bounded) {
                unresolvedActionError = bounded
                resultVersion++
            }
        }
    }

    @Synchronized
    fun snapshotResult(result: () -> ScannerAuditResult): ScannerRecordResultSnapshot =
        ScannerRecordResultSnapshot(result(), resultVersion)

    @Synchronized
    fun resultVersionMatches(version: Long): Boolean = resultVersion == version

    @Synchronized
    fun isCurrentIssueObservation(sequence: Long): Boolean =
        lastState != ScannerAuditTaskState.CANCELLED &&
            sequence == lastAppliedStatusObservationSequence &&
            sequence == lastAppliedIssueObservationSequence

    @Synchronized
    fun toScrubbedResult(
        status: ScannerAuditToolStatus,
        actionState: ScannerAuditActionState,
        projectId: String?,
        error: String,
    ): ScannerAuditResult {
        val cancellationResolved = lastState == ScannerAuditTaskState.CANCELLED
        val retainedError = unresolvedActionError.takeUnless { cancellationResolved }
        val effectiveActionState = when {
            cancellationResolved -> ScannerAuditActionState.COMPLETED
            retainedError != null -> ScannerAuditActionState.UNCERTAIN
            else -> actionState
        }
        val effectiveError = when {
            cancellationResolved && status == ScannerAuditToolStatus.PROJECT_MISMATCH ->
                "Scanner audit cancellation completed, but the Burp project changed before this request completed"
            cancellationResolved ->
                "Scanner audit cancellation completed, but Burp could not safely establish the current project for this request"
            retainedError == null || retainedError == error -> error
            else -> "$retainedError; $error"
        }.take(MAX_STRUCTURED_TOOL_ERROR_CHARS)
        return scannerAuditError(
            status = status,
            actionState = effectiveActionState,
            projectId = projectId,
            error = effectiveError,
        ).copy(
            taskState = lastState.takeIf { cancellationResolved || retainedError != null },
        )
    }

    @Synchronized
    fun toResult(
        status: ScannerAuditToolStatus,
        actionState: ScannerAuditActionState,
        issues: List<ScannerIssueSummary> = emptyList(),
        discoveredIssueCount: Int? = lastIssueCount,
        issuesTruncated: Boolean = false,
        issuesAccessDenied: Boolean = false,
        issuesUnavailable: Boolean = false,
        issuesRequested: Boolean = false,
        preserveFailureAfterCancellation: Boolean = false,
        error: String? = null,
    ): ScannerAuditResult {
        val cancellationResolved = lastState == ScannerAuditTaskState.CANCELLED
        if (actionState == ScannerAuditActionState.UNCERTAIN && !cancellationResolved) {
            val bounded = (error ?: uncertainExecutionError("Scanner audit side-effect state remains uncertain"))
                .take(MAX_STRUCTURED_TOOL_ERROR_CHARS)
            if (unresolvedActionError != bounded) {
                unresolvedActionError = bounded
                resultVersion++
            }
        }
        val retainedError = unresolvedActionError.takeUnless { cancellationResolved }
        val independentFailure = cancellationResolved && preserveFailureAfterCancellation &&
            status == ScannerAuditToolStatus.BURP_ERROR
        val effectiveStatus = when {
            independentFailure -> ScannerAuditToolStatus.BURP_ERROR
            cancellationResolved -> ScannerAuditToolStatus.OK
            retainedError != null -> ScannerAuditToolStatus.EXECUTION_UNCERTAIN
            else -> status
        }
        val effectiveActionState = when {
            cancellationResolved -> ScannerAuditActionState.COMPLETED
            retainedError != null -> ScannerAuditActionState.UNCERTAIN
            else -> actionState
        }
        val effectiveError = when {
            independentFailure -> error
            cancellationResolved -> null
            retainedError == null -> error
            error == null || error == retainedError -> retainedError
            else -> "$retainedError; $error"
        }?.take(MAX_STRUCTURED_TOOL_ERROR_CHARS)
        return ScannerAuditResult(
            status = effectiveStatus,
            actionState = effectiveActionState,
            projectId = projectId,
            taskId = taskId,
            mode = mode,
            taskState = lastState,
            statusMessage = lastStatusMessage,
            startedAt = startedAt.toString(),
            cancelledAt = cancelledAt?.toString(),
            targets = targets,
            targetCount = targets.size,
            insertionPointCount = targets.sumOf { it.insertionPointCount },
            auditedInsertionPointCount = lastAuditedInsertionPointCount,
            requestCount = lastRequestCount,
            errorCount = lastErrorCount,
            discoveredIssueCount = discoveredIssueCount.takeUnless { cancellationResolved },
            issues = issues.takeUnless { cancellationResolved } ?: emptyList(),
            issuesTruncated = issuesTruncated && !cancellationResolved,
            issuesAccessDenied = issuesAccessDenied && !cancellationResolved,
            issuesUnavailable = if (cancellationResolved) issuesRequested else issuesUnavailable,
            error = effectiveError,
        )
    }
}

private class ScannerAuditValidationException(message: String) : IllegalArgumentException(message)

private fun scannerRequestBytes(message: ResolvedHttpMessage): Int {
    val header = message.request.bodyOffset()
    val body = message.request.body().length()
    if (header < 0 || body < 0) throw ScannerAuditValidationException("request reported an invalid byte length")
    val total = header.toLong() + body.toLong()
    if (total > Int.MAX_VALUE) throw ScannerAuditValidationException("request is too large")
    return total.toInt()
}

private fun ScannerAuditMode.builtInConfiguration(): BuiltInAuditConfiguration = when (this) {
    ScannerAuditMode.PASSIVE -> BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
    ScannerAuditMode.ACTIVE -> BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
}

private fun retentionElapsed(now: Long, since: Long, duration: Duration): Boolean =
    now - since >= duration.toNanos()

private fun classifyTaskState(message: String?, previous: ScannerAuditTaskState): ScannerAuditTaskState {
    if (previous.isTerminal()) return previous
    val normalized = message?.trim()?.lowercase().orEmpty()
    return when {
        normalized.isEmpty() -> previous.takeIf { it != ScannerAuditTaskState.STARTING } ?: ScannerAuditTaskState.UNKNOWN
        listOf("finished", "complete", "completed", "done").any(normalized::contains) -> ScannerAuditTaskState.FINISHED
        listOf("cancelled", "canceled", "deleted").any(normalized::contains) -> ScannerAuditTaskState.CANCELLED
        listOf("failed", "fatal").any(normalized::contains) -> ScannerAuditTaskState.FAILED
        "paused" in normalized -> ScannerAuditTaskState.PAUSED
        listOf("running", "queued", "auditing", "scanning", "processing", "starting").any(normalized::contains) ->
            ScannerAuditTaskState.RUNNING
        else -> ScannerAuditTaskState.UNKNOWN
    }
}

private fun ScannerAuditTaskState.isTerminal(): Boolean =
    this == ScannerAuditTaskState.FINISHED || this == ScannerAuditTaskState.CANCELLED || this == ScannerAuditTaskState.FAILED

private fun HttpMessageResolutionStatus.toScannerAuditStatus(): ScannerAuditToolStatus = when (this) {
    HttpMessageResolutionStatus.ACCESS_DENIED -> ScannerAuditToolStatus.ACCESS_DENIED
    HttpMessageResolutionStatus.INVALID_ARGUMENT -> ScannerAuditToolStatus.INVALID_ARGUMENT
    HttpMessageResolutionStatus.INVALID_ID -> ScannerAuditToolStatus.INVALID_ID
    HttpMessageResolutionStatus.PROJECT_MISMATCH -> ScannerAuditToolStatus.PROJECT_MISMATCH
    HttpMessageResolutionStatus.NOT_FOUND -> ScannerAuditToolStatus.NOT_FOUND
    HttpMessageResolutionStatus.REQUEST_UNAVAILABLE -> ScannerAuditToolStatus.REQUEST_UNAVAILABLE
    HttpMessageResolutionStatus.BURP_ERROR -> ScannerAuditToolStatus.BURP_ERROR
}

private fun scannerAuditError(
    status: ScannerAuditToolStatus,
    actionState: ScannerAuditActionState,
    projectId: String?,
    mode: ScannerAuditMode? = null,
    error: String,
    errorTargetIndex: Int? = null,
) = ScannerAuditResult(
    status = status,
    actionState = actionState,
    projectId = projectId?.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
    mode = mode,
    targets = emptyList(),
    targetCount = 0,
    insertionPointCount = 0,
    issues = emptyList(),
    issuesTruncated = false,
    issuesAccessDenied = false,
    issuesUnavailable = false,
    errorTargetIndex = errorTargetIndex,
    error = error.take(MAX_STRUCTURED_TOOL_ERROR_CHARS),
)

private fun validProjectId(value: String): Boolean =
    value.isNotEmpty() && value.length <= MAX_HTTP_REFERENCE_PROJECT_ID_CHARS && value.none(Char::isISOControl)

private fun safeScannerAuditException(error: Exception): String =
    if (error is StaleScannerProjectObservationException) {
        "project observation superseded by a newer boundary check"
    } else {
        "internal Burp API failure"
    }

private fun Throwable.asException(): Exception = this as? Exception ?: RuntimeException(message, this)
