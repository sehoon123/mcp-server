package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.audit.Audit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.SensitiveActionSecurity
import java.security.SecureRandom
import java.time.Instant
import java.util.HexFormat
import java.util.concurrent.ConcurrentHashMap

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
private val SCANNER_TASK_ID_PATTERN = Regex("scanner_audit_[0-9a-f]{32}")

@Serializable
data class ScannerAuditTarget(
    val ref: HttpMessageReference,
    val insertionPoints: List<HttpInsertionPointSelector>? = null,
)

@Serializable
data class StartScannerAuditFromIds(
    val projectId: String,
    val mode: ScannerAuditMode,
    val targets: List<ScannerAuditTarget>,
)

@Serializable
data class GetScannerAudit(
    val projectId: String,
    val taskId: String,
    val issueLimit: Int? = null,
)

@Serializable
data class CancelScannerAudit(
    val projectId: String,
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
    val status: ScannerAuditToolStatus,
    val actionState: ScannerAuditActionState,
    val projectId: String?,
    val taskId: String? = null,
    val mode: ScannerAuditMode? = null,
    val taskState: ScannerAuditTaskState? = null,
    val statusMessage: String? = null,
    val startedAt: String? = null,
    val cancelledAt: String? = null,
    val targets: List<ScannerAuditTargetSummary> = emptyList(),
    val targetCount: Int = 0,
    val insertionPointCount: Int = 0,
    val auditedInsertionPointCount: Int? = null,
    val requestCount: Int? = null,
    val errorCount: Int? = null,
    val discoveredIssueCount: Int? = null,
    val issues: List<ScannerIssueSummary> = emptyList(),
    val issuesTruncated: Boolean = false,
    val issuesAccessDenied: Boolean = false,
    val issuesUnavailable: Boolean = false,
    val errorTargetIndex: Int? = null,
    val error: String? = null,
)

internal class ScannerAuditService(private val api: MontoyaApi) {
    private val records = ConcurrentHashMap<String, ScannerAuditRecord>()
    private val startMutex = Mutex()
    private val random = SecureRandom()

    suspend fun start(input: StartScannerAuditFromIds, config: McpConfig): ScannerAuditResult {
        val targetLimit = when (input.mode) {
            ScannerAuditMode.ACTIVE -> MAX_ACTIVE_SCANNER_TARGETS
            ScannerAuditMode.PASSIVE -> MAX_PASSIVE_SCANNER_TARGETS
        }
        if (!validProjectId(input.projectId)) {
            return scannerAuditError(
                ScannerAuditToolStatus.INVALID_ARGUMENT,
                ScannerAuditActionState.NOT_STARTED,
                input.projectId.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
                input.mode,
                "projectId is empty, too long, or contains control characters",
            )
        }
        if (input.targets.isEmpty() || input.targets.size > targetLimit) {
            return scannerAuditError(
                ScannerAuditToolStatus.INVALID_ARGUMENT,
                ScannerAuditActionState.NOT_STARTED,
                input.projectId,
                input.mode,
                "${input.mode.name.lowercase()} audit targets must contain between 1 and $targetLimit items",
            )
        }
        val refs = input.targets.map { it.ref }
        if (refs.distinct().size != refs.size) {
            return scannerAuditError(
                ScannerAuditToolStatus.INVALID_ARGUMENT,
                ScannerAuditActionState.NOT_STARTED,
                input.projectId,
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
            } catch (e: Exception) {
                return scannerAuditError(
                    ScannerAuditToolStatus.INVALID_ARGUMENT,
                    ScannerAuditActionState.NOT_STARTED,
                    input.projectId,
                    input.mode,
                    e.message ?: "invalid request size",
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
                        prepareInsertionPoints(message.request, selectors).also {
                            totalInsertionPoints += it.ranges.size
                            require(totalInsertionPoints <= MAX_TOTAL_SCANNER_INSERTION_POINTS) {
                                "active audit targets can contain at most $MAX_TOTAL_SCANNER_INSERTION_POINTS total insertion points"
                            }
                        }
                    } catch (e: IllegalArgumentException) {
                        return scannerAuditError(
                            ScannerAuditToolStatus.INVALID_ARGUMENT,
                            ScannerAuditActionState.NOT_STARTED,
                            input.projectId,
                            input.mode,
                            e.message.orEmpty(),
                            index,
                        )
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

        val targetSummaries = prepared.map { it.summary() }
        val review = buildScannerReview(input.mode, prepared)
        val approved = try {
            SensitiveActionSecurity.checkPermission(
                action = "start a focused ${input.mode.name.lowercase()} Scanner audit",
                summary = buildScannerApprovalSummary(input.projectId, input.mode, prepared),
                reviewContent = review.content,
                renderContentAsHttp = review.renderAsHttp,
                api = api,
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
                error = "Scanner audit denied by Burp Suite",
            )
        }

        currentCoroutineContext().ensureActive()
        return startMutex.withLock {
            refreshAndTrimRecords()
            if (records.values.count { !it.lastState.isTerminal() } >= MAX_ACTIVE_SCANNER_AUDITS) {
                return@withLock scannerAuditError(
                    ScannerAuditToolStatus.CAPACITY_EXCEEDED,
                    ScannerAuditActionState.NOT_STARTED,
                    input.projectId,
                    input.mode,
                    "at most $MAX_ACTIVE_SCANNER_AUDITS MCP-started Scanner audits may be active",
                )
            }
            val currentProjectId = try {
                api.project().id()
            } catch (e: Exception) {
                return@withLock scannerAuditError(
                    ScannerAuditToolStatus.BURP_ERROR,
                    ScannerAuditActionState.NOT_STARTED,
                    null,
                    input.mode,
                    "Burp could not recheck the project before Scanner start: ${safeScannerAuditException(e)}",
                )
            }
            if (currentProjectId != input.projectId) {
                return@withLock scannerAuditError(
                    ScannerAuditToolStatus.PROJECT_MISMATCH,
                    ScannerAuditActionState.NOT_STARTED,
                    currentProjectId,
                    input.mode,
                    "Burp project changed before the Scanner audit started",
                )
            }
            prepared.forEachIndexed { index, target ->
                val stillInScope = try {
                    api.scope().isInScope(target.message.request.url())
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
            } catch (e: Exception) {
                return@withLock scannerAuditError(
                    ScannerAuditToolStatus.BURP_ERROR,
                    ScannerAuditActionState.NOT_STARTED,
                    input.projectId,
                    input.mode,
                    "Burp could not prepare the Scanner audit configuration: ${safeScannerAuditException(e)}",
                )
            }
            val audit: Audit = try {
                api.scanner().startAudit(configuration)
            } catch (e: Exception) {
                auditScanner(input.mode, prepared.size, null, "start execution uncertain")
                return@withLock scannerAuditError(
                    ScannerAuditToolStatus.EXECUTION_UNCERTAIN,
                    ScannerAuditActionState.UNCERTAIN,
                    input.projectId,
                    input.mode,
                    "Burp may have started the Scanner audit but did not return a task handle: ${safeScannerAuditException(e)}",
                )
            }

            val record = ScannerAuditRecord(
                taskId = taskId,
                projectId = input.projectId,
                mode = input.mode,
                audit = audit,
                targets = targetSummaries,
                startedAt = Instant.now(),
            )
            records[taskId] = record

            try {
                prepared.forEach { target ->
                    when (input.mode) {
                        ScannerAuditMode.PASSIVE -> audit.addRequestResponse(requireNotNull(target.requestResponse))
                        ScannerAuditMode.ACTIVE -> audit.addRequest(
                            target.message.request,
                            requireNotNull(target.insertionPoints).ranges,
                        )
                    }
                }
                record.lastState = ScannerAuditTaskState.RUNNING
            } catch (e: Exception) {
                record.lastState = ScannerAuditTaskState.UNKNOWN
                auditScanner(input.mode, prepared.size, taskId, "target submission uncertain")
                return@withLock record.toResult(
                    status = ScannerAuditToolStatus.EXECUTION_UNCERTAIN,
                    actionState = ScannerAuditActionState.UNCERTAIN,
                    error = "Scanner audit started, but one or more targets may not have been submitted: " +
                        safeScannerAuditException(e),
                )
            }

            auditScanner(input.mode, prepared.size, taskId, "started")
            record.toResult(
                status = ScannerAuditToolStatus.OK,
                actionState = ScannerAuditActionState.COMPLETED,
            )
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
        val record = records[input.taskId] ?: return scannerAuditError(
            ScannerAuditToolStatus.NOT_FOUND,
            ScannerAuditActionState.NOT_STARTED,
            input.projectId,
            error = "Scanner audit task was not found; only tasks started by this extension instance are available",
        )
        if (record.projectId != input.projectId) {
            return scannerAuditError(
                ScannerAuditToolStatus.PROJECT_MISMATCH,
                ScannerAuditActionState.NOT_STARTED,
                api.project().id(),
                error = "Scanner audit task belongs to a different Burp project",
            )
        }

        if (record.lastState == ScannerAuditTaskState.CANCELLED) {
            return record.toResult(ScannerAuditToolStatus.OK, ScannerAuditActionState.COMPLETED)
        }
        val errors = ArrayList<String>(4)
        val statusMessage = runCatching { record.audit.statusMessage().take(MAX_SCANNER_STATUS_MESSAGE_CHARS) }
            .onFailure { errors += "status unavailable: ${safeScannerAuditException(it.asException())}" }
            .getOrNull()
        val auditedInsertionPointCount = runCatching { record.audit.insertionPointCount() }
            .onFailure { errors += "insertion-point count unavailable: ${safeScannerAuditException(it.asException())}" }
            .getOrNull()
        val requestCount = runCatching { record.audit.requestCount() }
            .onFailure { errors += "request count unavailable: ${safeScannerAuditException(it.asException())}" }
            .getOrNull()
        val errorCount = runCatching { record.audit.errorCount() }
            .onFailure { errors += "error count unavailable: ${safeScannerAuditException(it.asException())}" }
            .getOrNull()
        record.lastState = classifyTaskState(statusMessage, record.lastState)
        record.lastStatusMessage = statusMessage
        record.lastAuditedInsertionPointCount = auditedInsertionPointCount
        record.lastRequestCount = requestCount
        record.lastErrorCount = errorCount

        var issuesAllowed = try {
            DataAccessSecurity.checkDataAccessPermission(DataAccessType.SCANNER_ISSUES, config)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            errors += "issue access check failed: ${safeScannerAuditException(e)}"
            false
        }
        val issuePermissionDenied = !issuesAllowed
        val projectBeforeIssues = try {
            api.project().id()
        } catch (e: Exception) {
            errors += "project recheck failed: ${safeScannerAuditException(e)}"
            null
        }
        if (projectBeforeIssues == null) {
            issuesAllowed = false
        } else if (projectBeforeIssues != record.projectId) {
            return scannerAuditError(
                ScannerAuditToolStatus.PROJECT_MISMATCH,
                ScannerAuditActionState.NOT_STARTED,
                projectBeforeIssues,
                record.mode,
                "Burp project changed while reading the Scanner audit",
            )
        }

        var issueCount: Int? = null
        var issues = emptyList<ScannerIssueSummary>()
        var truncated = false
        var issueWarning: String? = null
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
                record.lastIssueCount = issueCount
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                issueWarning = "issues unavailable: ${safeScannerAuditException(e)}"
            }
        }

        return record.toResult(
            status = if (errors.isEmpty()) ScannerAuditToolStatus.OK else ScannerAuditToolStatus.BURP_ERROR,
            actionState = ScannerAuditActionState.COMPLETED,
            issues = issues,
            discoveredIssueCount = issueCount ?: record.lastIssueCount,
            issuesTruncated = truncated,
            issuesAccessDenied = issuePermissionDenied,
            issuesUnavailable = issueWarning != null,
            error = (errors + listOfNotNull(issueWarning)).takeIf { it.isNotEmpty() }
                ?.joinToString("; ")?.take(512),
        )
    }

    suspend fun cancel(input: CancelScannerAudit): ScannerAuditResult {
        val validation = validateTaskInput(input.projectId, input.taskId)
        if (validation != null) return validation
        val record = records[input.taskId] ?: return scannerAuditError(
            ScannerAuditToolStatus.NOT_FOUND,
            ScannerAuditActionState.NOT_STARTED,
            input.projectId,
            error = "Scanner audit task was not found; only tasks started by this extension instance are available",
        )
        if (record.projectId != input.projectId) {
            return scannerAuditError(
                ScannerAuditToolStatus.PROJECT_MISMATCH,
                ScannerAuditActionState.NOT_STARTED,
                api.project().id(),
                error = "Scanner audit task belongs to a different Burp project",
            )
        }
        if (record.lastState == ScannerAuditTaskState.CANCELLED) {
            return record.toResult(ScannerAuditToolStatus.OK, ScannerAuditActionState.COMPLETED)
        }

        val approved = try {
            SensitiveActionSecurity.checkPermission(
                action = "cancel an MCP-started Scanner audit",
                summary = "Project: ${record.projectId}\nTask: ${record.taskId}\nMode: ${record.mode.name.lowercase()}\n" +
                    "Targets: ${record.targets.size}",
                api = api,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return record.toResult(
                ScannerAuditToolStatus.BURP_ERROR,
                ScannerAuditActionState.NOT_STARTED,
                error = "Burp could not request Scanner cancellation approval: ${safeScannerAuditException(e)}",
            )
        }
        if (!approved) {
            auditScanner(record.mode, record.targets.size, record.taskId, "cancellation denied")
            return record.toResult(
                ScannerAuditToolStatus.ACTION_DENIED,
                ScannerAuditActionState.NOT_STARTED,
                error = "Scanner audit cancellation denied by Burp Suite",
            )
        }

        currentCoroutineContext().ensureActive()
        val currentProjectId = try {
            api.project().id()
        } catch (e: Exception) {
            return record.toResult(
                ScannerAuditToolStatus.BURP_ERROR,
                ScannerAuditActionState.NOT_STARTED,
                error = "Burp could not recheck the project before Scanner cancellation: ${safeScannerAuditException(e)}",
            )
        }
        if (currentProjectId != record.projectId) {
            return scannerAuditError(
                ScannerAuditToolStatus.PROJECT_MISMATCH,
                ScannerAuditActionState.NOT_STARTED,
                currentProjectId,
                record.mode,
                "Burp project changed before Scanner cancellation",
            )
        }
        return try {
            record.audit.delete()
            record.lastState = ScannerAuditTaskState.CANCELLED
            record.cancelledAt = Instant.now()
            auditScanner(record.mode, record.targets.size, record.taskId, "cancelled")
            record.toResult(ScannerAuditToolStatus.OK, ScannerAuditActionState.COMPLETED)
        } catch (e: Exception) {
            record.lastState = ScannerAuditTaskState.UNKNOWN
            auditScanner(record.mode, record.targets.size, record.taskId, "cancellation uncertain")
            record.toResult(
                ScannerAuditToolStatus.EXECUTION_UNCERTAIN,
                ScannerAuditActionState.UNCERTAIN,
                error = "Scanner audit may have been cancelled: ${safeScannerAuditException(e)}",
            )
        }
    }

    private fun validateTaskInput(projectId: String, taskId: String): ScannerAuditResult? {
        if (!validProjectId(projectId)) {
            return scannerAuditError(
                ScannerAuditToolStatus.INVALID_ARGUMENT,
                ScannerAuditActionState.NOT_STARTED,
                projectId.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
                error = "projectId is empty, too long, or contains control characters",
            )
        }
        if (taskId.length !in 1..MAX_SCANNER_TASK_ID_CHARS || !taskId.matches(SCANNER_TASK_ID_PATTERN)) {
            return scannerAuditError(
                ScannerAuditToolStatus.INVALID_ID,
                ScannerAuditActionState.NOT_STARTED,
                projectId,
                error = "taskId must be copied from start_scanner_audit_from_ids",
            )
        }
        val currentProjectId = try {
            api.project().id()
        } catch (e: Exception) {
            return scannerAuditError(
                ScannerAuditToolStatus.BURP_ERROR,
                ScannerAuditActionState.NOT_STARTED,
                null,
                error = "Burp could not read the current project: ${safeScannerAuditException(e)}",
            )
        }
        if (currentProjectId != projectId) {
            return scannerAuditError(
                ScannerAuditToolStatus.PROJECT_MISMATCH,
                ScannerAuditActionState.NOT_STARTED,
                currentProjectId,
                error = "Scanner audit task belongs to a different Burp project",
            )
        }
        return null
    }

    private fun refreshAndTrimRecords() {
        records.values.forEach { record ->
            if (!record.lastState.isTerminal()) {
                val status = runCatching { record.audit.statusMessage().take(MAX_SCANNER_STATUS_MESSAGE_CHARS) }.getOrNull()
                if (status != null) {
                    record.lastStatusMessage = status
                    record.lastState = classifyTaskState(status, record.lastState)
                }
            }
        }
        if (records.size < MAX_RETAINED_SCANNER_AUDITS) return
        val removable = records.values.filter { it.lastState.isTerminal() }.sortedBy { it.startedAt }
        val removeCount = (records.size - MAX_RETAINED_SCANNER_AUDITS + 1).coerceAtLeast(0)
        removable.take(removeCount).forEach { records.remove(it.taskId, it) }
    }

    private fun nextTaskId(): String {
        while (true) {
            val bytes = ByteArray(16).also(random::nextBytes)
            val id = "scanner_audit_${HexFormat.of().formatHex(bytes)}"
            if (!records.containsKey(id)) return id
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

private class ScannerAuditRecord(
    val taskId: String,
    val projectId: String,
    val mode: ScannerAuditMode,
    val audit: Audit,
    val targets: List<ScannerAuditTargetSummary>,
    val startedAt: Instant,
) {
    @Volatile
    var lastState: ScannerAuditTaskState = ScannerAuditTaskState.STARTING
    @Volatile
    var lastStatusMessage: String? = null
    @Volatile
    var lastAuditedInsertionPointCount: Int? = null
    @Volatile
    var lastRequestCount: Int? = null
    @Volatile
    var lastErrorCount: Int? = null
    @Volatile
    var lastIssueCount: Int? = null
    @Volatile
    var cancelledAt: Instant? = null

    fun toResult(
        status: ScannerAuditToolStatus,
        actionState: ScannerAuditActionState,
        issues: List<ScannerIssueSummary> = emptyList(),
        discoveredIssueCount: Int? = lastIssueCount,
        issuesTruncated: Boolean = false,
        issuesAccessDenied: Boolean = false,
        issuesUnavailable: Boolean = false,
        error: String? = null,
    ) = ScannerAuditResult(
        status = status,
        actionState = actionState,
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
        discoveredIssueCount = discoveredIssueCount,
        issues = issues,
        issuesTruncated = issuesTruncated,
        issuesAccessDenied = issuesAccessDenied,
        issuesUnavailable = issuesUnavailable,
        error = error?.take(512),
    )
}

private fun scannerRequestBytes(message: ResolvedHttpMessage): Int {
    val header = message.request.bodyOffset()
    val body = message.request.body().length()
    require(header >= 0 && body >= 0) { "request reported an invalid byte length" }
    val total = header.toLong() + body.toLong()
    require(total <= Int.MAX_VALUE) { "request is too large" }
    return total.toInt()
}

private fun ScannerAuditMode.builtInConfiguration(): BuiltInAuditConfiguration = when (this) {
    ScannerAuditMode.PASSIVE -> BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
    ScannerAuditMode.ACTIVE -> BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
}

private fun classifyTaskState(message: String?, previous: ScannerAuditTaskState): ScannerAuditTaskState {
    if (previous == ScannerAuditTaskState.CANCELLED) return previous
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
    projectId = projectId,
    mode = mode,
    errorTargetIndex = errorTargetIndex,
    error = error.take(512),
)

private fun validProjectId(value: String): Boolean =
    value.isNotEmpty() && value.length <= MAX_HTTP_REFERENCE_PROJECT_ID_CHARS && value.none(Char::isISOControl)

private fun safeScannerAuditException(error: Exception): String =
    "${error::class.simpleName ?: "Exception"}: ${error.message.orEmpty()}".take(512)

private fun Throwable.asException(): Exception = this as? Exception ?: RuntimeException(message, this)
