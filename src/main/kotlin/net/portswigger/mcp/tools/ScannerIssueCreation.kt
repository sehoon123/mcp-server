package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.security.SensitiveActionAuditOperation
import net.portswigger.mcp.security.SensitiveActionSecurity
import net.portswigger.mcp.security.safeExceptionSummary
import java.net.URI
import java.util.Base64

private const val MAX_SCANNER_ISSUE_REFS = 8
private const val MAX_SCANNER_ISSUE_NAME_CHARS = 256
private const val MAX_SCANNER_ISSUE_TEXT_CHARS = 8_192
private const val MAX_SCANNER_ISSUE_URL_CHARS = 2_048
private const val MAX_SCANNER_ISSUE_HOST_CHARS = 512
private const val MAX_SCANNER_EVIDENCE_PART_BYTES = 256 * 1024
private const val MAX_SCANNER_EVIDENCE_TOTAL_BYTES = 1024 * 1024
private const val CALLER_AUTHORED_BACKGROUND =
    "Caller-authored, human-reviewed finding. This extension did not automatically verify the claim."

@Serializable
enum class ScannerIssueSeverity {
    @SerialName("high") HIGH,
    @SerialName("medium") MEDIUM,
    @SerialName("low") LOW,
    @SerialName("information") INFORMATION,
    @SerialName("false_positive") FALSE_POSITIVE,
}

@Serializable
enum class ScannerIssueConfidence {
    @SerialName("certain") CERTAIN,
    @SerialName("firm") FIRM,
    @SerialName("tentative") TENTATIVE,
}

@Serializable
data class CreateScannerIssue(
    @JsonSchemaMetadata(description = MCP_PROJECT_ID_INPUT_DESCRIPTION, minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(description = "One to eight canonically distinct existing HTTP references used as complete issue evidence.", minItems = 1, maxItems = MAX_SCANNER_ISSUE_REFS)
    val refs: List<HttpMessageReference>,
    @JsonSchemaMetadata(description = "Caller-authored issue name; this extension does not verify the finding.", minLength = 1, maxLength = MAX_SCANNER_ISSUE_NAME_CHARS)
    val name: String,
    @JsonSchemaMetadata(description = "Caller-authored plain-text detail; this extension does not verify the finding.", minLength = 1, maxLength = MAX_SCANNER_ISSUE_TEXT_CHARS)
    val detail: String,
    @JsonSchemaMetadata(description = "Caller-selected issue severity.")
    val severity: ScannerIssueSeverity,
    @JsonSchemaMetadata(description = "Caller-selected issue confidence.")
    val confidence: ScannerIssueConfidence,
    @JsonSchemaMetadata(description = "Required true attestation that a human reviewed the caller-authored finding; it is not proof of validation.")
    val humanReviewed: Boolean,
    @JsonSchemaMetadata(description = "Optional caller-authored plain-text remediation.", maxLength = MAX_SCANNER_ISSUE_TEXT_CHARS)
    val remediation: String? = null,
)

@Serializable
internal data class CreateScannerIssueResult(
    @JsonSchemaMetadata(description = TOOL_STATUS_RETRY_DESCRIPTION)
    val status: NativeToolStatus,
    @JsonSchemaMetadata(description = TOOL_RETRY_DESCRIPTION)
    val retry: ToolRetryGuidance,
    @JsonSchemaMetadata(description = TOOL_EXECUTION_STATE_DESCRIPTION)
    val executionState: StandardExecutionState,
    val projectId: String?,
    @JsonSchemaMetadata(description = "Number of existing HTTP references submitted as evidence; completion does not independently verify persistence.", minimum = 0, maximum = 8)
    val evidenceCount: Int,
    @JsonSchemaMetadata(maxLength = MAX_STANDARD_TOOL_ERROR_CHARS)
    val error: String? = null,
)

private data class ScannerEvidenceSnapshot(
    val ref: HttpMessageReference,
    val url: String,
    val host: String,
    val port: Int,
    val secure: Boolean,
    val requestBytes: ByteArray,
    val responseBytes: ByteArray?,
)

@Serializable
private data class ScannerIssueApprovalPreview(
    val projectId: String,
    val name: String,
    val detail: String,
    val remediation: String?,
    val severity: ScannerIssueSeverity,
    val confidence: ScannerIssueConfidence,
    val humanReviewed: Boolean,
    val baseUrl: String,
    val evidence: List<ScannerEvidencePreview>,
)

@Serializable
private data class ScannerEvidencePreview(
    val ref: HttpMessageReference,
    val service: ScannerServicePreview,
    val url: String,
    val requestEncoding: String,
    val request: String,
    val responseEncoding: String?,
    val response: String?,
)

@Serializable
private data class ScannerServicePreview(val host: String, val port: Int, val secure: Boolean)

private class ScannerEvidenceLimitException(message: String) : IllegalArgumentException(message)
private class ScannerEvidenceInvalidException : IllegalArgumentException("Burp returned invalid issue evidence")
private class ScannerIssuePreconditionException(
    val status: NativeToolStatus,
    val projectId: String?,
    message: String,
) : IllegalStateException(message)
private class ScannerIssueStaleException : IllegalStateException("HTTP evidence changed")
private class ScannerIssueEmergencyException : IllegalStateException("Emergency read-only mode enabled")
private class ScannerIssueProjectException(val currentProjectId: String?) : IllegalStateException("Burp project changed")

internal class ScannerIssueCreationService(
    private val api: MontoyaApi,
    private val config: McpConfig,
    private val withMutation: suspend (String, suspend () -> Unit) -> Unit,
) {
    private val resolver = HttpMessageResolver(api, config)

    suspend fun create(input: CreateScannerIssue): CreateScannerIssueResult {
        validateScannerIssueInput(input)?.let {
            return failure(NativeToolStatus.INVALID_ARGUMENT, null, 0, it)
        }
        val resolution = resolver.resolveAll(input.projectId, input.refs, MAX_SCANNER_ISSUE_REFS)
        if (resolution is HttpMessageBatchResolution.Failed) {
            return failure(resolution.status.toNativeToolStatus(), resolution.projectId, 0, resolution.error)
        }
        val found = resolution as HttpMessageBatchResolution.Found
        val approvedEvidence = try {
            snapshotEvidence(found.messages)
        } catch (e: CancellationException) {
            throw e
        } catch (e: ScannerEvidenceLimitException) {
            return failure(NativeToolStatus.LIMIT_EXCEEDED, found.projectId, 0, e.message.orEmpty())
        } catch (e: Exception) {
            return failure(
                NativeToolStatus.BURP_ERROR,
                found.projectId,
                0,
                "Burp could not capture complete issue evidence: ${safeExceptionSummary(e)}",
            )
        }
        val baseUrl = validateBaseUrl(approvedEvidence.first().url)
            ?: return failure(
                NativeToolStatus.INVALID_ARGUMENT,
                found.projectId,
                0,
                "the first evidence request does not have a safe bounded HTTP(S) URL",
            )
        val preview = approvalPreview(input, found.projectId, baseUrl, approvedEvidence)
        val approved = try {
            SensitiveActionSecurity.checkPermission(
                action = "create one human-reviewed Scanner issue",
                summary = "Submit one caller-authored, human-reviewed and not automatically verified finding with ${input.refs.size} exact evidence item(s)",
                reviewContent = preview,
                renderContentAsHttp = false,
                api = api,
                config = config,
                auditOperation = SensitiveActionAuditOperation.SCANNER_ISSUE_CREATE,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return failure(
                NativeToolStatus.BURP_ERROR,
                found.projectId,
                0,
                "Burp could not request Scanner issue approval: ${safeExceptionSummary(e)}",
            )
        }
        val projectAfterApproval = try {
            api.project().id()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return failure(
                NativeToolStatus.BURP_ERROR,
                found.projectId,
                0,
                "Burp could not recheck the project after Scanner issue approval: ${safeExceptionSummary(e)}",
            )
        }
        if (projectAfterApproval != found.projectId) {
            return failure(
                NativeToolStatus.PROJECT_MISMATCH,
                projectAfterApproval,
                0,
                "Burp project changed during Scanner issue approval",
            )
        }
        if (!approved) {
            return failure(
                NativeToolStatus.ACCESS_DENIED,
                found.projectId,
                0,
                "Scanner issue submission denied by Burp Suite",
            )
        }

        val callContext = currentCoroutineContext()
        var attempted = false
        try {
            withMutation(found.projectId) {
                callContext.ensureActive()
                if (config.emergencyReadOnlyMode) throw ScannerIssueEmergencyException()
                val refreshed = when (val outcome = resolver.resolveAllAuthorized(
                    found.projectId,
                    input.refs,
                    found.authorization,
                    MAX_SCANNER_ISSUE_REFS,
                )) {
                    is HttpMessageBatchResolution.Failed -> {
                        if (outcome.status == HttpMessageResolutionStatus.NOT_FOUND ||
                            outcome.status == HttpMessageResolutionStatus.REQUEST_UNAVAILABLE
                        ) throw ScannerIssueStaleException()
                        throw ScannerIssuePreconditionException(
                            outcome.status.toNativeToolStatus(), outcome.projectId, outcome.error,
                        )
                    }
                    is HttpMessageBatchResolution.Found -> try {
                        snapshotEvidence(outcome.messages)
                    } catch (_: ScannerEvidenceLimitException) {
                        throw ScannerIssueStaleException()
                    } catch (_: ScannerEvidenceInvalidException) {
                        throw ScannerIssueStaleException()
                    }
                }
                if (!sameEvidence(approvedEvidence, refreshed)) throw ScannerIssueStaleException()
                val issue = buildIssue(input, baseUrl, approvedEvidence)
                val siteMap = api.siteMap()

                callContext.ensureActive()
                if (config.emergencyReadOnlyMode) throw ScannerIssueEmergencyException()
                val projectBeforeAdd = api.project().id()
                if (projectBeforeAdd != found.projectId) throw ScannerIssueProjectException(projectBeforeAdd)
                callContext.ensureActive()
                if (config.emergencyReadOnlyMode) throw ScannerIssueEmergencyException()
                attempted = true
                siteMap.add(issue)
                callContext.ensureActive()
                val projectAfterAdd = api.project().id()
                if (projectAfterAdd != found.projectId) throw ScannerIssueProjectException(projectAfterAdd)
            }
            callContext.ensureActive()
            val projectAfterMutation = api.project().id()
            if (projectAfterMutation != found.projectId) throw ScannerIssueProjectException(projectAfterMutation)
        } catch (e: ScannerIssuePreconditionException) {
            return failure(e.status, e.projectId, 0, e.message.orEmpty())
        } catch (_: ScannerIssueStaleException) {
            return failure(
                NativeToolStatus.STALE_STATE,
                found.projectId,
                0,
                "the selected HTTP evidence, service, or URL changed while approval was pending",
            )
        } catch (e: ScannerIssueEmergencyException) {
            if (attempted) return uncertain(e)
            return failure(
                NativeToolStatus.DISABLED,
                found.projectId,
                0,
                "Emergency read-only mode was enabled before Scanner issue submission",
            )
        } catch (e: ScannerIssueProjectException) {
            if (attempted) return uncertain(e)
            return failure(
                NativeToolStatus.PROJECT_MISMATCH,
                e.currentProjectId,
                0,
                "Burp project changed before Scanner issue submission",
            )
        } catch (e: OrganizerProjectMismatchBeforeMutationException) {
            return failure(
                NativeToolStatus.PROJECT_MISMATCH,
                e.currentProjectId,
                0,
                "Burp project changed before Scanner issue submission",
            )
        } catch (e: OrganizerMutationNotStartedException) {
            return failure(
                NativeToolStatus.BURP_ERROR,
                found.projectId,
                0,
                "Burp could not start Scanner issue submission: ${safeExceptionSummary(e)}",
            )
        } catch (e: CancellationException) {
            if (!callContext.isActive || !attempted) throw e
            return uncertain(e)
        } catch (e: Exception) {
            if (!attempted) {
                return failure(
                    NativeToolStatus.BURP_ERROR,
                    found.projectId,
                    0,
                    "Burp could not prepare Scanner issue submission: ${safeExceptionSummary(e)}",
                )
            }
            return uncertain(e)
        }
        return success(found.projectId, input.refs.size)
    }

    private suspend fun snapshotEvidence(messages: List<ResolvedHttpMessage>): List<ScannerEvidenceSnapshot> {
        var aggregate = 0L
        return messages.map { message ->
            currentCoroutineContext().ensureActive()
            val requestLength = requestByteLength(message.request).toLong()
            val responseLength = message.response?.let {
                val offset = it.bodyOffset()
                val bodyLength = it.body().length()
                require(offset >= 0 && bodyLength >= 0) { "response reported an invalid byte length" }
                offset.toLong() + bodyLength
            }
            if (requestLength > MAX_SCANNER_EVIDENCE_PART_BYTES ||
                (responseLength ?: 0) > MAX_SCANNER_EVIDENCE_PART_BYTES
            ) {
                throw ScannerEvidenceLimitException(
                    "issue evidence exceeds the $MAX_SCANNER_EVIDENCE_PART_BYTES-byte per-part limit"
                )
            }
            aggregate += requestLength + (responseLength ?: 0)
            if (aggregate > MAX_SCANNER_EVIDENCE_TOTAL_BYTES) {
                throw ScannerEvidenceLimitException(
                    "issue evidence exceeds the $MAX_SCANNER_EVIDENCE_TOTAL_BYTES-byte aggregate limit"
                )
            }
            val request = completeBytes(message.request.toByteArray(), requestLength)
            val response = message.response?.let {
                completeBytes(it.toByteArray(), requireNotNull(responseLength))
            }
            val service = message.request.httpService()
            val host = service.host()
            val port = service.port()
            val secure = service.secure()
            if (host.isEmpty() || host.length > MAX_SCANNER_ISSUE_HOST_CHARS || host.any(Char::isISOControl) ||
                port !in 1..65_535
            ) {
                throw ScannerEvidenceInvalidException()
            }
            val url = message.request.url()
            if (url.isEmpty() || url.length > MAX_SCANNER_ISSUE_URL_CHARS || url.any(Char::isISOControl)) {
                throw ScannerEvidenceInvalidException()
            }
            ScannerEvidenceSnapshot(
                message.ref,
                url,
                host,
                port,
                secure,
                request,
                response,
            )
        }
    }

    private fun completeBytes(bytes: MontoyaByteArray, expectedLength: Long): ByteArray {
        val length = bytes.length()
        if (length.toLong() != expectedLength) throw ScannerEvidenceInvalidException()
        val raw = bytes.getBytes()
        if (raw.size != length) throw ScannerEvidenceInvalidException()
        return raw
    }

    private fun buildIssue(
        input: CreateScannerIssue,
        baseUrl: String,
        evidence: List<ScannerEvidenceSnapshot>,
    ): AuditIssue {
        val requestResponses = evidence.map { snapshot ->
            val service = HttpService.httpService(snapshot.host, snapshot.port, snapshot.secure)
            val request = HttpRequest.httpRequest(service, MontoyaByteArray.byteArray(*snapshot.requestBytes))
            val response = snapshot.responseBytes?.let { HttpResponse.httpResponse(MontoyaByteArray.byteArray(*it)) }
            HttpRequestResponse.httpRequestResponse(request, response)
        }
        return AuditIssue.auditIssue(
            html(input.name),
            html(input.detail),
            html(input.remediation.orEmpty()),
            baseUrl,
            AuditIssueSeverity.valueOf(input.severity.name),
            AuditIssueConfidence.valueOf(input.confidence.name),
            html(CALLER_AUTHORED_BACKGROUND),
            html(CALLER_AUTHORED_BACKGROUND),
            AuditIssueSeverity.valueOf(input.severity.name),
            requestResponses,
        )
    }

    private fun success(projectId: String, evidenceCount: Int) = CreateScannerIssueResult(
        NativeToolStatus.OK,
        ToolRetryGuidance.NOT_APPLICABLE,
        StandardExecutionState.COMPLETED,
        projectId,
        evidenceCount,
    )

    private fun failure(
        status: NativeToolStatus,
        projectId: String?,
        evidenceCount: Int,
        error: String,
    ) = CreateScannerIssueResult(
        status,
        status.defaultRetry(),
        StandardExecutionState.NOT_STARTED,
        projectId?.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
        evidenceCount.coerceIn(0, MAX_SCANNER_ISSUE_REFS),
        nativeToolError(error),
    )

    private fun uncertain(error: Exception) = CreateScannerIssueResult(
        NativeToolStatus.EXECUTION_UNCERTAIN,
        ToolRetryGuidance.DO_NOT_RETRY,
        StandardExecutionState.UNCERTAIN,
        null,
        0,
        uncertainExecutionError(
            "Burp may have accepted the Scanner issue; persistence was not independently verified",
            error,
            preserveCancellation = false,
            maxChars = MAX_STANDARD_TOOL_ERROR_CHARS,
        ),
    )
}

private fun validateScannerIssueInput(input: CreateScannerIssue): String? {
    if (!isValidProjectId(input.projectId)) return "projectId is invalid"
    if (input.refs.size !in 1..MAX_SCANNER_ISSUE_REFS) {
        return "refs must contain between 1 and $MAX_SCANNER_ISSUE_REFS items"
    }
    val identities = input.refs.map(::canonicalHttpReferenceIdentity)
    return when {
        identities.any { it == null } -> "refs contain an invalid HTTP reference"
        identities.filterNotNull().distinct().size != identities.size ->
            "refs must identify canonically distinct HTTP records"
        input.name.isEmpty() || input.name.length > MAX_SCANNER_ISSUE_NAME_CHARS || input.name.any(Char::isISOControl) ->
            "name must contain 1 to $MAX_SCANNER_ISSUE_NAME_CHARS characters without controls"
        !validIssueText(input.detail, required = true) ->
            "detail must contain 1 to $MAX_SCANNER_ISSUE_TEXT_CHARS plain-text characters"
        input.remediation != null && !validIssueText(input.remediation, required = false) ->
            "remediation must contain at most $MAX_SCANNER_ISSUE_TEXT_CHARS plain-text characters"
        !input.humanReviewed -> "humanReviewed must be true"
        else -> null
    }
}

private fun validIssueText(value: String, required: Boolean): Boolean =
    (!required || value.isNotEmpty()) && value.length <= MAX_SCANNER_ISSUE_TEXT_CHARS &&
        value.all { !it.isISOControl() || it == '\n' || it == '\r' || it == '\t' }

private fun validateBaseUrl(value: String): String? = try {
    val uri = URI(value)
    value.takeIf {
        value.length <= MAX_SCANNER_ISSUE_URL_CHARS &&
            uri.scheme?.lowercase() in setOf("http", "https") &&
            !uri.host.isNullOrBlank() && uri.userInfo == null && uri.fragment == null
    }
} catch (_: Exception) {
    null
}

private fun approvalPreview(
    input: CreateScannerIssue,
    projectId: String,
    baseUrl: String,
    evidence: List<ScannerEvidenceSnapshot>,
): String = Json.encodeToString(
    ScannerIssueApprovalPreview(
        projectId,
        input.name,
        input.detail,
        input.remediation,
        input.severity,
        input.confidence,
        input.humanReviewed,
        baseUrl,
        evidence.map {
            ScannerEvidencePreview(
                ref = it.ref,
                service = ScannerServicePreview(it.host, it.port, it.secure),
                url = it.url,
                requestEncoding = "base64",
                request = Base64.getEncoder().encodeToString(it.requestBytes),
                responseEncoding = if (it.responseBytes == null) null else "base64",
                response = it.responseBytes?.let(Base64.getEncoder()::encodeToString),
            )
        },
    )
)

private fun sameEvidence(
    approved: List<ScannerEvidenceSnapshot>,
    refreshed: List<ScannerEvidenceSnapshot>,
): Boolean = approved.size == refreshed.size && approved.zip(refreshed).all { (left, right) ->
    left.ref == right.ref && left.url == right.url && left.host == right.host && left.port == right.port &&
        left.secure == right.secure && left.requestBytes.contentEquals(right.requestBytes) &&
        when {
            left.responseBytes == null -> right.responseBytes == null
            right.responseBytes == null -> false
            else -> left.responseBytes.contentEquals(right.responseBytes)
        }
}

private fun html(value: String): String {
    val normalized = value.replace("\r\n", "\n").replace('\r', '\n')
    return buildString(normalized.length) {
        normalized.forEach {
            append(
                when (it) {
                    '&' -> "&amp;"
                    '<' -> "&lt;"
                    '>' -> "&gt;"
                    '"' -> "&quot;"
                    '\'' -> "&#39;"
                    '\n' -> "<br>"
                    '\t' -> "&#9;"
                    else -> it
                }
            )
        }
    }
}
