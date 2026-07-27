package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpHeader
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.JsonSchemaMetadata
import java.net.URI
import java.time.LocalDateTime
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeFormatterBuilder
import java.time.format.ResolverStyle
import java.time.temporal.ChronoField
import java.util.Locale

internal const val MAX_SESSION_ANALYSIS_MESSAGES = 32
internal const val MAX_SESSION_HEADERS_PER_PART = 128
internal const val MAX_SESSION_HEADER_NAME_CHARS = 256
internal const val MAX_SESSION_HEADER_LINE_CHARS = 8_192
internal const val MAX_SESSION_SELECTED_HEADER_CHARS = 256 * 1_024
internal const val MAX_SESSION_COOKIES_PER_MESSAGE = 32
internal const val MAX_SESSION_COOKIES_PER_ANALYSIS = 256
internal const val MAX_SESSION_REDIRECT_HOPS = 16
private const val MAX_COOKIE_NAME_CHARS = 128
private const val MAX_METHOD_CHARS = 32

private val SESSION_ANALYSIS_PROGRESS_MESSAGES = listOf(
    "Validating session analysis input",
    "Resolving selected HTTP references",
    "Analyzing bounded header evidence",
    "Finalizing session analysis evidence",
)

@Serializable
data class AnalyzeHttpSessionSecurity(
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(
        description = "One to 32 distinct ordered stable Proxy, Site Map, or Organizer HTTP references.",
        minItems = 1,
        maxItems = 32,
    )
    val refs: List<HttpMessageReference>,
)

@Serializable
enum class HttpSessionAnalysisStatus {
    @SerialName("ok")
    OK,

    @SerialName("access_denied")
    ACCESS_DENIED,

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

    @SerialName("burp_error")
    BURP_ERROR,
}

@Serializable
enum class SessionEndpointRole {
    @SerialName("login")
    LOGIN,

    @SerialName("logout")
    LOGOUT,

    @SerialName("refresh")
    REFRESH,

    @SerialName("redirect")
    REDIRECT,
}

@Serializable
enum class SessionSameSite {
    @SerialName("strict")
    STRICT,

    @SerialName("lax")
    LAX,

    @SerialName("none")
    NONE,

    @SerialName("missing")
    MISSING,

    @SerialName("invalid")
    INVALID,
}

@Serializable
enum class SessionRedirectRelation {
    @SerialName("relative")
    RELATIVE,

    @SerialName("same_origin")
    SAME_ORIGIN,

    @SerialName("cross_origin")
    CROSS_ORIGIN,

    @SerialName("unknown")
    UNKNOWN,
}

@Serializable
enum class SessionEvidenceWarning {
    @SerialName("request_headers_truncated")
    REQUEST_HEADERS_TRUNCATED,

    @SerialName("response_headers_truncated")
    RESPONSE_HEADERS_TRUNCATED,

    @SerialName("selected_header_chars_truncated")
    SELECTED_HEADER_CHARS_TRUNCATED,

    @SerialName("cookies_truncated")
    COOKIES_TRUNCATED,

    @SerialName("malformed_cookie_header")
    MALFORMED_COOKIE_HEADER,

    @SerialName("malformed_set_cookie_header")
    MALFORMED_SET_COOKIE_HEADER,

    @SerialName("redirect_hops_truncated")
    REDIRECT_HOPS_TRUNCATED,

    @SerialName("malformed_redirect_location")
    MALFORMED_REDIRECT_LOCATION,
}

@Serializable
enum class SessionSecurityAttribute {
    @SerialName("request_authorization_present")
    REQUEST_AUTHORIZATION_PRESENT,

    @SerialName("request_cookie_present")
    REQUEST_COOKIE_PRESENT,

    @SerialName("response_set_cookie_present")
    RESPONSE_SET_COOKIE_PRESENT,

    @SerialName("response_auth_challenge_present")
    RESPONSE_AUTH_CHALLENGE_PRESENT,

    @SerialName("redirect_present")
    REDIRECT_PRESENT,
}

@Serializable
enum class SessionDomainScope {
    @SerialName("host_only")
    HOST_ONLY,

    @SerialName("explicit_same_host")
    EXPLICIT_SAME_HOST,

    @SerialName("parent_domain")
    PARENT_DOMAIN,

    @SerialName("unrelated")
    UNRELATED,

    @SerialName("invalid")
    INVALID,
}

@Serializable
enum class SessionPathScope {
    @SerialName("default")
    DEFAULT,

    @SerialName("root")
    ROOT,

    @SerialName("request_path_prefix")
    REQUEST_PATH_PREFIX,

    @SerialName("other")
    OTHER,

    @SerialName("invalid")
    INVALID,
}

@Serializable
enum class SessionCookieLifetime {
    @SerialName("session")
    SESSION,

    @SerialName("persistent")
    PERSISTENT,

    @SerialName("deletion")
    DELETION,

    @SerialName("invalid")
    INVALID,
}

@Serializable
enum class SessionCookiePrefix {
    @SerialName("host")
    HOST,

    @SerialName("secure")
    SECURE,

    @SerialName("none")
    NONE,
}

@Serializable
enum class SessionCookieWarning {
    @SerialName("ambiguous_folded_header")
    AMBIGUOUS_FOLDED_HEADER,

    @SerialName("malformed_attribute")
    MALFORMED_ATTRIBUTE,

    @SerialName("duplicate_attribute")
    DUPLICATE_ATTRIBUTE,

    @SerialName("invalid_same_site")
    INVALID_SAME_SITE,

    @SerialName("invalid_domain")
    INVALID_DOMAIN,

    @SerialName("invalid_path")
    INVALID_PATH,

    @SerialName("invalid_max_age")
    INVALID_MAX_AGE,

    @SerialName("invalid_expires")
    INVALID_EXPIRES,

    @SerialName("same_site_none_without_secure")
    SAME_SITE_NONE_WITHOUT_SECURE,

    @SerialName("prefix_not_compliant")
    PREFIX_NOT_COMPLIANT,
}

@Serializable
enum class SessionCookieAttribute {
    @SerialName("secure")
    SECURE,

    @SerialName("http_only")
    HTTP_ONLY,

    @SerialName("partitioned")
    PARTITIONED,

    @SerialName("same_site")
    SAME_SITE,

    @SerialName("domain_scope")
    DOMAIN_SCOPE,

    @SerialName("path_scope")
    PATH_SCOPE,

    @SerialName("lifetime")
    LIFETIME,

    @SerialName("prefix")
    PREFIX,

    @SerialName("prefix_compliant")
    PREFIX_COMPLIANT,

    @SerialName("max_age_present")
    MAX_AGE_PRESENT,

    @SerialName("expires_present")
    EXPIRES_PRESENT,
}

@Serializable
data class SessionRequestSignals(
    val authorizationPresent: Boolean,
    val proxyAuthorizationPresent: Boolean,
    val cookiePresent: Boolean,
    val csrfTokenHeaderPresent: Boolean,
)

@Serializable
data class SessionResponseSignals(
    val setCookiePresent: Boolean,
    val authChallengePresent: Boolean,
    val proxyAuthChallengePresent: Boolean,
    val authenticationInfoPresent: Boolean,
)

@Serializable
data class SessionResponseCookie(
    val name: String,
    val secure: Boolean,
    val httpOnly: Boolean,
    val partitioned: Boolean,
    val sameSite: SessionSameSite,
    val domainScope: SessionDomainScope,
    val pathScope: SessionPathScope,
    val lifetime: SessionCookieLifetime,
    val domainPresent: Boolean,
    val pathPresent: Boolean,
    val maxAgePresent: Boolean,
    val expiresPresent: Boolean,
    val prefix: SessionCookiePrefix,
    val prefixCompliant: Boolean?,
    val warnings: List<SessionCookieWarning>,
)

@Serializable
data class SessionRedirectSignal(
    val statusCode: Int,
    val locationPresent: Boolean,
    val relation: SessionRedirectRelation?,
    val targetRoles: List<SessionEndpointRole>,
)

@Serializable
data class HttpSessionMessageSummary(
    val index: Int,
    val ref: HttpMessageReference,
    val method: String,
    val secureTransport: Boolean,
    val statusCode: Int?,
    val hasResponse: Boolean,
    val roles: List<SessionEndpointRole>,
    val requestSignals: SessionRequestSignals,
    val responseSignals: SessionResponseSignals?,
    val requestCookieNames: List<String>,
    val responseCookies: List<SessionResponseCookie>,
    val redirect: SessionRedirectSignal?,
    val evidenceWarnings: List<SessionEvidenceWarning>,
)

@Serializable
data class SessionCookieCrossMessageSummary(
    val name: String,
    val setOnMessageIndices: List<Int>,
    val sentOnMessageIndices: List<Int>,
    val invariantAttributes: List<SessionCookieAttribute>,
    val variantAttributes: List<SessionCookieAttribute>,
)

@Serializable
data class HttpSessionEvidenceBounds(
    val proposedFlowOnly: Boolean = true,
    val chronologyOrCausalityEstablished: Boolean = false,
    val vulnerabilityAssessment: Boolean = false,
    val selectedMessages: Int,
    val messagesWithResponses: Int,
    val headersScanned: Int,
    val selectedHeaderValuesInspected: Int,
    val selectedHeaderCharsInspected: Int,
    val cookiesObserved: Int,
    val redirectHopsInspected: Int,
    val maxMessages: Int = MAX_SESSION_ANALYSIS_MESSAGES,
    val maxHeadersPerRequestOrResponse: Int = MAX_SESSION_HEADERS_PER_PART,
    val maxHeaderLineChars: Int = MAX_SESSION_HEADER_LINE_CHARS,
    val maxSelectedHeaderChars: Int = MAX_SESSION_SELECTED_HEADER_CHARS,
    val maxRequestCookieNamesPerMessage: Int = MAX_SESSION_COOKIES_PER_MESSAGE,
    val maxResponseCookiesPerMessage: Int = MAX_SESSION_COOKIES_PER_MESSAGE,
    val maxCookiesPerAnalysis: Int = MAX_SESSION_COOKIES_PER_ANALYSIS,
    val maxRedirectHops: Int = MAX_SESSION_REDIRECT_HOPS,
    val headersTruncated: Boolean,
    val selectedCharsTruncated: Boolean,
    val cookiesTruncated: Boolean,
    val redirectHopsTruncated: Boolean,
    val limitations: List<String> = listOf(
        "Input order is only a proposed flow and does not prove chronology or causality.",
        "Header and cookie presence does not prove authentication, browser acceptance, or session behavior.",
        "Truncated or missing evidence is omitted from invariant and variant conclusions.",
        "Cookie summaries correlate by case-sensitive name and may combine cookies with distinct private scopes.",
        "Expires is syntax-checked but not compared with wall-clock time; deletion requires non-positive Max-Age evidence.",
        "Site Map stable-ID verification may inspect bounded identity samples before body-free analysis.",
        "This result reports passive observations only, without severity or vulnerability claims.",
    ),
)

@Serializable
data class AnalyzeHttpSessionSecurityResult(
    val status: HttpSessionAnalysisStatus,
    val projectId: String?,
    val refs: List<HttpMessageReference>,
    val messages: List<HttpSessionMessageSummary>,
    val cookieSummaries: List<SessionCookieCrossMessageSummary>,
    val invariants: List<SessionSecurityAttribute>,
    val variants: List<SessionSecurityAttribute>,
    val evidence: HttpSessionEvidenceBounds,
    val errorRefIndex: Int? = null,
    val error: String? = null,
)

internal class HttpSessionSecurityAnalyzerService(private val api: MontoyaApi) {
    suspend fun analyze(
        input: AnalyzeHttpSessionSecurity,
        config: McpConfig,
        reportProgress: ToolProgressReporter = NO_TOOL_PROGRESS_REPORTER,
    ): AnalyzeHttpSessionSecurityResult {
        val progress = FixedStageProgress(SESSION_ANALYSIS_PROGRESS_MESSAGES, reportProgress)
        progress.report(0)
        if (input.refs.size !in 1..MAX_SESSION_ANALYSIS_MESSAGES) {
            return sessionAnalysisError(
                HttpSessionAnalysisStatus.INVALID_ARGUMENT,
                input.projectId,
                input.refs,
                "refs must contain between 1 and $MAX_SESSION_ANALYSIS_MESSAGES items",
            )
        }
        if (input.refs.map { it.sessionAnalysisIdentity() }.distinct().size != input.refs.size) {
            return sessionAnalysisError(
                HttpSessionAnalysisStatus.INVALID_ARGUMENT,
                input.projectId,
                input.refs,
                "refs must not contain duplicates",
            )
        }

        progress.report(1)
        // Preserve the v4.8 Site Map identity contract: resolving a Site Map reference can privately inspect
        // bounded body samples and header values while recomputing its stable ID. Analyzer materialization below
        // remains body-free, and neither identity material nor selected header values are returned.
        val messages = when (
            val resolution = HttpMessageResolver(api, config).resolveAll(
                input.projectId,
                input.refs,
                MAX_SESSION_ANALYSIS_MESSAGES,
            )
        ) {
            is HttpMessageBatchResolution.Found -> resolution.messages
            is HttpMessageBatchResolution.Failed -> return sessionAnalysisError(
                status = resolution.status.toSessionAnalysisStatus(),
                projectId = resolution.projectId,
                refs = input.refs,
                error = if (resolution.status == HttpMessageResolutionStatus.BURP_ERROR) {
                    "Burp could not resolve the selected HTTP messages"
                } else {
                    resolution.error
                },
                errorRefIndex = resolution.refIndex,
            )
        }

        val projectBeforeAnalysis = currentProjectIdOrError() ?: return sessionAnalysisError(
            HttpSessionAnalysisStatus.BURP_ERROR,
            input.projectId,
            input.refs,
            "Burp could not recheck the project before session analysis",
        )
        if (projectBeforeAnalysis != input.projectId) {
            return sessionAnalysisError(
                HttpSessionAnalysisStatus.PROJECT_MISMATCH,
                projectBeforeAnalysis,
                input.refs,
                "Burp project changed before session analysis",
            )
        }

        progress.report(2)
        val analysis = try {
            analyzeResolvedSessionMessages(messages)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return sessionAnalysisError(
                HttpSessionAnalysisStatus.BURP_ERROR,
                input.projectId,
                input.refs,
                "Burp could not prepare bounded session evidence",
            )
        }

        progress.report(3)
        val projectAfterAnalysis = currentProjectIdOrError() ?: return sessionAnalysisError(
            HttpSessionAnalysisStatus.BURP_ERROR,
            input.projectId,
            input.refs,
            "Burp could not recheck the project after session analysis",
        )
        if (projectAfterAnalysis != input.projectId) {
            return sessionAnalysisError(
                HttpSessionAnalysisStatus.PROJECT_MISMATCH,
                projectAfterAnalysis,
                input.refs,
                "Burp project changed while session evidence was prepared",
            )
        }

        return AnalyzeHttpSessionSecurityResult(
            status = HttpSessionAnalysisStatus.OK,
            projectId = input.projectId,
            refs = input.refs,
            messages = analysis.messages,
            cookieSummaries = analysis.cookieSummaries,
            invariants = analysis.invariants,
            variants = analysis.variants,
            evidence = analysis.evidence,
        )
    }

    private fun currentProjectIdOrError(): String? = try {
        api.project().id()
    } catch (e: CancellationException) {
        throw e
    } catch (_: Exception) {
        null
    }
}

private data class SessionAnalysisMaterial(
    val messages: List<HttpSessionMessageSummary>,
    val cookieSummaries: List<SessionCookieCrossMessageSummary>,
    val invariants: List<SessionSecurityAttribute>,
    val variants: List<SessionSecurityAttribute>,
    val evidence: HttpSessionEvidenceBounds,
)

private data class InspectedHeaderValue(val text: String, val truncated: Boolean)

private class SessionAnalysisBudget {
    var headersScanned = 0
    var selectedValues = 0
    var selectedChars = 0
    var cookies = 0
    var redirectHops = 0
    var headersTruncated = false
    var selectedCharsTruncated = false
    var cookiesTruncated = false
    var redirectHopsTruncated = false

    fun inspectValue(header: HttpHeader, headerNameLength: Int): InspectedHeaderValue? {
        if (selectedChars >= MAX_SESSION_SELECTED_HEADER_CHARS) {
            selectedCharsTruncated = true
            return null
        }
        val raw = header.value()
        selectedValues++
        val lineAllowance = (MAX_SESSION_HEADER_LINE_CHARS - headerNameLength.coerceAtMost(MAX_SESSION_HEADER_NAME_CHARS))
            .coerceAtLeast(0)
        val allowed = minOf(lineAllowance, MAX_SESSION_SELECTED_HEADER_CHARS - selectedChars)
        val inspected = raw.take(allowed)
        selectedChars += inspected.length
        val truncated = raw.length > inspected.length
        if (truncated) selectedCharsTruncated = true
        return InspectedHeaderValue(inspected, truncated)
    }
}

private data class HeaderScan(
    val names: Set<String>,
    val cookieNames: List<String> = emptyList(),
    val responseCookies: List<SessionResponseCookie> = emptyList(),
    val locationHeader: HttpHeader? = null,
    val warnings: Set<SessionEvidenceWarning> = emptySet(),
)

private suspend fun analyzeResolvedSessionMessages(messages: List<ResolvedHttpMessage>): SessionAnalysisMaterial {
    val budget = SessionAnalysisBudget()
    val summaries = ArrayList<HttpSessionMessageSummary>(messages.size)

    messages.forEachIndexed { index, resolved ->
        currentCoroutineContext().ensureActive()
        val request = resolved.request
        val response = resolved.response
        val requestService = request.httpService()
        val rawRequestPath = request.path()
        val boundedRequestPath = rawRequestPath.take(MAX_SESSION_HEADER_LINE_CHARS)
        val cookieContext = SessionCookieContext(
            requestHost = requestService.host().take(MAX_SESSION_HEADER_LINE_CHARS),
            requestPath = boundedRequestPath.substringBefore('?').substringBefore('#'),
            secureTransport = requestService.secure(),
        )
        val requestScan = scanHeaders(request.headers(), true, budget)
        val responseScan = response?.let { scanHeaders(it.headers(), false, budget, cookieContext) }
        val statusCode = response?.statusCode()?.toInt()
        val pathRoles = endpointRoles(rawRequestPath)
        val redirectStatus = statusCode != null && statusCode in REDIRECT_STATUS_CODES
        val warnings = linkedSetOf<SessionEvidenceWarning>().apply {
            addAll(requestScan.warnings)
            addAll(responseScan?.warnings.orEmpty())
        }
        val redirect = if (redirectStatus) {
            val locationPresent = responseScan?.names?.contains("location") == true
            var relation: SessionRedirectRelation? = null
            var targetRoles = emptyList<SessionEndpointRole>()
            if (locationPresent) {
                if (budget.redirectHops >= MAX_SESSION_REDIRECT_HOPS) {
                    budget.redirectHopsTruncated = true
                    warnings += SessionEvidenceWarning.REDIRECT_HOPS_TRUNCATED
                    relation = SessionRedirectRelation.UNKNOWN
                } else {
                    budget.redirectHops++
                    val selected = responseScan?.locationHeader?.let {
                        budget.inspectValue(it, "location".length)
                    }
                    if (selected == null || selected.truncated) {
                        warnings += SessionEvidenceWarning.SELECTED_HEADER_CHARS_TRUNCATED
                        relation = SessionRedirectRelation.UNKNOWN
                    } else {
                        val redirectEvidence = redirectEvidence(
                            selected.text,
                            cookieContext.requestHost,
                            requestService.port(),
                            requestService.secure(),
                        )
                        relation = redirectEvidence.first
                        targetRoles = redirectEvidence.second
                        if (relation == SessionRedirectRelation.UNKNOWN) {
                            warnings += SessionEvidenceWarning.MALFORMED_REDIRECT_LOCATION
                        }
                    }
                }
            }
            SessionRedirectSignal(statusCode, locationPresent, relation, targetRoles)
        } else {
            null
        }
        if (budget.selectedCharsTruncated) warnings += SessionEvidenceWarning.SELECTED_HEADER_CHARS_TRUNCATED
        if (budget.cookiesTruncated) warnings += SessionEvidenceWarning.COOKIES_TRUNCATED

        val roles = LinkedHashSet<SessionEndpointRole>().apply {
            addAll(pathRoles)
            if (redirectStatus) add(SessionEndpointRole.REDIRECT)
        }.toList()
        summaries += HttpSessionMessageSummary(
            index = index,
            ref = resolved.ref,
            method = request.method().take(MAX_METHOD_CHARS),
            secureTransport = requestService.secure(),
            statusCode = statusCode,
            hasResponse = response != null,
            roles = roles,
            requestSignals = SessionRequestSignals(
                authorizationPresent = "authorization" in requestScan.names,
                proxyAuthorizationPresent = "proxy-authorization" in requestScan.names,
                cookiePresent = "cookie" in requestScan.names,
                csrfTokenHeaderPresent = requestScan.names.any(::isCsrfTokenHeader),
            ),
            responseSignals = responseScan?.let {
                SessionResponseSignals(
                    setCookiePresent = "set-cookie" in it.names,
                    authChallengePresent = "www-authenticate" in it.names,
                    proxyAuthChallengePresent = "proxy-authenticate" in it.names,
                    authenticationInfoPresent = "authentication-info" in it.names,
                )
            },
            requestCookieNames = requestScan.cookieNames,
            responseCookies = responseScan?.responseCookies.orEmpty(),
            redirect = redirect,
            evidenceWarnings = warnings.toList(),
        )
    }

    val completeCookieEvidence = !budget.headersTruncated && !budget.selectedCharsTruncated && !budget.cookiesTruncated
    val cookieSummaries = crossMessageCookies(summaries, completeCookieEvidence)
    val (invariants, variants) = crossMessageSignals(summaries, budget)
    return SessionAnalysisMaterial(
        messages = summaries,
        cookieSummaries = cookieSummaries,
        invariants = invariants,
        variants = variants,
        evidence = HttpSessionEvidenceBounds(
            selectedMessages = summaries.size,
            messagesWithResponses = summaries.count { it.hasResponse },
            headersScanned = budget.headersScanned,
            selectedHeaderValuesInspected = budget.selectedValues,
            selectedHeaderCharsInspected = budget.selectedChars,
            cookiesObserved = budget.cookies,
            redirectHopsInspected = budget.redirectHops,
            headersTruncated = budget.headersTruncated,
            selectedCharsTruncated = budget.selectedCharsTruncated,
            cookiesTruncated = budget.cookiesTruncated,
            redirectHopsTruncated = budget.redirectHopsTruncated,
        ),
    )
}

private data class SessionCookieContext(
    val requestHost: String,
    val requestPath: String,
    val secureTransport: Boolean,
)

private fun scanHeaders(
    headers: List<HttpHeader>,
    request: Boolean,
    budget: SessionAnalysisBudget,
    cookieContext: SessionCookieContext? = null,
): HeaderScan {
    val names = LinkedHashSet<String>()
    val cookieNames = LinkedHashSet<String>()
    val responseCookies = ArrayList<SessionResponseCookie>()
    val warnings = LinkedHashSet<SessionEvidenceWarning>()
    var locationHeader: HttpHeader? = null
    if (headers.size > MAX_SESSION_HEADERS_PER_PART) {
        budget.headersTruncated = true
        warnings += if (request) {
            SessionEvidenceWarning.REQUEST_HEADERS_TRUNCATED
        } else {
            SessionEvidenceWarning.RESPONSE_HEADERS_TRUNCATED
        }
    }

    for (header in headers.take(MAX_SESSION_HEADERS_PER_PART)) {
        budget.headersScanned++
        val rawName = header.name()
        if (rawName.length > MAX_SESSION_HEADER_NAME_CHARS) {
            budget.headersTruncated = true
            warnings += if (request) {
                SessionEvidenceWarning.REQUEST_HEADERS_TRUNCATED
            } else {
                SessionEvidenceWarning.RESPONSE_HEADERS_TRUNCATED
            }
        }
        val name = rawName.take(MAX_SESSION_HEADER_NAME_CHARS).lowercase()
        names += name
        when {
            request && name == "cookie" -> {
                if (cookieNames.size >= MAX_SESSION_COOKIES_PER_MESSAGE || budget.cookies >= MAX_SESSION_COOKIES_PER_ANALYSIS) {
                    budget.cookiesTruncated = true
                    warnings += SessionEvidenceWarning.COOKIES_TRUNCATED
                    continue
                }
                val value = budget.inspectValue(header, rawName.length)
                if (value == null || value.truncated) {
                    warnings += SessionEvidenceWarning.SELECTED_HEADER_CHARS_TRUNCATED
                    continue
                }
                val parsed = parseRequestCookieNames(
                    value.text,
                    MAX_SESSION_COOKIES_PER_MESSAGE - cookieNames.size,
                    MAX_SESSION_COOKIES_PER_ANALYSIS - budget.cookies,
                )
                cookieNames += parsed.first
                budget.cookies += parsed.first.size
                if (parsed.second) {
                    budget.cookiesTruncated = true
                    warnings += SessionEvidenceWarning.COOKIES_TRUNCATED
                }
                if (parsed.third) warnings += SessionEvidenceWarning.MALFORMED_COOKIE_HEADER
            }

            !request && name == "set-cookie" -> {
                if (responseCookies.size >= MAX_SESSION_COOKIES_PER_MESSAGE || budget.cookies >= MAX_SESSION_COOKIES_PER_ANALYSIS) {
                    budget.cookiesTruncated = true
                    warnings += SessionEvidenceWarning.COOKIES_TRUNCATED
                    continue
                }
                val value = budget.inspectValue(header, rawName.length)
                if (value == null || value.truncated) {
                    warnings += SessionEvidenceWarning.SELECTED_HEADER_CHARS_TRUNCATED
                    continue
                }
                val context = requireNotNull(cookieContext)
                val parsed = parseSessionResponseCookie(
                    value.text,
                    context.requestHost,
                    context.requestPath,
                    context.secureTransport,
                )
                if (parsed == null) {
                    warnings += SessionEvidenceWarning.MALFORMED_SET_COOKIE_HEADER
                } else {
                    responseCookies += parsed
                    budget.cookies++
                }
            }

            !request && name == "location" && locationHeader == null -> locationHeader = header
        }
    }
    return HeaderScan(names, cookieNames.toList(), responseCookies, locationHeader, warnings)
}

private fun parseRequestCookieNames(value: String, perMessageRemaining: Int, totalRemaining: Int): Triple<List<String>, Boolean, Boolean> {
    val result = LinkedHashSet<String>()
    var malformed = false
    var truncated = false
    for (segment in value.split(';')) {
        val separator = segment.indexOf('=')
        if (separator <= 0) {
            if (segment.isNotBlank()) malformed = true
            continue
        }
        val name = segment.substring(0, separator).trim()
        if (!isCookieName(name)) {
            malformed = true
            continue
        }
        if (result.size >= perMessageRemaining || result.size >= totalRemaining) {
            truncated = true
            break
        }
        result += name
    }
    return Triple(result.toList(), truncated, malformed)
}

internal fun parseSessionResponseCookie(
    boundedValue: String,
    requestHost: String,
    requestPath: String,
    secureTransport: Boolean,
): SessionResponseCookie? {
    val warnings = LinkedHashSet<SessionCookieWarning>()
    val foldedAt = FOLDED_SET_COOKIE_PATTERN.find(boundedValue)?.range?.first
    val value = if (foldedAt == null) {
        boundedValue
    } else {
        warnings += SessionCookieWarning.AMBIGUOUS_FOLDED_HEADER
        boundedValue.take(foldedAt)
    }
    val segments = value.split(';')
    val first = segments.firstOrNull()?.trim() ?: return null
    val separator = first.indexOf('=')
    if (separator <= 0) return null
    val name = first.substring(0, separator).trim()
    if (!isCookieName(name)) return null

    var secure = false
    var httpOnly = false
    var partitioned = false
    var sameSite = SessionSameSite.MISSING
    var domainValue: String? = null
    var pathValue: String? = null
    var maxAgeValue: String? = null
    var expiresValue: String? = null
    val seenAttributes = HashSet<String>()

    segments.drop(1).forEach { rawAttribute ->
        val attribute = rawAttribute.trim()
        if (attribute.isEmpty()) return@forEach
        val equals = attribute.indexOf('=')
        val attributeName = (if (equals < 0) attribute else attribute.substring(0, equals)).trim().lowercase()
        if (attributeName !in RECOGNIZED_COOKIE_ATTRIBUTES) return@forEach
        if (!seenAttributes.add(attributeName)) warnings += SessionCookieWarning.DUPLICATE_ATTRIBUTE
        val attributeValue = if (equals < 0) null else attribute.substring(equals + 1).trim()
        when (attributeName) {
            "secure" -> if (attributeValue == null) secure = true else warnings += SessionCookieWarning.MALFORMED_ATTRIBUTE
            "httponly" -> if (attributeValue == null) httpOnly = true else warnings += SessionCookieWarning.MALFORMED_ATTRIBUTE
            "partitioned" -> if (attributeValue == null) partitioned = true else warnings += SessionCookieWarning.MALFORMED_ATTRIBUTE
            "samesite" -> sameSite = when {
                attributeValue == null -> SessionSameSite.INVALID
                attributeValue.equals("strict", ignoreCase = true) -> SessionSameSite.STRICT
                attributeValue.equals("lax", ignoreCase = true) -> SessionSameSite.LAX
                attributeValue.equals("none", ignoreCase = true) -> SessionSameSite.NONE
                else -> SessionSameSite.INVALID
            }.also {
                if (it == SessionSameSite.INVALID) warnings += SessionCookieWarning.INVALID_SAME_SITE
            }
            "domain" -> domainValue = attributeValue
            "path" -> pathValue = attributeValue
            "max-age" -> maxAgeValue = attributeValue
            "expires" -> expiresValue = attributeValue
        }
    }

    val domainPresent = "domain" in seenAttributes
    val pathPresent = "path" in seenAttributes
    val maxAgePresent = "max-age" in seenAttributes
    val expiresPresent = "expires" in seenAttributes
    val domainScope = classifyDomainScope(domainPresent, domainValue, requestHost).also {
        if (it == SessionDomainScope.INVALID) warnings += SessionCookieWarning.INVALID_DOMAIN
    }
    val pathScope = classifyPathScope(pathPresent, pathValue, requestPath).also {
        if (it == SessionPathScope.INVALID) warnings += SessionCookieWarning.INVALID_PATH
    }
    val lifetime = classifyLifetime(maxAgePresent, maxAgeValue, expiresPresent, expiresValue, warnings)
    val prefix = when {
        name.startsWith("__Host-") -> SessionCookiePrefix.HOST
        name.startsWith("__Secure-") -> SessionCookiePrefix.SECURE
        else -> SessionCookiePrefix.NONE
    }
    val prefixCompliant = when (prefix) {
        SessionCookiePrefix.HOST -> secure && secureTransport && domainScope == SessionDomainScope.HOST_ONLY &&
            pathScope == SessionPathScope.ROOT
        SessionCookiePrefix.SECURE -> secure && secureTransport
        SessionCookiePrefix.NONE -> null
    }
    if (prefixCompliant == false) warnings += SessionCookieWarning.PREFIX_NOT_COMPLIANT
    if (sameSite == SessionSameSite.NONE && !secure) {
        warnings += SessionCookieWarning.SAME_SITE_NONE_WITHOUT_SECURE
    }

    return SessionResponseCookie(
        name = name,
        secure = secure,
        httpOnly = httpOnly,
        partitioned = partitioned,
        sameSite = sameSite,
        domainScope = domainScope,
        pathScope = pathScope,
        lifetime = lifetime,
        domainPresent = domainPresent,
        pathPresent = pathPresent,
        maxAgePresent = maxAgePresent,
        expiresPresent = expiresPresent,
        prefix = prefix,
        prefixCompliant = prefixCompliant,
        warnings = warnings.toList(),
    )
}

private fun classifyDomainScope(
    present: Boolean,
    rawDomain: String?,
    rawRequestHost: String,
): SessionDomainScope {
    if (!present) return SessionDomainScope.HOST_ONLY
    val requestHost = normalizeCookieHost(rawRequestHost) ?: return SessionDomainScope.INVALID
    val domain = rawDomain?.takeIf { it.isNotEmpty() && it == it.trim() }
        ?.removePrefix(".")
        ?.lowercase()
        ?.takeIf { normalizeCookieHost(it) == it }
        ?: return SessionDomainScope.INVALID
    return when {
        domain == requestHost -> SessionDomainScope.EXPLICIT_SAME_HOST
        requestHost.endsWith(".$domain") && !isIpAddress(requestHost) -> SessionDomainScope.PARENT_DOMAIN
        else -> SessionDomainScope.UNRELATED
    }
}

private fun normalizeCookieHost(raw: String): String? {
    val value = raw.trimEnd('.').lowercase()
    if (value.isEmpty() || value.length > 253 || value.any { it.code !in 0x21..0x7e }) return null
    if (isIpAddress(value)) return value
    if (value.split('.').any { label ->
            label.isEmpty() || label.length > 63 || label.first() == '-' || label.last() == '-' ||
                label.any { !it.isLetterOrDigit() && it != '-' }
        }
    ) return null
    return value
}

private fun isIpAddress(value: String): Boolean =
    value.contains(':') || value.split('.').size == 4 && value.split('.').all { part ->
        part.toIntOrNull()?.let { it in 0..255 } == true
    }

private fun classifyPathScope(
    present: Boolean,
    rawPath: String?,
    requestPath: String,
): SessionPathScope {
    if (!present) return SessionPathScope.DEFAULT
    val path = rawPath?.takeIf { it.isNotEmpty() && it == it.trim() && it.startsWith('/') }
        ?: return SessionPathScope.INVALID
    if (path == "/") return SessionPathScope.ROOT
    val matchesRequestPath = requestPath.startsWith(path) &&
        (path.endsWith('/') || requestPath.length == path.length || requestPath.getOrNull(path.length) == '/')
    return if (matchesRequestPath) SessionPathScope.REQUEST_PATH_PREFIX else SessionPathScope.OTHER
}

private fun HttpMessageReference.sessionAnalysisIdentity(): Pair<HttpMessageSource, String> = source to when (source) {
    HttpMessageSource.SITE_MAP -> id
    HttpMessageSource.PROXY, HttpMessageSource.ORGANIZER -> id.toIntOrNull()?.takeIf { it >= 0 }?.toString() ?: id
}

private fun classifyLifetime(
    maxAgePresent: Boolean,
    maxAgeValue: String?,
    expiresPresent: Boolean,
    expiresValue: String?,
    warnings: MutableSet<SessionCookieWarning>,
): SessionCookieLifetime {
    if (maxAgePresent) {
        val maxAge = maxAgeValue?.takeIf { MAX_AGE_PATTERN.matches(it) }?.toLongOrNull()
        if (maxAge == null) {
            warnings += SessionCookieWarning.INVALID_MAX_AGE
            return SessionCookieLifetime.INVALID
        }
        return if (maxAge <= 0) SessionCookieLifetime.DELETION else SessionCookieLifetime.PERSISTENT
    }
    if (expiresPresent) {
        if (!validCookieExpires(expiresValue)) {
            warnings += SessionCookieWarning.INVALID_EXPIRES
            return SessionCookieLifetime.INVALID
        }
        return SessionCookieLifetime.PERSISTENT
    }
    return SessionCookieLifetime.SESSION
}

private val RFC_850_COOKIE_EXPIRES_FORMATTER = DateTimeFormatterBuilder()
    .parseCaseInsensitive()
    .appendPattern("EEEE, dd-MMM-")
    .appendValueReduced(ChronoField.YEAR, 2, 2, 1970)
    .appendPattern(" HH:mm:ss zzz")
    .toFormatter(Locale.US)
    .withResolverStyle(ResolverStyle.SMART)
private val ASCTIME_COOKIE_EXPIRES_FORMATTER = DateTimeFormatter.ofPattern(
    "EEE MMM d HH:mm:ss uuuu",
    Locale.US,
).withResolverStyle(ResolverStyle.SMART)

private fun validCookieExpires(value: String?): Boolean {
    if (value == null) return false
    if (runCatching { ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME) }.isSuccess) return true
    if (runCatching { ZonedDateTime.parse(value, RFC_850_COOKIE_EXPIRES_FORMATTER) }.isSuccess) return true
    return runCatching { LocalDateTime.parse(value, ASCTIME_COOKIE_EXPIRES_FORMATTER) }.isSuccess
}

private fun isCookieName(name: String): Boolean =
    name.length in 1..MAX_COOKIE_NAME_CHARS && name.all { it.code in 0x21..0x7e && it !in COOKIE_NAME_SEPARATORS }

private val COOKIE_NAME_SEPARATORS = setOf('(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}', ' ', '\t')
private val FOLDED_SET_COOKIE_PATTERN = Regex(",\\s*[!#$%&'*+.^_`|~A-Za-z0-9-]{1,128}=")
private val MAX_AGE_PATTERN = Regex("-?[0-9]+")
private val RECOGNIZED_COOKIE_ATTRIBUTES = setOf(
    "secure",
    "httponly",
    "partitioned",
    "samesite",
    "domain",
    "path",
    "max-age",
    "expires",
)
private val REDIRECT_STATUS_CODES = setOf(301, 302, 303, 307, 308)

private fun endpointRoles(rawPath: String): List<SessionEndpointRole> {
    val path = rawPath.take(MAX_SESSION_HEADER_LINE_CHARS).substringBefore('?').substringBefore('#')
    val tokens = path.lowercase().split('/', '-', '_', '.').filter(String::isNotEmpty).toSet()
    return buildList {
        if (tokens.any { it in setOf("login", "signin", "logon", "authenticate") }) add(SessionEndpointRole.LOGIN)
        if (tokens.any { it in setOf("logout", "signout", "logoff") }) add(SessionEndpointRole.LOGOUT)
        if (tokens.any { it in setOf("refresh", "renew") }) add(SessionEndpointRole.REFRESH)
    }
}

private fun redirectEvidence(
    rawLocation: String,
    requestHost: String,
    requestPort: Int,
    requestSecure: Boolean,
): Pair<SessionRedirectRelation, List<SessionEndpointRole>> = try {
    val uri = URI(rawLocation)
    val roles = endpointRoles(uri.rawPath.orEmpty())
    when {
        !uri.isAbsolute && uri.host == null -> SessionRedirectRelation.RELATIVE to roles
        uri.host == null -> SessionRedirectRelation.UNKNOWN to emptyList()
        uri.scheme != null && uri.scheme.lowercase() !in setOf("http", "https") ->
            SessionRedirectRelation.UNKNOWN to emptyList()
        else -> {
            val scheme = uri.scheme?.lowercase()
            val secure = scheme == "https" || scheme == null && requestSecure
            val defaultPort = if (secure) 443 else 80
            val port = if (uri.port < 0) defaultPort else uri.port
            val same = uri.host.equals(requestHost, ignoreCase = true) && port == requestPort && secure == requestSecure
            (if (same) SessionRedirectRelation.SAME_ORIGIN else SessionRedirectRelation.CROSS_ORIGIN) to roles
        }
    }
} catch (_: Exception) {
    SessionRedirectRelation.UNKNOWN to emptyList()
}

private fun isCsrfTokenHeader(name: String): Boolean {
    val normalized = name.lowercase()
    return normalized in setOf("x-csrf-token", "x-xsrf-token", "csrf-token", "xsrf-token")
}

private fun crossMessageCookies(
    messages: List<HttpSessionMessageSummary>,
    completeCookieEvidence: Boolean,
): List<SessionCookieCrossMessageSummary> {
    val names = LinkedHashSet<String>()
    messages.forEach { message ->
        names += message.requestCookieNames
        message.responseCookies.forEach { names += it.name }
    }
    return names.take(MAX_SESSION_COOKIES_PER_ANALYSIS).map { name ->
        val occurrences = messages.flatMap { message ->
            message.responseCookies.filter { it.name == name }.map { message.index to it }
        }
        val invariant = ArrayList<SessionCookieAttribute>()
        val variant = ArrayList<SessionCookieAttribute>()
        if (completeCookieEvidence && occurrences.size >= 2 && occurrences.all { it.second.warnings.isEmpty() }) {
            compareCookieAttribute(occurrences.map { it.second.secure }, SessionCookieAttribute.SECURE, invariant, variant)
            compareCookieAttribute(occurrences.map { it.second.httpOnly }, SessionCookieAttribute.HTTP_ONLY, invariant, variant)
            compareCookieAttribute(occurrences.map { it.second.partitioned }, SessionCookieAttribute.PARTITIONED, invariant, variant)
            compareCookieAttribute(occurrences.map { it.second.sameSite }, SessionCookieAttribute.SAME_SITE, invariant, variant)
            compareCookieAttribute(occurrences.map { it.second.domainScope }, SessionCookieAttribute.DOMAIN_SCOPE, invariant, variant)
            compareCookieAttribute(occurrences.map { it.second.pathScope }, SessionCookieAttribute.PATH_SCOPE, invariant, variant)
            compareCookieAttribute(occurrences.map { it.second.lifetime }, SessionCookieAttribute.LIFETIME, invariant, variant)
            compareCookieAttribute(occurrences.map { it.second.prefix }, SessionCookieAttribute.PREFIX, invariant, variant)
            compareCookieAttribute(occurrences.map { it.second.prefixCompliant }, SessionCookieAttribute.PREFIX_COMPLIANT, invariant, variant)
            compareCookieAttribute(occurrences.map { it.second.maxAgePresent }, SessionCookieAttribute.MAX_AGE_PRESENT, invariant, variant)
            compareCookieAttribute(occurrences.map { it.second.expiresPresent }, SessionCookieAttribute.EXPIRES_PRESENT, invariant, variant)
        }
        SessionCookieCrossMessageSummary(
            name = name,
            setOnMessageIndices = occurrences.map { it.first }.distinct(),
            sentOnMessageIndices = messages.filter { name in it.requestCookieNames }.map { it.index },
            invariantAttributes = invariant,
            variantAttributes = variant,
        )
    }
}

private fun <T> compareCookieAttribute(
    states: List<T>,
    attribute: SessionCookieAttribute,
    invariant: MutableList<SessionCookieAttribute>,
    variant: MutableList<SessionCookieAttribute>,
) {
    if (states.distinct().size == 1) invariant += attribute else variant += attribute
}

private fun crossMessageSignals(
    messages: List<HttpSessionMessageSummary>,
    budget: SessionAnalysisBudget,
): Pair<List<SessionSecurityAttribute>, List<SessionSecurityAttribute>> {
    if (messages.size < 2 || budget.headersTruncated || budget.selectedCharsTruncated || budget.cookiesTruncated) {
        return emptyList<SessionSecurityAttribute>() to emptyList()
    }
    val invariant = ArrayList<SessionSecurityAttribute>()
    val variant = ArrayList<SessionSecurityAttribute>()
    compareSignal(messages.map { it.requestSignals.authorizationPresent }, SessionSecurityAttribute.REQUEST_AUTHORIZATION_PRESENT, invariant, variant)
    compareSignal(messages.map { it.requestSignals.cookiePresent }, SessionSecurityAttribute.REQUEST_COOKIE_PRESENT, invariant, variant)
    val withResponses = messages.filter { it.responseSignals != null }
    if (withResponses.size >= 2) {
        compareSignal(withResponses.map { it.responseSignals!!.setCookiePresent }, SessionSecurityAttribute.RESPONSE_SET_COOKIE_PRESENT, invariant, variant)
        compareSignal(withResponses.map { it.responseSignals!!.authChallengePresent }, SessionSecurityAttribute.RESPONSE_AUTH_CHALLENGE_PRESENT, invariant, variant)
        compareSignal(withResponses.map { it.redirect != null }, SessionSecurityAttribute.REDIRECT_PRESENT, invariant, variant)
    }
    return invariant to variant
}

private fun compareSignal(
    states: List<Boolean>,
    attribute: SessionSecurityAttribute,
    invariant: MutableList<SessionSecurityAttribute>,
    variant: MutableList<SessionSecurityAttribute>,
) {
    if (states.distinct().size == 1) invariant += attribute else variant += attribute
}

private fun HttpMessageResolutionStatus.toSessionAnalysisStatus(): HttpSessionAnalysisStatus = when (this) {
    HttpMessageResolutionStatus.ACCESS_DENIED -> HttpSessionAnalysisStatus.ACCESS_DENIED
    HttpMessageResolutionStatus.INVALID_ARGUMENT -> HttpSessionAnalysisStatus.INVALID_ARGUMENT
    HttpMessageResolutionStatus.INVALID_ID -> HttpSessionAnalysisStatus.INVALID_ID
    HttpMessageResolutionStatus.PROJECT_MISMATCH -> HttpSessionAnalysisStatus.PROJECT_MISMATCH
    HttpMessageResolutionStatus.NOT_FOUND -> HttpSessionAnalysisStatus.NOT_FOUND
    HttpMessageResolutionStatus.REQUEST_UNAVAILABLE -> HttpSessionAnalysisStatus.REQUEST_UNAVAILABLE
    HttpMessageResolutionStatus.BURP_ERROR -> HttpSessionAnalysisStatus.BURP_ERROR
}

private fun sessionAnalysisError(
    status: HttpSessionAnalysisStatus,
    projectId: String?,
    refs: List<HttpMessageReference>,
    error: String,
    errorRefIndex: Int? = null,
) = AnalyzeHttpSessionSecurityResult(
    status = status,
    projectId = projectId?.take(MAX_HTTP_REFERENCE_PROJECT_ID_CHARS),
    refs = refs.take(MAX_SESSION_ANALYSIS_MESSAGES).map {
        HttpMessageReference(it.source, it.id.take(MAX_HTTP_REFERENCE_ID_CHARS))
    },
    messages = emptyList(),
    cookieSummaries = emptyList(),
    invariants = emptyList(),
    variants = emptyList(),
    evidence = HttpSessionEvidenceBounds(
        selectedMessages = 0,
        messagesWithResponses = 0,
        headersScanned = 0,
        selectedHeaderValuesInspected = 0,
        selectedHeaderCharsInspected = 0,
        cookiesObserved = 0,
        redirectHopsInspected = 0,
        headersTruncated = false,
        selectedCharsTruncated = false,
        cookiesTruncated = false,
        redirectHopsTruncated = false,
    ),
    errorRefIndex = errorRefIndex,
    error = error.take(512),
)
