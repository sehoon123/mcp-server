package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import io.mockk.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HttpSessionSecurityAnalyzerTest {
    private val api = mockk<MontoyaApi>()
    private val project = mockk<Project>()
    private val proxy = mockk<Proxy>()
    private val logging = mockk<Logging>(relaxed = true)
    private lateinit var originalDataHandler: DataAccessApprovalHandler

    @BeforeEach
    fun setUp() {
        originalDataHandler = DataAccessSecurity.approvalHandler
        every { api.project() } returns project
        every { project.id() } returns "project-session"
        every { api.proxy() } returns proxy
        every { api.logging() } returns logging
    }

    @AfterEach
    fun tearDown() {
        DataAccessSecurity.approvalHandler = originalDataHandler
    }

    @Test
    fun `ordered flow returns bounded useful signals without secrets or body and auth value access`() = runBlocking {
        val authorization = header("Authorization", "AUTHORIZATION_VALUE_SENTINEL")
        val csrf = header("X-CSRF-Token", "CSRF_VALUE_SENTINEL")
        val requestCookie = header("Cookie", "sid=COOKIE_VALUE_SENTINEL")
        val setCookie = header(
            "Set-Cookie",
            "sid=SET_COOKIE_VALUE_SENTINEL; Secure; HttpOnly; SameSite=Lax; " +
                "Domain=domain-value-sentinel.test; Path=/path-value-sentinel; " +
                "Expires=Wed, 21 Oct 2015 07:28:00 GMT; Max-Age=3600",
        )
        val challenge = header("WWW-Authenticate", "CHALLENGE_VALUE_SENTINEL")
        val location = header("Location", "https://other.test/refresh/LOCATION_VALUE_SENTINEL?token=QUERY_SENTINEL")
        val firstRequest = request("POST", "/account/login?credential=PATH_QUERY_SENTINEL", listOf(authorization, csrf))
        val secondRequest = request("GET", "/account/logout", listOf(requestCookie))
        val firstResponse = response(302, listOf(setCookie, challenge, location))
        val secondResponse = response(200, listOf(header("Set-Cookie", "sid=DELETE_VALUE_SENTINEL; Secure; HttpOnly; SameSite=None")))
        val first = proxyItem(1, firstRequest, firstResponse)
        val second = proxyItem(2, secondRequest, secondResponse)
        every { proxy.history(any()) } returnsMany listOf(listOf(first), listOf(second))

        val result = service().analyze(
            AnalyzeHttpSessionSecurity("project-session", refs(1, 2)),
            config(requireDataApproval = false),
        )

        assertEquals(HttpSessionAnalysisStatus.OK, result.status)
        assertEquals(refs(1, 2), result.refs)
        assertEquals(listOf(SessionEndpointRole.LOGIN, SessionEndpointRole.REDIRECT), result.messages[0].roles)
        assertEquals(listOf(SessionEndpointRole.LOGOUT), result.messages[1].roles)
        assertTrue(result.messages[0].requestSignals.authorizationPresent)
        assertTrue(result.messages[0].requestSignals.csrfTokenHeaderPresent)
        assertTrue(result.messages[1].requestSignals.cookiePresent)
        assertEquals(listOf("sid"), result.messages[1].requestCookieNames)
        assertEquals(SessionSameSite.LAX, result.messages[0].responseCookies.single().sameSite)
        assertTrue(result.messages[0].responseCookies.single().secure)
        assertTrue(result.messages[0].responseCookies.single().httpOnly)
        assertEquals(SessionDomainScope.UNRELATED, result.messages[0].responseCookies.single().domainScope)
        assertEquals(SessionPathScope.OTHER, result.messages[0].responseCookies.single().pathScope)
        assertEquals(SessionCookieLifetime.PERSISTENT, result.messages[0].responseCookies.single().lifetime)
        assertTrue(result.messages[0].responseCookies.single().expiresPresent)
        assertTrue(result.messages[0].responseCookies.single().maxAgePresent)
        assertEquals(SessionRedirectRelation.CROSS_ORIGIN, result.messages[0].redirect?.relation)
        assertEquals(listOf(SessionEndpointRole.REFRESH), result.messages[0].redirect?.targetRoles)
        assertEquals(listOf(0, 1), result.cookieSummaries.single().setOnMessageIndices)
        assertEquals(listOf(1), result.cookieSummaries.single().sentOnMessageIndices)
        assertTrue(SessionCookieAttribute.SAME_SITE in result.cookieSummaries.single().variantAttributes)
        assertTrue(SessionCookieAttribute.DOMAIN_SCOPE in result.cookieSummaries.single().variantAttributes)
        assertTrue(SessionCookieAttribute.PATH_SCOPE in result.cookieSummaries.single().variantAttributes)
        assertTrue(SessionCookieAttribute.LIFETIME in result.cookieSummaries.single().variantAttributes)
        assertTrue(SessionCookieAttribute.PARTITIONED in result.cookieSummaries.single().invariantAttributes)
        assertTrue(result.evidence.proposedFlowOnly)
        assertFalse(result.evidence.chronologyOrCausalityEstablished)
        assertFalse(result.evidence.vulnerabilityAssessment)

        val serialized = Json.encodeToString(result)
        listOf(
            "AUTHORIZATION_VALUE_SENTINEL",
            "CSRF_VALUE_SENTINEL",
            "COOKIE_VALUE_SENTINEL",
            "SET_COOKIE_VALUE_SENTINEL",
            "DELETE_VALUE_SENTINEL",
            "CHALLENGE_VALUE_SENTINEL",
            "LOCATION_VALUE_SENTINEL",
            "QUERY_SENTINEL",
            "domain-value-sentinel.test",
            "/path-value-sentinel",
            "Wed, 21 Oct 2015 07:28:00 GMT",
            "3600",
            "PATH_QUERY_SENTINEL",
        ).forEach { assertFalse(serialized.contains(it), "leaked $it") }
        verify(exactly = 0) { authorization.value() }
        verify(exactly = 0) { csrf.value() }
        verify(exactly = 0) { challenge.value() }
        verify(exactly = 0) { firstRequest.body() }
        verify(exactly = 0) { secondRequest.body() }
        verify(exactly = 0) { firstRequest.toByteArray() }
        verify(exactly = 0) { firstResponse.body() }
        verify(exactly = 0) { secondResponse.body() }
        verify(exactly = 0) { firstResponse.toByteArray() }
        verify(exactly = 0) { logging.logToOutput(match<String> { "_VALUE_SENTINEL" in it }) }
        verify(exactly = 0) { logging.logToError(match<String> { "_VALUE_SENTINEL" in it }) }
    }

    @Test
    fun `response cookie classifications are value free and deterministic`() {
        data class Case(
            val header: String,
            val host: String = "example.test",
            val path: String = "/account/login",
            val secureTransport: Boolean = true,
            val domain: SessionDomainScope,
            val pathScope: SessionPathScope,
            val lifetime: SessionCookieLifetime,
            val sameSite: SessionSameSite = SessionSameSite.MISSING,
            val partitioned: Boolean = false,
            val prefix: SessionCookiePrefix = SessionCookiePrefix.NONE,
            val prefixCompliant: Boolean? = null,
            val warnings: Set<SessionCookieWarning> = emptySet(),
        )

        val cases = listOf(
            Case(
                header = "sid=PRIVATE; Secure; HttpOnly; Partitioned; SameSite=None; Path=/",
                domain = SessionDomainScope.HOST_ONLY,
                pathScope = SessionPathScope.ROOT,
                lifetime = SessionCookieLifetime.SESSION,
                sameSite = SessionSameSite.NONE,
                partitioned = true,
            ),
            Case(
                header = "sid=PRIVATE; Domain=example.test; Path=/account; Max-Age=3600; SameSite=Strict",
                domain = SessionDomainScope.EXPLICIT_SAME_HOST,
                pathScope = SessionPathScope.REQUEST_PATH_PREFIX,
                lifetime = SessionCookieLifetime.PERSISTENT,
                sameSite = SessionSameSite.STRICT,
            ),
            Case(
                header = "sid=PRIVATE; Domain=.example.test; Path=/other; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
                host = "app.example.test",
                domain = SessionDomainScope.PARENT_DOMAIN,
                pathScope = SessionPathScope.OTHER,
                lifetime = SessionCookieLifetime.PERSISTENT,
            ),
            Case(
                header = "sid=PRIVATE; Expires=Sunday, 06-Nov-94 08:49:37 GMT",
                domain = SessionDomainScope.HOST_ONLY,
                pathScope = SessionPathScope.DEFAULT,
                lifetime = SessionCookieLifetime.PERSISTENT,
            ),
            Case(
                header = "sid=PRIVATE; Domain=unrelated.test; Max-Age=0",
                domain = SessionDomainScope.UNRELATED,
                pathScope = SessionPathScope.DEFAULT,
                lifetime = SessionCookieLifetime.DELETION,
            ),
            Case(
                header = "__Host-sid=PRIVATE; Secure; Path=/",
                domain = SessionDomainScope.HOST_ONLY,
                pathScope = SessionPathScope.ROOT,
                lifetime = SessionCookieLifetime.SESSION,
                prefix = SessionCookiePrefix.HOST,
                prefixCompliant = true,
            ),
            Case(
                header = "__Secure-sid=PRIVATE; Secure",
                domain = SessionDomainScope.HOST_ONLY,
                pathScope = SessionPathScope.DEFAULT,
                lifetime = SessionCookieLifetime.SESSION,
                prefix = SessionCookiePrefix.SECURE,
                prefixCompliant = true,
            ),
            Case(
                header = "__Host-sid=PRIVATE; Secure; Domain=example.test; Path=/",
                domain = SessionDomainScope.EXPLICIT_SAME_HOST,
                pathScope = SessionPathScope.ROOT,
                lifetime = SessionCookieLifetime.SESSION,
                prefix = SessionCookiePrefix.HOST,
                prefixCompliant = false,
                warnings = setOf(SessionCookieWarning.PREFIX_NOT_COMPLIANT),
            ),
            Case(
                header = "sid=PRIVATE; Domain=; Domain=bad_domain; Path=relative; Max-Age=nope; SameSite=odd",
                domain = SessionDomainScope.INVALID,
                pathScope = SessionPathScope.INVALID,
                lifetime = SessionCookieLifetime.INVALID,
                sameSite = SessionSameSite.INVALID,
                warnings = setOf(
                    SessionCookieWarning.DUPLICATE_ATTRIBUTE,
                    SessionCookieWarning.INVALID_DOMAIN,
                    SessionCookieWarning.INVALID_PATH,
                    SessionCookieWarning.INVALID_MAX_AGE,
                    SessionCookieWarning.INVALID_SAME_SITE,
                ),
            ),
            Case(
                header = "sid=PRIVATE; Secure=bad; Secure; Expires=not-a-date",
                domain = SessionDomainScope.HOST_ONLY,
                pathScope = SessionPathScope.DEFAULT,
                lifetime = SessionCookieLifetime.INVALID,
                warnings = setOf(
                    SessionCookieWarning.MALFORMED_ATTRIBUTE,
                    SessionCookieWarning.DUPLICATE_ATTRIBUTE,
                    SessionCookieWarning.INVALID_EXPIRES,
                ),
            ),
            Case(
                header = "sid=PRIVATE; Expires=Wed, 21 Oct 2015 07:28:00 GMT, second=SECRET; Secure=bad; Secure",
                domain = SessionDomainScope.HOST_ONLY,
                pathScope = SessionPathScope.DEFAULT,
                lifetime = SessionCookieLifetime.PERSISTENT,
                warnings = setOf(SessionCookieWarning.AMBIGUOUS_FOLDED_HEADER),
            ),
        )

        cases.forEachIndexed { index, case ->
            val parsed = requireNotNull(
                parseSessionResponseCookie(case.header, case.host, case.path, case.secureTransport)
            )
            assertEquals(case.domain, parsed.domainScope, "domain case $index")
            assertEquals(case.pathScope, parsed.pathScope, "path case $index")
            assertEquals(case.lifetime, parsed.lifetime, "lifetime case $index")
            assertEquals(case.sameSite, parsed.sameSite, "SameSite case $index")
            assertEquals(case.partitioned, parsed.partitioned, "Partitioned case $index")
            assertEquals(case.prefix, parsed.prefix, "prefix case $index")
            assertEquals(case.prefixCompliant, parsed.prefixCompliant, "prefix compliance case $index")
            assertTrue(parsed.warnings.containsAll(case.warnings), "warnings case $index: ${parsed.warnings}")
            assertFalse(Json.encodeToString(parsed).contains("PRIVATE"), "cookie value leaked in case $index")
            assertFalse(Json.encodeToString(parsed).contains("SECRET"), "folded value leaked in case $index")
        }
    }

    @Test
    fun `exactly 32 distinct references preserve caller order with one source approval`() = runBlocking {
        val orderedIds = (1..32).toList().reversed()
        var approvals = 0
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                approvals++
                return true
            }
        }
        val items = orderedIds.map { id -> proxyItem(id, request("GET", "/session/$id"), response(200)) }
        every { proxy.history(any()) } returnsMany items.map(::listOf)

        val result = service().analyze(
            AnalyzeHttpSessionSecurity("project-session", refs(*orderedIds.toIntArray())),
            config(true),
        )

        assertEquals(HttpSessionAnalysisStatus.OK, result.status)
        assertEquals(1, approvals)
        assertEquals(32, result.messages.size)
        assertEquals(orderedIds.map(Int::toString), result.messages.map { it.ref.id })
        assertEquals(listOf("2", "1"), result.messages.takeLast(2).map { it.ref.id })
        verify(exactly = 32) { proxy.history(any()) }
    }

    @Test
    fun `duplicate references are rejected before project approval or source access`() = runBlocking {
        val result = service().analyze(
            AnalyzeHttpSessionSecurity("project-session", refs(7, 7)),
            config(requireDataApproval = true),
        )

        assertEquals(HttpSessionAnalysisStatus.INVALID_ARGUMENT, result.status)
        assertEquals("refs must not contain duplicates", result.error)
        assertTrue(result.messages.isEmpty())

        val aliased = service().analyze(
            AnalyzeHttpSessionSecurity(
                "project-session",
                listOf(
                    HttpMessageReference(HttpMessageSource.PROXY, "1"),
                    HttpMessageReference(HttpMessageSource.PROXY, "01"),
                ),
            ),
            config(requireDataApproval = true),
        )
        assertEquals(HttpSessionAnalysisStatus.INVALID_ARGUMENT, aliased.status)
        assertEquals("refs must not contain duplicates", aliased.error)
        assertTrue(aliased.messages.isEmpty())
        verify(exactly = 0) { api.project() }
        verify(exactly = 0) { api.proxy() }
        verify(exactly = 0) { proxy.history(any()) }
    }

    @Test
    fun `33 references are rejected before project approval or source access`() = runBlocking {
        val result = service().analyze(
            AnalyzeHttpSessionSecurity("project-session", refs(*(1..33).toList().toIntArray())),
            config(requireDataApproval = true),
        )

        assertEquals(HttpSessionAnalysisStatus.INVALID_ARGUMENT, result.status)
        assertTrue(result.messages.isEmpty())
        assertEquals(32, result.refs.size)
        verify(exactly = 0) { api.project() }
        verify(exactly = 0) { api.proxy() }
        verify(exactly = 0) { proxy.history(any()) }
    }

    @Test
    fun `resolver approval project transition prevents source access`() = runBlocking {
        var currentProject = "project-session"
        every { project.id() } answers { currentProject }
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean {
                currentProject = "other-project"
                return true
            }
        }

        val result = service().analyze(
            AnalyzeHttpSessionSecurity("project-session", refs(1, 2)),
            config(requireDataApproval = true),
        )

        assertEquals(HttpSessionAnalysisStatus.PROJECT_MISMATCH, result.status)
        assertEquals("other-project", result.projectId)
        assertTrue(result.messages.isEmpty())
        verify(exactly = 0) { proxy.history(any()) }
    }

    @Test
    fun `project transition during bounded header analysis discards prepared evidence`() = runBlocking {
        var currentProject = "project-session"
        every { project.id() } answers { currentProject }
        val trigger = header("X-Test", "unused")
        every { trigger.name() } answers {
            currentProject = "other-project"
            "X-Test"
        }
        val item = proxyItem(1, request("GET", "/login", listOf(trigger)), response(200))
        every { proxy.history(any()) } returns listOf(item)

        val result = service().analyze(
            AnalyzeHttpSessionSecurity("project-session", refs(1)),
            config(false),
        )

        assertEquals(HttpSessionAnalysisStatus.PROJECT_MISMATCH, result.status)
        assertTrue(result.messages.isEmpty())
        assertTrue(result.cookieSummaries.isEmpty())
    }

    @Test
    fun `endpoint role processing ignores tokens beyond the path character cap`() = runBlocking {
        val oversizedPath = "/" + "a".repeat(MAX_SESSION_HEADER_LINE_CHARS) + "/login?secret=PATH_SENTINEL"
        val item = proxyItem(1, request("GET", oversizedPath), response(200))
        every { proxy.history(any()) } returns listOf(item)

        val result = service().analyze(
            AnalyzeHttpSessionSecurity("project-session", refs(1)),
            config(false),
        )

        assertEquals(HttpSessionAnalysisStatus.OK, result.status)
        assertTrue(result.messages.single().roles.isEmpty())
        assertFalse(Json.encodeToString(result).contains("PATH_SENTINEL"))
    }

    @Test
    fun `malformed and oversized headers produce fixed warnings and bounded output`() = runBlocking {
        val oversized = header("Cookie", "sid=${"SENSITIVE_VALUE".repeat(1_000)}")
        val malformed = header("Set-Cookie", "not-a-cookie")
        val cookies = (0 until 40).map { header("Set-Cookie", "cookie$it=PRIVATE_$it; Secure") }
        val requestHeaders = (0 until 127).map { header("X-$it", "ignored") } + oversized + header("X-TAIL", "TAIL_SENTINEL")
        val responseHeaders = listOf(malformed) + cookies
        val req = request("GET", "/session", requestHeaders)
        val res = response(200, responseHeaders)
        val item = proxyItem(1, req, res)
        every { proxy.history(any()) } returns listOf(item)

        val result = service().analyze(
            AnalyzeHttpSessionSecurity("project-session", refs(1)),
            config(false),
        )

        assertEquals(HttpSessionAnalysisStatus.OK, result.status)
        assertTrue(result.evidence.headersTruncated)
        assertTrue(result.evidence.selectedCharsTruncated)
        assertTrue(result.evidence.cookiesTruncated)
        assertTrue(result.evidence.headersScanned <= MAX_SESSION_HEADERS_PER_PART * 2)
        assertTrue(result.evidence.selectedHeaderCharsInspected <= MAX_SESSION_SELECTED_HEADER_CHARS)
        assertTrue(result.evidence.cookiesObserved <= MAX_SESSION_COOKIES_PER_MESSAGE * 2)
        assertEquals(MAX_SESSION_COOKIES_PER_MESSAGE, result.evidence.maxRequestCookieNamesPerMessage)
        assertEquals(MAX_SESSION_COOKIES_PER_MESSAGE, result.evidence.maxResponseCookiesPerMessage)
        assertTrue(result.messages.single().responseCookies.size <= MAX_SESSION_COOKIES_PER_MESSAGE)
        assertTrue(SessionEvidenceWarning.MALFORMED_SET_COOKIE_HEADER in result.messages.single().evidenceWarnings)
        assertFalse(Json.encodeToString(result).contains("SENSITIVE_VALUE"))
        verify(exactly = 0) { requestHeaders.last().name() }
        cookies.drop(MAX_SESSION_COOKIES_PER_MESSAGE).forEach { verify(exactly = 0) { it.value() } }
    }

    @Test
    fun `accessor failures return fixed errors without secret exception text`() = runBlocking {
        val dangerous = mockk<HttpHeader>()
        every { dangerous.name() } throws IllegalStateException("COOKIE_ERROR_VALUE_SENTINEL")
        val item = proxyItem(1, request("GET", "/session", listOf(dangerous)), response(200))
        every { proxy.history(any()) } returns listOf(item)

        val result = service().analyze(
            AnalyzeHttpSessionSecurity("project-session", refs(1)),
            config(false),
        )

        assertEquals(HttpSessionAnalysisStatus.BURP_ERROR, result.status)
        assertTrue(result.messages.isEmpty())
        assertFalse(Json.encodeToString(result).contains("COOKIE_ERROR_VALUE_SENTINEL"))
        verify(exactly = 0) { logging.logToOutput(match<String> { "COOKIE_ERROR_VALUE_SENTINEL" in it }) }
        verify(exactly = 0) { logging.logToError(match<String> { "COOKIE_ERROR_VALUE_SENTINEL" in it }) }
    }

    @Test
    fun `unsupported absolute redirect schemes are not classified as same origin`() = runBlocking {
        val location = header("Location", "ftp://example.test/private/LOCATION_SCHEME_SENTINEL")
        val item = proxyItem(
            1,
            request("GET", "/session", port = 80, secure = false),
            response(302, listOf(location)),
        )
        every { proxy.history(any()) } returns listOf(item)

        val result = service().analyze(
            AnalyzeHttpSessionSecurity("project-session", refs(1)),
            config(false),
        )

        assertEquals(HttpSessionAnalysisStatus.OK, result.status)
        assertEquals(SessionRedirectRelation.UNKNOWN, result.messages.single().redirect?.relation)
        assertFalse(Json.encodeToString(result).contains("LOCATION_SCHEME_SENTINEL"))
    }

    @Test
    fun `redirect inspection stops at the explicit hop cap`() = runBlocking {
        val locations = (0..MAX_SESSION_REDIRECT_HOPS).map { index ->
            header("Location", "/refresh/private-$index")
        }
        val items = locations.mapIndexed { index, location ->
            proxyItem(index + 1, request("GET", "/session"), response(302, listOf(location)))
        }
        every { proxy.history(any()) } returnsMany items.map(::listOf)

        val result = service().analyze(
            AnalyzeHttpSessionSecurity("project-session", refs(*(1..items.size).toList().toIntArray())),
            config(false),
        )

        assertEquals(HttpSessionAnalysisStatus.OK, result.status)
        assertEquals(MAX_SESSION_REDIRECT_HOPS, result.evidence.redirectHopsInspected)
        assertTrue(result.evidence.redirectHopsTruncated)
        verify(exactly = 0) { locations.last().value() }
        assertEquals(SessionRedirectRelation.UNKNOWN, result.messages.last().redirect?.relation)
    }

    private fun service() = HttpSessionSecurityAnalyzerService(api)

    private fun config(requireDataApproval: Boolean): McpConfig {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers {
            when (firstArg<String>()) {
                "requireDataAccessApproval" -> requireDataApproval
                else -> false
            }
        }
        every { storage.getString(any()) } returns ""
        return McpConfig(storage, logging)
    }

    private fun refs(vararg ids: Int) = ids.map {
        HttpMessageReference(HttpMessageSource.PROXY, it.toString())
    }

    private fun proxyItem(id: Int, request: HttpRequest, response: HttpResponse?): ProxyHttpRequestResponse =
        mockk<ProxyHttpRequestResponse>().also {
            every { it.id() } returns id
            every { it.request() } returns request
            every { it.response() } returns response
        }

    private fun request(
        method: String,
        path: String,
        headers: List<HttpHeader> = emptyList(),
        host: String = "example.test",
        port: Int = 443,
        secure: Boolean = true,
    ): HttpRequest = mockk<HttpRequest>().also { request ->
        val service = mockk<HttpService>()
        every { service.host() } returns host
        every { service.port() } returns port
        every { service.secure() } returns secure
        every { request.method() } returns method
        every { request.path() } returns path
        every { request.headers() } returns headers
        every { request.httpService() } returns service
    }

    private fun response(status: Int, headers: List<HttpHeader> = emptyList()): HttpResponse =
        mockk<HttpResponse>().also {
            every { it.statusCode() } returns status.toShort()
            every { it.headers() } returns headers
        }

    private fun header(name: String, value: String): HttpHeader = mockk<HttpHeader>().also {
        every { it.name() } returns name
        every { it.value() } returns value
    }
}
