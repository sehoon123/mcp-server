package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.RedirectionMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.repeater.Repeater
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.RequestActionApprovalHandler
import net.portswigger.mcp.security.RequestActionSecurity
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class RawHttpToolsTest {
    private val api = mockk<MontoyaApi>()
    private val logging = mockk<Logging>(relaxed = true)
    private val storedBooleans = mutableMapOf<String, Boolean>()
    private lateinit var config: McpConfig
    private lateinit var service: RawHttpActionService
    private lateinit var originalRoutingApprovalHandler: RequestActionApprovalHandler

    @BeforeEach
    fun setUp() {
        originalRoutingApprovalHandler = RequestActionSecurity.approvalHandler
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers { storedBooleans[firstArg()] ?: false }
        every { storage.setBoolean(any(), any()) } answers { storedBooleans[firstArg()] = secondArg() }
        every { storage.getString(any()) } returns ""
        every { api.logging() } returns logging
        config = McpConfig(storage, logging)
        service = RawHttpActionService(api, config)
        mockkStatic(HttpService::class)
        mockkStatic(HttpRequest::class)
        mockkStatic(RequestOptions::class)
    }

    @AfterEach
    fun tearDown() {
        RequestActionSecurity.approvalHandler = originalRoutingApprovalHandler
        unmockkStatic(RequestOptions::class)
        unmockkStatic(HttpRequest::class)
        unmockkStatic(HttpService::class)
    }

    @Test
    fun `raw send enforces explicit HTTP mode timeout and redirect denial`() = runBlocking {
        val fixture = http1Fixture()
        val options = mockk<RequestOptions>()
        every { RequestOptions.requestOptions() } returns options
        every { options.withHttpMode(HttpMode.HTTP_1) } returns options
        every { options.withRedirectionMode(RedirectionMode.NEVER) } returns options
        every { options.withResponseTimeout(2500) } returns options
        val http = mockk<Http>()
        every { api.http() } returns http
        every { http.sendRequest(fixture.request, options) } returns null

        val result = service.send(
            SendRawHttpRequest(
                protocol = RawHttpProtocol.HTTP_1,
                http1 = RawHttp1Input("GET / HTTP/1.1\nHost: example.test\n\n"),
                targetHostname = "example.test",
                targetPort = 443,
                usesHttps = true,
                responseTimeoutMs = 2500,
                responseBodyLimit = 0,
            )
        )

        assertEquals(HttpMessageActionStatus.OK, result.status)
        assertEquals(HttpMessageExecutionState.COMPLETED, result.executionState)
        assertEquals(HttpMessageActionDestination.HTTP, result.destination)
        assertEquals(48, result.requestBytes)
        assertNull(result.response)
        assertEquals(false, result.recordedInSiteMap)
        verify(exactly = 1) { options.withHttpMode(HttpMode.HTTP_1) }
        verify(exactly = 1) { options.withRedirectionMode(RedirectionMode.NEVER) }
        verify(exactly = 1) { options.withResponseTimeout(2500) }
        verify(exactly = 1) { http.sendRequest(fixture.request, options) }
    }

    @Test
    fun `raw send reports post-delivery exceptions as execution uncertain`() = runBlocking {
        val fixture = http1Fixture()
        val options = mockk<RequestOptions>()
        every { RequestOptions.requestOptions() } returns options
        every { options.withHttpMode(HttpMode.HTTP_1) } returns options
        every { options.withRedirectionMode(RedirectionMode.NEVER) } returns options
        every { options.withResponseTimeout(30_000) } returns options
        val http = mockk<Http>()
        every { api.http() } returns http
        every { http.sendRequest(fixture.request, options) } throws IllegalStateException("secret /home/user/value")

        val result = service.send(defaultHttp1Send())

        assertEquals(HttpMessageActionStatus.EXECUTION_UNCERTAIN, result.status)
        assertEquals(HttpMessageExecutionState.UNCERTAIN, result.executionState)
        assertTrue(result.error.orEmpty().contains("do not retry automatically"))
        assertTrue(!result.error.orEmpty().contains("/home/user/value"))
    }

    @Test
    fun `protocol variant conflicts fail before factories or network access`() = runBlocking {
        val result = service.send(
            defaultHttp1Send().copy(
                http2 = RawHttp2Input(
                    pseudoHeaders = mapOf("method" to "GET", "path" to "/"),
                    headers = emptyMap(),
                    requestBody = "",
                )
            )
        )

        assertEquals(HttpMessageActionStatus.INVALID_ARGUMENT, result.status)
        assertEquals(HttpMessageExecutionState.NOT_STARTED, result.executionState)
        verify(exactly = 0) { HttpService.httpService(any(), any(), any()) }
        verify(exactly = 0) { api.http() }
    }

    @Test
    fun `raw routing preserves approval denial instead of claiming execution`() = runBlocking {
        http1Fixture()
        config.requireRequestActionApproval = true
        RequestActionSecurity.approvalHandler = object : RequestActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                source: String,
                target: String,
                changes: String,
                requestContent: String,
                config: McpConfig,
                api: MontoyaApi,
            ) = false
        }

        val result = service.route(defaultHttp1Route())

        assertEquals(HttpMessageActionStatus.ACTION_DENIED, result.status)
        assertEquals(HttpMessageExecutionState.NOT_STARTED, result.executionState)
        assertTrue(result.error.orEmpty().contains("denied"))
        verify(exactly = 0) { api.repeater() }
    }

    @Test
    fun `raw routing reports ambiguous Burp failures as execution uncertain`() = runBlocking {
        val fixture = http1Fixture()
        val repeater = mockk<Repeater>()
        every { api.repeater() } returns repeater
        every { repeater.sendToRepeater(fixture.request, "raw") } throws IllegalStateException("unknown")

        val result = service.route(defaultHttp1Route(tabName = "raw"))

        assertEquals(HttpMessageActionStatus.EXECUTION_UNCERTAIN, result.status)
        assertEquals(HttpMessageExecutionState.UNCERTAIN, result.executionState)
        assertTrue(result.error.orEmpty().contains("do not retry automatically"))
    }

    @Test
    fun `HTTP2 to Intruder is rejected before approval or request construction`() = runBlocking {
        val result = service.route(
            RouteRawHttpRequest(
                destination = RawHttpRouteDestination.INTRUDER,
                protocol = RawHttpProtocol.HTTP_2,
                http2 = RawHttp2Input(
                    pseudoHeaders = mapOf("method" to "GET", "path" to "/"),
                    headers = emptyMap(),
                    requestBody = "",
                ),
                targetHostname = "example.test",
                targetPort = 443,
                usesHttps = true,
            )
        )

        assertEquals(HttpMessageActionStatus.INVALID_ARGUMENT, result.status)
        assertTrue(result.error.orEmpty().contains("until verified"))
        verify(exactly = 0) { HttpService.httpService(any(), any(), any()) }
        verify(exactly = 0) { api.intruder() }
    }

    private fun http1Fixture(): Http1Fixture {
        val httpService = mockk<HttpService>()
        val request = mockk<HttpRequest>()
        val body = mockk<MontoyaByteArray>()
        every { HttpService.httpService("example.test", 443, true) } returns httpService
        every { HttpRequest.httpRequest(httpService, any<String>()) } returns request
        every { request.bodyOffset() } returns 48
        every { request.body() } returns body
        every { body.length() } returns 0
        return Http1Fixture(request)
    }

    private fun defaultHttp1Send() = SendRawHttpRequest(
        protocol = RawHttpProtocol.HTTP_1,
        http1 = RawHttp1Input("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
        targetHostname = "example.test",
        targetPort = 443,
        usesHttps = true,
    )

    private fun defaultHttp1Route(tabName: String? = null) = RouteRawHttpRequest(
        destination = RawHttpRouteDestination.REPEATER,
        protocol = RawHttpProtocol.HTTP_1,
        http1 = RawHttp1Input("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
        targetHostname = "example.test",
        targetPort = 443,
        usesHttps = true,
        tabName = tabName,
    )

    private data class Http1Fixture(val request: HttpRequest)
}
