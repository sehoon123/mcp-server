package net.portswigger.mcp.providers

import com.sun.net.httpserver.HttpServer
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import net.portswigger.mcp.MCP_SESSION_ID_HEADER
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors
import java.util.concurrent.Flow
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class JdkDoctorExchangeTest {
    @Test
    fun `status-only exchange does not wait for body completion and cancels the unread body`() {
        val client = mockk<HttpClient>(relaxed = true)
        val subscription = mockk<Flow.Subscription>(relaxed = true)
        every { client.send(any<HttpRequest>(), any<HttpResponse.BodyHandler<InputStream>>()) } answers {
            val subscriber = secondArg<HttpResponse.BodyHandler<InputStream>>().apply(mockk(relaxed = true))
            subscriber.onSubscribe(subscription)
            val body = subscriber.body.toCompletableFuture()
            // No onNext/onComplete: status collection must not depend on receiving or finishing a response body.
            assertTrue(body.isDone, "Doctor must collect status without waiting for response-body completion")
            mockk<HttpResponse<InputStream>> {
                every { statusCode() } returns 400
                every { body() } returns body.join()
            }
        }

        val result = JdkDoctorExchange { client }.execute(runningConfig())

        assertEquals(400, result)
        verify(exactly = 1) { subscription.cancel() }
        verify(exactly = 1) { client.close() }
    }

    @Test
    fun `status extraction failure still closes the body and HTTP client`() {
        val client = mockk<HttpClient>(relaxed = true)
        val body = mockk<InputStream>(relaxed = true)
        val response = mockk<HttpResponse<InputStream>> {
            every { body() } returns body
            every { statusCode() } throws IOException("synthetic status failure")
        }
        every { client.send(any<HttpRequest>(), any<HttpResponse.BodyHandler<InputStream>>()) } returns response

        assertThrows<IOException> { JdkDoctorExchange { client }.execute(runningConfig()) }

        verify(exactly = 0) { body.read() }
        verify(exactly = 1) { body.close() }
        verify(exactly = 1) { client.close() }
    }

    private fun runningConfig() = DoctorRequestConfig(
        "127.0.0.1", 9876, "a".repeat(43), DoctorListenerCode.RUNNING,
    )

    @Test
    fun `production exchange sends one controlled request and never follows redirects or retains response content`() {
        val firstRequests = AtomicInteger()
        val redirectedRequests = AtomicInteger()
        val body = AtomicReference<String>()
        val authorization = AtomicReference<String>()
        val accept = AtomicReference<String>()
        val contentType = AtomicReference<String>()
        val sessionId = AtomicReference<String>()
        val origin = AtomicReference<String?>()
        val protocol = AtomicReference<String>()
        val upgrade = AtomicReference<String?>()
        val proxyAuthorization = AtomicReference<String?>()
        val executor = Executors.newCachedThreadPool { runnable ->
            Thread(runnable, "doctor-test-http").apply { isDaemon = true }
        }
        val server = HttpServer.create(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0).apply {
            this.executor = executor
            createContext("/mcp") { exchange ->
                firstRequests.incrementAndGet()
                body.set(exchange.requestBody.readBytes().toString(StandardCharsets.UTF_8))
                authorization.set(exchange.requestHeaders.getFirst("Authorization"))
                accept.set(exchange.requestHeaders.getFirst("Accept"))
                contentType.set(exchange.requestHeaders.getFirst("Content-Type"))
                sessionId.set(exchange.requestHeaders.getFirst(MCP_SESSION_ID_HEADER))
                origin.set(exchange.requestHeaders.getFirst("Origin"))
                protocol.set(exchange.protocol)
                upgrade.set(exchange.requestHeaders.getFirst("Upgrade"))
                proxyAuthorization.set(exchange.requestHeaders.getFirst("Proxy-Authorization"))
                val response = "Bearer response-body-sentinel /Users/private/config".toByteArray()
                exchange.responseHeaders.add("Location", "/redirect-target")
                exchange.sendResponseHeaders(302, response.size.toLong())
                exchange.responseBody.use { it.write(response) }
            }
            createContext("/redirect-target") { exchange ->
                redirectedRequests.incrementAndGet()
                exchange.sendResponseHeaders(400, -1)
                exchange.close()
            }
            start()
        }

        try {
            val token = "doctor-production-transport-token-000001-abcd"
            val config = DoctorRequestConfig(
                host = "127.0.0.1",
                port = server.address.port,
                bearerToken = token,
                listener = DoctorListenerCode.RUNNING,
            )
            val report = ConnectionDoctor(JdkDoctorExchange()).run(config)

            assertEquals(DoctorProbeCode.INCOMPATIBLE_RESPONSE, report.probe)
            assertEquals(1, firstRequests.get())
            assertEquals(0, redirectedRequests.get())
            assertEquals("{}", body.get())
            assertEquals("Bearer $token", authorization.get())
            assertEquals("application/json, text/event-stream", accept.get())
            assertEquals("application/json", contentType.get())
            assertEquals(DOCTOR_SESSION_ID, sessionId.get())
            assertNull(origin.get())
            assertEquals("HTTP/1.1", protocol.get())
            assertNull(upgrade.get())
            assertNull(proxyAuthorization.get())
            val output = formatDoctorSummary(report) + formatDoctorEvidence(report)
            assertFalse(output.contains("response-body-sentinel"))
            assertFalse(output.contains("/Users/"))
            assertFalse(output.contains(token))
        } finally {
            server.stop(0)
            executor.shutdownNow()
        }
    }
}
