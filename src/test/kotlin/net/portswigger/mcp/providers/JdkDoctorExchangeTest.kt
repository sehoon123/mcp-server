package net.portswigger.mcp.providers

import com.sun.net.httpserver.HttpServer
import net.portswigger.mcp.MCP_SESSION_ID_HEADER
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull

class JdkDoctorExchangeTest {
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
