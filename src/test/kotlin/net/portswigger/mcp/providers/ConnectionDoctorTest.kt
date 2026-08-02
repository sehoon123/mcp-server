package net.portswigger.mcp.providers

import net.portswigger.mcp.MCP_MAX_SESSION_ID_CHARS
import net.portswigger.mcp.MCP_SESSION_ID_HEADER
import org.junit.jupiter.api.Test
import java.io.IOException
import java.net.ConnectException
import java.net.http.HttpClient
import java.net.http.HttpTimeoutException
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.concurrent.Flow
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ConnectionDoctorTest {
    private val token = "doctor-token-value-that-is-long-enough-0001"

    @Test
    fun `listener state mapping is closed and never echoes unknown input`() {
        assertEquals(DoctorListenerCode.RUNNING, doctorListenerCode("running"))
        assertEquals(DoctorListenerCode.STARTING, doctorListenerCode("starting"))
        assertEquals(DoctorListenerCode.STOPPING, doctorListenerCode("stopping"))
        assertEquals(DoctorListenerCode.STOPPED, doctorListenerCode("stopped"))
        assertEquals(DoctorListenerCode.FAILED, doctorListenerCode("failed"))
        assertEquals(DoctorListenerCode.UNAVAILABLE, doctorListenerCode(null))
        assertEquals(DoctorListenerCode.UNKNOWN, doctorListenerCode("Bearer sentinel /Users/private"))
    }

    @Test
    fun `status classification is exact and conservative`() {
        assertEquals(DoctorProbeCode.AUTHENTICATED_REACHABLE, classifyDoctorStatus(400))
        assertEquals(DoctorProbeCode.CREDENTIAL_REJECTED, classifyDoctorStatus(401))
        assertEquals(DoctorProbeCode.LOOPBACK_POLICY_REJECTED, classifyDoctorStatus(403))
        assertEquals(DoctorProbeCode.WRONG_ENDPOINT_OR_LISTENER, classifyDoctorStatus(404))
        assertEquals(DoctorProbeCode.LISTENER_BUSY, classifyDoctorStatus(429))
        assertEquals(DoctorProbeCode.LISTENER_BUSY, classifyDoctorStatus(503))
        listOf(200, 201, 301, 399, 402, 405, 500, 502, 504).forEach { status ->
            assertEquals(DoctorProbeCode.INCOMPATIBLE_RESPONSE, classifyDoctorStatus(status))
        }
    }

    @Test
    fun `inactive listener does not read or send a bearer`() {
        val calls = AtomicInteger()
        val doctor = ConnectionDoctor(DoctorExchange {
            calls.incrementAndGet()
            400
        })
        DoctorListenerCode.entries.filter { it != DoctorListenerCode.RUNNING }.forEach { listener ->
            val report = doctor.run(DoctorRequestConfig("127.0.0.1", 9876, null, listener))
            assertEquals(DoctorProbeCode.NOT_RUN_LISTENER_INACTIVE, report.probe)
        }
        assertEquals(0, calls.get())
    }

    @Test
    fun `invalid or mismatched local configuration performs no exchange`() {
        val calls = AtomicInteger()
        val doctor = ConnectionDoctor(DoctorExchange {
            calls.incrementAndGet()
            400
        })
        val invalid = listOf(
            DoctorRequestConfig("localhost", 9876, token, DoctorListenerCode.RUNNING),
            DoctorRequestConfig("127.0.0.1", 1, token, DoctorListenerCode.RUNNING),
            DoctorRequestConfig("127.0.0.1", 9876, null, DoctorListenerCode.RUNNING),
            DoctorRequestConfig("127.0.0.1", 9876, "a".repeat(42), DoctorListenerCode.RUNNING),
            DoctorRequestConfig("127.0.0.1", 9876, "a".repeat(129), DoctorListenerCode.RUNNING),
            DoctorRequestConfig("127.0.0.1", 9876, "a".repeat(42) + "!", DoctorListenerCode.RUNNING),
            DoctorRequestConfig(
                "127.0.0.1",
                9876,
                null,
                DoctorListenerCode.RUNNING,
                configurationValid = false,
            ),
        )
        invalid.forEach { config ->
            assertEquals(DoctorProbeCode.INVALID_CONFIGURATION, doctor.run(config).probe)
        }
        val mismatch = DoctorRequestConfig(
            "127.0.0.1",
            9876,
            null,
            DoctorListenerCode.RUNNING,
            endpointMatchesListener = false,
        )
        assertEquals(DoctorProbeCode.ENDPOINT_MISMATCH, doctor.run(mismatch).probe)
        assertEquals(0, calls.get())
    }

    @Test
    fun `transport failures map to closed codes without exposing arbitrary messages`() {
        val failures = listOf(
            HttpTimeoutException("Bearer timeout-sentinel /Users/private") to DoctorProbeCode.TIMEOUT,
            IOException("wrapped timeout", HttpTimeoutException("wrapped-timeout-sentinel")) to DoctorProbeCode.TIMEOUT,
            ConnectException("Bearer refused-sentinel C:\\private") to DoctorProbeCode.CONNECTION_REFUSED,
            IOException("Authorization: Bearer io-sentinel /home/private") to DoctorProbeCode.CONNECTION_FAILED,
            IllegalStateException("Bearer runtime-sentinel /Users/private") to DoctorProbeCode.CONNECTION_FAILED,
        )
        failures.forEach { (failure, expected) ->
            val report = ConnectionDoctor(DoctorExchange { throw failure }).run(runningConfig())
            assertEquals(expected, report.probe)
            val output = formatDoctorSummary(report) + formatDoctorEvidence(report)
            listOf(
                "timeout-sentinel",
                "wrapped-timeout-sentinel",
                "refused-sentinel",
                "io-sentinel",
                "runtime-sentinel",
                "/Users/",
                "/home/",
            )
                .forEach { forbidden -> assertFalse(output.contains(forbidden)) }
        }
    }

    @Test
    fun `wrapped refusal and interruption are classified without losing interrupt status`() {
        val wrapped = IOException("outer", ConnectException("inner sentinel"))
        assertEquals(
            DoctorProbeCode.CONNECTION_REFUSED,
            ConnectionDoctor(DoctorExchange { throw wrapped }).run(runningConfig()).probe,
        )

        assertFalse(Thread.currentThread().isInterrupted)
        try {
            val interrupted = ConnectionDoctor(DoctorExchange { throw InterruptedException("secret") })
                .run(runningConfig())
            assertEquals(DoctorProbeCode.CANCELLED, interrupted.probe)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun `summary and evidence are fixed shape and endpoint free`() {
        DoctorProbeCode.entries.forEach { probe ->
            val report = DoctorReport(DoctorListenerCode.RUNNING, probe)
            val summary = formatDoctorSummary(report)
            val evidence = formatDoctorEvidence(report)
            assertTrue(summary.isNotBlank())
            assertEquals(3, evidence.lines().size)
            assertTrue(evidence.startsWith("Connection Doctor safe evidence\nListener: "))
            listOf("http://", "127.0.0.1", "9876", "Authorization", token, "/Users/", "C:\\")
                .forEach { forbidden ->
                    assertFalse(summary.contains(forbidden), "$probe summary disclosed $forbidden")
                    assertFalse(evidence.contains(forbidden), "$probe evidence disclosed $forbidden")
                }
        }
    }

    @Test
    fun `request and client use one bounded direct HTTP 1 guard shape`() {
        val config = runningConfig()
        val request = buildDoctorHttpRequest(config)

        buildDoctorHttpClient().use { client ->
            assertEquals(DOCTOR_CONNECT_TIMEOUT, client.connectTimeout().orElseThrow())
            assertEquals(HttpClient.Redirect.NEVER, client.followRedirects())
            assertEquals(HttpClient.Version.HTTP_1_1, client.version())
            val proxySelector = client.proxy().orElseThrow()
            assertTrue(proxySelector === HttpClient.Builder.NO_PROXY)
            assertEquals(
                listOf(java.net.Proxy.NO_PROXY),
                proxySelector.select(java.net.URI("http://127.0.0.1:9876/mcp")),
            )
        }
        assertEquals("http://127.0.0.1:9876/mcp", request.uri().toString())
        assertEquals("POST", request.method())
        assertEquals(DOCTOR_REQUEST_TIMEOUT, request.timeout().orElseThrow())
        assertEquals("Bearer $token", request.headers().firstValue("Authorization").orElseThrow())
        assertEquals("application/json", request.headers().firstValue("Content-Type").orElseThrow())
        assertEquals(
            "application/json, text/event-stream",
            request.headers().firstValue("Accept").orElseThrow(),
        )
        assertEquals(DOCTOR_SESSION_ID, request.headers().firstValue(MCP_SESSION_ID_HEADER).orElseThrow())
        assertEquals(128, MCP_MAX_SESSION_ID_CHARS)
        assertEquals(MCP_MAX_SESSION_ID_CHARS + 1, DOCTOR_SESSION_ID.length)
        assertTrue(DOCTOR_SESSION_ID.all { it == 'd' })
        assertNull(request.headers().firstValue("Origin").orElse(null))
        assertNull(request.headers().firstValue("Cookie").orElse(null))
        assertNull(request.headers().firstValue("Mcp-Protocol-Version").orElse(null))
        assertEquals("{}", request.bodyPublisher().orElseThrow().readUtf8())
    }

    @Test
    fun `sensitive configuration string representations redact bearer material`() {
        val config = DoctorRequestConfig(
            host = "127.0.0.1-secret-sentinel",
            port = 9876,
            bearerToken = "bearer-secret-sentinel",
            listener = DoctorListenerCode.RUNNING,
        )
        val doctorRendered = config.toString()
        assertFalse(doctorRendered.contains("127.0.0.1-secret-sentinel"))
        assertFalse(doctorRendered.contains("9876"))
        assertFalse(doctorRendered.contains("bearer-secret-sentinel"))
        assertTrue(doctorRendered.contains("<redacted>"))

        val installRendered = ProviderInstallConfig(
            "127.0.0.1",
            9876,
            "provider-bearer-secret-sentinel",
        ).toString()
        assertFalse(installRendered.contains("provider-bearer-secret-sentinel"))
        assertFalse(installRendered.contains("127.0.0.1"))
        assertFalse(installRendered.contains("9876"))
        assertTrue(installRendered.contains("<redacted>"))
    }

    private fun runningConfig() = DoctorRequestConfig(
        host = "127.0.0.1",
        port = 9876,
        bearerToken = token,
        listener = DoctorListenerCode.RUNNING,
    )
}

private fun java.net.http.HttpRequest.BodyPublisher.readUtf8(): String {
    val bytes = mutableListOf<Byte>()
    val completed = java.util.concurrent.CountDownLatch(1)
    var failure: Throwable? = null
    subscribe(object : Flow.Subscriber<ByteBuffer> {
        override fun onSubscribe(subscription: Flow.Subscription) = subscription.request(Long.MAX_VALUE)

        override fun onNext(item: ByteBuffer) {
            while (item.hasRemaining()) bytes += item.get()
        }

        override fun onError(throwable: Throwable) {
            failure = throwable
            completed.countDown()
        }

        override fun onComplete() = completed.countDown()
    })
    assertTrue(completed.await(5, TimeUnit.SECONDS))
    failure?.let { throw it }
    return bytes.toByteArray().toString(StandardCharsets.UTF_8)
}
