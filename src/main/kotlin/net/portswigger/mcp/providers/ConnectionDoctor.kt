package net.portswigger.mcp.providers

import net.portswigger.mcp.MCP_MAX_SESSION_ID_CHARS
import net.portswigger.mcp.MCP_SESSION_ID_HEADER
import net.portswigger.mcp.config.isValidLocalBearerToken
import java.io.IOException
import java.net.ConnectException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.http.HttpTimeoutException
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.concurrent.CancellationException

internal val DOCTOR_CONNECT_TIMEOUT: Duration = Duration.ofSeconds(1)
internal val DOCTOR_REQUEST_TIMEOUT: Duration = Duration.ofSeconds(2)
internal val DOCTOR_SESSION_ID: String = "d".repeat(MCP_MAX_SESSION_ID_CHARS + 1)

internal enum class DoctorListenerCode {
    RUNNING,
    STARTING,
    STOPPING,
    STOPPED,
    FAILED,
    UNAVAILABLE,
    UNKNOWN,
}

internal enum class DoctorProbeCode {
    AUTHENTICATED_REACHABLE,
    CREDENTIAL_REJECTED,
    LOOPBACK_POLICY_REJECTED,
    WRONG_ENDPOINT_OR_LISTENER,
    LISTENER_BUSY,
    TIMEOUT,
    CONNECTION_REFUSED,
    CONNECTION_FAILED,
    INCOMPATIBLE_RESPONSE,
    INVALID_CONFIGURATION,
    ENDPOINT_MISMATCH,
    CANCELLED,
    NOT_RUN_LISTENER_INACTIVE,
}

internal enum class DoctorCheckOutcome {
    PASS,
    WARN,
    FAIL,
}

/** A short-lived sensitive click-time snapshot. It must never be retained in a report or copied to the UI. */
internal data class DoctorRequestConfig(
    val host: String,
    val port: Int,
    val bearerToken: String?,
    val listener: DoctorListenerCode,
    val configurationValid: Boolean = true,
    val endpointMatchesListener: Boolean = true,
) {
    override fun toString(): String =
        "DoctorRequestConfig(endpoint=<redacted>, bearerToken=<redacted>, listener=$listener, " +
            "configurationValid=$configurationValid, endpointMatchesListener=$endpointMatchesListener)"
}

internal data class DoctorReport(
    val listener: DoctorListenerCode,
    val probe: DoctorProbeCode,
)

internal fun doctorListenerCode(state: String?): DoctorListenerCode = when (state) {
    "running" -> DoctorListenerCode.RUNNING
    "starting" -> DoctorListenerCode.STARTING
    "stopping" -> DoctorListenerCode.STOPPING
    "stopped" -> DoctorListenerCode.STOPPED
    "failed" -> DoctorListenerCode.FAILED
    null -> DoctorListenerCode.UNAVAILABLE
    else -> DoctorListenerCode.UNKNOWN
}

internal fun DoctorReport.listenerOutcome(): DoctorCheckOutcome = when (listener) {
    DoctorListenerCode.RUNNING -> DoctorCheckOutcome.PASS
    DoctorListenerCode.STARTING,
    DoctorListenerCode.STOPPING -> DoctorCheckOutcome.WARN
    DoctorListenerCode.STOPPED,
    DoctorListenerCode.FAILED,
    DoctorListenerCode.UNAVAILABLE,
    DoctorListenerCode.UNKNOWN -> DoctorCheckOutcome.FAIL
}

internal fun DoctorReport.probeOutcome(): DoctorCheckOutcome = when (probe) {
    DoctorProbeCode.AUTHENTICATED_REACHABLE -> DoctorCheckOutcome.PASS
    DoctorProbeCode.LISTENER_BUSY,
    DoctorProbeCode.TIMEOUT,
    DoctorProbeCode.CANCELLED -> DoctorCheckOutcome.WARN
    DoctorProbeCode.NOT_RUN_LISTENER_INACTIVE -> when (listener) {
        DoctorListenerCode.STARTING,
        DoctorListenerCode.STOPPING -> DoctorCheckOutcome.WARN
        else -> DoctorCheckOutcome.FAIL
    }
    DoctorProbeCode.CREDENTIAL_REJECTED,
    DoctorProbeCode.LOOPBACK_POLICY_REJECTED,
    DoctorProbeCode.WRONG_ENDPOINT_OR_LISTENER,
    DoctorProbeCode.CONNECTION_REFUSED,
    DoctorProbeCode.CONNECTION_FAILED,
    DoctorProbeCode.INCOMPATIBLE_RESPONSE,
    DoctorProbeCode.INVALID_CONFIGURATION,
    DoctorProbeCode.ENDPOINT_MISMATCH -> DoctorCheckOutcome.FAIL
}

internal fun formatDoctorSummary(report: DoctorReport): String = when (report.probe) {
    DoctorProbeCode.AUTHENTICATED_REACHABLE ->
        "The configured local endpoint admitted the current bearer credential. A full MCP handshake and client configuration were not tested."
    DoctorProbeCode.CREDENTIAL_REJECTED ->
        "The local endpoint rejected the current credential. After rotation, restart the listener and update or reinstall every client."
    DoctorProbeCode.LOOPBACK_POLICY_REJECTED ->
        "The local endpoint rejected the loopback request policy. Verify the numeric loopback host and current listener settings."
    DoctorProbeCode.WRONG_ENDPOINT_OR_LISTENER ->
        "The expected /mcp endpoint was not found. Verify the configured port and keep only one bridge listener enabled."
    DoctorProbeCode.LISTENER_BUSY ->
        "The local listener is temporarily busy or its project binding is unavailable. Wait briefly and run the check again."
    DoctorProbeCode.TIMEOUT ->
        "The bounded local check timed out. Verify the listener state and configured port before retrying."
    DoctorProbeCode.CONNECTION_REFUSED ->
        "No listener accepted the configured local connection. Enable or restart the MCP Bridge listener."
    DoctorProbeCode.CONNECTION_FAILED ->
        "The bounded local connection check failed. Verify the listener state and numeric loopback configuration."
    DoctorProbeCode.INCOMPATIBLE_RESPONSE ->
        "The local endpoint returned an incompatible response. Verify that the configured port belongs to this MCP Bridge listener."
    DoctorProbeCode.INVALID_CONFIGURATION ->
        "The local endpoint or credential configuration is invalid. Correct the MCP Bridge settings before retrying."
    DoctorProbeCode.ENDPOINT_MISMATCH ->
        "The displayed endpoint does not match the running listener. Apply the settings and restart the listener before retrying."
    DoctorProbeCode.CANCELLED ->
        "The Connection Doctor check was cancelled."
    DoctorProbeCode.NOT_RUN_LISTENER_INACTIVE ->
        "The authenticated check was not run because the in-process MCP listener is not running."
}

internal fun formatDoctorEvidence(report: DoctorReport): String = buildString {
    appendLine("Connection Doctor safe evidence")
    appendLine("Scope: LOCAL_ADMISSION_ONLY EXTERNAL_CLIENT_NOT_TESTED")
    appendLine("Listener: ${report.listenerOutcome()} ${report.listener}")
    append("Probe: ${report.probeOutcome()} ${report.probe}")
}

internal fun interface DoctorExchange {
    @Throws(Exception::class)
    fun execute(config: DoctorRequestConfig): Int
}

internal class ConnectionDoctor(
    private val exchange: DoctorExchange = JdkDoctorExchange(),
) {
    fun run(config: DoctorRequestConfig): DoctorReport {
        if (!config.configurationValid) {
            return DoctorReport(config.listener, DoctorProbeCode.INVALID_CONFIGURATION)
        }
        if (config.listener != DoctorListenerCode.RUNNING) {
            return DoctorReport(config.listener, DoctorProbeCode.NOT_RUN_LISTENER_INACTIVE)
        }
        if (!config.endpointMatchesListener) {
            return DoctorReport(config.listener, DoctorProbeCode.ENDPOINT_MISMATCH)
        }
        if (!isValidDoctorConfig(config)) {
            return DoctorReport(config.listener, DoctorProbeCode.INVALID_CONFIGURATION)
        }
        if (Thread.currentThread().isInterrupted) {
            return DoctorReport(config.listener, DoctorProbeCode.CANCELLED)
        }

        val probe = try {
            classifyDoctorStatus(exchange.execute(config))
        } catch (_: HttpTimeoutException) {
            DoctorProbeCode.TIMEOUT
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            DoctorProbeCode.CANCELLED
        } catch (_: CancellationException) {
            DoctorProbeCode.CANCELLED
        } catch (error: IOException) {
            when {
                error.hasCause<HttpTimeoutException>() -> DoctorProbeCode.TIMEOUT
                error.hasCause<ConnectException>() -> DoctorProbeCode.CONNECTION_REFUSED
                else -> DoctorProbeCode.CONNECTION_FAILED
            }
        } catch (error: RuntimeException) {
            when {
                error.hasCause<HttpTimeoutException>() -> DoctorProbeCode.TIMEOUT
                error.hasCause<ConnectException>() -> DoctorProbeCode.CONNECTION_REFUSED
                else -> DoctorProbeCode.CONNECTION_FAILED
            }
        }
        return DoctorReport(config.listener, probe)
    }
}

internal fun classifyDoctorStatus(status: Int): DoctorProbeCode = when (status) {
    400 -> DoctorProbeCode.AUTHENTICATED_REACHABLE
    401 -> DoctorProbeCode.CREDENTIAL_REJECTED
    403 -> DoctorProbeCode.LOOPBACK_POLICY_REJECTED
    404 -> DoctorProbeCode.WRONG_ENDPOINT_OR_LISTENER
    429, 503 -> DoctorProbeCode.LISTENER_BUSY
    else -> DoctorProbeCode.INCOMPATIBLE_RESPONSE
}

private fun isValidDoctorConfig(config: DoctorRequestConfig): Boolean {
    if (runCatching { ClientSetupEndpoint.from(config.host, config.port) }.isFailure) return false
    val token = config.bearerToken ?: return false
    return isValidLocalBearerToken(token)
}

private inline fun <reified T : Throwable> Throwable.hasCause(): Boolean {
    var current: Throwable? = this
    repeat(16) {
        if (current is T) return true
        current = current?.cause
        if (current == null) return false
    }
    return false
}

internal fun buildDoctorHttpClient(): HttpClient = HttpClient.newBuilder()
    .connectTimeout(DOCTOR_CONNECT_TIMEOUT)
    .followRedirects(HttpClient.Redirect.NEVER)
    .proxy(HttpClient.Builder.NO_PROXY)
    .version(HttpClient.Version.HTTP_1_1)
    .build()

internal fun buildDoctorHttpRequest(config: DoctorRequestConfig): HttpRequest {
    val token = requireNotNull(config.bearerToken) { "Doctor credential is unavailable" }
    val endpoint = streamableHttpEndpoint(config.host, config.port)
    return HttpRequest.newBuilder()
        .uri(URI.create(endpoint))
        .timeout(DOCTOR_REQUEST_TIMEOUT)
        .header("Authorization", "Bearer $token")
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header(MCP_SESSION_ID_HEADER, DOCTOR_SESSION_ID)
        .POST(HttpRequest.BodyPublishers.ofString("{}", StandardCharsets.UTF_8))
        .build()
}

internal class JdkDoctorExchange(
    private val clientFactory: () -> HttpClient = ::buildDoctorHttpClient,
) : DoctorExchange {
    override fun execute(config: DoctorRequestConfig): Int = clientFactory().use { client ->
        client.send(
            buildDoctorHttpRequest(config),
            HttpResponse.BodyHandlers.discarding(),
        ).statusCode()
    }
}
