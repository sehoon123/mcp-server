package net.portswigger.mcp.tools

import burp.api.montoya.http.HttpService
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.util.HexFormat
import kotlin.test.assertEquals

/**
 * Frozen compatibility vectors for Scanner issue fingerprints and their versioned external IDs.
 *
 * The literal hashes were generated before this test with an independent Python implementation. The local preimage
 * builder documents and cross-checks the framing without calling production helpers. An intentional framing change must
 * advance the `issue_v2` ID version rather than silently updating these literals.
 */
class ScannerIssueIdentityGoldenVectorTest {
    @Test
    fun `bounded Scanner metadata and base-36 locator match the golden vectors`() {
        val vector = ScannerIssueVector(
            typeIndex = 0x1234,
            name = "n".repeat(255) + "😀" + "z".repeat(300),
            baseUrl = "https://example.test/" + "p".repeat(2_100),
            service = ServiceVector(
                host = "h".repeat(260) + ".example",
                port = 8_443,
                secure = false,
            ),
            severity = AuditIssueSeverity.HIGH,
            confidence = AuditIssueConfidence.FIRM,
        )
        val issue = vector.toMontoyaIssue()
        val expectedFingerprint = independentFingerprint(vector)

        assertEquals("5608e429d03d63d38765218b432596a9", expectedFingerprint)
        assertEquals("5608e429d03d63d38765218b432596a9", issue.scannerIssueFingerprint())
        assertEquals("issue_v2_x_5608e429d03d63d38765218b432596a9", issue.stableHistoryId())
        assertEquals("issue_v2_z_5608e429d03d63d38765218b432596a9", issue.stableHistoryId(35))
    }

    @Test
    fun `absent Scanner service fields match the golden vectors`() {
        val vector = ScannerIssueVector(
            typeIndex = 7,
            name = "No service",
            baseUrl = "https://例.test/path",
            service = null,
            severity = AuditIssueSeverity.INFORMATION,
            confidence = AuditIssueConfidence.TENTATIVE,
        )
        val issue = vector.toMontoyaIssue()
        val expectedFingerprint = independentFingerprint(vector)

        assertEquals("87300097006c0fb34f9c637244c30bf2", expectedFingerprint)
        assertEquals("87300097006c0fb34f9c637244c30bf2", issue.scannerIssueFingerprint())
        assertEquals("issue_v2_x_87300097006c0fb34f9c637244c30bf2", issue.stableHistoryId())
    }

    private fun independentFingerprint(vector: ScannerIssueVector): String {
        val fields = listOf(
            vector.typeIndex.toString() to 32,
            vector.name to 512,
            vector.baseUrl to 2_048,
            vector.service?.host.orEmpty() to 253,
            vector.service?.port?.toString().orEmpty() to 16,
            vector.service?.secure?.toString().orEmpty() to 8,
            vector.severity.name to 32,
            vector.confidence.name to 32,
        )
        val preimage = fields.joinToString("\u0000") { (value, maxChars) -> value.take(maxChars) }
            .toByteArray(Charsets.UTF_8)
        val digest = MessageDigest.getInstance("SHA-256").digest(preimage)
        return HexFormat.of().formatHex(digest, 0, 16)
    }

    private fun ScannerIssueVector.toMontoyaIssue(): AuditIssue {
        val definitionMock = mockk<AuditIssueDefinition>()
        every { definitionMock.typeIndex() } returns typeIndex
        val serviceMock = service?.let { service ->
            mockk<HttpService>().also { mock ->
                every { mock.host() } returns service.host
                every { mock.port() } returns service.port
                every { mock.secure() } returns service.secure
            }
        }
        return mockk<AuditIssue>().also { issue ->
            every { issue.definition() } returns definitionMock
            every { issue.name() } returns name
            every { issue.baseUrl() } returns baseUrl
            every { issue.httpService() } returns serviceMock
            every { issue.severity() } returns severity
            every { issue.confidence() } returns confidence
        }
    }

    private data class ScannerIssueVector(
        val typeIndex: Int,
        val name: String,
        val baseUrl: String,
        val service: ServiceVector?,
        val severity: AuditIssueSeverity,
        val confidence: AuditIssueConfidence,
    )

    private data class ServiceVector(
        val host: String,
        val port: Int,
        val secure: Boolean,
    )
}
