package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.PersistedObject
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import kotlin.test.assertFalse

class ToolServicesTest {
    @Test
    fun `project reset does not initialize unused lazy services`() = runBlocking {
        val api = mockk<MontoyaApi>(relaxed = true)
        val services = ToolServices(api, mockk<PersistedObject>(relaxed = true))

        try {
            assertLazyServicesUninitialized(services)

            services.resetForProjectBoundary()

            assertLazyServicesUninitialized(services)
            verify(exactly = 0) { api.burpSuite() }
        } finally {
            services.close()
        }
    }

    private fun assertLazyServicesUninitialized(services: ToolServices) {
        listOf(
            "collaboratorDelegate",
            "scannerAuditsDelegate",
            "httpMetadataIndexDelegate",
            "httpSessionSecurityAnalyzerDelegate",
        ).forEach { fieldName ->
            val field = ToolServices::class.java.getDeclaredField(fieldName).apply { isAccessible = true }
            assertFalse((field.get(services) as Lazy<*>).isInitialized(), "$fieldName was initialized")
        }
    }
}
