package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.Registration
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.http.InterceptedRequest
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.proxy.http.ProxyRequestHandler
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction
import burp.api.montoya.scanner.Scanner
import burp.api.montoya.scanner.audit.AuditIssueHandler
import burp.api.montoya.scanner.audit.issues.AuditIssue
import io.mockk.confirmVerified
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkStatic
import io.mockk.verify
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame

class MontoyaMetadataEventBridgeTest {
    @Test
    fun `callbacks retain only fixed signals and continue exact messages and annotations`() {
        val api = mockk<MontoyaApi>()
        val proxy = mockk<Proxy>()
        val scanner = mockk<Scanner>()
        val requestRegistration = registration()
        val responseRegistration = registration()
        val scannerRegistration = registration()
        val requestHandler = slot<ProxyRequestHandler>()
        val responseHandler = slot<ProxyResponseHandler>()
        val auditHandler = slot<AuditIssueHandler>()
        every { api.proxy() } returns proxy
        every { api.scanner() } returns scanner
        every { proxy.registerRequestHandler(capture(requestHandler)) } returns requestRegistration
        every { proxy.registerResponseHandler(capture(responseHandler)) } returns responseRegistration
        every { scanner.registerAuditIssueHandler(capture(auditHandler)) } returns scannerRegistration
        val signals = MetadataChangeSignals()
        val bridge = MontoyaMetadataEventBridge(api, signals)
        val request = mockk<InterceptedRequest>()
        val requestAnnotations = mockk<Annotations>()
        val response = mockk<InterceptedResponse>()
        val responseAnnotations = mockk<Annotations>()
        every { request.annotations() } returns requestAnnotations
        every { response.annotations() } returns responseAnnotations
        val receivedRequestAction = mockk<ProxyRequestReceivedAction>()
        val sentRequestAction = mockk<ProxyRequestToBeSentAction>()
        val receivedResponseAction = mockk<ProxyResponseReceivedAction>()
        val sentResponseAction = mockk<ProxyResponseToBeSentAction>()
        val auditIssue = mockk<AuditIssue>()
        mockkStatic(
            ProxyRequestReceivedAction::class,
            ProxyRequestToBeSentAction::class,
            ProxyResponseReceivedAction::class,
            ProxyResponseToBeSentAction::class,
        )
        try {
            every { ProxyRequestReceivedAction.continueWith(request, requestAnnotations) } returns receivedRequestAction
            every { ProxyRequestToBeSentAction.continueWith(request, requestAnnotations) } returns sentRequestAction
            every { ProxyResponseReceivedAction.continueWith(response, responseAnnotations) } returns receivedResponseAction
            every { ProxyResponseToBeSentAction.continueWith(response, responseAnnotations) } returns sentResponseAction

            assertSame(receivedRequestAction, requestHandler.captured.handleRequestReceived(request))
            assertSame(sentRequestAction, requestHandler.captured.handleRequestToBeSent(request))
            assertSame(receivedResponseAction, responseHandler.captured.handleResponseReceived(response))
            assertSame(sentResponseAction, responseHandler.captured.handleResponseToBeSent(response))
            auditHandler.captured.handleNewAuditIssue(auditIssue)

            assertEquals(4L, signals.revision(MetadataChangeSource.PROXY_HTTP))
            assertEquals(3L, signals.revision(MetadataChangeSource.SITE_MAP))
            assertEquals(1L, signals.revision(MetadataChangeSource.SCANNER_ISSUES))
            verify(exactly = 2) { request.annotations() }
            verify(exactly = 2) { response.annotations() }
            confirmVerified(request, response, auditIssue)
        } finally {
            unmockkStatic(
                ProxyResponseToBeSentAction::class,
                ProxyResponseReceivedAction::class,
                ProxyRequestToBeSentAction::class,
                ProxyRequestReceivedAction::class,
            )
        }

        bridge.close()
        bridge.close()
        verify(exactly = 1) { requestRegistration.deregister() }
        verify(exactly = 1) { responseRegistration.deregister() }
        verify(exactly = 1) { scannerRegistration.deregister() }
    }

    @Test
    fun `registration and cleanup failures are isolated`() {
        val api = mockk<MontoyaApi>()
        val proxy = mockk<Proxy>()
        val responseRegistration = registration()
        every { api.proxy() } returns proxy
        every { proxy.registerRequestHandler(any()) } throws IllegalStateException("request registration unavailable")
        every { proxy.registerResponseHandler(any()) } returns responseRegistration
        every { api.scanner() } throws IllegalStateException("scanner unavailable")
        every { responseRegistration.deregister() } throws IllegalStateException("cleanup unavailable")

        val bridge = MontoyaMetadataEventBridge(api, MetadataChangeSignals())
        bridge.close()
        bridge.close()

        verify(exactly = 1) { proxy.registerRequestHandler(any()) }
        verify(exactly = 1) { proxy.registerResponseHandler(any()) }
        verify(exactly = 1) { responseRegistration.deregister() }
    }

    @Test
    fun `unavailable Scanner registration leaves both Proxy handlers active`() {
        val api = mockk<MontoyaApi>()
        val proxy = mockk<Proxy>()
        val requestRegistration = registration()
        val responseRegistration = registration()
        every { api.proxy() } returns proxy
        every { proxy.registerRequestHandler(any()) } returns requestRegistration
        every { proxy.registerResponseHandler(any()) } returns responseRegistration
        every { api.scanner() } throws UnsupportedOperationException("Scanner unavailable")

        val bridge = MontoyaMetadataEventBridge(api, MetadataChangeSignals())
        bridge.close()

        verify(exactly = 1) { proxy.registerRequestHandler(any()) }
        verify(exactly = 1) { proxy.registerResponseHandler(any()) }
        verify(exactly = 1) { requestRegistration.deregister() }
        verify(exactly = 1) { responseRegistration.deregister() }
    }

    @Test
    fun `one deregistration failure cannot suppress remaining cleanup`() {
        val api = mockk<MontoyaApi>()
        val proxy = mockk<Proxy>()
        val scanner = mockk<Scanner>()
        val requestRegistration = registration()
        val responseRegistration = registration()
        val scannerRegistration = registration()
        every { api.proxy() } returns proxy
        every { api.scanner() } returns scanner
        every { proxy.registerRequestHandler(any()) } returns requestRegistration
        every { proxy.registerResponseHandler(any()) } returns responseRegistration
        every { scanner.registerAuditIssueHandler(any()) } returns scannerRegistration
        every { requestRegistration.deregister() } throws IllegalStateException("cleanup unavailable")

        val bridge = MontoyaMetadataEventBridge(api, MetadataChangeSignals())
        bridge.close()

        verify(exactly = 1) { requestRegistration.deregister() }
        verify(exactly = 1) { responseRegistration.deregister() }
        verify(exactly = 1) { scannerRegistration.deregister() }
    }

    private fun registration(): Registration = mockk {
        every { isRegistered } returns true
        every { deregister() } returns Unit
    }
}
