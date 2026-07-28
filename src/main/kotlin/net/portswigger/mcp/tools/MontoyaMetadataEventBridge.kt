package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Registration
import burp.api.montoya.proxy.http.InterceptedRequest
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.proxy.http.ProxyRequestHandler
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction
import burp.api.montoya.scanner.audit.AuditIssueHandler
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Extension-lifetime Montoya registrations that translate callbacks into value-free atomic change signals.
 *
 * Each registration is independent: unsupported or failing registration degrades to bounded anchor/age validation and
 * never prevents the extension from starting. Callback arguments are continued unchanged and are never retained.
 */
internal class MontoyaMetadataEventBridge(
    api: MontoyaApi,
    private val signals: MetadataChangeSignals,
) : AutoCloseable {
    private val closed = AtomicBoolean()
    private val registrations = arrayOfNulls<Registration>(3)

    init {
        registrations[0] = registerSafely {
            api.proxy().registerRequestHandler(object : ProxyRequestHandler {
                override fun handleRequestReceived(request: InterceptedRequest): ProxyRequestReceivedAction {
                    signals.markChanged(MetadataChangeSource.PROXY_HTTP)
                    return ProxyRequestReceivedAction.continueWith(request, request.annotations())
                }

                override fun handleRequestToBeSent(request: InterceptedRequest): ProxyRequestToBeSentAction {
                    signals.markChanged(MetadataChangeSource.PROXY_HTTP)
                    return ProxyRequestToBeSentAction.continueWith(request, request.annotations())
                }
            })
        }
        registrations[1] = registerSafely {
            api.proxy().registerResponseHandler(object : ProxyResponseHandler {
                override fun handleResponseReceived(response: InterceptedResponse): ProxyResponseReceivedAction {
                    signals.markChanged(MetadataChangeSource.PROXY_HTTP)
                    signals.markChanged(MetadataChangeSource.SITE_MAP)
                    return ProxyResponseReceivedAction.continueWith(response, response.annotations())
                }

                override fun handleResponseToBeSent(response: InterceptedResponse): ProxyResponseToBeSentAction {
                    signals.markChanged(MetadataChangeSource.PROXY_HTTP)
                    signals.markChanged(MetadataChangeSource.SITE_MAP)
                    return ProxyResponseToBeSentAction.continueWith(response, response.annotations())
                }
            })
        }
        registrations[2] = registerSafely {
            api.scanner().registerAuditIssueHandler(AuditIssueHandler {
                signals.markChanged(MetadataChangeSource.SCANNER_ISSUES)
                signals.markChanged(MetadataChangeSource.SITE_MAP)
            })
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        registrations.forEach { registration ->
            if (registration != null) {
                try {
                    registration.deregister()
                } catch (_: Exception) {
                    // Each registration is independent; continue cleaning up the remaining handlers.
                }
            }
        }
    }

    private inline fun registerSafely(register: () -> Registration): Registration? = try {
        register()
    } catch (_: Exception) {
        null
    }
}
