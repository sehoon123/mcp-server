package net.portswigger.mcp.tools

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.proxy.ProxyHttpRequestResponse

/** Montoya source records retained only for one HTTP search invocation. */
internal sealed interface HttpSourceRecords {
    val source: HttpMessageSource

    data class Proxy(
        val items: List<ProxyHttpRequestResponse>,
    ) : HttpSourceRecords {
        override val source: HttpMessageSource = HttpMessageSource.PROXY
    }

    data class SiteMap(
        val items: List<HttpRequestResponse>,
    ) : HttpSourceRecords {
        override val source: HttpMessageSource = HttpMessageSource.SITE_MAP
    }

    data class Organizer(
        val items: List<OrganizerItem>,
    ) : HttpSourceRecords {
        override val source: HttpMessageSource = HttpMessageSource.ORGANIZER
    }
}
