package net.portswigger.mcp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ProductIdentityTest {
    @Test
    fun `independent distribution identity is explicit and distinct from upstream`() {
        assertEquals("Independent MCP Bridge", ProductIdentity.PRODUCT_NAME)
        assertEquals("independent-mcp-bridge", ProductIdentity.MCP_SERVER_NAME)
        assertEquals("burp-independent", ProductIdentity.CLIENT_CONFIGURATION_NAME)
        assertEquals("sehoon123", ProductIdentity.VENDOR)
        assertNotEquals("Burp MCP Server", ProductIdentity.EXTENSION_NAME)
        assertTrue(ProductIdentity.UNOFFICIAL_NOTICE.contains("not published or supported by PortSwigger"))
        assertTrue(ProductIdentity.SOURCE_URL.startsWith("https://github.com/sehoon123/"))
        assertTrue(ProductIdentity.SUPPORT_URL.startsWith(ProductIdentity.SOURCE_URL))
    }
}
