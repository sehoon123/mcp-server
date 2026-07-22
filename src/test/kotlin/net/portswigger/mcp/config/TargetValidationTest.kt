package net.portswigger.mcp.config

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class TargetValidationTest {

    private fun isValidTarget(target: String): Boolean {
        return TargetValidation.isValidTarget(target)
    }

    @Test
    fun `isValidTarget should accept valid formats`() {
        // Basic hostnames
        assertTrue(isValidTarget("example.com"))
        assertTrue(isValidTarget("test.org"))
        assertTrue(isValidTarget("sub.domain.co.uk"))
        assertTrue(isValidTarget("localhost"))
        assertTrue(isValidTarget("127.0.0.1"))

        // With ports
        assertTrue(isValidTarget("example.com:80"))
        assertTrue(isValidTarget("example.com:8080"))
        assertTrue(isValidTarget("localhost:3000"))
        assertTrue(isValidTarget("127.0.0.1:9876"))

        // Wildcards
        assertTrue(isValidTarget("*.example.com"))
        assertTrue(isValidTarget("*.api.test.org"))
        assertTrue(isValidTarget("*.co.uk"))

        // IPv6 formats
        assertTrue(isValidTarget("::1"))
        assertTrue(isValidTarget("2001:db8::1"))
        assertTrue(isValidTarget("[::1]:8080"))

    }

    @Test
    fun `isValidTarget should reject invalid formats`() {
        // Empty/blank input
        assertFalse(isValidTarget(""))
        assertFalse(isValidTarget("   "))

        // Ambiguous, injected, or malformed hosts
        assertFalse(isValidTarget("256.0.0.1"))
        assertFalse(isValidTarget("01.2.3.4"))
        assertFalse(isValidTarget("test@example.com"))
        assertFalse(isValidTarget("*.*.com"))
        assertFalse(isValidTarget("*.localhost"))
        assertFalse(isValidTarget("*.example.com:443"))
        assertFalse(isValidTarget("https://example.com"))

        // Invalid ports
        assertFalse(isValidTarget("example.com:"))
        assertFalse(isValidTarget("example.com:abc"))
        assertFalse(isValidTarget("example.com:0"))
        assertFalse(isValidTarget("example.com:65536"))

        // Control characters
        assertFalse(isValidTarget("example\tcom"))
        assertFalse(isValidTarget("example\ncom"))
        assertFalse(isValidTarget("example\rcom"))

        assertFalse(isValidTarget("example com"))
        assertFalse(isValidTarget("example.com 127.0.0.1"))

        assertFalse(isValidTarget("example.com,127.0.0.1"))
        assertFalse(isValidTarget("example.com,127.0.0.1,*.attacker.com,169.254.169.254"))
        assertFalse(isValidTarget(","))
        assertFalse(isValidTarget("a,"))

        // Malformed multi-colon strings (not valid IPv6)
        assertFalse(isValidTarget("garbage:foo:bar"))
        assertFalse(isValidTarget("example.com:notaport:extra"))
        assertFalse(isValidTarget("*.example.com:notaport:extra"))

        // Oversized input
        assertFalse(isValidTarget("a".repeat(256)))
    }

    @Test
    fun `targets are canonicalized and wildcard matching is one label only`() {
        assertTrue(TargetValidation.normalizeTarget("EXAMPLE.COM.") == "example.com")
        assertTrue(TargetValidation.normalizeTarget("[::1]:443")?.endsWith(":443") == true)
        assertTrue(TargetValidation.isApproved("example.com:443", "EXAMPLE.COM", 443))
        assertFalse(TargetValidation.isApproved("example.com:443", "example.com", 80))
        assertTrue(TargetValidation.isApproved("*.example.com", "api.example.com", 443))
        assertFalse(TargetValidation.isApproved("*.example.com", "deep.api.example.com", 443))
        assertFalse(TargetValidation.isApproved("*.example.com", "example.com", 443))
    }
}