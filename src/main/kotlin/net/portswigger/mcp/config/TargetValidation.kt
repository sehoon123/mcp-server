package net.portswigger.mcp.config

import java.net.IDN
import java.net.Inet6Address
import java.net.InetAddress

private const val MAX_TARGET_LENGTH = 255
private const val MAX_HOST_LENGTH = 253
private val ASCII_DOMAIN_LABEL = Regex("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

object TargetValidation {

    /**
     * Validates and canonicalizes one auto-approval target without DNS resolution.
     *
     * Accepted forms are an exact DNS host, strict IPv4/IPv6 literal, optional explicit port, or a single
     * leftmost DNS wildcard (for example `*.example.com`). Wildcards match exactly one label and cannot carry a port.
     */
    fun normalizeTarget(target: String): String? = parse(target)?.render()

    fun isValidTarget(target: String): Boolean = normalizeTarget(target) != null

    fun formatTarget(hostname: String, port: Int): String {
        require(port in 1..65_535) { "port must be between 1 and 65535" }
        val host = hostname.removePrefix("[").removeSuffix("]")
        return if (':' in host) "[$host]:$port" else "$host:$port"
    }

    fun isApproved(approvedTarget: String, hostname: String, port: Int): Boolean {
        val approved = parse(approvedTarget) ?: return false
        val actual = parse(formatTarget(hostname, port)) ?: return false
        if (approved.port != null && approved.port != actual.port) return false

        return if (approved.wildcard) {
            !actual.ipLiteral &&
                actual.host.endsWith(".${approved.host}") &&
                actual.host.removeSuffix(".${approved.host}").let { prefix ->
                    prefix.isNotEmpty() && '.' !in prefix
                }
        } else {
            approved.host == actual.host
        }
    }

    private fun parse(value: String): NormalizedTarget? {
        if (value.length !in 1..MAX_TARGET_LENGTH || value != value.trim()) return null
        if (value.any { it.isWhitespace() || it.isISOControl() }) return null
        if (value.any { it in charArrayOf(',', '/', '\\', '@', '?', '#') }) return null

        if (value.startsWith("*.")) {
            if (value.count { it == '*' } != 1 || ':' in value) return null
            val domain = normalizeDomain(value.substring(2)) ?: return null
            if ('.' !in domain) return null
            return NormalizedTarget(domain, null, wildcard = true, ipLiteral = false)
        }
        if ('*' in value) return null

        if (value.startsWith('[')) {
            val close = value.indexOf(']')
            if (close <= 1 || value.indexOf('[', 1) >= 0 || value.indexOf(']', close + 1) >= 0) return null
            val host = normalizeIpv6(value.substring(1, close)) ?: return null
            val suffix = value.substring(close + 1)
            val port = when {
                suffix.isEmpty() -> null
                suffix.startsWith(':') -> parsePort(suffix.substring(1)) ?: return null
                else -> return null
            }
            return NormalizedTarget(host, port, wildcard = false, ipLiteral = true)
        }

        val colonCount = value.count { it == ':' }
        if (colonCount > 1) {
            val host = normalizeIpv6(value) ?: return null
            return NormalizedTarget(host, null, wildcard = false, ipLiteral = true)
        }

        val rawHost: String
        val port: Int?
        if (colonCount == 1) {
            rawHost = value.substringBefore(':')
            port = parsePort(value.substringAfter(':')) ?: return null
        } else {
            rawHost = value
            port = null
        }
        if (rawHost.isEmpty()) return null

        normalizeIpv4(rawHost)?.let {
            return NormalizedTarget(it, port, wildcard = false, ipLiteral = true)
        }
        if (rawHost.all { it.isDigit() || it == '.' }) return null
        val domain = normalizeDomain(rawHost) ?: return null
        return NormalizedTarget(domain, port, wildcard = false, ipLiteral = false)
    }

    private fun normalizeDomain(value: String): String? {
        val withoutRootDot = value.removeSuffix(".")
        if (withoutRootDot.isEmpty()) return null
        val ascii = try {
            IDN.toASCII(withoutRootDot, IDN.USE_STD3_ASCII_RULES).lowercase()
        } catch (_: IllegalArgumentException) {
            return null
        }
        if (ascii.length !in 1..MAX_HOST_LENGTH) return null
        val labels = ascii.split('.')
        if (labels.any { !it.matches(ASCII_DOMAIN_LABEL) }) return null
        return ascii
    }

    private fun normalizeIpv4(value: String): String? {
        val parts = value.split('.')
        if (parts.size != 4) return null
        val normalized = ArrayList<String>(4)
        for (part in parts) {
            if (part.isEmpty() || part.any { !it.isDigit() }) return null
            if (part.length > 1 && part.startsWith('0')) return null
            val octet = part.toIntOrNull() ?: return null
            if (octet !in 0..255) return null
            normalized += octet.toString()
        }
        return normalized.joinToString(".")
    }

    private fun normalizeIpv6(value: String): String? {
        if (value.isEmpty() || '%' in value || value.any { it !in "0123456789abcdefABCDEF:." }) return null
        return try {
            val address = InetAddress.getByName(value)
            (address as? Inet6Address)?.hostAddress?.lowercase()
        } catch (_: Exception) {
            null
        }
    }

    private fun parsePort(value: String): Int? {
        if (value.isEmpty() || value.any { !it.isDigit() }) return null
        return value.toIntOrNull()?.takeIf { it in 1..65_535 }
    }
}

private data class NormalizedTarget(
    val host: String,
    val port: Int?,
    val wildcard: Boolean,
    val ipLiteral: Boolean,
) {
    fun render(): String {
        val renderedHost = when {
            wildcard -> "*.$host"
            ipLiteral && ':' in host && port != null -> "[$host]"
            else -> host
        }
        return renderedHost + (port?.let { ":$it" } ?: "")
    }
}
