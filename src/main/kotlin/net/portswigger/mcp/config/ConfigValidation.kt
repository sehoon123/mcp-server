package net.portswigger.mcp.config

object ConfigValidation {

    /** Returns the canonical numeric loopback bind host, or null for every remotely reachable value. */
    fun normalizeLoopbackHost(host: String): String? = when (host.trim().lowercase()) {
        "127.0.0.1" -> "127.0.0.1"
        "::1", "[::1]" -> "::1"
        else -> null
    }

    fun validateServerConfig(host: String, portText: String): String? {
        val port = portText.trim().toIntOrNull()

        if (normalizeLoopbackHost(host) == null) {
            return "Host must be the numeric loopback address 127.0.0.1 or ::1"
        }

        if (port == null) {
            return "Port must be a valid number"
        }

        if (port < 1024 || port > 65535) {
            return "Port is not within valid range"
        }

        return null
    }
}