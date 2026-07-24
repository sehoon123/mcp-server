package net.portswigger.mcp.security

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.awt.Frame

/**
 * Finds the Burp Suite main frame or the largest available frame as fallback
 */
fun findBurpFrame(): Frame? {
    val burpIdentifiers = listOf("Burp Suite", "Professional", "Community", "burp")

    return Frame.getFrames().find { frame ->
        frame.isVisible && frame.isDisplayable && burpIdentifiers.any { identifier ->
            frame.title.contains(identifier, ignoreCase = true) ||
                    frame.javaClass.name.contains(identifier, ignoreCase = true) ||
                    frame.javaClass.simpleName.contains(identifier, ignoreCase = true)
        }
    } ?: Frame.getFrames()
        .filter { it.isVisible && it.isDisplayable }
        .maxByOrNull { it.width * it.height }
}

// Normalized keys whose values may contain credentials in exported Burp options or equivalent nested configuration.
// Matching is deliberately exact after removing ASCII separators: broad substring matching would redact unrelated
// settings such as token-handling rule names. Sensitive containers retain their JSON shape but redact every primitive.
private val SENSITIVE_KEYS = setOf(
    "password",
    "passwords",
    "passwd",
    "passphrase",
    "secret",
    "secrets",
    "clientsecret",
    "apikey",
    "apikeys",
    "xapikey",
    "xapitoken",
    "accesskey",
    "accesskeys",
    "secretkey",
    "hashedkey",
    "token",
    "tokens",
    "authtoken",
    "xauthtoken",
    "accesstoken",
    "xaccesstoken",
    "refreshtoken",
    "idtoken",
    "bearer",
    "bearertoken",
    "basicauth",
    "authorization",
    "proxyauthorization",
    "cookie",
    "cookies",
    "cookiejar",
    "setcookie",
    "certificatepassword",
    "keystorepassword",
    "truststorepassword",
    "privatekey",
    "privatekeydata",
    "certificate",
    "certificates",
    "certificatedata",
    "clientcertificate",
    "clientcertificates",
    "clientcertificatedata",
    "pkcs12",
    "pkcs12data",
    "pfx",
    "pfxdata",
)

private val SENSITIVE_LABEL_KEYS = setOf(
    "name",
    "key",
    "type",
    "header",
    "headername",
    "parameter",
    "parametername",
)

private val LABELED_VALUE_KEYS = setOf(
    "value",
    "values",
    "data",
    "content",
    "headervalue",
    "parametervalue",
    "replacement",
)

private val SENSITIVE_LABELS = setOf(
    "password",
    "passphrase",
    "secret",
    "clientsecret",
    "apikey",
    "xapikey",
    "xapitoken",
    "accesskey",
    "secretkey",
    "token",
    "authtoken",
    "xauthtoken",
    "accesstoken",
    "xaccesstoken",
    "refreshtoken",
    "idtoken",
    "bearer",
    "bearertoken",
    "basicauth",
    "authorization",
    "proxyauthorization",
    "cookie",
    "setcookie",
    "privatekey",
    "certificate",
    "certificatedata",
    "clientcertificate",
    "pkcs12",
    "pfx",
)

private val PRIVATE_MATERIAL_MARKERS = listOf(
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN CERTIFICATE-----",
    "-----BEGIN PKCS7-----",
)

private const val REDACTED = "*****"

fun filterConfigCredentials(json: String): String {
    return try {
        Json.encodeToString(filterJsonElement(Json.parseToJsonElement(json)))
    } catch (_: SerializationException) {
        // Burp's export is expected to always be valid JSON. If it isn't, fail closed:
        // do not echo the original or the parser's message (it quotes surrounding input,
        // which can include credential values).
        """{"error":"failed to parse config json"}"""
    }
}

private fun filterJsonElement(element: JsonElement): JsonElement = when (element) {
    is JsonObject -> filterJsonObject(element)
    is JsonArray -> JsonArray(element.map(::filterJsonElement))
    is JsonPrimitive -> filterStandalonePrimitive(element)
}

private fun filterJsonObject(element: JsonObject): JsonObject {
    val containsSensitiveLabel = element.any { (key, value) ->
        normalizeSensitiveName(key) in SENSITIVE_LABEL_KEYS &&
            value is JsonPrimitive && value.isString &&
            normalizeSensitiveName(value.content) in SENSITIVE_LABELS
    }
    return JsonObject(element.mapValues { (key, value) ->
        val normalizedKey = normalizeSensitiveName(key)
        when {
            normalizedKey in SENSITIVE_KEYS -> redactSensitiveElement(value)
            containsSensitiveLabel && normalizedKey in LABELED_VALUE_KEYS -> redactSensitiveElement(value)
            else -> filterJsonElement(value)
        }
    })
}

private fun filterStandalonePrimitive(value: JsonPrimitive): JsonElement {
    if (!value.isString) return value
    val content = value.content
    if (PRIVATE_MATERIAL_MARKERS.any { marker -> content.contains(marker, ignoreCase = true) }) {
        return JsonPrimitive(REDACTED)
    }
    val separator = content.indexOf(':')
    if (separator in 1..128 && normalizeSensitiveName(content.substring(0, separator)) in SENSITIVE_LABELS) {
        return JsonPrimitive(content.substring(0, separator + 1) + " " + REDACTED)
    }
    return value
}

private fun redactSensitiveElement(element: JsonElement): JsonElement = when (element) {
    is JsonObject -> JsonObject(element.mapValues { (_, value) -> redactSensitiveElement(value) })
    is JsonArray -> JsonArray(element.map(::redactSensitiveElement))
    is JsonPrimitive -> if (element === JsonNull) element else JsonPrimitive(REDACTED)
}

private fun normalizeSensitiveName(value: String): String = buildString(value.length) {
    value.forEach { character ->
        when (character) {
            in 'A'..'Z' -> append(character.lowercaseChar())
            in 'a'..'z', in '0'..'9' -> append(character)
        }
    }
}
