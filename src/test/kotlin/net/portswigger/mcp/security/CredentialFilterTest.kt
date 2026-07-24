package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.logging.Logging
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach
import io.mockk.mockk
import io.mockk.every
import kotlinx.serialization.json.*

class CredentialFilterTest {

    private lateinit var config: McpConfig
    private lateinit var api: MontoyaApi
    private lateinit var mockLogging: Logging
    private lateinit var persistedObject: PersistedObject
    private lateinit var projectOptionString: String
    private lateinit var usersOptionString: String

    @BeforeEach
    fun setUp() {
        api = mockk<MontoyaApi>()
        mockLogging = mockk<Logging>()
        persistedObject = mockk<PersistedObject>()
        val storage = mutableMapOf<String, Any>(
            "enabled" to true,
            "configEditingTooling" to false,
            "requireHttpRequestApproval" to true,
            "host" to "127.0.0.1",
            "_autoApproveTargets" to "",
            "port" to 9876
        )

        persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { storage[firstArg()] as? Boolean ?: false }
            every { getString(any()) } answers { storage[firstArg()] as? String ?: "" }
            every { getInteger(any()) } answers { storage[firstArg()] as? Int ?: 0 }
            every { setBoolean(any(), any()) } answers {
                storage[firstArg()] = secondArg<Boolean>()
            }
            every { setString(any(), any()) } answers {
                storage[firstArg()] = secondArg<String>()
            }
            every { setInteger(any(), any()) } answers {
                storage[firstArg()] = secondArg<Int>()
            }
        }

        mockLogging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
        }

        this.get_user_options_with_customizable_field()
        this.get_project_options_with_customizable_field()
        config = McpConfig(persistedObject, mockLogging)
    }

    fun get_user_options_with_customizable_field(username: String = "", password: String = ""): String {
        this.usersOptionString = """
        {
            "user_options": {
                "bchecks": {},
                "connections": {
                    "platform_authentication": {
                        "credentials": [
                            {
                                "username": "$username",
                                "password": "$password"
                            }
                        ],
                        "do_platform_authentication": false,
                        "prompt_on_authentication_failure": false
                    },
                    "socks_proxy": {
                        "username": "$username",
                        "password": "$password"
                    },
                    "upstream_proxy": {
                        "servers": []
                    }
                },
                "display": {},
                "extender": {},
                "intruder": {},
                "misc": {},
                "proxy": {},
                "repeater": {},
                "ssl": {}
            }
        }
        """.trimIndent()
        return this.usersOptionString
    }

    fun get_project_options_with_customizable_field(username: String = "", password: String = ""): String {
        this.projectOptionString = """
        {
            "bambda": {},
            "logger": {},
            "organiser": {},
            "project_options": {
                "connections": {
                    "out_of_scope_requests": {},
                    "platform_authentication": {
                        "credentials": [
                            {
                                "username": "$username",
                                "password": "$password"
                            }
                        ],
                        "do_platform_authentication": false,
                        "prompt_on_authentication_failure": false,
                        "use_user_options": true
                    },
                    "socks_proxy": {
                        "username": "$username",
                        "password": "$password"
                    },
                    "timeouts": {
                        "connect_timeout": 5000,
                        "read_timeout": 5000
                    },
                    "upstream_proxy": {
                        "servers": [],
                        "use_user_options": true
                    }
                },
                "dns": {},
                "http": {},
                "misc": {},
                "sessions": {},
                "ssl": {}
            },
            "proxy": {},
            "repeater": {},
            "sequencer": {},
            "target": {}
        }
        """.trimIndent()
       return this.projectOptionString
    }

    @Test
    fun `test security filter on project_options `() {
        config.filterConfigCredentials = true
        projectOptionString = get_project_options_with_customizable_field("testuser", "testpass")
        val filteredProjectJson = filterConfigCredentials(projectOptionString)
        val parsedJson = Json.parseToJsonElement(filteredProjectJson).jsonObject

        val credentials = parsedJson["project_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("platform_authentication")?.jsonObject
            ?.get("credentials")?.jsonArray

        val socks_proxy = parsedJson["project_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("socks_proxy")?.jsonObject

        credentials?.forEach { credential ->
            val credentialObj = credential.jsonObject
            Assertions.assertEquals("*****", credentialObj["password"]?.jsonPrimitive?.content)
        }

        socks_proxy?.let {
            Assertions.assertEquals("*****", socks_proxy["password"]?.jsonPrimitive?.content)
        }
    }

    @Test
    fun `test security filter on user_options`() {
        config.filterConfigCredentials = true
        usersOptionString = get_user_options_with_customizable_field("testuser", "testpass")
        val filteredUserJson = filterConfigCredentials(usersOptionString)
        val parsedJson = Json.parseToJsonElement(filteredUserJson).jsonObject

        val credentials = parsedJson["user_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("platform_authentication")?.jsonObject
            ?.get("credentials")?.jsonArray

        val socks_proxy = parsedJson["user_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("socks_proxy")?.jsonObject

        credentials?.forEach { credential ->
            val credentialObj = credential.jsonObject
            Assertions.assertEquals("*****", credentialObj["password"]?.jsonPrimitive?.content)
        }

        socks_proxy?.let {
            Assertions.assertEquals("*****", it["password"]?.jsonPrimitive?.content)
        }
    }

    @Test
    fun `test security filter with empty credentials on user_options`() {
        config.filterConfigCredentials = true
        val empty_user_credentials: String = get_user_options_with_customizable_field("", "")
        val filteredJson = filterConfigCredentials(empty_user_credentials)
        val parsedJson = Json.parseToJsonElement(filteredJson).jsonObject

        val credentials = parsedJson["user_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("platform_authentication")?.jsonObject
            ?.get("credentials")?.jsonArray

        val socks_proxy = parsedJson["user_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("socks_proxy")?.jsonObject

        credentials?.forEach { credential ->
            val credentialObj = credential.jsonObject
            Assertions.assertTrue(credentialObj["username"]?.jsonPrimitive?.content.isNullOrEmpty())
            Assertions.assertEquals("*****", credentialObj["password"]?.jsonPrimitive?.content)
        }
        socks_proxy?.let {
            Assertions.assertTrue(socks_proxy["username"]?.jsonPrimitive?.content.isNullOrEmpty())
            Assertions.assertEquals("*****", socks_proxy["password"]?.jsonPrimitive?.content)
        }
    }

    @Test
    fun `test security filter with empty credentials on project_options`() {
        config.filterConfigCredentials = true
        val empty_project_credentials = get_project_options_with_customizable_field("", "")
        val filteredJson = filterConfigCredentials(empty_project_credentials)
        val parsedJson = Json.parseToJsonElement(filteredJson).jsonObject

        val credentials = parsedJson["project_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("platform_authentication")?.jsonObject
            ?.get("credentials")?.jsonArray

        val socks_proxy = parsedJson["project_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("socks_proxy")?.jsonObject

        credentials?.forEach { credential ->
            val credentialObj = credential.jsonObject
            Assertions.assertTrue(credentialObj["username"]?.jsonPrimitive?.content.isNullOrEmpty())
            Assertions.assertEquals("*****", credentialObj["password"]?.jsonPrimitive?.content)
        }
        socks_proxy?.let {
            Assertions.assertTrue(socks_proxy["username"]?.jsonPrimitive?.content.isNullOrEmpty())
            Assertions.assertEquals("*****", socks_proxy["password"]?.jsonPrimitive?.content)
        }
    }

    @Test
    fun `test security filter with malformed Json on user_options`() {
        val malformedJson = """
        {
            "user_options": {
                "connections": {
                    "socks_proxy": { "password": "leakme"
                }
            }
        """.trimIndent()
        val result = filterConfigCredentials(malformedJson)
        Assertions.assertFalse(result.contains("leakme"), "Original input must not be echoed on parse failure")
        val parsed = Json.parseToJsonElement(result).jsonObject
        Assertions.assertNotNull(parsed["error"])
    }

    @Test
    fun `test security filter with malformed Json on project_options`() {
        val malformedJson = """
        {
            "project_options": {
                "connections": {
                    "socks_proxy": { "password": "leakme" }
                }
        """.trimIndent()
        val result = filterConfigCredentials(malformedJson)
        Assertions.assertFalse(result.contains("leakme"), "Original input must not be echoed on parse failure")
        val parsed = Json.parseToJsonElement(result).jsonObject
        Assertions.assertNotNull(parsed["error"])
    }

    @Test
    fun `proxy listener certificate password and REST API hashed key are redacted`() {
        val input = """
        {
            "proxy": { "request_listeners": [ { "certificate_password": "p12pass" } ] },
            "misc": { "api": { "keys": [ { "name": "k1", "hashed_key": "deadbeef" } ] } }
        }
        """.trimIndent()
        val parsed = Json.parseToJsonElement(filterConfigCredentials(input)).jsonObject
        val listener = parsed["proxy"]!!.jsonObject["request_listeners"]!!.jsonArray[0].jsonObject
        Assertions.assertEquals("*****", listener["certificate_password"]?.jsonPrimitive?.content)
        val apiKey = parsed["misc"]!!.jsonObject["api"]!!.jsonObject["keys"]!!.jsonArray[0].jsonObject
        Assertions.assertEquals("*****", apiKey["hashed_key"]?.jsonPrimitive?.content)
        Assertions.assertEquals("k1", apiKey["name"]?.jsonPrimitive?.content)
    }

    @Test
    fun `sensitive key matching is case insensitive`() {
        val input = """{"Password":"a","Certificate_Password":"b","HASHED_KEY":"c"}"""
        val parsed = Json.parseToJsonElement(filterConfigCredentials(input)).jsonObject
        Assertions.assertEquals("*****", parsed["Password"]?.jsonPrimitive?.content)
        Assertions.assertEquals("*****", parsed["Certificate_Password"]?.jsonPrimitive?.content)
        Assertions.assertEquals("*****", parsed["HASHED_KEY"]?.jsonPrimitive?.content)
    }

    @Test
    fun `nested API keys tokens cookies and certificate material are recursively redacted`() {
        val input = """
        {
            "auth": {
                "api-key": "api-secret",
                "client_secret": { "value": "client-secret", "version": 2 },
                "tokens": ["access-secret", { "refresh_token": "refresh-secret" }]
            },
            "cookies": [
                { "name": "session", "value": "cookie-secret", "secure": true }
            ],
            "tls": {
                "client-certificates": [
                    { "certificate_data": "certificate-secret", "private_key": "private-secret" }
                ]
            },
            "optional": { "password": null },
            "literal": { "password": "null" }
        }
        """.trimIndent()

        val filtered = filterConfigCredentials(input)
        listOf(
            "api-secret",
            "client-secret",
            "access-secret",
            "refresh-secret",
            "cookie-secret",
            "certificate-secret",
            "private-secret",
        ).forEach { secret -> Assertions.assertFalse(filtered.contains(secret), secret) }

        val parsed = Json.parseToJsonElement(filtered).jsonObject
        Assertions.assertEquals("*****", parsed["auth"]!!.jsonObject["api-key"]!!.jsonPrimitive.content)
        Assertions.assertEquals(JsonNull, parsed["optional"]!!.jsonObject["password"])
        Assertions.assertEquals("*****", parsed["literal"]!!.jsonObject["password"]!!.jsonPrimitive.content)
    }

    @Test
    fun `sensitive name value header forms and raw header lines are redacted`() {
        val input = """
        {
            "headers": [
                { "name": "Authorization", "value": "Bearer auth-secret" },
                { "header_name": "X-API-Key", "header_value": "header-secret" },
                { "name": "X-Auth-Token", "value": "auth-token-secret" },
                { "key": "Proxy-Authorization", "values": ["proxy-secret"] },
                { "name": "User-Agent", "value": "safe-agent" }
            ],
            "raw": [
                "Cookie: session=raw-cookie-secret",
                "Set-Cookie: response-cookie-secret",
                "Host: example.test"
            ]
        }
        """.trimIndent()

        val parsed = Json.parseToJsonElement(filterConfigCredentials(input)).jsonObject
        val headers = parsed["headers"]!!.jsonArray
        Assertions.assertEquals("*****", headers[0].jsonObject["value"]!!.jsonPrimitive.content)
        Assertions.assertEquals("*****", headers[1].jsonObject["header_value"]!!.jsonPrimitive.content)
        Assertions.assertEquals("*****", headers[2].jsonObject["value"]!!.jsonPrimitive.content)
        Assertions.assertEquals("*****", headers[3].jsonObject["values"]!!.jsonArray.single().jsonPrimitive.content)
        Assertions.assertEquals("safe-agent", headers[4].jsonObject["value"]!!.jsonPrimitive.content)
        val raw = parsed["raw"]!!.jsonArray.map { it.jsonPrimitive.content }
        Assertions.assertEquals("Cookie: *****", raw[0])
        Assertions.assertEquals("Set-Cookie: *****", raw[1])
        Assertions.assertEquals("Host: example.test", raw[2])
    }

    @Test
    fun `private material markers are redacted even below an otherwise generic key`() {
        val input = """{"blob":"-----BEGIN PRIVATE KEY-----\\nprivate-secret","other":"public"}"""
        val parsed = Json.parseToJsonElement(filterConfigCredentials(input)).jsonObject
        Assertions.assertEquals("*****", parsed["blob"]!!.jsonPrimitive.content)
        Assertions.assertEquals("public", parsed["other"]!!.jsonPrimitive.content)
    }

    @Test
    fun `exact normalized matching preserves unrelated key value settings`() {
        val input = """
        {
            "token_handling_rule": "preserve-me",
            "certificate_validation_enabled": true,
            "entry": { "key": "timeout", "value": "5000" }
        }
        """.trimIndent()
        val parsed = Json.parseToJsonElement(filterConfigCredentials(input)).jsonObject
        Assertions.assertEquals("preserve-me", parsed["token_handling_rule"]!!.jsonPrimitive.content)
        Assertions.assertTrue(parsed["certificate_validation_enabled"]!!.jsonPrimitive.boolean)
        Assertions.assertEquals("5000", parsed["entry"]!!.jsonObject["value"]!!.jsonPrimitive.content)
    }

    @Test
    fun `test security filter with username but no password on user_options`() {
        config.filterConfigCredentials = true
        val jsonWithUsernameOnly = get_user_options_with_customizable_field("testuser", "")
        val filteredJson = filterConfigCredentials(jsonWithUsernameOnly)
        val parsedJson = Json.parseToJsonElement(filteredJson).jsonObject

        val credentials = parsedJson["user_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("platform_authentication")?.jsonObject
            ?.get("credentials")?.jsonArray

        val socks_proxy = parsedJson["user_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("socks_proxy")?.jsonObject

        credentials?.forEach { credential ->
            val credentialObj = credential.jsonObject
            Assertions.assertEquals("*****", credentialObj["password"]?.jsonPrimitive?.content)
        }

        socks_proxy?.let {
            Assertions.assertEquals("*****", socks_proxy["password"]?.jsonPrimitive?.content)
        }
    }

    @Test
    fun `test security filter with username but no password on project_options`() {
        config.filterConfigCredentials = true
        val jsonWithUsernameOnly = get_project_options_with_customizable_field("testuser", "")
        val filteredJson = filterConfigCredentials(jsonWithUsernameOnly)
        val parsedJson = Json.parseToJsonElement(filteredJson).jsonObject

        val credentials = parsedJson["project_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("platform_authentication")?.jsonObject
            ?.get("credentials")?.jsonArray

        val socks_proxy = parsedJson["project_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("socks_proxy")?.jsonObject

        credentials?.forEach { credential ->
            val credentialObj = credential.jsonObject
            Assertions.assertEquals("*****", credentialObj["password"]?.jsonPrimitive?.content)
        }
        socks_proxy?.let {
            Assertions.assertEquals("*****", socks_proxy["password"]?.jsonPrimitive?.content)
        }
    }
}