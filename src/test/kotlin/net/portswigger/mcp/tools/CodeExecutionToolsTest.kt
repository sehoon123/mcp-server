package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.bambda.Bambda
import burp.api.montoya.bambda.BambdaImportResult as MontoyaBambdaImportResult
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.utilities.Utilities
import burp.api.montoya.utilities.shell.ExecuteOptions
import burp.api.montoya.utilities.shell.ExitCodeBehavior
import burp.api.montoya.utilities.shell.ShellUtils
import burp.api.montoya.utilities.shell.StderrBehavior
import burp.api.montoya.utilities.shell.TimeoutBehavior
import io.mockk.*
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.SensitiveActionApprovalHandler
import net.portswigger.mcp.security.SensitiveActionSecurity
import net.portswigger.mcp.testPreferences
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CodeExecutionToolsTest {
    private val api = mockk<MontoyaApi>()
    private val utilities = mockk<Utilities>()
    private val shellUtils = mockk<ShellUtils>()
    private val bambda = mockk<Bambda>()
    private val logging = mockk<Logging>(relaxed = true)
    private lateinit var originalSensitiveHandler: SensitiveActionApprovalHandler

    @BeforeEach
    fun setUp() {
        originalSensitiveHandler = SensitiveActionSecurity.approvalHandler
        SensitiveActionSecurity.approvalHandler = allowSensitive()
        every { api.utilities() } returns utilities
        every { utilities.shellUtils() } returns shellUtils
        every { api.bambda() } returns bambda
        mockkStatic(ExecuteOptions::class)
    }

    @AfterEach
    fun tearDown() {
        SensitiveActionSecurity.approvalHandler = originalSensitiveHandler
        unmockkStatic(ExecuteOptions::class)
    }

    @Test
    fun `local command requires the non-bypassable code execution toggle`() = runBlocking {
        val result = LocalCommandService(api, config(enabled = false)).execute(
            ExecuteLocalCommand(ShellInvocationMode.DIRECT, command = listOf("printf", "ok"))
        )

        assertEquals(NativeToolStatus.DISABLED, result.status)
        assertEquals(StandardExecutionState.NOT_STARTED, result.executionState)
        verify(exactly = 0) { utilities.shellUtils() }
    }

    @Test
    fun `shell approval preview preserves every argument boundary and environment value`() = runBlocking {
        var preview: String? = null
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean {
                preview = reviewContent
                return false
            }
        }

        options()
        val result = LocalCommandService(api, config(enabled = true)).execute(
            ExecuteLocalCommand(
                ShellInvocationMode.DIRECT,
                command = listOf("tool", "a\"b", ""),
                environment = mapOf("TOKEN" to "line1\nline2"),
            )
        )

        assertEquals(NativeToolStatus.ACCESS_DENIED, result.status)
        assertTrue(preview.orEmpty().contains("\"a\\\"b\" \"\""))
        assertTrue(preview.orEmpty().contains("TOKEN=line1\\nline2"))
        verify(exactly = 0) { shellUtils.execute(any<ExecuteOptions>(), *anyVararg()) }
    }

    @Test
    fun `YOLO cannot enable code execution and emergency mode wins after approval`() = runBlocking {
        val yoloDisabled = LocalCommandService(api, config(enabled = false, yolo = true)).execute(
            ExecuteLocalCommand(ShellInvocationMode.DIRECT, command = listOf("printf", "no"))
        )
        assertEquals(NativeToolStatus.DISABLED, yoloDisabled.status)

        var emergency = false
        SensitiveActionSecurity.approvalHandler = object : SensitiveActionApprovalHandler {
            override suspend fun requestApproval(
                action: String,
                summary: String,
                reviewContent: String?,
                renderContentAsHttp: Boolean,
                api: MontoyaApi,
            ): Boolean {
                emergency = true
                return true
            }
        }
        options()
        val blocked = LocalCommandService(
            api,
            config(enabled = true, emergency = { emergency }),
        ).execute(ExecuteLocalCommand(ShellInvocationMode.DIRECT, command = listOf("printf", "no")))

        assertEquals(NativeToolStatus.DISABLED, blocked.status)
        verify(exactly = 0) { shellUtils.execute(any<ExecuteOptions>(), *anyVararg()) }
    }

    @Test
    fun `direct command passes bounded options and truncates only the MCP preview`() = runBlocking {
        val options = options()
        every { shellUtils.execute(options, "printf", "%s", "hello") } returns "hello"

        val result = LocalCommandService(api, config(enabled = true)).execute(
            ExecuteLocalCommand(
                mode = ShellInvocationMode.DIRECT,
                command = listOf("printf", "%s", "hello"),
                timeoutSeconds = 5,
                outputLimitChars = 3,
            )
        )

        assertEquals(NativeToolStatus.OK, result.status)
        assertEquals("hel", result.output)
        assertEquals(5, result.outputChars)
        assertEquals(true, result.outputTruncated)
        verify(exactly = 1) { shellUtils.execute(options, "printf", "%s", "hello") }
        verify(exactly = 0) { shellUtils.dangerouslyExecute(any<ExecuteOptions>(), any()) }
    }

    @Test
    fun `native command failure is execution uncertain and forbids retry`() = runBlocking {
        val options = options()
        every { shellUtils.dangerouslyExecute(options, "touch /tmp/example") } throws IllegalStateException("private")

        val result = LocalCommandService(api, config(enabled = true)).execute(
            ExecuteLocalCommand(
                mode = ShellInvocationMode.SYSTEM_SHELL,
                commandLine = "touch /tmp/example",
            )
        )

        assertEquals(NativeToolStatus.EXECUTION_UNCERTAIN, result.status)
        assertEquals(ToolRetryGuidance.DO_NOT_RETRY, result.retry)
        assertFalse(result.error.orEmpty().contains("private"))
    }

    @Test
    fun `Bambda import wraps a deterministic Repeater custom action and bounds compiler errors`() = runBlocking {
        val nativeResult = mockk<MontoyaBambdaImportResult>()
        every { nativeResult.status() } returns MontoyaBambdaImportResult.Status.LOADED_WITH_ERRORS
        every { nativeResult.importErrors() } returns List(40) { "error-$it" }
        val envelope = slot<String>()
        every { bambda.importBambda(capture(envelope)) } returns nativeResult

        val result = BambdaService(api, config(enabled = true)).import(
            ImportBambda("Audit helper", "logging().logToOutput(\"ok\");")
        )

        assertEquals(NativeToolStatus.OK, result.status)
        assertEquals("imported_with_errors", result.importStatus)
        assertEquals(32, result.importErrors.size)
        assertTrue(result.importErrorsTruncated)
        assertTrue(envelope.captured.contains("function: CUSTOM_ACTION"))
        assertTrue(envelope.captured.contains("location: REPEATER"))
        assertTrue(envelope.captured.contains("  logging().logToOutput"))
        assertEquals(result.bambdaId, BambdaService(api, config(enabled = true)).import(
            ImportBambda("Audit helper", "logging().logToOutput(\"ok\");")
        ).bambdaId)
    }

    @Test
    fun `Bambda imports cap distinct persistent IDs while allowing replacement`() = runBlocking {
        val nativeResult = mockk<MontoyaBambdaImportResult>()
        every { nativeResult.status() } returns MontoyaBambdaImportResult.Status.LOADED_WITHOUT_ERRORS
        every { nativeResult.importErrors() } returns emptyList()
        every { bambda.importBambda(any()) } returns nativeResult
        val service = BambdaService(api, config(enabled = true))

        repeat(32) { index ->
            assertEquals(
                NativeToolStatus.OK,
                service.import(ImportBambda("Owned $index", "logging().logToOutput(\"ok\");")).status,
            )
        }
        assertEquals(
            NativeToolStatus.OK,
            service.import(ImportBambda("Owned 0", "logging().logToOutput(\"replacement\");")).status,
        )
        val exceeded = service.import(ImportBambda("Owned 32", "logging().logToOutput(\"no\");"))

        assertEquals(NativeToolStatus.LIMIT_EXCEEDED, exceeded.status)
        verify(exactly = 33) { bambda.importBambda(any()) }
    }

    @Test
    fun `chain rejects repeated optional regex quantifiers before native import`() = runBlocking {
        val result = BambdaService(api, config(enabled = true)).generateAndImport(
            GenerateBambdaChain(
                "Rejected selector", "example.test", 443, true,
                listOf(BambdaChainStep("GET", "/", extract = mapOf("value" to "(a?b?)"))),
            )
        )
        assertEquals(NativeToolStatus.INVALID_ARGUMENT, result.status)
        assertEquals(StandardExecutionState.NOT_STARTED, result.executionState)
        assertEquals(null, result.generatedBambda)
        verify(exactly = 0) { bambda.importBambda(any()) }
    }

    @Test
    fun `chain generator escapes literals validates dataflow and never logs extracted values`() {
        val generated = generateChainSource(
            GenerateBambdaChain(
                name = "Token chain",
                targetHostname = "example.test",
                targetPort = 443,
                usesHttps = true,
                steps = listOf(
                    BambdaChainStep(
                        method = "POST",
                        path = "/login",
                        body = "{\"name\":\"a\\\"b\"}",
                        extract = mapOf("token" to "$.token"),
                    ),
                    BambdaChainStep(
                        method = "GET",
                        path = "/me",
                        inject = mapOf("token" to "Authorization: Bearer {{token}}"),
                    ),
                ),
            )
        )

        assertTrue(generated.contains("HttpRequest.httpRequestFromUrl"))
        assertTrue(generated.contains("utilities().jsonUtils().readString"))
        assertTrue(generated.contains("vars.containsKey(\"token\")"))
        assertTrue(generated.contains("vars.getOrDefault(\"token\""))
        assertTrue(generated.contains("indexOf('\\r')"))
        assertFalse(generated.contains("extracted token="))
        val ipv6 = generateChainSource(
            GenerateBambdaChain(
                "IPv6 chain",
                "2001:db8::1",
                8443,
                true,
                listOf(BambdaChainStep("GET", "/")),
            )
        )
        assertTrue(ipv6.contains("https://[2001:db8::1]:8443/"))
        assertTrue(runCatching {
            generateChainSource(
                GenerateBambdaChain(
                    "Bad chain",
                    "example.test",
                    443,
                    true,
                    listOf(BambdaChainStep("GET", "/", inject = mapOf("missing" to "X: {{missing}}"))),
                )
            )
        }.isFailure)
        assertTrue(runCatching {
            generateChainSource(
                GenerateBambdaChain(
                    "Bad regex",
                    "example.test",
                    443,
                    true,
                    listOf(BambdaChainStep("GET", "/", extract = mapOf("value" to "(a)(b)"))),
                )
            )
        }.isFailure)
    }

    private fun options(): ExecuteOptions {
        val options = mockk<ExecuteOptions>()
        every { ExecuteOptions.executeOptions() } returns options
        every { options.withTimeout(any<java.time.Duration>()) } returns options
        every { options.withTimeoutBehavior(any()) } returns options
        every { options.withStderrBehavior(any()) } returns options
        every { options.withExitCodeBehavior(any()) } returns options
        every { options.withEnvironmentVariable(any(), any()) } returns options
        return options
    }

    private fun config(
        enabled: Boolean,
        yolo: Boolean = false,
        emergency: () -> Boolean = { false },
    ): McpConfig {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers {
            when (firstArg<String>()) {
                "codeExecutionTooling" -> enabled
                "approvalYoloMode" -> yolo
                "emergencyReadOnlyMode" -> emergency()
                else -> false
            }
        }
        return McpConfig(storage, logging, testPreferences())
    }

    private fun allowSensitive() = object : SensitiveActionApprovalHandler {
        override suspend fun requestApproval(
            action: String,
            summary: String,
            reviewContent: String?,
            renderContentAsHttp: Boolean,
            api: MontoyaApi,
        ): Boolean = true
    }
}
